[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'Preflight',
        'InspectCandidate',
        'InstallCandidate',
        'RemoveCandidate',
        'ProvisionDockerStart',
        'DockerStop',
        'DockerStart',
        'MissingImage',
        'CloneExpiredConfig',
        'CompareExpiredConfig',
        'DiagnoseConfig',
        'DiagnoseExpiredConfig',
        'StoreCredential',
        'BackupConfig',
        'CorruptConfig',
        'RestoreConfig',
        'CleanupWorkspace'
    )]
    [string]$Action,
    [string]$CandidateSha256 = '',
    [string]$CandidateVersion = '',
    [string]$ArchitectureOverride = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RuntimeDirectory = 'C:\RapporLab\runtime'
$script:CandidatePath = Join-Path $script:RuntimeDirectory 'candidate.msix'
$script:PackageIdentity = 'Rappor.RapporSecurity'
$script:InstallDirectory = Join-Path $env:LOCALAPPDATA 'Rappor Security\Agent'
$script:ConfigVolume = 'rappor-agent-self-hosted-config'
$script:ExpiredConfigVolume = 'rappor-agent-lab-expired-config'
$script:BackupConfigVolume = 'rappor-agent-lab-config-backup'
$script:ConfigurationPath = '/var/lib/rappor-agent/config/agent.json'
$script:CredentialPath = '/var/lib/rappor-agent/config/agent-credential'
$script:DockerConfigDirectory = 'C:\RapporLab\docker-config'

function Write-Result([hashtable]$Value) {
    Write-Output ('RAPPOR_LAB_RESULT=' + ($Value | ConvertTo-Json -Compress -Depth 8))
}

function Invoke-Native([string]$FilePath, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = [int]$LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output }
}

function Invoke-ReadinessProbe([string]$Phase, [string]$FilePath, [string[]]$Arguments) {
    Write-Host ('RAPPOR_LAB_PHASE=' + $Phase)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    # WSL treats a quoted option as a shell command. Quote only arguments containing whitespace.
    # These arguments are fixed readiness literals, never credentials or caller input.
    if (@($Arguments | Where-Object { $_.Contains('"') }).Count -ne 0) {
        throw 'Readiness probe arguments must not contain quotes.'
    }
    $start.Arguments = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(20000)) {
            & taskkill.exe /PID $process.Id /T /F *> $null
            throw ('The bounded readiness probe timed out: ' + $Phase)
        }
        $output = $stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        if ($output.Length -gt 1048576) { throw 'Readiness output exceeded its limit.' }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @($output) }
    }
    finally { $process.Dispose() }
}

function Get-DockerPath {
    $command = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Docker\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\resources\bin\docker.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Initialize-DockerConfig {
    $dockerPath = Get-DockerPath
    if ([string]::IsNullOrWhiteSpace($dockerPath)) { return }
    $resources = Split-Path (Split-Path $dockerPath -Parent) -Parent
    $plugins = Join-Path $resources 'cli-plugins'
    if (-not (Test-Path -LiteralPath (Join-Path $plugins 'docker-compose.exe') -PathType Leaf)) {
        throw 'The official Docker Compose plugin is unavailable.'
    }
    [IO.Directory]::CreateDirectory($script:DockerConfigDirectory) | Out-Null
    $configuration = @{ cliPluginsExtraDirs = @($plugins); auths = @{ 'ghcr.io' = @{} } } | ConvertTo-Json -Compress -Depth 5
    [IO.File]::WriteAllText((Join-Path $script:DockerConfigDirectory 'config.json'), $configuration,
        [Text.UTF8Encoding]::new($false))
    $env:DOCKER_CONFIG = $script:DockerConfigDirectory
}

function Get-DockerDesktopPath {
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Get-InstallImage {
    $environmentPath = Join-Path $script:InstallDirectory 'install.env'
    if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
        throw 'The installed agent environment is unavailable.'
    }
    $content = Get-Content -LiteralPath $environmentPath -Raw
    $match = [regex]::Match($content, "(?:^|\s)RAPPOR_AGENT_IMAGE='([^']+)'(?:\s|$)")
    if (-not $match.Success) {
        throw 'The installed agent image coordinate is invalid.'
    }
    return $match.Groups[1].Value
}

function Get-ControlPlane {
    $environmentPath = Join-Path $script:InstallDirectory 'install.env'
    $content = Get-Content -LiteralPath $environmentPath -Raw
    $match = [regex]::Match($content, "(?:^|\s)RAPPOR_AGENT_CONTROL_PLANE='([^']+)'(?:\s|$)")
    if (-not $match.Success) {
        throw 'The installed control-plane coordinate is invalid.'
    }
    return $match.Groups[1].Value
}

function Invoke-Docker([string[]]$Arguments) {
    $docker = Get-DockerPath
    if ([string]::IsNullOrWhiteSpace($docker)) { throw 'Docker CLI is unavailable.' }
    return Invoke-Native $docker $Arguments
}

function Get-VolumeExists([string]$Name) {
    return (Invoke-Docker @('volume', 'inspect', $Name)).ExitCode -eq 0
}

function Copy-Volume([string]$Source, [string]$Target) {
    if (-not (Get-VolumeExists $Source)) { throw 'The source Docker volume is unavailable.' }
    [void](Invoke-Docker @('volume', 'rm', '--force', $Target))
    $created = Invoke-Docker @('volume', 'create', $Target)
    if ($created.ExitCode -ne 0) { throw 'The disposable Docker volume could not be created.' }
    $image = Get-InstallImage
    $copy = Invoke-Docker @(
        'run', '--rm', '--user', '0:0',
        '--mount', "type=volume,src=$Source,dst=/source,readonly",
        '--mount', "type=volume,src=$Target,dst=/target",
        '--entrypoint', '/bin/sh', $image, '-c', 'cp -a /source/. /target/'
    )
    if ($copy.ExitCode -ne 0) { throw 'The disposable Docker volume could not be populated.' }
}

function Invoke-Preflight {
    Write-Host 'RAPPOR_LAB_PHASE=processor'
    $processor = @(Get-CimInstance Win32_Processor | Select-Object -First 1)
    $observedArchitecture = if ($processor.Count -eq 1 -and $processor[0].Architecture -eq 12) {
        'arm64'
    } elseif ($processor.Count -eq 1 -and $processor[0].Architecture -eq 9) {
        'x64'
    } else {
        'unsupported'
    }
    $effectiveArchitecture = if ([string]::IsNullOrWhiteSpace($ArchitectureOverride)) {
        $observedArchitecture
    } else {
        $ArchitectureOverride
    }
    $drive = Get-PSDrive -Name C
    $wslStatus = Invoke-ReadinessProbe 'wsl-status' 'wsl.exe' @('--status')
    $wslVersion = Invoke-ReadinessProbe 'wsl-version' 'wsl.exe' @('--version')
    $dockerPath = Get-DockerPath
    $desktopPath = Get-DockerDesktopPath
    $dockerReady = $false
    $composeReady = $false
    $linuxContainers = $false
    $dockerVersion = $null
    if (-not [string]::IsNullOrWhiteSpace($dockerPath)) {
        $info = Invoke-ReadinessProbe 'docker-info' $dockerPath @('info', '--format', '{{json .}}')
        if ($info.ExitCode -eq 0) {
            try {
                $parsedInfo = ((@($info.Output) -join [Environment]::NewLine) | ConvertFrom-Json)
                $dockerReady = $true
                $linuxContainers = $parsedInfo.OSType -eq 'linux'
            } catch { }
        }
        $composeReady = (Invoke-ReadinessProbe 'compose-version' $dockerPath @('compose', 'version')).ExitCode -eq 0
        $version = Invoke-ReadinessProbe 'docker-version' $dockerPath @('version', '--format', '{{.Server.Version}}')
        if ($version.ExitCode -eq 0) { $dockerVersion = (@($version.Output) -join '').Trim() }
    }
    $desktopVersion = $null
    if (-not [string]::IsNullOrWhiteSpace($desktopPath)) {
        $desktopVersion = (Get-Item -LiteralPath $desktopPath).VersionInfo.ProductVersion
    }
    Write-Host 'RAPPOR_LAB_PHASE=package'
    $package = Get-AppxPackage -Name $script:PackageIdentity -ErrorAction SilentlyContinue
    $installedVersion = if ($null -eq $package) { $null } else { [string]$package.Version }
    $failureClass = if ($effectiveArchitecture -notin @('x64', 'arm64')) {
        'unsupported-architecture'
    } elseif (-not $dockerReady) {
        'docker-not-ready'
    } elseif (-not $linuxContainers) {
        'windows-containers-active'
    } else {
        $null
    }
    Write-Result @{
        passed = $null -eq $failureClass
        failureClass = $failureClass
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        observedArchitecture = $observedArchitecture
        effectiveArchitecture = $effectiveArchitecture
        guestFreeBytes = [int64]$drive.Free
        wsl2 = $wslStatus.ExitCode -eq 0 -and $wslVersion.ExitCode -eq 0
        dockerDesktop = $null -ne $desktopVersion
        dockerDesktopVersion = $desktopVersion
        dockerReady = $dockerReady
        dockerVersion = $dockerVersion
        composeV2 = $composeReady
        installedVersion = $installedVersion
        packageStatus = if ($null -eq $package) { $null } else { [string]$package.Status }
        linuxContainers = $linuxContainers
    }
}

function Get-PackageResult {
    $package = Get-AppxPackage -Name $script:PackageIdentity -ErrorAction SilentlyContinue
    if ($null -eq $package) {
        return @{ installed = $false; version = $null; architecture = $null; status = $null }
    }
    return @{
        installed = $true
        version = [string]$package.Version
        architecture = [string]$package.Architecture
        status = [string]$package.Status
    }
}

function Assert-Candidate {
    if ($CandidateSha256 -notmatch '^[a-f0-9]{64}$') { throw 'The candidate SHA-256 is invalid.' }
    if (-not (Test-Path -LiteralPath $script:CandidatePath -PathType Leaf)) {
        throw 'The staged official MSIX candidate is unavailable.'
    }
    $observed = (Get-FileHash -LiteralPath $script:CandidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($observed -ne $CandidateSha256) { throw 'The staged official MSIX hash does not match the pinned candidate.' }
}

function Invoke-InspectCandidate {
    Assert-Candidate
    $signature = Get-AuthenticodeSignature -LiteralPath $script:CandidatePath
    if ($signature.Status -ne 'Valid') { throw 'The staged official MSIX signature is not valid.' }
    $package = Get-PackageResult
    Write-Result @{
        candidateSha256 = $CandidateSha256
        signatureStatus = [string]$signature.Status
        installed = $package.installed
        installedVersion = $package.version
        installedArchitecture = $package.architecture
        packageStatus = $package.status
    }
}

function Invoke-InstallCandidate {
    Assert-Candidate
    # AppX deployment must use the existing desktop token, not the SSH logon token.
    if ((Get-Process -Id $PID).SessionId -eq 0) {
        & (Join-Path $script:RuntimeDirectory 'package-interactive.ps1') -CandidateSha256 $CandidateSha256 -CandidateVersion $CandidateVersion
        if ($LASTEXITCODE -ne 0) { throw 'The interactive package installation failed.' }
        return
    }
    if ($CandidateVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw 'The candidate version is invalid.'
    }
    $idempotent = $false
    try {
        Add-AppxPackage -Path $script:CandidatePath -ForceApplicationShutdown -ErrorAction Stop
    }
    catch {
        $package = Get-PackageResult
        if ($package.installed -and $package.version -eq $CandidateVersion -and $package.status -eq 'Ok') {
            $idempotent = $true
        }
        else { throw }
    }
    $installed = Get-PackageResult
    if (-not $installed.installed -or $installed.version -ne $CandidateVersion -or
        $installed.architecture -ne 'X64' -or $installed.status -ne 'Ok') {
        throw 'The official MSIX candidate did not reach the expected installed state.'
    }
    Write-Result @{
        installed = $true
        version = $installed.version
        architecture = $installed.architecture
        status = $installed.status
        idempotent = $idempotent
    }
}

function Invoke-RemoveCandidate {
    $package = Get-AppxPackage -Name $script:PackageIdentity -ErrorAction SilentlyContinue
    if ($null -ne $package) { Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop }
    if ($null -ne (Get-AppxPackage -Name $script:PackageIdentity -ErrorAction SilentlyContinue)) {
        throw 'The candidate package remained installed.'
    }
    Write-Result @{ removed = $true }
}

function Invoke-DockerStop {
    $docker = Get-DockerPath
    if ([string]::IsNullOrWhiteSpace($docker)) { throw 'Docker CLI is unavailable.' }
    $result = Invoke-Native $docker @('desktop', 'stop', '--timeout', '120')
    if ($result.ExitCode -ne 0) { throw 'Docker Desktop could not be stopped.' }
    Write-Result @{ stopped = $true }
}

function Test-DockerDaemonReady {
    param([Parameter(Mandatory=$true)][string]$DockerPath)
    try {
        $info = Invoke-ReadinessProbe 'docker-info' $DockerPath @('info', '--format', '{{json .}}')
        if ($info.ExitCode -ne 0) { return $false }
        $server = (@($info.Output) -join [Environment]::NewLine) | ConvertFrom-Json
        return -not [string]::IsNullOrWhiteSpace([string]$server.ServerVersion)
    } catch { return $false }
}

function Invoke-DockerStart {
    $docker = Get-DockerPath
    if ([string]::IsNullOrWhiteSpace($docker)) { throw 'Docker CLI is unavailable.' }
    # Ending the task can also terminate its healthy Docker child processes.
    if (Test-DockerDaemonReady $docker) {
        Write-Result @{ started = $true; alreadyReady = $true }
        return
    }
    [void](Invoke-Native 'schtasks.exe' @('/End', '/TN', '\RapporLab-StartDocker'))
    $start = Invoke-Native 'schtasks.exe' @('/Run', '/TN', '\RapporLab-StartDocker')
    if ($start.ExitCode -ne 0) { throw 'The headless Docker Desktop task could not be started.' }
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
    do {
        if (Test-DockerDaemonReady $docker) {
            Write-Result @{ started = $true; alreadyReady = $false }
            return
        }
        Start-Sleep -Seconds 3
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Docker Desktop did not become ready.'
}

function Invoke-ProvisionDockerStart {
    $keepalive = 'C:\RapporLab\docker-keepalive.ps1'
    if (-not (Test-Path -LiteralPath $keepalive -PathType Leaf)) {
        throw 'The headless Docker Desktop keepalive is unavailable.'
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $keepalive + '"')
    $principal = New-ScheduledTaskPrincipal -UserId ("$env:COMPUTERNAME\$env:USERNAME") `
        -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'RapporLab-StartDocker' -Action $action -Principal $principal `
        -Settings $settings -Force | Out-Null
    Write-Result @{ provisioned = $true; credentialStored = $false }
}

function Invoke-MissingImage {
    $result = Invoke-Docker @('manifest', 'inspect', 'ghcr.io/renersilv/rappor-agent-self-hosted:sha-0000000000000000000000000000000000000000')
    if ($result.ExitCode -eq 0) { throw 'The deliberately absent image unexpectedly exists.' }
    Write-Result @{ failureClass = 'image-unavailable'; recovered = $true }
}

function Invoke-CompareExpiredConfiguration {
    if (-not (Get-VolumeExists $script:ConfigVolume) -or
        -not (Get-VolumeExists $script:ExpiredConfigVolume)) {
        throw 'The source or expired configuration volume is unavailable.'
    }
    $image = Get-InstallImage
    $mounts = @(
        '--mount', "type=volume,src=$($script:ConfigVolume),dst=/source,readonly",
        '--mount', "type=volume,src=$($script:ExpiredConfigVolume),dst=/target,readonly"
    )
    function Invoke-Comparison([string]$EntryPoint, [string[]]$ToolArguments) {
        $arguments = @('run', '--rm', '--user', '0:0', '--read-only') + $mounts +
            @('--entrypoint', $EntryPoint, $image) + $ToolArguments
        return Invoke-Docker $arguments
    }
    $configurationContent = Invoke-Comparison '/usr/bin/cmp' @('-s', '/source/agent.json', '/target/agent.json')
    $credentialContent = Invoke-Comparison '/usr/bin/cmp' @('-s', '/source/agent-credential', '/target/agent-credential')
    $metadata = Invoke-Comparison '/bin/stat' @(
        '-c', '%u:%g:%a:%s', '/source/agent.json', '/target/agent.json',
        '/source/agent-credential', '/target/agent-credential'
    )
    $rootMetadata = Invoke-Comparison '/bin/stat' @('-c', '%u:%g:%a', '/source', '/target')
    $metadataLines = @($metadata.Output | ForEach-Object { [string]$_ })
    $rootLines = @($rootMetadata.Output | ForEach-Object { [string]$_ })
    if ($configurationContent.ExitCode -notin @(0, 1) -or $credentialContent.ExitCode -notin @(0, 1) -or
        $metadata.ExitCode -ne 0 -or $rootMetadata.ExitCode -ne 0 -or
        $metadataLines.Count -ne 4 -or $rootLines.Count -ne 2) {
        throw 'The configuration copies could not be compared safely.'
    }
    Write-Result @{
        rootMetadataMatch = $rootLines[0] -eq $rootLines[1]
        configurationContentMatch = $configurationContent.ExitCode -eq 0
        configurationMetadataMatch = $metadataLines[0] -eq $metadataLines[1]
        credentialContentMatch = $credentialContent.ExitCode -eq 0
        credentialMetadataMatch = $metadataLines[2] -eq $metadataLines[3]
    }
}

function Invoke-DiagnoseVolume([string]$Volume) {
    $controlPlane = Get-ControlPlane
    $result = Invoke-Docker @(
        'compose', '--env-file', (Join-Path $script:InstallDirectory 'install.env'),
        '--file', (Join-Path $script:InstallDirectory 'compose.yaml'),
        'run', '--rm', '--no-deps', '--no-TTY',
        '--entrypoint', '/app/agent/rappor-agent',
        '--volume', "$Volume`:/var/lib/rappor-agent/config:ro",
        'agent', 'diagnose',
        $script:ConfigurationPath, '--expected-url', $controlPlane, '--without-heartbeat'
    )
    $text = @($result.Output) -join [Environment]::NewLine
    foreach ($category in @(
        'ready', 'credential-rejected', 'protocol-incompatible', 'control-plane-unavailable',
        'different-control-plane', 'configuration-invalid', 'local-requirements-unavailable',
        'diagnosis-inconclusive'
    )) {
        if ($text -match ('RAPPOR_DIAGNOSTIC_RESULT=' + [regex]::Escape($category))) { return $category }
    }
    return 'diagnosis-inconclusive'
}

function Invoke-StoreCredential {
    $credential = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($credential)) { throw 'The replacement credential is required.' }
    $image = Get-InstallImage
    $docker = Get-DockerPath
    $arguments = @(
        'run', '--rm', '--interactive', '--user', '1654:1654', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--mount', "type=volume,src=$($script:ConfigVolume),dst=/var/lib/rappor-agent/config",
        '--entrypoint', '/app/agent/rappor-agent', $image, 'store-credential',
        $script:ConfigurationPath, $script:CredentialPath
    )
    try {
        $credential | & $docker @arguments *> $null
        if ($LASTEXITCODE -ne 0) { throw 'The replacement credential was rejected.' }
    }
    finally {
        $credential = $null
    }
    $compose = @(
        'compose', '--env-file', (Join-Path $script:InstallDirectory 'install.env'),
        '--file', (Join-Path $script:InstallDirectory 'compose.yaml'),
        'up', '--detach', '--force-recreate', '--no-build', 'agent'
    )
    if ((Invoke-Native $docker $compose).ExitCode -ne 0) { throw 'The agent could not restart after rotation.' }
    Write-Result @{ stored = $true }
}

function Invoke-CorruptConfig {
    $image = Get-InstallImage
    $stop = Invoke-Docker @(
        'compose', '--env-file', (Join-Path $script:InstallDirectory 'install.env'),
        '--file', (Join-Path $script:InstallDirectory 'compose.yaml'), 'stop', 'agent'
    )
    if ($stop.ExitCode -ne 0) { throw 'The agent could not be stopped for the invalid configuration case.' }
    $result = Invoke-Docker @(
        'run', '--rm', '--user', '0:0',
        '--mount', "type=volume,src=$($script:ConfigVolume),dst=/var/lib/rappor-agent/config",
        '--entrypoint', '/bin/sh', $image, '-c',
        "printf invalid > '$($script:ConfigurationPath)'"
    )
    if ($result.ExitCode -ne 0) { throw 'The controlled invalid configuration could not be installed.' }
    Write-Result @{ corrupted = $true }
}

Initialize-DockerConfig

switch ($Action) {
    'Preflight' { Invoke-Preflight }
    'InspectCandidate' { Invoke-InspectCandidate }
    'InstallCandidate' { Invoke-InstallCandidate }
    'RemoveCandidate' { Invoke-RemoveCandidate }
    'ProvisionDockerStart' { Invoke-ProvisionDockerStart }
    'DockerStop' { Invoke-DockerStop }
    'DockerStart' { Invoke-DockerStart }
    'MissingImage' { Invoke-MissingImage }
    'CloneExpiredConfig' {
        Copy-Volume $script:ConfigVolume $script:ExpiredConfigVolume
        Write-Result @{ cloned = $true; configurationPreserved = $true; credentialPreserved = $true }
    }
    'CompareExpiredConfig' { Invoke-CompareExpiredConfiguration }
    'DiagnoseConfig' {
        Write-Result @{ category = (Invoke-DiagnoseVolume $script:ConfigVolume) }
    }
    'DiagnoseExpiredConfig' {
        Write-Result @{ category = (Invoke-DiagnoseVolume $script:ExpiredConfigVolume) }
    }
    'StoreCredential' { Invoke-StoreCredential }
    'BackupConfig' {
        Copy-Volume $script:ConfigVolume $script:BackupConfigVolume
        Write-Result @{ backedUp = $true }
    }
    'CorruptConfig' { Invoke-CorruptConfig }
    'RestoreConfig' {
        Copy-Volume $script:BackupConfigVolume $script:ConfigVolume
        [void](Invoke-Docker @('volume', 'rm', '--force', $script:BackupConfigVolume))
        $restart = Invoke-Docker @(
            'compose', '--env-file', (Join-Path $script:InstallDirectory 'install.env'),
            '--file', (Join-Path $script:InstallDirectory 'compose.yaml'),
            'up', '--detach', '--force-recreate', '--no-build', 'agent'
        )
        if ($restart.ExitCode -ne 0) { throw 'The agent could not restart with the restored configuration.' }
        Write-Result @{ restored = $true }
    }
    'CleanupWorkspace' {
        if (Test-Path -LiteralPath 'C:\RapporLab\corpus') {
            Remove-Item -LiteralPath 'C:\RapporLab\corpus' -Recurse -Force
        }
        if (Test-Path -LiteralPath $script:CandidatePath) {
            Remove-Item -LiteralPath $script:CandidatePath -Force
        }
        foreach ($volume in @($script:ExpiredConfigVolume, $script:BackupConfigVolume)) {
            [void](Invoke-Docker @('volume', 'rm', '--force', $volume))
        }
        Write-Result @{ cleaned = $true }
    }
}
