[CmdletBinding()]
param(
    [ValidateSet('ClientInfo', 'Continue')][string]$Action = 'ClientInfo',
    [ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$Operation = '00000000-0000-0000-0000-000000000000',
    [string]$Origin = '',
    [ValidatePattern('^[0-9a-f]{32}$')][string]$Run = '',
    [long]$DeadlineUnix = 0,
    [switch]$Worker
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'RapporLab-WorkspaceContinuation'
$root = 'C:\RapporLab\runtime'
if (-not $Worker) { $Run = [guid]::NewGuid().ToString('N') }
$directory = Join-Path $root ('workspace-call-' + $Run)
$resultPath = Join-Path $directory 'result.json'
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($Action -eq 'ClientInfo') { $DeadlineUnix = $now + 45 }
if ($DeadlineUnix -le $now + 10 -or $DeadlineUnix -gt $now + 590) { throw 'The bounded continuation deadline is invalid.' }
if ($Action -eq 'Continue') {
    $parsed = [uri]$Origin
    if ($parsed.Scheme -ne 'https' -or $parsed.UserInfo -or $parsed.Query -or $parsed.Fragment -or $parsed.AbsolutePath -ne '/') {
        throw 'Invalid workspace origin.'
    }
    [void][guid]::ParseExact($Operation, 'D')
}
if ($Worker) {
    $result = @{ exitCode = 1; failureClass = 'interactive-client-failed'; graphicalSession = $false }
    $process = $null
    try {
        $sessionId = (Get-Process -Id $PID).SessionId
        if ($sessionId -eq 0) { throw 'Interactive session is required.' }
        $result.graphicalSession = $true
        $uiScope = $null
        if ($Action -eq 'Continue') {
            $uiScope = Get-Content -LiteralPath (Join-Path $root 'browser-preparation\workspace-ui-scope.json') -Raw | ConvertFrom-Json
            if ($uiScope.origin -ne $Origin -or $uiScope.deadlineUnix -ne $DeadlineUnix -or $uiScope.workspace -ne 'C:\RapporLab\corpus') { throw 'The authorized UI scope does not match this invocation.' }
            [void][guid]::ParseExact($uiScope.computerId, 'D')
            . (Join-Path $root 'workspace-ui.ps1')
        }
        $package = Get-AppxPackage -Name Rappor.RapporSecurity
        if ($null -eq $package) { throw 'Official package is unavailable.' }
        $executable = Join-Path $package.InstallLocation 'rappor.exe'
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Official client is unavailable.' }
        $arguments = if ($Action -eq 'ClientInfo') { @('client-info') } else {
            @('workspace', 'continue', '--operation', $Operation, '--control-plane', $Origin, '--protocol', '1')
        }
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $executable
        $start.Arguments = $arguments -join ' '
        $start.WorkingDirectory = if ($Action -eq 'Continue') { 'C:\RapporLab\corpus' } else { $root }
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $uiEvents = @()
        while (-not $process.WaitForExit(500)) {
            if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $DeadlineUnix - 10) {
                & taskkill.exe /PID $process.Id /T /F *> $null
                $result.failureClass = 'interactive-client-timeout'
                throw 'The public client timed out.'
            }
            if ($Action -eq 'Continue') {
                $uiState = Invoke-LaboratoryWorkspaceUi -ClientProcessId $process.Id -Operation $Operation -Origin $Origin -ComputerId $uiScope.computerId
                if ($uiState -notin $uiEvents) {
                    $uiEvents += $uiState
                    [IO.File]::WriteAllText((Join-Path $directory 'ui-progress.json'), ($uiEvents | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
                }
                if ($uiState -like 'unexpected-*' -or $uiState -in @('native-controls-unavailable', 'browser-controls-unavailable')) {
                    & taskkill.exe /PID $process.Id /T /F *> $null
                    $result.failureClass = $uiState
                    throw 'The public UI does not match the authorized target.'
                }
            }
        }
        $output = $stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        if ($output.Length -gt 65536) { throw 'Public client output exceeded its limit.' }
        $events = @($output -split '\r?\n' | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
        $result = @{ exitCode = $process.ExitCode; graphicalSession = $true; events = $events; uiEvents = $uiEvents }
    }
    catch { if ($null -ne $process -and -not $process.HasExited) { & taskkill.exe /PID $process.Id /T /F *> $null } }
    $temporary = Join-Path $directory 'result.tmp'
    [IO.File]::WriteAllText($temporary, ($result | ConvertTo-Json -Compress -Depth 8), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $resultPath
    exit
}
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
if ($interactiveUser -ne "$env:COMPUTERNAME\$env:USERNAME") { throw 'The laboratory desktop login is required.' }
if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { throw 'Another continuation task is present.' }
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
# Only the already authenticated laboratory account and SYSTEM can read continuation metadata.
& icacls.exe $directory /inheritance:r /grant:r ('{0}:(OI)(CI)F' -f $interactiveUser) '*S-1-5-18:(OI)(CI)F' *> $null
if ($LASTEXITCODE -ne 0) { throw 'The private continuation directory could not be secured.' }
$script = $PSCommandPath.Replace("'", "''")
$escapedOrigin = $Origin.Replace("'", "''")
$command = "& '$script' -Worker -Action $Action -Run $Run -Operation '$Operation' -Origin '$escapedOrigin' -DeadlineUnix $DeadlineUnix"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
$principal = New-ScheduledTaskPrincipal -UserId $interactiveUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds($DeadlineUnix - $now))
try {
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $principal -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTimeOffset]::FromUnixTimeSeconds($DeadlineUnix)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        if ([DateTimeOffset]::UtcNow -gt $deadline) { throw 'The graphical continuation task timed out.' }
        Start-Sleep -Milliseconds 500
    }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($Action -eq 'ClientInfo') {
        if ($result.exitCode -ne 0 -or -not $result.graphicalSession) { throw 'The public client probe failed.' }
        $info = @($result.events)[-1]
        Write-Output ('RAPPOR_LAB_RESULT=' + (@{ passed = $true; graphicalSession = $true; client = $info.client; protocolVersion = $info.protocolVersion; sourceRevision = $info.sourceRevision; computerAvailable = $info.computerAvailable; managedAvailable = $info.managedAvailable } | ConvertTo-Json -Compress))
    }
    else {
        if ($result.PSObject.Properties.Name -contains 'events') {
            foreach ($event in $result.events) { Write-Output ($event | ConvertTo-Json -Compress -Depth 8) }
        }
        else { Write-Output '{"failureCode":"InteractiveClientUnavailable"}' }
    }
    if ($result.PSObject.Properties.Name -contains 'uiEvents') { Write-Output ('RAPPOR_LAB_UI=' + ($result.uiEvents | ConvertTo-Json -Compress)) }
    if ($result.PSObject.Properties.Name -contains 'failureClass') { Write-Output ('RAPPOR_LAB_FAILURE=' + $result.failureClass) }
    exit $result.exitCode
}
finally {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($name in @('result.json', 'result.tmp', 'ui-progress.json')) {
        $file = Join-Path $directory $name
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
    if (@(Get-ChildItem -LiteralPath $directory).Count -eq 0) { Remove-Item -LiteralPath $directory }
}
