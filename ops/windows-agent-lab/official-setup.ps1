[CmdletBinding()]
param(
    [ValidateSet('Inspect', 'Open', 'Refresh', 'DownloadAgent', 'PrepareAgent', 'StartAgent')]
    [string]$Action = 'Inspect',
    [string]$Origin = '',
    [switch]$InteractiveProbe
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$resultPath = 'C:\RapporLab\runtime\official-setup-result.json'
if ($InteractiveProbe) {
    try {
        if ($Action -eq 'Open') {
            $uri = [uri]$Origin
            if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') {
                throw 'Invalid laboratory origin.'
            }
            Start-Process ('rappor-security://connect?origin=' + [uri]::EscapeDataString($uri.AbsoluteUri))
            $result = @{ state = 'opened'; action = 'Open' }
        }
        else {
            Add-Type -AssemblyName UIAutomationClient
            Add-Type -AssemblyName UIAutomationTypes
            $session = (Get-Process -Id $PID).SessionId
            $processes = @(Get-Process Rappor.Windows -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session)
            if ($processes.Count -ne 1) { throw 'Official application is unavailable.' }
            $condition = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty, $processes[0].Id)
            $window = [Windows.Automation.AutomationElement]::RootElement.FindFirst([Windows.Automation.TreeScope]::Children, $condition)
            if ($null -eq $window) { throw 'Official window is unavailable.' }
            $elements = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
            # Intentional locale test data from the released application's public controls.
            $labels = @{
                Refresh = @('Verificar novamente', 'Check again')
                DownloadAgent = @('Baixar o agente verificado', 'Download the verified agent')
                PrepareAgent = @('Preparar o agente', 'Prepare the agent')
                StartAgent = @('Iniciar a conexão segura', 'Start the secure connection')
            }
            $buttons = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and -not $_.Current.IsOffscreen })
            if ($Action -eq 'Inspect') {
                $names = @($elements | ForEach-Object { $_.Current.Name })
                $available = @($labels.Keys | Where-Object { $label = $labels[$_]; @($buttons | Where-Object { $_.Current.IsEnabled -and $label -contains $_.Current.Name }).Count -eq 1 })
                $result = @{
                    state = 'inspected'; actions = $available
                    connected = ($names -contains 'Computador conectado' -or $names -contains 'Computer connected')
                    repairRequired = ($names -contains 'Substituir a conexão inativa' -or $names -contains 'Replace the inactive connection')
                    checking = ($names -contains 'Verificando este computador' -or $names -contains 'Checking this computer')
                }
            }
            else {
                $matches = @($buttons | Where-Object { $_.Current.IsEnabled -and $labels[$Action] -contains $_.Current.Name })
                if ($matches.Count -ne 1) { throw 'Expected public action is unavailable.' }
                $pattern = $matches[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)
                $pattern.Invoke()
                $result = @{ state = 'invoked'; action = $Action }
            }
        }
    }
    catch { $result = @{ state = 'failed'; failureClass = 'official-setup-ui-unavailable' } }
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Compress -Depth 4), [Text.UTF8Encoding]::new($false))
    exit
}
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
if ($interactiveUser -ne "$env:COMPUTERNAME\$env:USERNAME") {
    Write-Output 'RAPPOR_LAB_RESULT={"state":"failed","failureClass":"laboratory-desktop-login-required"}'
    exit
}
if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
$script = $PSCommandPath.Replace("'", "''")
$escapedOrigin = $Origin.Replace("'", "''")
$command = "& '$script' -InteractiveProbe -Action $Action -Origin '$escapedOrigin'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
$principal = New-ScheduledTaskPrincipal -UserId $interactiveUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(45))
$bridgeStage = 'register'
try {
    Register-ScheduledTask -TaskName RapporLab-OfficialSetupProbe -Action $taskAction -Principal $principal -Settings $settings -Force | Out-Null
    $bridgeStage = 'start'
    Start-ScheduledTask -TaskName RapporLab-OfficialSetupProbe
    $bridgeStage = 'wait'
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(40)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        if ([DateTimeOffset]::UtcNow -gt $deadline) { throw 'Official UI probe timed out.' }
        Start-Sleep -Milliseconds 250
    }
    $bridgeStage = 'read'
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    Write-Output ('RAPPOR_LAB_RESULT=' + ($result | ConvertTo-Json -Compress -Depth 4))
}
catch {
    $failureClass = 'official-setup-' + $bridgeStage + '-failed'
    $taskState = 'unavailable'
    $taskCode = -1
    try {
        $task = Get-ScheduledTask -TaskName RapporLab-OfficialSetupProbe -ErrorAction Stop
        $taskState = if (@('Disabled', 'Queued', 'Ready', 'Running') -contains [string]$task.State) {
            ([string]$task.State).ToLowerInvariant()
        } else { 'unknown' }
        $taskCode = [long](Get-ScheduledTaskInfo -TaskName RapporLab-OfficialSetupProbe -ErrorAction Stop).LastTaskResult
    }
    catch { }
    Write-Output ('RAPPOR_LAB_RESULT=' + (@{
        state = 'failed'; failureClass = $failureClass; bridgeState = $taskState; bridgeCode = $taskCode
    } | ConvertTo-Json -Compress))
}
finally {
    Stop-ScheduledTask -TaskName RapporLab-OfficialSetupProbe -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName RapporLab-OfficialSetupProbe -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
}
