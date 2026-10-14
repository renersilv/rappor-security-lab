[CmdletBinding()]
param(
    [ValidateSet('OpenLogin','Inspect','Login')][string]$Action = 'Inspect',
    [string]$Origin,
    [switch]$Worker
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\RapporLab\runtime\browser-preparation'
$resultPath = Join-Path $root 'result.json'
$credentialPath = Join-Path $root 'credentials.json'
$uri = [uri]$Origin
if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') { throw 'Invalid laboratory origin.' }
if ($Worker) {
    $stage = 'desktop'
    $counts = @{ windows = 0; addresses = 0; matchedOrigin = 0; documents = 0; email = 0; password = 0; submit = 0; candidates = 0 }
    try {
        if ((Get-Process -Id $PID).SessionId -eq 0) { throw 'Desktop required.' }
        if ($Action -eq 'OpenLogin') {
            $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
            if (-not (Test-Path -LiteralPath $edge)) { throw 'Browser unavailable.' }
            Start-Process -FilePath $edge -ArgumentList @('--new-window', ($uri.AbsoluteUri + 'login'))
            $result = @{ state = 'opened' }
        } else {
            $stage = 'browser-window'
            Add-Type -AssemblyName UIAutomationClient
            Add-Type -AssemblyName UIAutomationTypes
            $session = (Get-Process -Id $PID).SessionId
            $ids = @(Get-Process msedge -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session | ForEach-Object Id)
            $windows = [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
            $candidates = @()
            foreach ($window in $windows) {
                if ($window.Current.ProcessId -notin $ids) { continue }
                $counts.windows++
                $elements = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
                if ($elements.Count -gt 3000) { continue }
                # Intentional locale fixtures from the browser's public accessibility controls.
                $addresses = @($elements | Where-Object {
                    $_.Current.ControlType -eq [Windows.Automation.ControlType]::Edit -and
                    -not $_.Current.IsPassword -and
                    ($_.Current.AutomationId -eq 'addressEditBox' -or $_.Current.ClassName -eq 'OmniboxViewViews' -or
                    $_.Current.Name -in @('Address and search bar', 'Barra de endereços e pesquisa'))
                })
                $counts.addresses += $addresses.Count
                if ($addresses.Count -ne 1) { continue }
                $value = $addresses[0].GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
                if ($value -notmatch '^https://') { $value = 'https://' + $value }
                $current = [uri]$value
                if ($current.GetLeftPart([UriPartial]::Authority) -ne $uri.GetLeftPart([UriPartial]::Authority) -or $current.UserInfo) { continue }
                $counts.matchedOrigin++
                if ($current.AbsolutePath -eq '/login') {
                    try { $window.SetFocus() } catch { }
                    Start-Sleep -Milliseconds 500
                    $elements = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
                }
                $counts.documents += @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Document }).Count
                $email = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Edit -and -not $_.Current.IsPassword -and ($_.Current.AutomationId -eq 'login-email' -or $_.Current.Name -in @('E-mail','Email')) })
                $password = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Edit -and $_.Current.IsPassword -and ($_.Current.AutomationId -eq 'login-password' -or $_.Current.Name -in @('Senha','Password')) })
                $submit = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.Name -in @('Entrar','Sign in') -and $_.Current.IsEnabled })
                $counts.email += $email.Count
                $counts.password += $password.Count
                $counts.submit += $submit.Count
                if ($current.AbsolutePath -eq '/login' -and $email.Count -eq 1 -and $password.Count -eq 1 -and $submit.Count -eq 1) {
                    $candidates += @{ state = 'login-ready'; email = $email[0]; password = $password[0]; submit = $submit[0] }
                } elseif ($current.AbsolutePath -eq '/overview') { $candidates += @{ state = 'authenticated' } }
            }
            $counts.candidates = $candidates.Count
            if ($candidates.Count -ne 1) { throw 'One authorized browser page is required.' }
            $candidate = $candidates[0]
            if ($Action -eq 'Login') {
                $stage = 'login-controls'
                if ($candidate.state -ne 'login-ready') { throw 'Expected login form unavailable.' }
                if (-not $candidate.password.Current.IsPassword) { throw 'Protected password input required.' }
                $secret = Get-Content -LiteralPath $credentialPath -Raw | ConvertFrom-Json
                $candidate.email.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue($secret.email)
                $candidate.password.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue($secret.password)
                $secret = $null
                $candidate.submit.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
                $result = @{ state = 'login-submitted' }
            } else { $result = @{ state = $candidate.state } }
        }
    } catch { $result = @{ state = 'failed'; stage = $stage; counts = $counts } }
    finally {
        if ($Action -eq 'Login' -and (Test-Path -LiteralPath $credentialPath)) { Remove-Item -LiteralPath $credentialPath -Force }
    }
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    exit
}
$user = (Get-CimInstance Win32_ComputerSystem).UserName
if ($user -ne "$env:COMPUTERNAME\$env:USERNAME") { throw 'Authorized desktop unavailable.' }
$name = 'RapporLab-BrowserPreparation'
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'Browser preparation is busy.' }
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root /inheritance:r /grant:r ('{0}:(OI)(CI)F' -f $user) '*S-1-5-18:(OI)(CI)F' *> $null
if ($LASTEXITCODE -ne 0) { throw 'Private browser preparation directory required.' }
if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
$command = "& '$($PSCommandPath.Replace("'", "''"))' -Worker -Action $Action -Origin '$($uri.AbsoluteUri)'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$actionDefinition = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(45))
try {
    Register-ScheduledTask -TaskName $name -Action $actionDefinition -Principal $principal -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $name
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(40)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        if ([DateTimeOffset]::UtcNow -gt $deadline) { throw 'Browser preparation timed out.' }
        Start-Sleep -Milliseconds 250
    }
    Write-Output ('RAPPOR_LAB_RESULT=' + (Get-Content -LiteralPath $resultPath -Raw))
} finally {
    Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($file in @($resultPath, $credentialPath)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
}
