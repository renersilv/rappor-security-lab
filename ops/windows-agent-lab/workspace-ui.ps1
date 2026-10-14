Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Web

function Invoke-LaboratoryWorkspaceUi {
    param([int]$ClientProcessId, [string]$Operation, [string]$Origin, [string]$ComputerId)
    $originUri = [uri]$Origin
    $roots = [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
    foreach ($window in $roots) {
        if ($window.Current.ProcessId -ne $ClientProcessId) { continue }
        $elements = @($window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition))
        $text = ($elements | ForEach-Object { $_.Current.Name }) -join "`n"
        # Intentional locale fixtures from the public Windows client.
        $originLine = '(?m)^(Destino|Destination): ' + [regex]::Escape($originUri.GetLeftPart([UriPartial]::Authority)) + '/?\r?$'
        if ($text -notmatch $originLine) { return 'unexpected-native-target' }
        $trust = @($elements | Where-Object { $_.Current.Name -in @('Confirme a plataforma Rappor Security','Confirm the Rappor Security platform') })
        $computer = @($elements | Where-Object { $_.Current.Name -in @('Autorize a análise neste computador','Authorize analysis on this computer') })
        if ($trust.Count -gt 0) {
            $verification = @('Reconheço este endereço como minha Rappor Security','I recognize this address as my Rappor Security')
            $accept = @('Confiar e continuar','Trust and continue')
            $state = 'origin-confirmed'
        } elseif ($computer.Count -gt 0) {
            $folderLine = '(?m)^(Pasta atual|Current folder): C:\\RapporLab\\corpus\r?$'
            $computerLine = '(?m)^(Identificador deste computador|This computer''s identifier): ' + [regex]::Escape($ComputerId) + '\r?$'
            if ($text -notmatch $folderLine -or $text -notmatch $computerLine) { return 'unexpected-native-target' }
            $verification = @('Autorizo a leitura desta pasta neste computador','I authorize reading this folder on this computer')
            $accept = @('Autorizar e analisar','Authorize and analyze')
            $state = 'folder-confirmed'
        } else { return 'unexpected-native-dialog' }
        $checks = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::CheckBox -and $_.Current.Name -in $verification })
        $buttons = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.Name -in $accept -and $_.Current.IsEnabled })
        if ($checks.Count -ne 1 -or $buttons.Count -ne 1) { return 'native-controls-unavailable' }
        $toggle = $checks[0].GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
        if ($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::Off) { $toggle.Toggle() }
        if ($toggle.Current.ToggleState -ne [Windows.Automation.ToggleState]::On) { return 'native-controls-unavailable' }
        $buttons[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        return $state
    }
    $session = (Get-Process -Id $PID).SessionId
    $edgeIds = @(Get-Process msedge -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session | ForEach-Object Id)
    foreach ($window in $roots) {
        if ($window.Current.ProcessId -notin $edgeIds) { continue }
        $elements = @($window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition))
        $addresses = @($elements | Where-Object {
            $_.Current.ControlType -eq [Windows.Automation.ControlType]::Edit -and -not $_.Current.IsPassword -and
            ($_.Current.AutomationId -eq 'addressEditBox' -or $_.Current.ClassName -eq 'OmniboxViewViews' -or $_.Current.Name -in @('Address and search bar','Barra de endereços e pesquisa'))
        })
        if ($addresses.Count -ne 1) { continue }
        $value = $addresses[0].GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
        if ($value -notmatch '^https://') { $value = 'https://' + $value }
        $uri = [uri]$value
        if ($uri.GetLeftPart([UriPartial]::Authority) -ne $originUri.GetLeftPart([UriPartial]::Authority) -or $uri.UserInfo -or $uri.AbsolutePath -ne '/workspace/authorize') { continue }
        $query = [Web.HttpUtility]::ParseQueryString($uri.Query)
        if ($query['operation'] -ne $Operation) { continue }
        try { $window.SetFocus() } catch { }
        $elements = @($window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition))
        $names = @($elements | ForEach-Object { $_.Current.Name })
        if (-not ($names -contains 'Neste computador' -or $names -contains 'On this computer')) { return 'unexpected-browser-processing' }
        if (-not ($names -contains 'Autorizar a análise do projeto atual' -or $names -contains 'Authorize the current project analysis')) { return 'browser-authorization-loading' }
        $buttons = @($elements | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.Name -in @('Autorizar esta tentativa','Authorize this attempt') -and $_.Current.IsEnabled })
        if ($buttons.Count -eq 0) { return 'browser-authorization-pending' }
        if ($buttons.Count -ne 1) { return 'browser-controls-unavailable' }
        $buttons[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        return 'browser-confirmed'
    }
    return 'waiting-for-public-ui'
}
