# Windows PowerShell 5.1 library. The host invokes only Invoke-WebZipParent.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Resolve-WebZipPhysicalPath([string]$Path) { return $Path }
function Get-WebZipCanonicalPath([string]$Path) { return [IO.Path]::GetFullPath($Path) }

function Get-WebZipHash([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}
function Assert-WebZipKeys($Value, [string[]]$Keys) {
    if (($Value.PSObject.Properties.Name | Sort-Object) -join ',' -cne (($Keys | Sort-Object) -join ',')) { throw 'invalid-object-fields' }
}
function Assert-WebZipPath([string]$Path, [string]$OwnerSid, [switch]$File) {
    if ((Get-WebZipCanonicalPath $Path) -cne $Path) { throw 'noncanonical-path' }
    $current = $Path
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse-path' }
        # Only the exact system volume has the Windows ancestor exception.
        $systemVolume = $current -ceq 'C:\'
        $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $allowedOwners = @($OwnerSid,'S-1-5-18','S-1-5-32-544')
        if ($systemVolume) {
            $allowedOwners += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        }
        if ($owner -notin $allowedOwners) { throw 'path-owner-invalid' }
        $mutationMask = if ($systemVolume) { 0x500D0152 } else { 0x500D0156 }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -notin @($OwnerSid,'S-1-5-18','S-1-5-32-544') -and
                ([int]$rule.FileSystemRights -band $mutationMask) -ne 0) { throw 'path-not-private' }
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($File -and $item.PSIsContainer) { throw 'file-required' }
}
function Set-WebZipPrivateDirectory([string]$Path, [string]$OwnerSid) {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true,$false)
    $sid = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
    $security.SetOwner($sid)
    foreach ($allowed in @($OwnerSid,'S-1-5-18','S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($allowed), 'FullControl',
            'ContainerInherit,ObjectInherit','None','Allow')
        $security.AddAccessRule($rule)
    }
    [IO.Directory]::CreateDirectory((Resolve-WebZipPhysicalPath $Path),$security) | Out-Null
    Assert-WebZipPath $Path $OwnerSid
}
function Write-WebZipBytes([string]$Path,[byte[]]$Bytes) {
    $stream = [IO.File]::Open((Resolve-WebZipPhysicalPath $Path),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Write-WebZipJson([string]$Path,$Value) {
    Write-WebZipBytes $Path ([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30 -Compress) + "`n"))
}
function Open-WebZipBoundFile([string]$Path,[string]$ExpectedHash,[string]$OwnerSid,[int]$Maximum=1048576) {
    Assert-WebZipPath $Path $OwnerSid -File
    # Keep this handle open through use; nobody can replace, delete or write the file.
    $stream = [IO.File]::Open((Resolve-WebZipPhysicalPath $Path),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $Maximum) { throw 'file-size-invalid' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($count -lt 1) { throw 'short-file-read' }
            $offset += $count
        }
        if ((Get-WebZipHash $bytes) -cne $ExpectedHash) { throw 'bound-file-hash-mismatch' }
        Assert-WebZipPath $Path $OwnerSid -File
        return @{ Stream=$stream; Bytes=$bytes }
    } catch { $stream.Dispose(); throw }
}
function Read-WebZipInstruction([string]$Path,[string]$Hash,[string]$OwnerSid) {
    $file = Open-WebZipBoundFile $Path $Hash $OwnerSid
    try {
        $value = [Text.Encoding]::UTF8.GetString($file.Bytes) | ConvertFrom-Json
        Assert-WebZipKeys $value @('schema','kind','issue','authorizationId','executorPass','candidate','requestSha256','sourceHashes','desktop','hostUuid','product','guestRoot','taskName','archiveFileName','archiveSha256','archiveSize','totalMs','cleanupReserveMs','parentReserveMs')
        if ($value.schema -ne 1 -or $value.kind -cne 'web_zip_bound_instruction' -or $value.issue -ne 19 -or
            $value.authorizationId -cne 'issue19-native-windows-20261023' -or $value.executorPass -le 237) { throw 'instruction-context-invalid' }
        if ($value.requestSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'request-hash-invalid' }
        $identity = $value.requestSha256.Substring(0,16)
        if ($value.guestRoot -cne ('C:\RapporLab\runtime\web-zip-' + $identity) -or
            $value.taskName -cne ('RapporLab-WebZip-' + $identity) -or
            $value.archiveFileName -cne 'issue19-web-zip-pass196.zip') { throw 'resource-binding-invalid' }
        if ($value.candidate.origin -cne 'https://linux-ai2.taile60a95.ts.net:8443' -or
            $value.candidate.sha -cne '3105b01067ac415786d9c041cc922195c00c9cc4' -or
            $value.candidate.version -cne 'v0.92.0') { throw 'candidate-binding-invalid' }
        if ($value.archiveSha256 -cne '8627e45b93043f90c664fb015901e68cb1cf82d1ba93453068e5a2f1ae508af6') { throw 'fixture-binding-invalid' }
        if ($value.totalMs -ne 600000 -or $value.cleanupReserveMs -ne 90000 -or $value.parentReserveMs -ne 15000) { throw 'deadline-binding-invalid' }
        if ($value.desktop.account -cne 'joao' -or $value.desktop.sid -cne $OwnerSid -or $value.desktop.sessionId -le 0) { throw 'desktop-binding-invalid' }
        Assert-WebZipKeys $value.product @('productId','analysisName','environment')
        if ($value.product.productId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
            $value.product.analysisName -cnotmatch '^Rappor Lab Web ZIP [A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$' -or
            $value.product.environment -cne 'Development') { throw 'product-binding-invalid' }
        return @{ File=$file; Value=$value }
    } catch { $file.Stream.Dispose(); throw }
}
function Get-WebZipOwnerSid($CimProcess) {
    $owner = Invoke-CimMethod -InputObject $CimProcess -MethodName GetOwnerSid -ErrorAction Stop
    if ($owner.ReturnValue -ne 0 -or -not $owner.Sid) { throw 'process-owner-unavailable' }
    return [string]$owner.Sid
}
function Get-WebZipDesktopObservation($Instruction) {
    $uuid = [string](Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
    $interactive = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
    if (-not $interactive) { throw 'interactive-account-unavailable' }
    $sid = ([Security.Principal.NTAccount]::new($interactive)).Translate([Security.Principal.SecurityIdentifier]).Value
    $explorers = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -ieq 'explorer.exe' -and $_.SessionId -eq $Instruction.desktop.sessionId
    })
    return @{uuid=$uuid.ToLowerInvariant();account=($interactive -split '\\')[-1];sid=$sid;
        sessionId=[int]$Instruction.desktop.sessionId;explorerCount=$explorers.Count;
        explorerSid=if($explorers.Count -eq 1){Get-WebZipOwnerSid $explorers[0]}else{$null};
        processSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
        processSessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId}
}
function Assert-WebZipDesktop($Instruction,[switch]$Worker) {
    $observed = Get-WebZipDesktopObservation $Instruction
    if ($observed.uuid -cne $Instruction.hostUuid -or $Instruction.hostUuid -cne '13918e5c-5b79-4a99-9029-0aa515f5a732') { throw 'host-identity-mismatch' }
    if ($observed.account -cne 'joao' -or $observed.sid -cne $Instruction.desktop.sid) { throw 'interactive-account-mismatch' }
    if ($observed.explorerCount -ne 1 -or $observed.explorerSid -cne $Instruction.desktop.sid -or
        $observed.sessionId -ne $Instruction.desktop.sessionId) { throw 'interactive-session-mismatch' }
    if ($Worker -and ($observed.processSid -cne $Instruction.desktop.sid -or
        $observed.processSessionId -ne $Instruction.desktop.sessionId)) { throw 'worker-session-mismatch' }
}
function New-WebZipClock([long]$AbsoluteDeadlineUnixMs) {
    $remaining = $AbsoluteDeadlineUnixMs - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    if ($remaining -le 90000 -or $remaining -gt 600000) { throw 'absolute-budget-invalid' }
    return @{ Stopwatch=[Diagnostics.Stopwatch]::StartNew(); Budget=$remaining }
}
function Get-WebZipRemaining($Clock,[int]$Reserve=0) {
    $remaining = [int64]$Clock.Budget - [int64]$Clock.Stopwatch.ElapsedMilliseconds - $Reserve
    if ($remaining -le 0) { throw 'absolute-deadline' }
    return $remaining
}
function Get-WebZipReadinessDiagnostic($Progress,[string]$Message) {
    $steps = @('process_binding','listener_wait','ui_initialization','cdp_process','cdp_listener','cdp_targets','cdp_socket','page_enable')
    $reasons = @('process-inventory-missing','process-identity-mismatch','process-owner-unavailable',
        'process-generation-mismatch','operation-deadline','absolute-deadline','browser-exited',
        'debug-listener-ownership-mismatch','debug-page-not-unique','debug-target-mismatch',
        'cdp-channel-closed','cdp-output-limit','cdp-command-rejected')
    $diagnostic = @{step='unknown';reason='unknown'}
    if ($Progress.stage -ceq 'browser_readiness') {
        if ($steps -ccontains $Progress.step) { $diagnostic.step = $Progress.step }
        if ($reasons -ccontains $Message) { $diagnostic.reason = $Message }
    }
    return $diagnostic
}
function Get-WebZipProcessBinding($Process,$Instruction,[string]$Profile) {
    $null = $Process.Handle
    $ticks = [string]$Process.StartTime.ToUniversalTime().Ticks
    $inventory = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ProcessId -eq $Process.Id })
    if ($inventory.Count -ne 1) { throw 'process-inventory-missing' }
    $cim = $inventory[0]
    if ($cim.Name -ine 'msedge.exe' -or $cim.SessionId -ne $Instruction.desktop.sessionId -or
        (Get-WebZipOwnerSid $cim) -cne $Instruction.desktop.sid -or -not $cim.CommandLine -or
        $cim.CommandLine.IndexOf(('--user-data-dir=' + $Profile),[StringComparison]::Ordinal) -lt 0) { throw 'process-identity-mismatch' }
    return @{ Process=$Process; Id=[int]$Process.Id; StartTicks=$ticks; SessionId=[int]$cim.SessionId;
        OwnerSid=$Instruction.desktop.sid; Profile=$Profile }
}
function Assert-WebZipProcess($Binding) {
    $null = $Binding.Process.Handle
    if ($Binding.Process.HasExited) { return $false }
    if ([string]$Binding.Process.StartTime.ToUniversalTime().Ticks -cne $Binding.StartTicks -or
        $Binding.Process.SessionId -ne $Binding.SessionId) { throw 'process-generation-mismatch' }
    return $true
}
function Get-WebZipWindowProcessId([IntPtr]$Window) {
    $processId = [uint32]0
    $null = [WebZipNative]::GetWindowThreadProcessId($Window,[ref]$processId)
    return [int]$processId
}
function Assert-WebZipWindow($Element,$Binding,[switch]$Dialog) {
    if (-not (Assert-WebZipProcess $Binding) -or $Element.Current.ProcessId -ne $Binding.Id) { throw 'foreign-window' }
    $handle = [IntPtr]$Element.Current.NativeWindowHandle
    if ($handle -eq [IntPtr]::Zero -or (Get-WebZipWindowProcessId $handle) -ne $Binding.Id) { throw 'window-process-mismatch' }
    if ($Dialog) {
        if ($Element.Current.ClassName -cne '#32770') { throw 'picker-class-mismatch' }
        $owner = [WebZipNative]::GetWindow($handle,4)
        if ($owner -eq [IntPtr]::Zero -or (Get-WebZipWindowProcessId $owner) -ne $Binding.Id) { throw 'picker-owner-mismatch' }
    }
}
function Initialize-WebZipUi {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class WebZipNative {
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
 [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr h, uint command);
}
'@
}
function Wait-WebZip($Clock,[int]$Limit,[scriptblock]$Condition,[int]$Reserve=90000) {
    $stop = [Math]::Min((Get-WebZipRemaining $Clock $Reserve),$Limit)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $stop) {
        $null = Get-WebZipRemaining $Clock $Reserve
        $value = & $Condition
        if ($value) { return $value }
        Start-Sleep -Milliseconds 100
    }
    throw 'operation-deadline'
}
function Connect-WebZipCdp($Binding,$Clock,$Progress) {
    $Progress.step = 'cdp_process'
    if (-not (Assert-WebZipProcess $Binding)) { throw 'browser-exited' }
    $Progress.step = 'cdp_listener'
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 9296 -ErrorAction Stop)
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1' -or
        $listeners[0].OwningProcess -ne $Binding.Id) { throw 'debug-listener-ownership-mismatch' }
    $Progress.step = 'cdp_targets'
    $targets = Invoke-RestMethod -Uri 'http://127.0.0.1:9296/json/list' -TimeoutSec 3 -ErrorAction Stop
    $pages = @($targets | Where-Object { $_.type -ceq 'page' -and $_.url -eq 'about:blank' })
    if ($pages.Count -ne 1) { throw 'debug-page-not-unique' }
    $uri = [Uri]$pages[0].webSocketDebuggerUrl
    if ($uri.Scheme -cne 'ws' -or $uri.Host -cne '127.0.0.1' -or $uri.Port -ne 9296) { throw 'debug-target-mismatch' }
    $Progress.step = 'cdp_socket'
    $socket = [Net.WebSockets.ClientWebSocket]::new()
    $cancel = [Threading.CancellationTokenSource]::new([int][Math]::Min(5000,(Get-WebZipRemaining $Clock 90000)))
    try { $socket.ConnectAsync($uri,$cancel.Token).GetAwaiter().GetResult() } finally { $cancel.Dispose() }
    return @{ Socket=$socket; Sequence=0; Events=[Collections.Generic.List[object]]::new(); Clock=$Clock }
}
function Invoke-WebZipCdp($Cdp,[string]$Method,$Parameters) {
    $Cdp.Sequence++
    $id = $Cdp.Sequence
    $json = @{id=$id;method=$Method;params=$Parameters} | ConvertTo-Json -Compress -Depth 20
    $cancel = [Threading.CancellationTokenSource]::new([int][Math]::Min(5000,(Get-WebZipRemaining $Cdp.Clock 90000)))
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $Cdp.Socket.SendAsync([ArraySegment[byte]]::new($bytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,$cancel.Token).GetAwaiter().GetResult()
        while ($true) {
            $stream = [IO.MemoryStream]::new()
            try {
                do {
                    $buffer = [byte[]]::new(65536)
                    $message = $Cdp.Socket.ReceiveAsync([ArraySegment[byte]]::new($buffer),$cancel.Token).GetAwaiter().GetResult()
                    if ($message.MessageType -ne [Net.WebSockets.WebSocketMessageType]::Text) { throw 'cdp-channel-closed' }
                    $stream.Write($buffer,0,$message.Count)
                    if ($stream.Length -gt 4194304) { throw 'cdp-output-limit' }
                } while (-not $message.EndOfMessage)
                $value = [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
            } finally { $stream.Dispose() }
            if ($value.PSObject.Properties.Name -contains 'id') {
                if ($value.id -ne $id -or $value.PSObject.Properties.Name -contains 'error') { throw 'cdp-command-rejected' }
                return $value.result
            }
            if ($Cdp.Events.Count -ge 1000) { throw 'cdp-event-limit' }
            $Cdp.Events.Add($value)
        }
    } finally { $cancel.Dispose() }
}
function Invoke-WebZipExpression($Cdp,[string]$Expression,[string]$Origin) {
    $guard = '(() => { if(location.origin !== ' + ($Origin | ConvertTo-Json -Compress) + ') throw new Error("origin-mismatch"); return (' + $Expression + '); })()'
    $response = Invoke-WebZipCdp $Cdp 'Runtime.evaluate' @{expression=$guard;returnByValue=$true;awaitPromise=$true;userGesture=$true}
    if ($response.PSObject.Properties.Name -contains 'exceptionDetails') { throw 'page-contract-unavailable' }
    return $response.result.value
}
function Save-WebZipScreenshot($Cdp,[string]$Path) {
    $value = Invoke-WebZipCdp $Cdp 'Page.captureScreenshot' @{format='png';captureBeyondViewport=$false}
    $bytes = [Convert]::FromBase64String($value.data)
    if ($bytes.Length -lt 100 -or $bytes.Length -gt 524288) { throw 'screenshot-size-invalid' }
    Write-WebZipBytes $Path $bytes
    return Get-WebZipHash $bytes
}
function Protect-WebZipLogin([byte[]]$Bytes) {
    Add-Type -AssemblyName System.Security
    return [Security.Cryptography.ProtectedData]::Protect($Bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
}
function Unprotect-WebZipLogin([byte[]]$Bytes) {
    Add-Type -AssemblyName System.Security
    return [Security.Cryptography.ProtectedData]::Unprotect($Bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
}
function Invoke-WebZipOfficialLogin($Cdp,$Instruction,$Clock,[string]$Root) {
    $loginPath = Join-Path $Root 'login.dpapi'
    Assert-WebZipPath $loginPath $Instruction.desktop.sid -File
    $encrypted = [IO.File]::ReadAllBytes((Resolve-WebZipPhysicalPath $loginPath))
    if ($encrypted.Length -gt 16384) { throw 'login-input-invalid' }
    $plain = $null; $login = $null; $expression = $null
    try {
        $plain = Unprotect-WebZipLogin $encrypted
        if ($plain.Length -gt 8192) { throw 'login-input-invalid' }
        $login = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
        Assert-WebZipKeys $login @('email','password')
        if ($login.email -isnot [string] -or $login.password -isnot [string] -or
            $login.email.Length -gt 320 -or $login.email -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$' -or
            $login.password.Length -lt 1 -or $login.password.Length -gt 1024 -or $login.password -match '[\x00\r\n]') { throw 'login-input-invalid' }
        $origin = $Instruction.candidate.origin
        # Do not collect authentication request bodies, headers or cookies.
        $null = Invoke-WebZipCdp $Cdp 'Network.disable' @{}
        $Cdp.Events.Clear()
        $null = Invoke-WebZipCdp $Cdp 'Page.navigate' @{url=($origin + '/login')}
        $null = Wait-WebZip $Clock 30000 {
            $location = Invoke-WebZipCdp $Cdp 'Runtime.evaluate' @{expression='location.origin';returnByValue=$true}
            if ($location.result.value -ceq 'null') { return $false }
            if ($location.result.value -cne $origin) { throw 'login-origin-mismatch' }
            Invoke-WebZipExpression $Cdp 'location.pathname === "/login" && !!document.querySelector("#login-email") && !!document.querySelector("#login-password")' $origin
        }
        $expression = '(() => { if(location.pathname !== "/login")throw new Error("login-path-mismatch");const e=document.querySelector("#login-email"),p=document.querySelector("#login-password");if(!e||!p||p.type!=="password"||e.disabled||p.disabled||!e.form||e.form!==p.form)throw new Error("login-controls-invalid");const b=[...e.form.querySelectorAll("button[type=submit]")].filter(x=>!x.disabled);if(b.length!==1)throw new Error("login-submit-invalid");const v=' + ($login | ConvertTo-Json -Compress) + ';const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set;set.call(e,v.email);e.dispatchEvent(new Event("input",{bubbles:true}));set.call(p,v.password);p.dispatchEvent(new Event("input",{bubbles:true}));b[0].click();return true;})()'
        $null = Get-WebZipRemaining $Clock 90000
        $null = Invoke-WebZipExpression $Cdp $expression $origin
        $login = $null; $expression = $null
        $null = Wait-WebZip $Clock 45000 {
            Invoke-WebZipExpression $Cdp '(() => {if(location.pathname === "/login" && document.querySelector("[role=alert]"))throw new Error("login-rejected");return location.pathname === "/overview";})()' $origin
        }
        $Cdp.Events.Clear()
    } finally {
        if ($plain) { [Array]::Clear($plain,0,$plain.Length) }
        if ($encrypted) { [Array]::Clear($encrypted,0,$encrypted.Length) }
        $login = $null; $expression = $null
    }
}
function Get-WebZipCreationExpression([string]$Action,$Product) {
    # Public wizard controls only; no application state or direct upload calls.
    $script = @'
(input => {
  const visible = element => element && element.getClientRects().length > 0;
  const unique = (root, selector) => {
    const items = [...(root?.querySelectorAll(selector) || [])].filter(visible);
    if (items.length !== 1 || items[0].disabled) throw new Error("creation-control-unavailable");
    return items[0];
  };
  const step = name => document.querySelector('[aria-labelledby="analysis-step-' + name + '"]');
  const next = name => {
    const buttons = [...(step(name)?.querySelectorAll('button[type="button"]') || [])]
      .filter(button => visible(button) && !button.disabled && /^(Next|Pr.xima)$/iu.test(button.innerText.trim()));
    if (buttons.length !== 1) throw new Error("creation-next-unavailable");
    buttons[0].click(); return true;
  };
  const expectedPath = '/products/' + input.product.productId + '/analyses/new';
  if (input.action === 'ready') return {path:location.pathname,version:document.body.innerText,ready:location.pathname === expectedPath && !!step('source')};
  if (location.pathname !== expectedPath) throw new Error("creation-path-mismatch");
  switch (input.action) {
    case 'choose-zip': unique(step('source'), 'input[type="radio"][name="source-choice"][value="zip"]').click(); return true;
    case 'zip-selected': return unique(step('source'), 'input[type="radio"][value="zip"]').checked;
    case 'source-next': return next('source');
    case 'details-ready': return !!step('details');
    case 'fill-details': {
      const name = unique(step('details'), 'input:not([type]), input[type="text"]');
      const environment = unique(step('details'), 'select');
      if (![...environment.options].some(option => option.value === input.product.environment)) throw new Error("creation-environment-unavailable");
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(name, input.product.analysisName);
      name.dispatchEvent(new Event('input', {bubbles:true}));
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(environment, input.product.environment);
      environment.dispatchEvent(new Event('change', {bubbles:true})); return true;
    }
    case 'details-match': return unique(step('details'), 'input:not([type]), input[type="text"]').value === input.product.analysisName && unique(step('details'), 'select').value === input.product.environment;
    case 'details-next': return next('details');
    case 'file-ready': return !!step('configuration')?.querySelector('input[type="file"]');
    case 'open-picker': {
      const file = unique(step('configuration'), 'input[type="file"]');
      if (file.files.length || file.accept !== '.zip,application/zip') throw new Error("input-not-empty");
      file.click(); return true;
    }
    case 'selection': {
      const file = unique(step('configuration'), 'input[type="file"]').files[0];
      return file ? {name:file.name,size:file.size,lastModified:file.lastModified} : null;
    }
    case 'configuration-next': return next('configuration');
    case 'review': {
      const review = step('review');
      if (!review) return false;
      const values = [...review.querySelectorAll('dd')].filter(visible).map(item => item.innerText.trim());
      if (!values.includes(input.product.analysisName) || !values.includes('Development') && !values.includes('Desenvolvimento')) throw new Error("creation-review-mismatch");
      unique(review, 'button[type="submit"]'); return true;
    }
    case 'confirm': unique(step('review'), 'button[type="submit"]').click(); return true;
    default: throw new Error("creation-action-invalid");
  }
})
'@
    return '(' + $script + ')(' + (@{action=$Action;product=$Product} | ConvertTo-Json -Compress) + ')'
}
function Get-WebZipCoverageExpression {
    $script = @'
(() => {
  const metrics = [...document.querySelectorAll('[data-summary-content="indicators"] h3')]
    .filter(element => element.getClientRects().length && /^(Coverage|Cobertura)$/iu.test(element.innerText.trim()));
  if (metrics.length !== 1) return false;
  const paragraphs = [...metrics[0].parentElement.children].filter(element => element.tagName === 'P');
  if (paragraphs.length !== 2 || !/^3 (of|de) 3 (tools|ferramentas)$/u.test(paragraphs[0].innerText.trim())) return false;
  const statuses = [...paragraphs[1].querySelectorAll('span')].map(element => element.innerText.trim());
  return statuses.some(text => /^(Complete|Completa)$/u.test(text)) &&
    statuses.some(text => /^Gitleaks, Semgrep,? (and|e) Trivy (completed|conclu\u00edram)\.?$/u.test(text));
})()
'@
    return $script
}
function Assert-WebZipUploadEvents($Cdp,[string]$Origin,[string]$ExpectedUpload,[switch]$BeforeSubmit) {
    $mutations = @($Cdp.Events | Where-Object {
        $_.method -ceq 'Network.requestWillBeSent' -and $_.params.request.url.StartsWith($Origin + '/') -and
        $_.params.request.method -cin @('POST','PUT','PATCH','DELETE')
    })
    if ($BeforeSubmit -and $mutations.Count -ne 0) { throw 'mutation-before-confirmation' }
    if ($mutations.Count -gt 1) { throw 'duplicate-or-unexpected-mutation' }
    if ($mutations.Count -eq 1 -and ($mutations[0].params.request.url -cne $ExpectedUpload -or
        $mutations[0].params.request.method -cne 'POST')) { throw 'unexpected-mutation' }
}
function Invoke-WebZipJourney($Instruction,$Clock,$Binding,[string]$Root,$Progress) {
    $Progress.step = 'ui_initialization'
    Initialize-WebZipUi
    $cdp = Connect-WebZipCdp $Binding $Clock $Progress
    try {
        $origin = $Instruction.candidate.origin
        $product = $Instruction.product
        $path = '/products/' + $product.productId + '/analyses/new'
        $Progress.step = 'page_enable'
        $null = Invoke-WebZipCdp $cdp 'Page.enable' @{}
        $Progress.stage = 'login'
        Invoke-WebZipOfficialLogin $cdp $Instruction $Clock $Root
        $Progress.stage = 'wizard_readiness'
        $null = Invoke-WebZipCdp $cdp 'Network.enable' @{}
        $null = Invoke-WebZipCdp $cdp 'Page.navigate' @{url=($origin + $path + '?type=source-code')}
        $null = Wait-WebZip $Clock 30000 {
            $location = Invoke-WebZipCdp $cdp 'Runtime.evaluate' @{expression='location.origin';returnByValue=$true}
            return $location.result.value -ceq $origin
        }
        $null = Wait-WebZip $Clock 30000 {
            $state = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'ready' $product) $origin
            if ($state.path -eq '/login') { throw 'authenticated-session-unavailable' }
            if ($state.path -ne $path) { return $false }
            if ($state.version -notmatch [regex]::Escape($Instruction.candidate.version)) { return $false }
            return $state.ready
        }
        $Progress.stage = 'configuration'
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'choose-zip' $product) $origin
        $null = Wait-WebZip $Clock 10000 { Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'zip-selected' $product) $origin }
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'source-next' $product) $origin
        $null = Wait-WebZip $Clock 10000 { Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'details-ready' $product) $origin }
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'fill-details' $product) $origin
        $null = Wait-WebZip $Clock 10000 { Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'details-match' $product) $origin }
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'details-next' $product) $origin
        $null = Wait-WebZip $Clock 10000 { Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'file-ready' $product) $origin }
        # Exactly one native selection. CDP clicks the official file input; it never sets files.
        $Progress.stage = 'file_selection'
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'open-picker' $product) $origin
        $dialog = Wait-WebZip $Clock 30000 {
            $windows = [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,
                [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty,$Binding.Id))
            $matches = @($windows | Where-Object { $_.Current.ClassName -ceq '#32770' })
            if ($matches.Count -gt 1) { throw 'picker-not-unique' }
            if ($matches.Count -eq 0) { return $false }
            Assert-WebZipWindow $matches[0] $Binding -Dialog
            return $matches[0]
        }
        $edits = @($dialog.FindAll([Windows.Automation.TreeScope]::Descendants,
            [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::AutomationIdProperty,'1148')))
        if ($edits.Count -ne 1) { throw 'picker-filename-control-unavailable' }
        Assert-WebZipWindow $dialog $Binding -Dialog
        $null = Get-WebZipRemaining $Clock 90000
        $edits[0].GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue((Join-Path $Root $Instruction.archiveFileName))
        $buttons = @($dialog.FindAll([Windows.Automation.TreeScope]::Descendants,
            [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::AutomationIdProperty,'1')))
        if ($buttons.Count -ne 1) { throw 'picker-confirm-control-unavailable' }
        $null = Get-WebZipRemaining $Clock 90000
        $buttons[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        $selection = Wait-WebZip $Clock 10000 {
            Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'selection' $product) $origin
        }
        if ($selection.name -cne $Instruction.archiveFileName -or $selection.size -ne $Instruction.archiveSize) { throw 'selected-file-mismatch' }
        $selectionFingerprint = Get-WebZipHash ([Text.Encoding]::UTF8.GetBytes(($selection | ConvertTo-Json -Compress)))
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'configuration-next' $product) $origin
        $null = Wait-WebZip $Clock 10000 { Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'review' $product) $origin }
        $confirmationScreenshot = Save-WebZipScreenshot $cdp (Join-Path $Root 'confirmation.png')
        $Progress.stage = 'upload'
        $expectedUpload = $origin + '/api/products/' + $product.productId + '/analysis-definitions/uploaded-code'
        Assert-WebZipUploadEvents $cdp $origin $expectedUpload -BeforeSubmit
        $null = Invoke-WebZipExpression $cdp (Get-WebZipCreationExpression 'confirm' $product) $origin
        $upload = Wait-WebZip $Clock 60000 {
            $null = Invoke-WebZipExpression $cdp '({path:location.pathname})' $origin
            Assert-WebZipUploadEvents $cdp $origin $expectedUpload
            $requests = @($cdp.Events | Where-Object { $_.method -ceq 'Network.requestWillBeSent' -and $_.params.request.url -ceq $expectedUpload })
            if ($requests.Count -gt 1) { throw 'duplicate-upload' }
            if ($requests.Count -ne 1) { return $false }
            $request = $requests[0]
            $responses = @($cdp.Events | Where-Object { $_.method -ceq 'Network.responseReceived' -and $_.params.requestId -ceq $request.params.requestId })
            if ($responses.Count -ne 1) { return $false }
            if ($request.params.request.method -cne 'POST' -or $responses[0].params.response.status -lt 200 -or $responses[0].params.response.status -ge 300) { throw 'upload-rejected' }
            $finished = @($cdp.Events | Where-Object { $_.method -ceq 'Network.loadingFinished' -and $_.params.requestId -ceq $request.params.requestId })
            if ($finished.Count -ne 1) { return $false }
            $body = Invoke-WebZipCdp $cdp 'Network.getResponseBody' @{requestId=$request.params.requestId}
            if ($body.base64Encoded) { throw 'upload-response-encoding-invalid' }
            $execution = $body.body | ConvertFrom-Json
            $post = Invoke-WebZipCdp $cdp 'Network.getRequestPostData' @{requestId=$request.params.requestId}
            # Observe only these public multipart fields; never persist bodies, cookies or headers.
            $fields = @{}
            foreach ($name in @('name','environment','idempotencyKey')) {
                $matches = [regex]::Matches($post.postData,'name="' + $name + '"\r?\n\r?\n([^\r\n]+)')
                if ($matches.Count -ne 1) { throw 'upload-field-unavailable' }
                $fields[$name] = $matches[0].Groups[1].Value
            }
            if ($fields.name -cne $product.analysisName -or $fields.environment -cne $product.environment -or
                $fields.idempotencyKey -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
                $post.postData -match 'name="analysisDefinitionRevisionId"') { throw 'upload-configuration-mismatch' }
            foreach ($id in @($execution.id,$execution.analysisDefinitionId,$execution.analysisDefinitionRevisionId)) {
                if ($id -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') { throw 'upload-execution-mismatch' }
            }
            if ($execution.productId -cne $product.productId -or $execution.profile -cne 'CodeBaseline' -or
                $execution.executionMode -cne 'Managed' -or $execution.targetType -cne 'UploadedCode') { throw 'upload-execution-mismatch' }
            return @{id=$execution.id;productId=$execution.productId;analysisDefinitionId=$execution.analysisDefinitionId;
                revisionId=$execution.analysisDefinitionRevisionId;analysisName=$fields.name;environment=$fields.environment;
                idempotencyKey=$fields.idempotencyKey;uploadPath=([Uri]$expectedUpload).AbsolutePath}
        }
        $executionPath = '/executions/' + $upload.id
        $Progress.stage = 'result'
        $rendered = Wait-WebZip $Clock 240000 {
            $state = Invoke-WebZipExpression $cdp '(() => {const summary=[...document.querySelectorAll("summary")].find(e=>/Technical details|Detalhes t.cnicos/iu.test(e.innerText));if(summary && !summary.parentElement.open)summary.click();const pairs=[...document.querySelectorAll("dt")].filter(e=>e.getClientRects().length).map(e=>[e.innerText.trim(),e.parentElement.querySelector("dd")?.innerText.trim()]);const value=p=>pairs.find(([k])=>p.test(k))?.[1];return {pathname:location.pathname,text:document.body.innerText,executionId:value(/Execution identifier|Identificador da execu/iu),revisionId:value(/Exact configuration revision|Revis.o exata da configura/iu),analysisDefinitionId:[...document.querySelectorAll("a[href]")].map(e=>new URL(e.href).pathname).find(x=>/^\/products\/[a-f0-9-]+\/analyses\/[a-f0-9-]+$/.test(x))?.split("/").pop(),productId:[...document.querySelectorAll("a[href]")].map(e=>new URL(e.href).pathname).find(x=>/^\/products\/[a-f0-9-]+$/.test(x))?.split("/").pop()};})()' $origin
            if ($state.pathname -ne $executionPath) { return $false }
            if (-not $state.executionId -or -not $state.revisionId -or -not $state.productId -or -not $state.analysisDefinitionId) { return $false }
            if ($state.analysisDefinitionId -cne $upload.analysisDefinitionId -or $state.executionId -cne $upload.id -or $state.revisionId -cne $upload.revisionId -or $state.productId -cne $upload.productId) { throw 'rendered-execution-mismatch' }
            if (-not (Invoke-WebZipExpression $cdp (Get-WebZipCoverageExpression) $origin)) { return $false }
            return $state
        }
        $scoreMatch = [regex]::Match($rendered.text,'(?i)(?:SCORE FOR THIS EXECUTION|NOTA DESTA EXECU|SCORE DESTA EXECU)[^0-9]{0,12}(\d+(?:[.,]\d+)?) (?:out of|de) 100')
        if (-not $scoreMatch.Success) { throw 'rendered-score-unavailable' }
        $countMatch = [regex]::Match($rendered.text,'(\d+) (?:Problems?|Problemas?)')
        $problemCount = if ($countMatch.Success) {[int]$countMatch.Groups[1].Value} elseif ($rendered.text -match 'No Problems|Nenhum problema') {0} else {throw 'rendered-problems-unavailable'}
        $executionScreenshot = Save-WebZipScreenshot $cdp (Join-Path $Root 'execution.png')
        $null = Invoke-WebZipCdp $cdp 'Page.navigate' @{url=($origin + '/products/' + $product.productId + '/executions')}
        $Progress.stage = 'history'
        $historyPath = '/products/' + $product.productId + '/executions'
        $null = Wait-WebZip $Clock 30000 {
            $expr = 'location.pathname === ' + ($historyPath | ConvertTo-Json -Compress) + ' && [...document.querySelectorAll("a[href]")].some(a=>a.getClientRects().length && new URL(a.href).pathname === ' + ($executionPath | ConvertTo-Json -Compress) + ')'
            Invoke-WebZipExpression $cdp $expr $origin
        }
        Assert-WebZipUploadEvents $cdp $origin $expectedUpload
        $historyScreenshot = Save-WebZipScreenshot $cdp (Join-Path $Root 'history.png')
        return @{execution=$upload;selectionFingerprint=$selectionFingerprint;confirmationObserved=$true;
            confirmationScreenshotSha256=$confirmationScreenshot;
            rendered=@{executionId=$upload.id;analysisDefinitionId=$upload.analysisDefinitionId;revisionId=$upload.revisionId;productId=$upload.productId;pathname=$executionPath;
                historyExecutionId=$upload.id;coverageComplete=$true;score=[double]::Parse($scoreMatch.Groups[1].Value.Replace(',','.'),[Globalization.CultureInfo]::InvariantCulture);
                problemCount=$problemCount;executionScreenshotSha256=$executionScreenshot;historyScreenshotSha256=$historyScreenshot}}
    } finally { $cdp.Socket.Abort(); $cdp.Socket.Dispose() }
}
function Initialize-WebZipJob {
    if ('WebZipJob' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System; using System.ComponentModel; using System.Diagnostics; using System.Runtime.InteropServices; using System.Text;
public sealed class WebZipJob : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long processTime,jobTime; public uint flags; public UIntPtr min,max; public uint active; public UIntPtr affinity; public uint priority,scheduling; }
 [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong a,b,c,d,e,f; }
 [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits { public BasicLimits basic; public IoCounters io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
 [StructLayout(LayoutKind.Sequential)] struct Accounting { public long a,b,c,d; public uint faults,total,active,terminated; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup { public uint cb; public string reserved,desktop,title; public uint x,y,xSize,ySize,xChars,yChars,fill,flags; public ushort show,reserved2; public IntPtr reservedPtr,input,output,error; }
 [StructLayout(LayoutKind.Sequential)] struct Information { public IntPtr process,thread; public uint processId,threadId; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,IntPtr value,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting value,uint size,IntPtr length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out Information information);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 IntPtr job; public Process Process {get;private set;}
 public WebZipJob(string executable,string arguments) {
  job=CreateJobObject(IntPtr.Zero,null); if(job==IntPtr.Zero)throw new Win32Exception();
  var limits=new ExtendedLimits(); limits.basic.flags=0x2000;
  IntPtr pointer=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ExtendedLimits)));
  try {Marshal.StructureToPtr(limits,pointer,false); if(!SetInformationJobObject(job,9,pointer,(uint)Marshal.SizeOf(typeof(ExtendedLimits))))throw new Win32Exception();}
  catch {Dispose();throw;} finally {Marshal.FreeHGlobal(pointer);}
  var startup=new Startup(); startup.cb=(uint)Marshal.SizeOf(typeof(Startup)); startup.desktop="winsta0\\default";
  Information information;
  if(!CreateProcess(executable,new StringBuilder("\""+executable+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,null,ref startup,out information)){Dispose();throw new Win32Exception();}
  try {
   if(!AssignProcessToJobObject(job,information.process))throw new Win32Exception();
   Process=System.Diagnostics.Process.GetProcessById((int)information.processId); var stable=Process.Handle;
   if(ResumeThread(information.thread)==0xffffffff)throw new Win32Exception();
  } catch {TerminateProcess(information.process,65);Dispose();throw;}
  finally {CloseHandle(information.thread);CloseHandle(information.process);}
 }
 public uint Active {get{Accounting value;if(!QueryInformationJobObject(job,1,out value,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero))throw new Win32Exception();return value.active;}}
 public void Terminate(){if(!TerminateJobObject(job,65))throw new Win32Exception();}
 public void Dispose(){if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}
}
'@
}
function Start-WebZipBrowser([string]$Profile,$Clock) {
    Initialize-WebZipJob
    $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    $arguments = '"--user-data-dir=' + $Profile + '" --remote-debugging-address=127.0.0.1 --remote-debugging-port=9296 --force-renderer-accessibility=complete --no-first-run --no-default-browser-check --disable-background-mode --new-window about:blank'
    $null = Get-WebZipRemaining $Clock 90000
    return [WebZipJob]::new($edge,$arguments)
}
function Stop-WebZipBrowserJob($Job,$Clock) {
    $null = Get-WebZipRemaining $Clock 15000
    $Job.Terminate()
    $null = Wait-WebZip $Clock 10000 { $Job.Active -eq 0 } 15000
    return $true
}

function Stop-WebZipOwnedBrowser($Ownership,$Instruction,$Clock) {
    if ($Ownership.Job) { $null = Stop-WebZipBrowserJob $Ownership.Job $Clock }
    foreach ($binding in $Ownership.Bindings) {
        $null = Get-WebZipRemaining $Clock 15000
        if (Assert-WebZipProcess $binding) { $null = Get-WebZipRemaining $Clock 15000; Stop-Process -InputObject $binding.Process -Force -ErrorAction Stop }
    }
    foreach ($binding in $Ownership.Bindings) {
        if (-not $binding.Process.WaitForExit([int][Math]::Min(5000,(Get-WebZipRemaining $Clock 15000)))) { throw 'owned-process-not-quiescent' }
    }
    $remaining = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -ieq 'msedge.exe' -and $_.SessionId -eq $Instruction.desktop.sessionId -and
        $_.CommandLine -and $_.CommandLine.IndexOf($Ownership.Profile,[StringComparison]::Ordinal) -ge 0
    })
    if ($remaining.Count -ne 0) { throw 'owned-browser-cohort-unresolved' }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq 9296 })
    if ($listeners.Count -ne 0) { throw 'listener-not-absent' }
    return $true
}
function Initialize-WebZipProfileDisposal {
    if ('WebZipProfileHandle' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
public sealed class WebZipProfileHandle : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint low, high; }
 [StructLayout(LayoutKind.Sequential)] struct Information {
  public uint attributes; public FileTime creation, access, write;
  public uint volume, sizeHigh, sizeLow, links, indexHigh, indexLow;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information value);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,StringBuilder path,uint length,uint flags);
 [DllImport("advapi32.dll", SetLastError=true)]
 static extern uint GetSecurityInfo(SafeFileHandle handle,uint type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("advapi32.dll", SetLastError=true)]
 static extern uint SetSecurityInfo(SafeFileHandle handle,uint type,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
 readonly SafeFileHandle handle;
 readonly string path, owner;
 readonly string identity;
 public bool IsDirectory {get; private set;}
 public string Identity {get{return identity;}}
 static Exception Invalid(){return new InvalidOperationException("profile-disposal-boundary");}
 public WebZipProfileHandle(string expectedPath,string expectedOwner,string expectedIdentity,long expectedCreationTicks) {
  path=expectedPath; owner=expectedOwner;
  if(!path.StartsWith(@"C:\RapporLab\runtime\",StringComparison.Ordinal) || Path.GetFullPath(path)!=path)throw Invalid();
  // MAXIMUM_ALLOWED suppresses SetSecurityInfo propagation to uninspected children.
  // Share READ only: existing writers/deleters and new write/delete opens must fail.
  handle=CreateFileW(path,0x02000000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(handle.IsInvalid){handle.Dispose();throw Invalid();}
  try {
   identity=Inspect(expectedCreationTicks);
   if(!String.IsNullOrEmpty(expectedIdentity) && identity!=expectedIdentity)throw Invalid();
   ValidateSecurity(ReadSecurity(),false);
  } catch {handle.Dispose();throw;}
 }
 string Inspect(long expectedCreationTicks) {
  Information value;
  if(!GetFileInformationByHandle(handle,out value) || (value.attributes&0x400)!=0)throw Invalid();
  bool directory=(value.attributes&0x10)!=0;
  if(!directory && value.links!=1)throw Invalid();
  IsDirectory=directory;
  long ticks=DateTime.FromFileTimeUtc(unchecked((long)(((ulong)value.creation.high<<32)|value.creation.low))).Ticks;
  if(expectedCreationTicks!=0 && ticks!=expectedCreationTicks)throw Invalid();
  var buffer=new StringBuilder(32768);
  uint count=GetFinalPathNameByHandleW(handle,buffer,(uint)buffer.Capacity,0);
  if(count==0 || count>=buffer.Capacity || buffer.ToString()!=@"\\?\"+path)throw Invalid();
  return path+"|"+value.volume+"|"+value.indexHigh+":"+value.indexLow+"|"+ticks+"|"+directory;
 }
 RawSecurityDescriptor ReadSecurity() {
  IntPtr o,g,d,s,descriptor;
  if(GetSecurityInfo(handle,1,5,out o,out g,out d,out s,out descriptor)!=0)throw Invalid();
  try {
   uint length=GetSecurityDescriptorLength(descriptor);
   if(length==0 || length>1048576)throw Invalid();
   byte[] bytes=new byte[length]; Marshal.Copy(descriptor,bytes,0,bytes.Length);
   return new RawSecurityDescriptor(bytes,0);
  } finally {LocalFree(descriptor);}
 }
 bool Trusted(SecurityIdentifier sid){return sid!=null && (sid.Value==owner || sid.Value=="S-1-5-18" || sid.Value=="S-1-5-32-544");}
 void ValidateSecurity(RawSecurityDescriptor security,bool restricted) {
  if(security.Owner==null || security.Owner.Value!=owner || security.DiscretionaryAcl==null)throw Invalid();
  if(restricted && ((security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || security.DiscretionaryAcl.Count!=3))throw Invalid();
  var found=new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
  foreach(GenericAce entry in security.DiscretionaryAcl) {
   var ace=entry as CommonAce;
   if(ace==null || ace.IsCallback)throw Invalid();
   if(restricted) {
    if(ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags!=AceFlags.None || ace.AccessMask!=0x1f01ff || !Trusted(ace.SecurityIdentifier) || !found.Add(ace.SecurityIdentifier.Value))throw Invalid();
   } else if((ace.AceFlags&AceFlags.InheritOnly)==0 && ace.AceQualifier==AceQualifier.AccessAllowed && !Trusted(ace.SecurityIdentifier) && (ace.AccessMask&0x100c0000)!=0)throw Invalid();
  }
 }
 public void Restrict() {
  if(Inspect(0)!=identity)throw Invalid();
  ValidateSecurity(ReadSecurity(),false);
  var acl=new RawAcl(2,3);
  foreach(string sid in new[]{owner,"S-1-5-18","S-1-5-32-544"})
   acl.InsertAce(acl.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,0x1f01ff,new SecurityIdentifier(sid),false,null));
  byte[] bytes=new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes,0);
  IntPtr memory=Marshal.AllocHGlobal(bytes.Length);
  try {
   Marshal.Copy(bytes,0,memory,bytes.Length);
   if(SetSecurityInfo(handle,1,0x80000004,IntPtr.Zero,IntPtr.Zero,memory,IntPtr.Zero)!=0)throw Invalid();
  } finally {Marshal.FreeHGlobal(memory);}
  if(Inspect(0)!=identity)throw Invalid();
  ValidateSecurity(ReadSecurity(),true);
 }
 public void Dispose(){handle.Dispose();}
}
'@
}
function Open-WebZipProfileHandle([string]$Path,[string]$OwnerSid,[string]$Identity,[long]$CreationTicks=0) {
    Initialize-WebZipProfileDisposal
    return [WebZipProfileHandle]::new($Path,$OwnerSid,$Identity,$CreationTicks)
}
function Get-WebZipProfileIdentity([string]$Profile,[string]$OwnerSid) {
    $handle = Open-WebZipProfileHandle $Profile $OwnerSid $null
    try { if (-not $handle.IsDirectory) { throw 'profile-directory-required' }; return $handle.Identity }
    finally { $handle.Dispose() }
}
function Protect-WebZipProfileForDisposal([string]$Root,[string]$Profile,[string]$OwnerSid,[string]$Identity,$Clock,[bool]$Quiescent) {
    if (-not $Quiescent -or [string]::IsNullOrEmpty($Identity) -or $Profile -cne (Join-Path $Root 'profile')) { throw 'profile-disposal-binding' }
    Assert-WebZipPath $Root $OwnerSid
    $pending = [Collections.Generic.Stack[object]]::new()
    $pending.Push(@{Path=$Profile;Identity=$Identity;CreationTicks=0})
    $count = 0
    while ($pending.Count) {
        $null = Get-WebZipRemaining $Clock 5000
        if (++$count -gt 20000) { throw 'profile-disposal-limit' }
        $entry = $pending.Pop()
        $handle = Open-WebZipProfileHandle $entry.Path $OwnerSid $entry.Identity $entry.CreationTicks
        try {
            $handle.Restrict()
            Assert-WebZipPath $entry.Path $OwnerSid
            if ($handle.IsDirectory) {
                foreach ($item in Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction Stop) {
                    $null = Get-WebZipRemaining $Clock 5000
                    if ($count + $pending.Count -ge 20000) { throw 'profile-disposal-limit' }
                    if ((Split-Path -Parent $item.FullName) -cne $entry.Path -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'profile-disposal-child' }
                    $pending.Push(@{Path=$item.FullName;Identity=$null;CreationTicks=$item.CreationTimeUtc.Ticks})
                }
            }
        } finally { $handle.Dispose() }
    }
}
function Invoke-WebZipWorker([string]$InstructionPath,[string]$InstructionSha256,[string]$OwnerSid,[long]$AbsoluteDeadlineUnixMs) {
    $clock = New-WebZipClock $AbsoluteDeadlineUnixMs
    $bound = $null; $archive = $null; $ownership = @{Bindings=[Collections.Generic.List[object]]::new();Profile=$null;ProfileIdentity=$null;Job=$null}
    $primary = @{schema=1;outcome='inconclusive';failureCode='admission_failed'}
    $progress = @{stage='admission';step='unknown'}
    $cleanup = @{schema=1;verified=$false;failureCode='cleanup_unresolved';ownedProcessesAbsent=$false}
    $root = Split-Path -Parent $InstructionPath
    try {
        $bound = Read-WebZipInstruction $InstructionPath $InstructionSha256 $OwnerSid
        $instruction = $bound.Value
        Assert-WebZipDesktop $instruction -Worker
        if ($root -cne $instruction.guestRoot) { throw 'worker-root-mismatch' }
        $archive = Open-WebZipBoundFile (Join-Path $root $instruction.archiveFileName) $instruction.archiveSha256 $OwnerSid
        $ownership.Profile = Join-Path $root 'profile'
        if (Test-Path -LiteralPath $ownership.Profile) { throw 'profile-preexists' }
        $existing = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq 9296 })
        if ($existing.Count -ne 0) { throw 'debug-port-preexists' }
        Set-WebZipPrivateDirectory $ownership.Profile $OwnerSid
        $ownership.ProfileIdentity = Get-WebZipProfileIdentity $ownership.Profile $OwnerSid
        $progress.stage = 'browser_start'
        $ownership.Job = Start-WebZipBrowser $ownership.Profile $clock
        $launcher = $ownership.Job.Process
        # Retain the exact launched Process handle before any discovery or wait.
        $null = $launcher.Handle
        $launchBinding = @{Process=$launcher;Id=[int]$launcher.Id;StartTicks=[string]$launcher.StartTime.ToUniversalTime().Ticks;
            SessionId=[int]$instruction.desktop.sessionId;OwnerSid=$OwnerSid;Profile=$ownership.Profile}
        $ownership.Bindings.Add($launchBinding)
        $progress.stage = 'browser_readiness'
        $progress.step = 'process_binding'
        $verified = Get-WebZipProcessBinding $launcher $instruction $ownership.Profile
        $progress.step = 'listener_wait'
        $null = Wait-WebZip $clock 25000 {
            @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq 9296 -and $_.OwningProcess -eq $launcher.Id }).Count -eq 1
        }
        $observed = Invoke-WebZipJourney $instruction $clock $verified $root $progress
        $primary = @{schema=1;outcome='completed';requestSha256=$instruction.requestSha256;candidate=$instruction.candidate;
            archiveSha256=$instruction.archiveSha256;sourceHashes=$instruction.sourceHashes;
            counts=@{pickerOpens=1;fileSelections=1;uploads=1;analyses=1};execution=$observed.execution;
            selectionFingerprint=$observed.selectionFingerprint;confirmationObserved=$observed.confirmationObserved;
            confirmationScreenshotSha256=$observed.confirmationScreenshotSha256;rendered=$observed.rendered}
    } catch {
        # Never persist raw exception text, paths, commands, URLs or credentials.
        $diagnostic = Get-WebZipReadinessDiagnostic $progress $_.Exception.Message
        $primary.failureCode = 'journey_unresolved'; $primary.failureStage = $progress.stage
        $primary.failureStep = $diagnostic.step; $primary.failureReason = $diagnostic.reason
    }
    finally {
        # Primary persistence is independent of teardown; neither can suppress the other.
        try { Write-WebZipJson (Join-Path $root 'primary.json') $primary } catch { $primary = @{schema=1;outcome='inconclusive';failureCode='primary_persistence_failed'} }
        try {
            if ($bound) {
                $null = Stop-WebZipOwnedBrowser $ownership $bound.Value $clock
                $cleanup.ownedProcessesAbsent = $true
                $cleanup.failureCode = 'profile_disposal_unresolved'
                if ($ownership.ProfileIdentity) {
                    Protect-WebZipProfileForDisposal $root $ownership.Profile $OwnerSid $ownership.ProfileIdentity $clock $true
                } elseif ($ownership.Profile -and (Test-Path -LiteralPath $ownership.Profile)) {
                    throw 'profile-identity-unbound'
                }
                $cleanup = @{schema=1;verified=$true;failureCode=$null;ownedProcessesAbsent=$true}
            }
        } catch { if (-not $cleanup.ownedProcessesAbsent) { $cleanup.failureCode='cleanup_unresolved' } }
        finally {
            try { if ($ownership.Job) { $ownership.Job.Dispose() } } catch { $cleanup.verified=$false; $cleanup.failureCode='job_close_failed' }
            try { if ($archive) { $archive.Stream.Dispose() } } catch { $cleanup.verified=$false; $cleanup.failureCode='archive_close_failed' }
            try { if ($bound) { $bound.File.Stream.Dispose() } } catch { $cleanup.verified=$false; $cleanup.failureCode='instruction_close_failed' }
            try { Write-WebZipJson (Join-Path $root 'worker-cleanup.json') $cleanup } catch { }
        }
    }
}
function Remove-WebZipTree([string]$Root,[string]$OwnerSid,$Clock) {
    Assert-WebZipPath $Root $OwnerSid
    $stack = [Collections.Generic.Stack[string]]::new(); $stack.Push($Root)
    $directories = [Collections.Generic.List[string]]::new(); $files = [Collections.Generic.List[string]]::new()
    while ($stack.Count) {
        $null = Get-WebZipRemaining $Clock 5000
        $directory = $stack.Pop(); $directories.Add($directory)
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            if ($directories.Count + $files.Count -gt 20000) { throw 'cleanup-inventory-limit' }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'cleanup-reparse-refused' }
            Assert-WebZipPath $item.FullName $OwnerSid
            if ($item.PSIsContainer) { $stack.Push($item.FullName) } else { $files.Add($item.FullName) }
        }
    }
    foreach ($file in $files) { $null = Get-WebZipRemaining $Clock 5000; Remove-Item -LiteralPath $file -Force -ErrorAction Stop }
    for ($index=$directories.Count-1;$index -ge 0;$index--) { $null = Get-WebZipRemaining $Clock 5000; Remove-Item -LiteralPath $directories[$index] -Force -ErrorAction Stop }
}
function Resolve-WebZipPrincipalSid([string]$Identity) {
    try {
        if ([string]::IsNullOrWhiteSpace($Identity)) { throw 'task-principal-unresolved' }
        if ($Identity -cmatch '^S-[0-9]+(?:-[0-9]+)+$') {
            return [Security.Principal.SecurityIdentifier]::new($Identity).Value
        }
        return ([Security.Principal.NTAccount]::new($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { throw 'task-principal-unresolved' }
}
function Invoke-WebZipParent([string]$EnvelopeBase64) {
    $envelope = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EnvelopeBase64)) | ConvertFrom-Json
    Assert-WebZipKeys $envelope @('schema','instructionBase64','instructionSha256','archiveBase64','archiveSha256','workerBase64','workerSha256','absoluteDeadlineUnixMs','loginBase64')
    $clock = New-WebZipClock $envelope.absoluteDeadlineUnixMs
    $instructionBytes = [Convert]::FromBase64String($envelope.instructionBase64)
    $workerBytes = [Convert]::FromBase64String($envelope.workerBase64)
    $archiveBytes = [Convert]::FromBase64String($envelope.archiveBase64)
    if ((Get-WebZipHash $instructionBytes) -cne $envelope.instructionSha256 -or
        (Get-WebZipHash $workerBytes) -cne $envelope.workerSha256 -or
        (Get-WebZipHash $archiveBytes) -cne $envelope.archiveSha256) { throw 'envelope-hash-mismatch' }
    $instruction = [Text.Encoding]::UTF8.GetString($instructionBytes) | ConvertFrom-Json
    Assert-WebZipDesktop $instruction
    $root = [string]$instruction.guestRoot
    $parent = Split-Path -Parent $root
    if ($parent -cne 'C:\RapporLab\runtime' -or $root -cne ('C:\RapporLab\runtime\web-zip-' + $instruction.requestSha256.Substring(0,16))) { throw 'root-binding-invalid' }
    Assert-WebZipPath $parent $instruction.desktop.sid
    if (Test-Path -LiteralPath $root) { throw 'runtime-root-preexists' }
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $instruction.taskName })
    if ($tasks.Count) { throw 'task-preexists' }
    $ownedRoot = $false; $rootCreationAttempted = $false; $ownedTask = $false; $workerQuiet = $false; $taskAbsent = $false
    $loginCreated = $false; $loginAbsent = $false
    $artifacts = @{}
    $primary = @{schema=1;outcome='inconclusive';failureCode='parent_unresolved'}
    $cleanup = @{schema=1;verified=$false;failureCode='cleanup_unresolved'}
    try {
        $null = Get-WebZipRemaining $clock 90000
        $rootCreationAttempted = $true
        Set-WebZipPrivateDirectory $root $instruction.desktop.sid
        $ownedRoot = $true
        Write-WebZipBytes (Join-Path $root 'instruction.json') $instructionBytes
        Write-WebZipBytes (Join-Path $root 'worker.ps1') $workerBytes
        $loginBytes = [Convert]::FromBase64String($envelope.loginBase64)
        try {
            if ($loginBytes.Length -gt 8192) { throw 'login-input-invalid' }
            $protectedLogin = Protect-WebZipLogin $loginBytes
            $null = Get-WebZipRemaining $clock 90000
            $loginCreated = $true
            Write-WebZipBytes (Join-Path $root 'login.dpapi') $protectedLogin
        } finally { [Array]::Clear($loginBytes,0,$loginBytes.Length); $envelope.loginBase64=$null }
        Write-WebZipBytes (Join-Path $root $instruction.archiveFileName) $archiveBytes
        $bound = Read-WebZipInstruction (Join-Path $root 'instruction.json') $envelope.instructionSha256 $instruction.desktop.sid
        $bound.File.Stream.Dispose()
        if ($envelope.workerSha256 -cne $instruction.sourceHashes.'web-zip-windows-orchestrator.ps1' -or
            $envelope.archiveSha256 -cne $instruction.archiveSha256) { throw 'materialization-binding-mismatch' }
        $quote = { param([string]$value) "'" + $value.Replace("'","''") + "'" }
        # Load the exact bound bytes as a command, without executing a script file
        # or changing the desktop account's execution policy.
        $command = '$ErrorActionPreference=''Stop''; $webZipWorkerBytes=[IO.File]::ReadAllBytes(' +
            (& $quote (Resolve-WebZipPhysicalPath (Join-Path $root 'worker.ps1'))) + '); $webZipWorkerHasher=[Security.Cryptography.SHA256]::Create(); ' +
            'try{$webZipWorkerHash=[BitConverter]::ToString($webZipWorkerHasher.ComputeHash($webZipWorkerBytes)).Replace(''-'','''').ToLowerInvariant()}finally{$webZipWorkerHasher.Dispose()}; ' +
            'if($webZipWorkerHash -cne ' + (& $quote $envelope.workerSha256) + '){throw ''worker-source-hash-mismatch''}; ' +
            '. ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($webZipWorkerBytes))); Invoke-WebZipWorker -InstructionPath ' +
            (& $quote (Join-Path $root 'instruction.json')) + ' -InstructionSha256 ' + (& $quote $envelope.instructionSha256) +
            ' -OwnerSid ' + (& $quote $instruction.desktop.sid) + ' -AbsoluteDeadlineUnixMs ' + [string]$envelope.absoluteDeadlineUnixMs
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded
        if (('powershell.exe ' + $arguments).Length -ge 8191) { throw 'worker-command-size-invalid' }
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        $principal = New-ScheduledTaskPrincipal -UserId $instruction.desktop.sid -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMilliseconds((Get-WebZipRemaining $clock 10000)))
        $null = Get-WebZipRemaining $clock 90000
        Register-ScheduledTask -TaskName $instruction.taskName -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
        $ownedTask = $true
        $null = Get-WebZipRemaining $clock 90000
        Start-ScheduledTask -TaskName $instruction.taskName -ErrorAction Stop
        $null = Wait-WebZip $clock ([int](Get-WebZipRemaining $clock 15000)) {
            $found = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $instruction.taskName })
            if ($found.Count -ne 1) { throw 'owned-task-disappeared' }
            return ($found[0].State -ne 'Running' -and (Test-Path -LiteralPath (Join-Path $root 'worker-cleanup.json')))
        } 15000
        $workerQuiet = $true
        $cleanup = Get-Content -LiteralPath (Join-Path $root 'worker-cleanup.json') -Raw -ErrorAction Stop | ConvertFrom-Json
        try { $primary = Get-Content -LiteralPath (Join-Path $root 'primary.json') -Raw -ErrorAction Stop | ConvertFrom-Json }
        catch { $primary = @{schema=1;outcome='inconclusive';failureCode='primary_persistence_failed'} }
        if ($primary.outcome -ceq 'completed') {
            foreach ($name in @('confirmation.png','execution.png','history.png')) {
                $path = Join-Path $root $name
                Assert-WebZipPath $path $instruction.desktop.sid -File
                $bytes = [IO.File]::ReadAllBytes((Resolve-WebZipPhysicalPath $path))
                if ($bytes.Length -lt 100 -or $bytes.Length -gt 524288) { throw 'screenshot-size-invalid' }
                $artifacts[$name] = @{sha256=(Get-WebZipHash $bytes);base64=[Convert]::ToBase64String($bytes)}
            }
        }
    } catch { $primary = @{schema=1;outcome='inconclusive';failureCode='parent_unresolved'} }
    finally {
        try {
            if ($loginCreated) {
                $loginPath = Join-Path $root 'login.dpapi'
                if (Test-Path -LiteralPath $loginPath) {
                    Assert-WebZipPath $loginPath $instruction.desktop.sid -File
                    $null = Get-WebZipRemaining $clock 5000
                    Remove-Item -LiteralPath $loginPath -Force -ErrorAction Stop
                }
            }
            $loginAbsent = -not (Test-Path -LiteralPath (Join-Path $root 'login.dpapi'))
        } catch { $loginAbsent=$false }
        try {
            if ($ownedTask) {
                $found = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $instruction.taskName })
                if ($found.Count -ne 1 -or $found[0].TaskPath -cne '\' -or @($found[0].Actions).Count -ne 1 -or
                    (Resolve-WebZipPrincipalSid $found[0].Principal.UserId) -cne $instruction.desktop.sid -or
                    $found[0].Principal.LogonType -cne 'Interactive' -or $found[0].Principal.RunLevel -cne 'Limited' -or
                    $found[0].Actions.Execute -cne $action.Execute -or
                    [string]($found[0].Actions.WorkingDirectory) -cne [string]($action.WorkingDirectory) -or
                    $found[0].Actions.Arguments -cne $action.Arguments) { throw 'task-ownership-changed' }
                if ($found[0].State -eq 'Running') {
                    $null = Get-WebZipRemaining $clock 5000
                    Stop-ScheduledTask -TaskName $instruction.taskName -TaskPath '\' -ErrorAction Stop
                    $null = Wait-WebZip $clock 5000 {
                        (Get-ScheduledTask -TaskName $instruction.taskName -TaskPath '\' -ErrorAction Stop).State -ne 'Running'
                    } 5000
                }
                $workerQuiet = $true
                $null = Get-WebZipRemaining $clock 5000
                Unregister-ScheduledTask -TaskName $instruction.taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
            }
            if (-not $ownedTask) {
                $workerQuiet=$true
                $cleanup=@{schema=1;verified=($ownedRoot -or -not $rootCreationAttempted);failureCode=$null;ownedProcessesAbsent=$true;runtimeRootAbsent=$false}
                if ($rootCreationAttempted -and -not $ownedRoot) { $cleanup.failureCode='root_ownership_unresolved' }
            }
            $taskAbsent = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $instruction.taskName }).Count -eq 0
            if ($ownedRoot -and $workerQuiet -and $cleanup.verified -eq $true -and $taskAbsent) {
                # Export sanitized settlements before deletion; screenshots stay private by hash.
                Remove-WebZipTree $root $instruction.desktop.sid $clock
                $cleanup | Add-Member -NotePropertyName runtimeRootAbsent -NotePropertyValue (-not (Test-Path -LiteralPath $root)) -Force
            } else { $cleanup.verified=$false }
        } catch { $cleanup.verified=$false; $cleanup.failureCode='parent_cleanup_unresolved' }
        if (-not $loginAbsent) { $cleanup.verified=$false; $cleanup.failureCode='login_cleanup_unresolved' }
        $cleanup | Add-Member -NotePropertyName loginMaterialAbsent -NotePropertyValue $loginAbsent -Force
        [Console]::Out.WriteLine((@{schema=1;instructionSha256=$envelope.instructionSha256;primary=$primary;cleanup=$cleanup;
            taskAbsent=$taskAbsent;workerQuiescent=$workerQuiet;artifacts=$artifacts} | ConvertTo-Json -Depth 30 -Compress))
    }
}
