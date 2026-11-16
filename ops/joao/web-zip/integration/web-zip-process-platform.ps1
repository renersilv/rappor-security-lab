# Offline platform fixture. Loaded after the exact production library in each
# process. Windows APIs are simulated; the parent, worker, bindings, receipt
# writes, hashing and cleanup control flow remain the production implementation.
$script:FixtureSid = 'S-1-5-21-100-200-300-1001'
$script:FixtureRoot = $env:WEB_ZIP_FIXTURE_ROOT
$drive=Join-Path $script:FixtureRoot 'drive'
[IO.Directory]::CreateDirectory((Join-Path $drive 'RapporLab/runtime')) | Out-Null
if(-not (Get-PSDrive -Name C -ErrorAction SilentlyContinue)) {New-PSDrive -Name C -PSProvider FileSystem -Root $drive|Out-Null}
$script:FixtureScenario = $env:WEB_ZIP_FIXTURE_SCENARIO
$script:FixtureWorker = $env:WEB_ZIP_FIXTURE_ROLE -eq 'worker'
$script:FixtureTask = $null
$script:FixtureTaskProcess = $null
$script:FixtureOwned = $null
$script:FixtureAuthenticated=$false
$script:FixtureLoginSubmits=0
$script:FixtureNetworkEnabled=$false
function Add-FixtureEvent([string]$Event) {
    [IO.File]::AppendAllText((Join-Path $script:FixtureRoot 'events.txt'),$Event + "`n")
}
function Resolve-WebZipPhysicalPath([string]$Path) {
    if ($Path -match '^C:\\') { return Join-Path $script:FixtureRoot ('drive/' + $Path.Substring(3).Replace('\','/')) }
    return $Path
}
function Get-WebZipCanonicalPath([string]$Path) {
    if ($Path -match '^C:\\' -and $Path -notmatch '\\[.]([.]?)\\' -and $Path -notmatch '\\\\') { return $Path }
    return [IO.Path]::GetFullPath($Path)
}
function Get-WebZipDesktopObservation {
    $sid=if($script:FixtureScenario -eq 'desktop-drift'){'S-1-5-21-100-200-300-1999'}else{$script:FixtureSid}
    return @{uuid='13918e5c-5b79-4a99-9029-0aa515f5a732';account='joao';sid=$sid;sessionId=1;explorerCount=1;explorerSid=$sid;processSid=$sid;processSessionId=1}
}
function Get-Acl {
    param([string]$LiteralPath)
    $value = [pscustomobject]@{OwnerValue=$script:FixtureSid}
    $value | Add-Member ScriptMethod GetOwner { param($Type) [pscustomobject]@{Value=$this.OwnerValue} }
    $value | Add-Member ScriptMethod GetAccessRules { param($Inherited,$Explicit,$Type) @() }
    return $value
}
function Set-WebZipPrivateDirectory([string]$Path,[string]$OwnerSid) {
    [IO.Directory]::CreateDirectory((Resolve-WebZipPhysicalPath $Path)) | Out-Null
    if($script:FixtureScenario -eq 'partial-root-creation'){
        [IO.File]::WriteAllText((Join-Path (Resolve-WebZipPhysicalPath $Path) 'partial-sentinel.txt'),'preserve-unconfirmed-root')
        Add-FixtureEvent 'partial-root-created';throw 'injected-acl-creation-failure'
    }
    Assert-WebZipPath $Path $OwnerSid
}
function Get-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    Microsoft.PowerShell.Management\Get-Item -LiteralPath (Resolve-WebZipPhysicalPath $LiteralPath) -Force -ErrorAction Stop
}
function Test-Path {
    [CmdletBinding()]param([string]$LiteralPath,[string]$PathType)
    if ($PathType) {return Microsoft.PowerShell.Management\Test-Path -LiteralPath (Resolve-WebZipPhysicalPath $LiteralPath) -PathType $PathType}
    return Microsoft.PowerShell.Management\Test-Path -LiteralPath (Resolve-WebZipPhysicalPath $LiteralPath)
}
function Get-Content {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Raw)
    Microsoft.PowerShell.Management\Get-Content -LiteralPath (Resolve-WebZipPhysicalPath $LiteralPath) -Raw -ErrorAction Stop
}
function Get-ChildItem {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath (Resolve-WebZipPhysicalPath $LiteralPath) -Force -ErrorAction Stop
}
function Remove-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    $physical=Resolve-WebZipPhysicalPath $LiteralPath
    if (-not $physical.StartsWith((Join-Path $script:FixtureRoot 'drive/RapporLab/runtime/web-zip-'),[StringComparison]::Ordinal)) {throw 'fixture-removal-outside-owned-root'}
    if($physical.EndsWith('/login.dpapi')){Add-FixtureEvent 'login-material-removed'}
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $physical -Force -ErrorAction Stop
}
function New-ScheduledTaskAction {param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Arguments=$Argument}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) [pscustomobject]@{UserId=$UserId}}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit)
    if($script:FixtureScenario -eq 'deadline-before-register'){$script:FixtureExpired=$true}
    [pscustomobject]@{ExecutionTimeLimit=$ExecutionTimeLimit}
}
function Register-ScheduledTask {
    [CmdletBinding()]param($TaskName,$Action,$Principal,$Settings)
    if ($script:FixtureWorker) {throw 'worker-must-not-register-task'}
    $script:FixtureTask=[pscustomobject]@{TaskName=$TaskName;TaskPath='\';Actions=$Action;Principal=$Principal;State='Ready'}
    Add-FixtureEvent 'task-registered'
}
function Get-ScheduledTask {
    [CmdletBinding()]param($TaskName)
    if ($script:FixtureTask) {
        if ($script:FixtureTaskProcess -and $script:FixtureTaskProcess.HasExited) {
            $script:FixtureTask.State='Ready'
            if (-not $script:WorkerOutputSaved) {
                [IO.File]::WriteAllText((Join-Path $script:FixtureRoot 'worker-stderr.txt'),$script:FixtureTaskProcess.StandardError.ReadToEnd())
                [IO.File]::WriteAllText((Join-Path $script:FixtureRoot 'worker-stdout.txt'),$script:FixtureTaskProcess.StandardOutput.ReadToEnd())
                $script:WorkerOutputSaved=$true
            }
        }
        return $script:FixtureTask
    }
    return @()
}
function Start-ScheduledTask {
    [CmdletBinding()]param($TaskName)
    if ($script:FixtureWorker) {throw 'worker-must-not-start-task'}
    $encoded=($script:FixtureTask.Actions.Arguments -split ' ')[-1]
    $command=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
    # Keep the actual generated invocation. Insert only platform fixture loading
    # after the library definition, as this child has independent function scope.
    $parts=$command -split '; Invoke-WebZipWorker',2
    if ($parts.Count -ne 2) {throw 'fixture-generated-worker-command-unrecognized'}
    $scriptText=$parts[0] + "; . '" + $env:WEB_ZIP_PLATFORM_FIXTURE.Replace("'","''") + "'; Invoke-WebZipWorker" + $parts[1]
    $scriptText=$scriptText.Replace(". 'C:\RapporLab\runtime\", ". '" + (Join-Path $script:FixtureRoot 'drive/RapporLab/runtime/'))
    $scriptText=$scriptText.Replace("\worker.ps1'", "/worker.ps1'")
    $path=Join-Path $script:FixtureRoot 'worker-launch.ps1'
    [IO.File]::WriteAllText($path,$scriptText)
    $info=[Diagnostics.ProcessStartInfo]::new($env:PWSH_BIN)
    $info.UseShellExecute=$false
    foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-File',$path)) {$info.ArgumentList.Add($argument)}
    $info.Environment['WEB_ZIP_FIXTURE_ROLE']='worker'
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $script:FixtureTaskProcess=[Diagnostics.Process]::Start($info)
    $script:FixtureTask.State='Running'
    Add-FixtureEvent ('worker-started:' + $script:FixtureTaskProcess.Id)
}
function Stop-ScheduledTask {
    [CmdletBinding()]param($TaskName)
    if ($script:FixtureWorker) {throw 'worker-must-not-stop-own-task'}
    Add-FixtureEvent 'parent-task-stop'
    if ($script:FixtureTaskProcess -and -not $script:FixtureTaskProcess.HasExited) {
        $script:FixtureTaskProcess.Kill();$script:FixtureTaskProcess.WaitForExit(2000)|Out-Null
    }
    $script:FixtureTask.State='Ready'
}
function Unregister-ScheduledTask {
    [CmdletBinding(SupportsShouldProcess)]param($TaskName)
    if ($script:FixtureWorker) {throw 'worker-must-not-remove-own-task'}
    if ($script:FixtureTaskProcess -and -not $script:FixtureTaskProcess.HasExited) {throw 'task-removed-before-worker-quiescence'}
    Add-FixtureEvent 'parent-task-removed';$script:FixtureTask=$null
}
function Start-Process {
    [CmdletBinding()]param($FilePath,$ArgumentList,[switch]$PassThru)
    if ($FilePath -cne 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe') {throw 'fixture-unexpected-launch'}
    $info=[Diagnostics.ProcessStartInfo]::new($env:PWSH_BIN)
    $info.UseShellExecute=$false
    foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 60')) {$info.ArgumentList.Add($argument)}
    $real=[Diagnostics.Process]::Start($info)
    $script:FixtureProfile=([string]($ArgumentList|Where-Object{$_ -like '--user-data-dir=*'})).Substring(16)
    $value=[pscustomobject]@{Id=$real.Id;StartTime=$real.StartTime;Handle=$real.Handle;SessionId=1;Real=$real}
    $value|Add-Member ScriptProperty HasExited {$this.Real.HasExited}
    $value|Add-Member ScriptMethod WaitForExit {param($Timeout) $this.Real.WaitForExit($Timeout)}
    $script:FixtureOwned=$value
    Add-FixtureEvent ('browser-started:'+$real.Id)
    return $value
}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName)
    if ($ClassName -cne 'Win32_Process') {throw ('fixture-unexpected-cim:'+$ClassName)}
    if ($script:FixtureOwned -and -not $script:FixtureOwned.HasExited) {
        if ($script:FixtureScenario -eq 'discovery-failure' -and -not $script:DiscoveryFailed) {
            $script:DiscoveryFailed=$true;throw 'injected-process-discovery-failure'
        }
        [pscustomobject]@{ProcessId=$script:FixtureOwned.Id;Name='msedge.exe';SessionId=1;CommandLine=('--user-data-dir='+$script:FixtureProfile)}
        [pscustomobject]@{ProcessId=[int]$env:WEB_ZIP_PREEXISTING_PID;Name='msedge.exe';SessionId=1;CommandLine='--user-data-dir=C:\UnrelatedProfile'}
        return
    }
    return @()
}
$script:DiscoveryFailed=$false
function Invoke-CimMethod {[CmdletBinding()]param($InputObject,$MethodName) [pscustomobject]@{ReturnValue=0;Sid=$script:FixtureSid}}
function Get-NetTCPConnection {
    [CmdletBinding()]param($State,$LocalPort)
    if ($script:FixtureOwned -and -not $script:FixtureOwned.HasExited) {
        return [pscustomobject]@{LocalPort=9296;LocalAddress='127.0.0.1';OwningProcess=$script:FixtureOwned.Id}
    }
    return @()
}
function Stop-Process {
    [CmdletBinding()]param($InputObject,[switch]$Force)
    if (-not $script:FixtureOwned -or $InputObject.Id -ne $script:FixtureOwned.Id) {throw 'fixture-refuses-unowned-stop'}
    $InputObject.Real.Kill();Add-FixtureEvent ('browser-stopped:'+$InputObject.Id)
}

$script:WorkerOutputSaved=$false
$script:FixtureExpired=$false
$script:ProductionRemaining=${function:Get-WebZipRemaining}
function Get-WebZipRemaining($Clock,[int]$Reserve=0) {
    if($script:FixtureScenario -eq 'login-timeout' -and $script:FixtureLoginSubmits -gt 0 -and $Reserve -eq 90000){return 1}
    if($script:FixtureExpired -and $Reserve -eq 90000){throw 'absolute-deadline'}
    if ($script:FixtureScenario -eq 'timeout' -and $script:FixtureOwned -and $Reserve -eq 90000) {return 1}
    return & $script:ProductionRemaining $Clock $Reserve
}
function Start-WebZipBrowser([string]$Profile) {
    $process=Start-Process -FilePath 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' -ArgumentList @('--user-data-dir='+$Profile) -PassThru
    $job=[pscustomobject]@{Process=$process}
    $job|Add-Member ScriptProperty Active {if($this.Process.HasExited){0}else{1}}
    $job|Add-Member ScriptMethod Terminate {
        if (-not $this.Process.HasExited) {$this.Process.Real.Kill();Add-FixtureEvent ('browser-stopped:'+$this.Process.Id)}
    }
    $job|Add-Member ScriptMethod Dispose {if(-not $this.Process.HasExited){$this.Process.Real.Kill()}}
    if ($script:FixtureScenario -eq 'primary-write-failure') {
        $parent=Split-Path -Parent $Profile
        [IO.File]::WriteAllText((Resolve-WebZipPhysicalPath (Join-Path $parent 'primary.json')),'{"schema":1,"outcome":"inconclusive","failureCode":"injected-existing-primary"}')
    }
    return $job
}
$script:ProductionTcp=${function:Get-NetTCPConnection}
function Get-NetTCPConnection {
    [CmdletBinding()]param($State,$LocalPort)
    if($script:FixtureScenario -eq 'timeout'){return @()}
    & $script:ProductionTcp -State $State -LocalPort $LocalPort
}
function Initialize-WebZipUi {
    Add-Type -TypeDefinition @'
using System;
namespace Windows.Automation {
 public enum TreeScope {Children,Descendants}
 public class PropertyCondition {public object Value;public PropertyCondition(object p,object v){Value=v;}}
 public class ValuePattern {public static object Pattern=new object();}
 public class InvokePattern {public static object Pattern=new object();}
 public class Pattern {public void SetValue(string value){AutomationElement.Selected=value;}public void Invoke(){AutomationElement.Clicked=true;}}
 public class CurrentData {public int ProcessId;public int NativeWindowHandle=22;public string ClassName="#32770";}
 public class AutomationElement {
  public static object ProcessIdProperty=new object(),AutomationIdProperty=new object();
  public static AutomationElement RootElement=new AutomationElement();
  public static int OwnedPid;public static bool Foreign;public static string Selected;public static bool Clicked;
  public CurrentData Current=new CurrentData();
  public AutomationElement[] FindAll(TreeScope scope,PropertyCondition condition){var e=new AutomationElement();e.Current.ProcessId=Foreign?999999:OwnedPid;return new[]{e};}
  public Pattern GetCurrentPattern(object pattern){return new Pattern();}
 }
}
public static class WebZipNative {
 public static int GetWindowThreadProcessId(IntPtr window,out uint pid){pid=(uint)Windows.Automation.AutomationElement.OwnedPid;return 1;}
 public static IntPtr GetWindow(IntPtr window,uint which){return new IntPtr(11);}
}
'@
    [Windows.Automation.AutomationElement]::OwnedPid=$script:FixtureOwned.Id
    [Windows.Automation.AutomationElement]::Foreign=$script:FixtureScenario -eq 'foreign-dialog'
}
function Connect-WebZipCdp($Binding,$Clock) {
    Add-FixtureEvent ('cdp-connected:'+$Binding.Id)
    $file=Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath (Join-Path $script:FixtureRoot 'drive/RapporLab/runtime') -Filter instruction.json -Recurse
    $script:FixtureInstruction=[IO.File]::ReadAllText($file.FullName)|ConvertFrom-Json
    $socket=[pscustomobject]@{}
    $socket|Add-Member ScriptMethod Abort {}
    $socket|Add-Member ScriptMethod Dispose {}
    return @{Socket=$socket;Events=[Collections.Generic.List[object]]::new();Clock=$Clock;Sequence=0}
}
function Invoke-WebZipCdp($Cdp,[string]$Method,$Parameters) {
    $i=$script:FixtureInstruction;$p=$i.product
    $execution='00000000-0000-4000-8000-000000000004'
    switch($Method){
      'Network.disable' {$script:FixtureNetworkEnabled=$false;Add-FixtureEvent 'network-disabled';return @{}}
      'Network.enable' {
        if(-not $script:FixtureAuthenticated){throw 'fixture-network-capture-before-authentication'}
        $script:FixtureNetworkEnabled=$true;Add-FixtureEvent 'network-enabled';return @{}
      }
      'Page.enable' {return @{}}
      'Page.navigate' {
        if($Parameters.url.EndsWith('/login')){Add-FixtureEvent 'login-navigation'}
        elseif(-not $script:FixtureAuthenticated){throw 'fixture-navigation-before-login'}
        else{Add-FixtureEvent 'authenticated-navigation'}
        return @{}
      }
      'Page.captureScreenshot' {return @{data=[Convert]::ToBase64String([byte[]]::new(128))}}
      'Network.getResponseBody' {return @{base64Encoded=$false;body=(@{id=$execution;productId=$p.productId;analysisDefinitionId=$p.analysisDefinitionId}|ConvertTo-Json -Compress)}}
      'Network.getRequestPostData' {return @{postData=('name="analysisDefinitionRevisionId"' + "`r`n`r`n" + $p.revisionId + "`r`n" + 'name="idempotencyKey"' + "`r`n`r`n00000000-0000-4000-8000-000000000005`r`n")}}
      'Runtime.evaluate' {
        $expression=[string]$Parameters.expression
        if($expression -ceq 'location.origin') {
          $value=if($script:FixtureScenario -eq 'login-cross-origin'){'https://unrelated.invalid'}else{$i.candidate.origin}
        }
        elseif($expression.Contains('login-controls-invalid')) {
          if($script:FixtureNetworkEnabled){throw 'fixture-secret-under-network-capture'}
          if(-not $expression.Contains('synthetic-login@example.invalid') -or -not $expression.Contains('Synthetic-Only-Lab-Password!42')){throw 'fixture-wrong-login-values'}
          $script:FixtureLoginSubmits++
          if($script:FixtureLoginSubmits -ne 1){throw 'fixture-duplicate-login'}
          Add-FixtureEvent 'login-submitted'
          $script:FixtureAuthenticated=$script:FixtureScenario -notin @('login-rejected','login-timeout')
          $value=$true
        }
        elseif($expression.Contains('login-rejected')) {
          if($script:FixtureScenario -eq 'login-rejected'){throw 'login-rejected'}
          $value=$script:FixtureAuthenticated
        }
        elseif($expression.Contains('#login-email')) {$value=$true}
        elseif($expression.Contains('version:document.body.innerText')) {$value=@{path=('/products/'+$p.productId+'/analyses/'+$p.analysisDefinitionId);version=$i.candidate.version;input=$true}}
        elseif($expression.Contains('lastModified')) {$value=@{name=$i.archiveFileName;size=$i.archiveSize;lastModified=1}}
        elseif($expression.Contains('const pairs=')) {$value=@{pathname=('/executions/'+$execution);executionId=$execution;revisionId=$p.revisionId;productId=$p.productId;text='3 of 3 tools Gitleaks, Semgrep, and Trivy completed SCORE FOR THIS EXECUTION 58.9 out of 100 70 Problems'}}
        elseif($expression.Contains('({path:location.pathname})')) {
          if($Cdp.Events.Count -eq 0){
            $Cdp.Events.Add([pscustomobject]@{method='Network.requestWillBeSent';params=@{requestId='fixture-request';request=@{url=($i.candidate.origin+'/api/analysis-definitions/'+$p.analysisDefinitionId+'/assessments/uploaded-code');method='POST'}}})
            $Cdp.Events.Add([pscustomobject]@{method='Network.responseReceived';params=@{requestId='fixture-request';response=@{status=200}}})
          }
          $value=@{path=('/executions/'+$execution)}
        } else {$value=$true}
        return @{result=@{value=$value}}
      }
      default {throw ('fixture-unexpected-cdp-method:'+$Method)}
    }
}
# Windows path spelling is an OS primitive; actual instruction/root comparisons
# remain unchanged and see exactly one backslash, as on the Windows filesystem.
function Join-Path {
    param([string]$Path,[string]$ChildPath)
    if($Path -match '^C:\\'){return $Path.TrimEnd('\') + '\' + $ChildPath}
    Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath
}
function Split-Path {
    param([string]$Path,[switch]$Parent)
    if($Path -match '^C:\\'){
        $index=$Path.TrimEnd('\').LastIndexOf('\')
        if($index -lt 2){return ''}
        if($index -eq 2){return 'C:\'}
        return $Path.Substring(0,$index)
    }
    Microsoft.PowerShell.Management\Split-Path -Path $Path -Parent
}

# DPAPI is a Windows primitive unavailable on Linux. This reversible synthetic
# encoding exercises encrypted-file lifetime only, not DPAPI security semantics.
function Protect-WebZipLogin([byte[]]$Bytes) {
    Add-FixtureEvent 'login-protected'
    $out=[byte[]]::new($Bytes.Length+1);$out[0]=42
    for($index=0;$index -lt $Bytes.Length;$index++){$out[$index+1]=$Bytes[$index] -bxor 90}
    return ,$out
}
function Unprotect-WebZipLogin([byte[]]$Bytes) {
    if($Bytes.Length -lt 2 -or $Bytes[0] -ne 42){throw 'fixture-encrypted-login-invalid'}
    $out=[byte[]]::new($Bytes.Length-1)
    for($index=0;$index -lt $out.Length;$index++){$out[$index]=$Bytes[$index+1] -bxor 90}
    Add-FixtureEvent 'login-unprotected'
    return ,$out
}
