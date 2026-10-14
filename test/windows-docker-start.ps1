param([string]$SourcePath='C:\RapporLab\guest.ps1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'Guest script parse failed.'}
foreach($name in @('Test-DockerDaemonReady','Invoke-DockerStart')){
 $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if($null -eq $node){throw 'Required function missing.'}
 Invoke-Expression $node.Extent.Text
}
function Get-DockerPath {return 'docker.exe'}
function Write-Result([hashtable]$Value){$script:result=$Value}
function Start-Sleep {param([int]$Seconds)}
function Invoke-ReadinessProbe {param($Phase,$FilePath,$Arguments)
 $entry=$script:probes.Dequeue();if($entry -eq 'timeout'){throw 'Synthetic native timeout.'}
 return $entry
}
function Invoke-Native {param($FilePath,$Arguments)
 if($FilePath -ne 'schtasks.exe'){throw 'Unexpected mutation.'}
 $script:tasks.Add($Arguments[0]);return @{ExitCode=$script:taskExit}
}
function Reset-Test($items){$script:probes=[Collections.Generic.Queue[object]]::new();foreach($item in $items){$script:probes.Enqueue($item)};$script:tasks=[Collections.Generic.List[string]]::new();$script:result=$null;$script:taskExit=0}
$ready=@{ExitCode=0;Output=@('{"ServerVersion":"29.8.0","OSType":"linux"}')}
Reset-Test @($ready);Invoke-DockerStart
if($script:tasks.Count -ne 0 -or -not $script:result.alreadyReady){throw 'Healthy daemon was interrupted.'}
foreach($failure in @(@{ExitCode=1;Output=@('')},@{ExitCode=0;Output=@('invalid-json')},'timeout')){
 Reset-Test @($failure,$ready);Invoke-DockerStart
 if(($script:tasks -join ',') -ne '/End,/Run' -or $script:result.alreadyReady -or -not $script:result.started){throw 'Bounded recovery failed.'}
}
Reset-Test @(@{ExitCode=1;Output=@('')});$script:taskExit=1;$rejected=$false
try{Invoke-DockerStart}catch{$rejected=$true}
if(-not $rejected -or $null -ne $script:result){throw 'Failed task start was accepted.'}
Write-Output 'RAPPOR_LAB_RESULT={"dockerStartTests":5,"passed":true}'
