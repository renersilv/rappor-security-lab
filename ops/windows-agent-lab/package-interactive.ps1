[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$CandidateSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^\d+\.\d+\.\d+\.\d+$')][string]$CandidateVersion,
 [switch]$Worker,
 [ValidatePattern('^[a-f0-9]{32}$')][string]$Run=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$taskName='RapporLab-InstallCandidate'
if(-not $Worker){$Run=[guid]::NewGuid().ToString('N')}
$directory=Join-Path 'C:\RapporLab\runtime' ('install-call-'+$Run)
$resultPath=Join-Path $directory 'result.json'
if($Worker){
 $result=@{passed=$false;failureClass='interactive-install-failed'}
 try{
  if((Get-Process -Id $PID).SessionId -eq 0){throw 'Interactive login required.'}
  $candidate='C:\RapporLab\runtime\candidate.msix'
  if((Get-AuthenticodeSignature -LiteralPath $candidate).Status -ne 'Valid'){throw 'Invalid signature.'}
  $output=& 'C:\RapporLab\guest.ps1' -Action InstallCandidate -CandidateSha256 $CandidateSha256 -CandidateVersion $CandidateVersion
  $marker=@($output | Where-Object {$_ -like 'RAPPOR_LAB_RESULT=*'})
  if($marker.Count -ne 1){throw 'Installation evidence missing.'}
  $installed=$marker[0].Substring('RAPPOR_LAB_RESULT='.Length)|ConvertFrom-Json
  if($installed.version -ne $CandidateVersion -or $installed.status -ne 'Ok'){throw 'Unexpected installed package.'}
  $result=@{passed=$true;installed=$installed.installed;version=$installed.version;architecture=$installed.architecture;status=$installed.status;idempotent=$installed.idempotent;graphicalSession=$true}
 }catch{$result.errorType=$_.Exception.GetType().Name;$result.hresult=$_.Exception.HResult}
 [IO.File]::WriteAllText((Join-Path $directory 'result.tmp'),($result|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
 Move-Item -LiteralPath (Join-Path $directory 'result.tmp') -Destination $resultPath
 exit
}
$user=(Get-CimInstance Win32_ComputerSystem).UserName
if($user -ne "$env:COMPUTERNAME\$env:USERNAME"){throw 'Existing laboratory desktop required.'}
if($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)){throw 'An installation task already exists.'}
New-Item -ItemType Directory -Path $directory | Out-Null
& icacls.exe $directory /inheritance:r /grant:r ('{0}:(OI)(CI)F' -f $user) '*S-1-5-18:(OI)(CI)F' *> $null
if($LASTEXITCODE -ne 0){throw 'Private directory ACL failed.'}
$command="& '$($PSCommandPath.Replace("'","''"))' -Worker -Run '$Run' -CandidateSha256 '$CandidateSha256' -CandidateVersion '$CandidateVersion'"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$action=New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded)
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(240))
try{
 Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
 Start-ScheduledTask -TaskName $taskName
 $deadline=[DateTimeOffset]::UtcNow.AddSeconds(250)
 while(-not (Test-Path -LiteralPath $resultPath)){
  if([DateTimeOffset]::UtcNow -gt $deadline){throw 'Interactive installation timed out.'}
  Start-Sleep -Milliseconds 500
 }
 $result=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
 Write-Output ('RAPPOR_LAB_RESULT='+($result | ConvertTo-Json -Compress))
 if(-not $result.passed){exit 1}
}finally{
 Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
 foreach($name in @('result.json','result.tmp')){$file=Join-Path $directory $name;if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}}
 if(@(Get-ChildItem -LiteralPath $directory).Count -eq 0){Remove-Item -LiteralPath $directory}
}
