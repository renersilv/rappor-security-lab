import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { POWERSHELL_STDIN_BOOTSTRAP_BASE64 } from '../../src/powershell-stdin-transport.mjs';
const { buildPreparationSource } = await import(process.env.JOAO_PREPARATION_SOURCE
  ? pathToFileURL(process.env.JOAO_PREPARATION_SOURCE).href : new URL('../../src/windows-ide-preparation.mjs', import.meta.url).href);
const image = 'mcr.microsoft.com/dotnet/sdk@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b';
const digest = value => createHash('sha256').update(value).digest('hex');
for (const scenario of ['ready', 'preexisting', 'write-failure', 'hash-mismatch', 'creation-race', 'unexpected-file', 'reparse-file', 'changed-generation', 'cleanup-failure', 'task-query-error']) {
  test(`generated preparation PowerShell: ${scenario}`, () => {
    const source = buildPreparationSource({ guestRoot: 'C:\\RapporLab\\runtime\\pass731-ide-readiness',
      taskName: 'RapporLab-Pass731-IdeReadiness', minimumGuestFreeBytes: 1000,
      interactiveBase64: Buffer.from('interactive-source').toString('base64'), observerBase64: Buffer.from('observer-source').toString('base64'),
      interactiveSha256: digest('interactive-source'), observerSha256: digest(scenario === 'hash-mismatch' || scenario === 'cleanup-failure' ? 'wrong' : 'observer-source') });
    const script = String.raw`
$ErrorActionPreference='Stop'
$scenario='${scenario}'
$directory='/tmp/preparation-fixture'
$null=Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $directory
$null=New-PSDrive -Name C -PSProvider FileSystem -Root $directory
$target='C:\RapporLab\runtime\pass731-ide-readiness'
$native=$directory+'/RapporLab/runtime/pass731-ide-readiness'
$null=Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path ($directory+'/RapporLab/runtime') -Force
$script:injected=$false
# Linux tmpfs does not provide NTFS birth time; model only that Windows metadata property.
# File bytes, handles, hashes, enumeration, creation and removal remain real filesystem operations.
$script:rootBirth=[DateTime]::Parse('2026-11-15T12:00:00Z').ToUniversalTime()
function Get-Item {
 param($LiteralPath,[switch]$Force,$ErrorAction)
 $item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
 if($item.FullName -eq $native){$item | Add-Member -NotePropertyName CreationTimeUtc -NotePropertyValue $script:rootBirth -Force}
 return $item
}
function Join-Path {
 param($Path,$ChildPath)
 $joined=Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath
 $resolved=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($joined)
 if($scenario -eq 'write-failure' -and $ChildPath -eq 'observe.ps1' -and -not $script:injected){$script:injected=$true;return $native}
 return $resolved
}
function Get-ScheduledTask {
 param($TaskName,$ErrorAction)
 if($scenario -eq 'task-query-error'){throw 'fixture-task-query-error'}
 if($TaskName -and $ErrorAction -eq 'Stop'){throw 'fixture-task-not-found'}
}
function Get-CimInstance { return [pscustomobject]@{UserName='fixture\joao'} }
function Get-PSDrive { param($Name,$ErrorAction); return [pscustomobject]@{Free=10000000} }
function New-Item {
 param($ItemType,$Path,$ErrorAction)
 if($scenario -eq 'creation-race' -and $Path -eq $target){
   $null=Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $Path
   [IO.File]::WriteAllText($native+'/sentinel','preserve')
   throw 'fixture-creation-race'
 }
 $item=Microsoft.PowerShell.Management\New-Item -ItemType $ItemType -Path $Path -ErrorAction Stop
 if($Path -eq $target){$item | Add-Member -NotePropertyName CreationTimeUtc -NotePropertyValue $script:rootBirth -Force}
 return $item
}
function Get-FileHash {
 param($LiteralPath,$Algorithm)
 if($scenario -in @('unexpected-file','reparse-file','changed-generation') -and -not $script:injected){
   $script:injected=$true
   if($scenario -eq 'changed-generation'){$script:rootBirth=$script:rootBirth.AddSeconds(1)}
   elseif($scenario -eq 'unexpected-file'){[IO.File]::WriteAllText($native+'/sentinel','preserve')}
   else{$null=Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path ($native+'/sentinel') -Target ($directory+'/outside')}
   throw 'fixture-ownership-change'
 }
 return Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
}
function Remove-Item {
 param($LiteralPath,[switch]$Force,$ErrorAction)
 if($scenario -eq 'cleanup-failure'){throw 'fixture-cleanup-failure'}
 Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
}
[IO.File]::WriteAllText($directory+'/outside','outside-preserved')
if($scenario -eq 'preexisting'){
 $null=Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $target
 [IO.File]::WriteAllText($native+'/sentinel','preserve')
}
$receipt=(& {
${source}
}) | ConvertFrom-Json
if($scenario -eq 'ready'){
 if($receipt.outcome -ne 'ready'){throw ('expected-ready:'+($receipt|ConvertTo-Json -Compress))}
 if([IO.File]::ReadAllText($native+'/interactive.ps1') -cne 'interactive-source' -or [IO.File]::ReadAllText($native+'/observe.ps1') -cne 'observer-source'){throw 'materialization-wrong'}
}elseif($scenario -in @('write-failure','hash-mismatch')){
 if($receipt.outcome -ne 'failed'){throw 'expected-failure'}
 if(Test-Path -LiteralPath $target){throw 'partial-owned-root-leaked'}
 if($receipt.cleanupOutcome -ne 'verified'){throw 'cleanup-not-verified'}
}elseif($scenario -in @('preexisting','creation-race','unexpected-file')){
 if($receipt.outcome -ne 'failed'){throw 'expected-failure'}
 if([IO.File]::ReadAllText($native+'/sentinel') -cne 'preserve'){throw 'unowned-content-changed'}
 if($scenario -ne 'preexisting' -and $receipt.cleanupOutcome -ne 'unresolved'){throw 'unowned-cleanup-not-unresolved'}
}elseif($scenario -eq 'reparse-file'){
 if($receipt.outcome -ne 'failed' -or $receipt.cleanupOutcome -ne 'unresolved'){throw 'reparse-not-refused'}
 if(-not(Test-Path -LiteralPath ($native+'/sentinel')) -or [IO.File]::ReadAllText($directory+'/outside') -cne 'outside-preserved'){throw 'reparse-target-changed'}
}elseif($scenario -eq 'changed-generation'){
 if($receipt.outcome -ne 'failed' -or $receipt.cleanupOutcome -ne 'unresolved' -or -not(Test-Path -LiteralPath ($native+'/interactive.ps1'))){throw 'changed-generation-not-preserved'}
}elseif($scenario -eq 'cleanup-failure'){
 if($receipt.outcome -ne 'failed' -or $receipt.cleanupOutcome -ne 'unresolved' -or -not(Test-Path -LiteralPath $target)){throw 'cleanup-failure-misreported'}
}else{
 if($receipt.outcome -ne 'failed' -or (Test-Path -LiteralPath $target)){throw 'query-error-not-closed'}
}
Write-Output 'PASS:${scenario}'
`;
    const result = spawnSync('docker', ['run','--rm','--network','none','--read-only','--cap-drop','ALL',
      '--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,nodev,size=16m','--env','HOME=/tmp',
      '--user','65534:65534','-i',image,'/usr/bin/pwsh','-NoLogo','-NoProfile','-NonInteractive',
      '-EncodedCommand',POWERSHELL_STDIN_BOOTSTRAP_BASE64], {input:script, encoding:'utf8',timeout:45000,maxBuffer:1024*1024});
    assert.equal(result.error, undefined); assert.equal(result.status,0,`${result.stdout}\n${result.stderr}`);
    assert.equal(result.stdout.trim(),`PASS:${scenario}`);
  });
}
