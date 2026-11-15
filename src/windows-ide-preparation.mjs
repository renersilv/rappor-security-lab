import assert from "node:assert/strict";

const STAGES = new Set([
  "initial_guards",
  "interactive_identity",
  "guest_capacity",
  "source_materialization",
]);
const CODES = new Set([
  "temporary-root-preexists",
  "task-preexists",
  "interactive-user-unavailable",
  "guest-capacity-unavailable",
  "source-write-failed",
  "source-hash-mismatch",
  "preparation-step-failed",
  "unsafe-preparation-path",
  "preparation-ownership-changed",
]);
const ROOT_DISPOSITIONS = new Set(["absent", "preexisting", "created_by_invocation", "unverified"]);

const closed = (value, keys, label) => {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label}-object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label}-keys`);
};
const powerShellLiteral = value => {
  assert.equal(typeof value, "string");
  assert.doesNotMatch(value, /[\r\n\u0000]/u);
  return value.replaceAll("'", "''");
};

export function validatePreparationReceipt(value, minimumGuestFreeBytes) {
  closed(value, ["schema", "outcome", "stage", "code", "rootDisposition", "interactiveUserKind",
    "guestFreeBytes", "cleanupOutcome"], "preparation-receipt");
  assert.equal(value.schema, 1);
  assert.ok(["not_required", "verified", "unresolved"].includes(value.cleanupOutcome), "preparation-cleanup-invalid");
  assert.ok(["ready", "failed"].includes(value.outcome), "preparation-outcome-invalid");
  assert.ok(STAGES.has(value.stage), "preparation-stage-invalid");
  assert.ok(value.code === null || CODES.has(value.code), "preparation-code-invalid");
  assert.ok(ROOT_DISPOSITIONS.has(value.rootDisposition), "preparation-root-disposition-invalid");
  assert.ok(value.interactiveUserKind === null || value.interactiveUserKind === "bound-joao-user",
    "preparation-interactive-user-invalid");
  assert.ok(value.guestFreeBytes === null || Number.isSafeInteger(value.guestFreeBytes),
    "preparation-guest-capacity-invalid");
  if (value.outcome === "ready") {
    assert.equal(value.stage, "source_materialization");
    assert.equal(value.code, null);
    assert.equal(value.cleanupOutcome, "not_required");
    assert.equal(value.rootDisposition, "created_by_invocation");
    assert.equal(value.interactiveUserKind, "bound-joao-user");
    assert.ok(value.guestFreeBytes >= minimumGuestFreeBytes, "preparation-guest-capacity-insufficient");
  } else {
    assert.ok(value.code !== null, "preparation-failure-code-required");
    if (value.code === "temporary-root-preexists") {
      assert.equal(value.rootDisposition, "preexisting"); assert.equal(value.cleanupOutcome, "not_required");
    }
    if (value.cleanupOutcome === "verified") assert.equal(value.rootDisposition, "created_by_invocation");
    if (value.rootDisposition === "created_by_invocation") assert.notEqual(value.cleanupOutcome, "not_required");
    if (value.rootDisposition === "unverified") assert.equal(value.cleanupOutcome, "unresolved");
  }
  return value;
}

export function buildPreparationSource({ guestRoot, taskName, minimumGuestFreeBytes,
  interactiveBase64, observerBase64, interactiveSha256, observerSha256 }) {
  assert.ok(Number.isSafeInteger(minimumGuestFreeBytes) && minimumGuestFreeBytes > 0);
  const pass = guestRoot.match(/^C:\\RapporLab\\runtime\\pass([1-9][0-9]{0,5})-ide-readiness$/u)?.[1];
  assert.ok(pass, "preparation-root-outside-fixed-scope");
  assert.equal(taskName, `RapporLab-Pass${pass}-IdeReadiness`, "preparation-task-mismatch");
  for (const hash of [interactiveSha256, observerSha256]) assert.match(hash, /^[a-f0-9]{64}$/u);
  for (const value of [interactiveBase64, observerBase64]) assert.match(value, /^[A-Za-z0-9+/]+={0,2}$/u);
  const values = Object.fromEntries(Object.entries({ guestRoot, taskName, interactiveBase64, observerBase64,
    interactiveSha256, observerSha256 }).map(([key, value]) => [key, powerShellLiteral(value)]));
  return String.raw`$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root='${values.guestRoot}'
$task='${values.taskName}'
$stage='initial_guards'
$rootDisposition='absent'
$cleanupOutcome='not_required'
$interactiveUserKind=$null
$guestFree=$null
$owned=$false
$rootTicks=$null
$marker='.rappor-preparation-owner'
$token=[Guid]::NewGuid().ToString('N')
$ownedFiles=@{}
function Assert-PlainPreparationPath([string]$path){
  $current=$path
  while($current){
    if(Test-Path -LiteralPath $current){
      $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe-preparation-path'}
    }
    $parent=Split-Path -Path $current -Parent
    if($parent -eq $current){break}
    $current=$parent
  }
}
function Assert-OwnedPreparationRoot {
  if(-not $owned){throw 'preparation-ownership-changed'}
  Assert-PlainPreparationPath $root
  $item=Get-Item -LiteralPath $root -Force -ErrorAction Stop
  if(-not $item.PSIsContainer -or $item.CreationTimeUtc.Ticks -ne $rootTicks){throw 'preparation-ownership-changed'}
  $markerPath=Join-Path $root $marker
  Assert-PlainPreparationPath $markerPath
  if((Get-Item -LiteralPath $markerPath -Force).Length -ne 32 -or [IO.File]::ReadAllText($markerPath) -cne $token){throw 'preparation-ownership-changed'}
  return $item
}
function Write-OwnedPreparationFile([string]$name,[byte[]]$bytes){
  $null=Assert-OwnedPreparationRoot
  $path=Join-Path $root $name
  $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}
  finally{
    try{
      $file.Position=0
      $algorithm=[Security.Cryptography.SHA256]::Create()
      try{$actual=[BitConverter]::ToString($algorithm.ComputeHash($file)).Replace('-','').ToLowerInvariant()}
      finally{$algorithm.Dispose()}
      $ownedFiles[$name]=@{hash=$actual;length=$file.Length;ticks=(Get-Item -LiteralPath $path -Force).CreationTimeUtc.Ticks}
    }finally{$file.Dispose()}
  }
}
function Assert-OwnedPreparationInventory {
  $directory=Assert-OwnedPreparationRoot
  $entries=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
  if($entries.Count -gt 3){throw 'preparation-ownership-changed'}
  foreach($entry in $entries){
    if($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'preparation-ownership-changed'}
    if($entry.Name -ceq $marker){continue}
    if(-not $ownedFiles.ContainsKey($entry.Name)){throw 'preparation-ownership-changed'}
    $bound=$ownedFiles[$entry.Name]
    if($entry.Length -ne $bound.length -or $entry.CreationTimeUtc.Ticks -ne $bound.ticks -or
       (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $bound.hash){throw 'preparation-ownership-changed'}
  }
  return $directory
}
function Remove-OwnedPreparationRoot {
  $null=Assert-OwnedPreparationInventory
  foreach($name in @($ownedFiles.Keys)){
    $null=Assert-OwnedPreparationInventory
    $path=Join-Path $root $name
    if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force -ErrorAction Stop}
    $ownedFiles.Remove($name)
  }
  $null=Assert-OwnedPreparationInventory
  Remove-Item -LiteralPath (Join-Path $root $marker) -Force -ErrorAction Stop
  Assert-PlainPreparationPath $root
  $directory=Get-Item -LiteralPath $root -Force -ErrorAction Stop
  if($directory.CreationTimeUtc.Ticks -ne $rootTicks -or @(Get-ChildItem -LiteralPath $root -Force).Count -ne 0){throw 'preparation-ownership-changed'}
  [IO.Directory]::Delete($directory.FullName,$false)
  if(Test-Path -LiteralPath $root){throw 'preparation-ownership-changed'}
}
try{
  Assert-PlainPreparationPath $root
  if(Test-Path -LiteralPath $root){$rootDisposition='preexisting';throw 'temporary-root-preexists'}
  if(@(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $task -and $_.TaskPath -ceq '\' }).Count -ne 0){throw 'task-preexists'}
  $stage='interactive_identity'
  $interactiveUser=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
  if([string]::IsNullOrWhiteSpace($interactiveUser) -or -not $interactiveUser.EndsWith('\joao',[StringComparison]::OrdinalIgnoreCase)){throw 'interactive-user-unavailable'}
  $interactiveUserKind='bound-joao-user'
  $stage='guest_capacity'
  $guestFree=[long](Get-PSDrive -Name C -ErrorAction Stop).Free
  if($guestFree -lt ${minimumGuestFreeBytes}){throw 'guest-capacity-unavailable'}
  $stage='source_materialization'
  Assert-PlainPreparationPath $root
  $created=New-Item -ItemType Directory -Path $root -ErrorAction Stop
  $rootTicks=$created.CreationTimeUtc.Ticks
  $owned=$true
  $rootDisposition='created_by_invocation'
  $markerPath=Join-Path $root $marker
  $file=[IO.File]::Open($markerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$bytes=[Text.Encoding]::UTF8.GetBytes($token);$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  Write-OwnedPreparationFile 'interactive.ps1' ([Convert]::FromBase64String('${values.interactiveBase64}'))
  Write-OwnedPreparationFile 'observe.ps1' ([Convert]::FromBase64String('${values.observerBase64}'))
  if((Get-FileHash -LiteralPath (Join-Path $root 'interactive.ps1') -Algorithm SHA256).Hash.ToLowerInvariant() -cne '${values.interactiveSha256}'){throw 'interactive-source-hash-mismatch'}
  if((Get-FileHash -LiteralPath (Join-Path $root 'observe.ps1') -Algorithm SHA256).Hash.ToLowerInvariant() -cne '${values.observerSha256}'){throw 'observer-source-hash-mismatch'}
  $null=Assert-OwnedPreparationInventory
  [ordered]@{schema=1;outcome='ready';stage=$stage;code=$null;rootDisposition=$rootDisposition;interactiveUserKind=$interactiveUserKind;guestFreeBytes=$guestFree;cleanupOutcome=$cleanupOutcome}|ConvertTo-Json -Compress
}catch{
  $message=[string]$_.Exception.Message
  $code='preparation-step-failed'
  if($message -in @('temporary-root-preexists','task-preexists','interactive-user-unavailable','guest-capacity-unavailable','unsafe-preparation-path','preparation-ownership-changed')){$code=$message}
  elseif($message -in @('interactive-source-hash-mismatch','observer-source-hash-mismatch')){$code='source-hash-mismatch'}
  elseif($stage -eq 'source_materialization'){$code='source-write-failed'}
  if($owned){
    # A missing or changed ownership marker cannot authorize removal, even after local creation.
    $cleanupOutcome='unresolved'
    try{Remove-OwnedPreparationRoot;$cleanupOutcome='verified'}catch{$rootDisposition='unverified'}
  }elseif($rootDisposition -ne 'preexisting'){
    try{if(Test-Path -LiteralPath $root){$rootDisposition='unverified';$cleanupOutcome='unresolved'}}catch{$rootDisposition='unverified';$cleanupOutcome='unresolved'}
  }
  [ordered]@{schema=1;outcome='failed';stage=$stage;code=$code;rootDisposition=$rootDisposition;interactiveUserKind=$interactiveUserKind;guestFreeBytes=$guestFree;cleanupOutcome=$cleanupOutcome}|ConvertTo-Json -Compress
}
`;
}

export async function executePreparation({ source, minimumGuestFreeBytes, runPowerShell, writeReceipt }) {
  assert.equal(typeof source, "string");
  assert.equal(typeof runPowerShell, "function");
  assert.equal(typeof writeReceipt, "function");
  const output = await runPowerShell(source);
  const prepared = validatePreparationReceipt(JSON.parse(String(output).replace(/^\uFEFF/u, "").trim()),
    minimumGuestFreeBytes);
  await writeReceipt(prepared);
  if (prepared.outcome !== "ready") {
    throw Object.assign(new Error(`preparation-${prepared.code}`),
      { code: "PREPARATION_REJECTED", preparation: prepared });
  }
  return prepared;
}

