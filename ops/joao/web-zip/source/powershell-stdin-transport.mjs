import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const WINDOWS_COMMAND_LINE_LIMIT = 8191;
// The native SSH shell adds its own executable path, options and quoting.
export const WINDOWS_SHELL_WRAPPER_RESERVE = 591;
export const MAX_DIRECT_COMMAND_CHARACTERS = WINDOWS_COMMAND_LINE_LIMIT - WINDOWS_SHELL_WRAPPER_RESERVE;
export const POWERSHELL_STDIN_BOOTSTRAP = [
  "$ProgressPreference = 'SilentlyContinue'",
  "$source = [Console]::In.ReadToEnd()",
  "& ([ScriptBlock]::Create($source))",
].join("; ");
export const POWERSHELL_STDIN_BOOTSTRAP_BASE64 = Buffer
  .from(POWERSHELL_STDIN_BOOTSTRAP, "utf16le").toString("base64");
export const POWERSHELL_STDIN_COMMAND =
  `powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ${POWERSHELL_STDIN_BOOTSTRAP_BASE64}`;
export const MAX_POWERSHELL_SOURCE_BYTES = 512 * 1024;

const sha256 = value => createHash("sha256").update(value).digest("hex");

export function createPowerShellStdinTransport(source) {
  assert.equal(typeof source, "string", "powershell-source-must-be-string");
  assert.ok(source.length > 0, "powershell-source-empty");
  assert.doesNotMatch(source, /\u0000/u, "powershell-source-contains-nul");
  assert.doesNotMatch(source, /[^\u0009\u000a\u000d\u0020-\u007e]/u,
    "powershell-source-must-be-ascii");
  const bytes = Buffer.from(source, "utf8");
  assert.ok(bytes.length <= MAX_POWERSHELL_SOURCE_BYTES, "powershell-source-too-large");
  assert.ok(POWERSHELL_STDIN_COMMAND.length < WINDOWS_COMMAND_LINE_LIMIT,
    "powershell-command-line-too-long");
  return Object.freeze({
    remoteCommand: POWERSHELL_STDIN_COMMAND,
    input: source,
    framing: "encoded-bootstrap-reads-complete-stdin",
    bootstrapSha256: sha256(Buffer.from(POWERSHELL_STDIN_BOOTSTRAP, "utf16le")),
    sourceBytes: bytes.length,
    sourceSha256: sha256(bytes),
  });
}

export async function executePowerShellStdin(adapter, source, options = {}) {
  assert.equal(typeof adapter?.execute, "function", "windows-adapter-required");
  assert.ok(Array.isArray(adapter.sshArguments), "windows-adapter-ssh-arguments-required");
  assert.equal(typeof adapter.sshTarget, "string", "windows-adapter-ssh-target-required");
  assert.equal(Object.hasOwn(options, "input"), false, "powershell-input-override-rejected");
  assert.equal(Object.hasOwn(options, "remoteCommandTransport"), false,
    "powershell-remote-transport-override-rejected");
  const transport = createPowerShellStdinTransport(source);
  return adapter.execute("ssh", [
    ...adapter.sshArguments,
    adapter.sshTarget,
    transport.remoteCommand,
  ], {
    ...options,
    input: transport.input,
    remoteCommandTransport: "openssh",
  });
}

export function transportCleanupFromSettlement(settlement) {
  assert.equal(settlement?.schema, 1, "transport-settlement-required");
  assert.equal(typeof settlement.cause, "string", "transport-settlement-cause-required");
  assert.equal(typeof settlement.spawnObserved, "boolean", "transport-spawn-state-required");
  assert.equal(typeof settlement.remoteQuiescenceObserved, "boolean",
    "transport-quiescence-state-required");
  const remoteQuiescence = settlement.remoteQuiescenceObserved === true;
  const remoteCommandNotStarted = settlement.cause === "spawn_error" && settlement.spawnObserved === false;
  const resolved = remoteQuiescence || remoteCommandNotStarted;
  return Object.freeze({
    required: !resolved,
    status: remoteQuiescence ? "verified_remote_quiescence" :
      (remoteCommandNotStarted ? "verified_not_started" : "unresolved"),
    localProcessTerminated: settlement.localProcessTerminated === true,
    remoteCommandTransport: settlement.remoteCommandTransport,
    remoteQuiescenceObserved: remoteQuiescence,
    reason: remoteQuiescence ? "The bounded process closed after an observed remote command exit." :
      (remoteCommandNotStarted ? "The local process failed before the remote command could start." :
        "Local termination does not prove that the remote PowerShell process is quiescent."),
  });
}

// Public source and fixture bytes use SFTP; only the bounded login is sent through stdin.
const STAGE_PREFIX = 'C:\\RapporLab\\runtime\\transport-web-zip-';
const STAGE_CLEANUP_RESERVE_MS = 15000;
const MAX_LOGIN_BYTES = 4034;
const commandPrefix = 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ';
const jsonBytes = value => Buffer.from(JSON.stringify(value) + '\n');
const exactFields = (value, names) => assert.deepEqual(Object.keys(value).sort(), [...names].sort());
function directCommand(source) {
  assert.doesNotMatch(source, /[^\u0009\u000a\u000d\u0020-\u007e]/u, 'bootstrap-must-be-ascii');
  // Templates contain only public statements and no multiline string data.
  const compactSource = source.split('\n').map(line => line.trim()).join('\n');
  const command = commandPrefix + Buffer.from(compactSource, 'utf16le').toString('base64');
  assert.ok(command.length <= MAX_DIRECT_COMMAND_CHARACTERS, `powershell-command-line-too-long:${command.length}`);
  return command;
}
function stageBindings(prepared) {
  assert.match(prepared.requestSha256, /^[a-f0-9]{64}$/u);
  assert.match(prepared.instruction.desktop.sid, /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/u);
  assert.match(prepared.package.workerSha256, /^[a-f0-9]{64}$/u);
  const bytes = jsonBytes(prepared.package);
  assert.ok(bytes.length > 0 && bytes.length <= 524288, 'public-package-size');
  assert.equal(Object.hasOwn(prepared.package, 'loginBase64'), false, 'public-package-contains-login');
  exactFields(prepared.package, ['schema','instructionBase64','instructionSha256','archiveBase64','archiveSha256','workerBase64','workerSha256']);
  const root = STAGE_PREFIX + prepared.requestSha256;
  const sid = prepared.instruction.desktop.sid;
  const common = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n$r='${root}';$s='${sid}'\n` + String.raw`
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $s){throw 'stage-owner'}
function Check([string]$p){
 if([IO.Path]::GetFullPath($p) -cne $p){throw 'stage-path'}
 while($p){
  $i=Get-Item -LiteralPath $p -Force
  if($i.Attributes -band 0x400){throw 'stage-reparse'}
  $a=Get-Acl -LiteralPath $p
  $ids=@($s,'S-1-5-18','S-1-5-32-544')
  $o=$ids;$m=0x500D0156
  if($p -ceq 'C:\'){$m=0x500D0152;$o+='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
  if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $o){throw 'stage-owner'}
  foreach($v in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   if($v.PropagationFlags -band 2){continue}
   if($v.AccessControlType -eq 'Allow' -and $v.IdentityReference.Value -notin $ids -and ([int]$v.FileSystemRights -band $m)){throw 'stage-acl'}
  }
  $up=Split-Path -Parent $p;if(!$up -or $up -eq $p){break};$p=$up
 }
}
`;
  return {root,sid,bytes,hash:sha256(bytes),common};
}
function bindStage(binding, ticks) {
  assert.match(ticks, /^[0-9]{17,19}$/u, 'stage-creation-invalid');
  return binding.common + `Check $r\n$dir=Get-Item -LiteralPath $r\nif(!$dir.PSIsContainer -or $dir.CreationTimeUtc.Ticks.ToString() -cne '${ticks}'){throw 'stage-generation'}\n`;
}
export function buildWebZipStagePreparation(prepared) {
  const binding = stageBindings(prepared);
  const source = binding.common + String.raw`
Check 'C:\RapporLab\runtime'
if(Test-Path -LiteralPath $r){throw 'stage-exists'}
$a=[Security.AccessControl.DirectorySecurity]::new();$a.SetAccessRuleProtection($true,$false)
$a.SetOwner([Security.Principal.SecurityIdentifier]::new($s))
foreach($id in @($s,'S-1-5-18','S-1-5-32-544')){
 $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($id),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
[IO.Directory]::CreateDirectory($r,$a)|Out-Null;Check $r
[Console]::Out.WriteLine((@{schema=1;creationTicks=(Get-Item -LiteralPath $r).CreationTimeUtc.Ticks.ToString()}|ConvertTo-Json -Compress))
`;
  return {command:directCommand(source),root:binding.root,packageSha256:binding.hash};
}
export function buildWebZipStageInvocation(prepared, ticks, remainingMs, nowUnixMs = Date.now()) {
  const binding = stageBindings(prepared);
  const guestRemainingMs = remainingMs - 3000 - prepared.instruction.parentReserveMs;
  assert.ok(Number.isSafeInteger(remainingMs) && remainingMs <= 600000 && guestRemainingMs > prepared.instruction.cleanupReserveMs,
    'remaining-budget-insufficient');
  const source = bindStage(binding,ticks) + `$h='${binding.hash}';$w='${prepared.package.workerSha256}';$due=${nowUnixMs + guestRemainingMs}\n` + String.raw`
$f=Join-Path $r 'package.json';Check $f
$fs=[IO.File]::Open($f,'Open','Read','Read');$u=[Text.Encoding]::UTF8
function Hash($v){$a=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($a.ComputeHash($v))).Replace('-','').ToLowerInvariant()}finally{$a.Dispose()}}
try{
 if($fs.Length -lt 1 -or $fs.Length -gt 524288){throw 'stage-size'}
 $hash=Hash $fs
 if($hash -cne $h){throw 'stage-hash'}
 $fs.Position=0;$reader=[IO.StreamReader]::new($fs);$pkg=$reader.ReadToEnd()|ConvertFrom-Json
 $src=[Convert]::FromBase64String($pkg.workerBase64)
 $hash=Hash $src
 if($hash -cne $w){throw 'worker-hash'}
 . ([ScriptBlock]::Create($u.GetString($src)))
 $reader=[IO.StreamReader]::new([Console]::OpenStandardInput(),[Text.UTF8Encoding]::new($false,$true),$false)
 $wire=$reader.ReadToEnd();$parts=$wire.Split([char]10)
 if([Text.Encoding]::UTF8.GetByteCount($wire) -gt 4034 -or $parts.Count -ne 3 -or $parts[2] -cne '' -or $wire.Contains([char]13)){throw 'login-input-invalid'}
 $login=([ordered]@{email=$parts[0];password=$parts[1]}|ConvertTo-Json -Compress)
 $parts=$null;$wire=$null
 $pkg|Add-Member -NotePropertyMembers @{absoluteDeadlineUnixMs=$due;loginBase64=[Convert]::ToBase64String($u.GetBytes($login))}
 $login=$null
 Invoke-WebZipParent -EnvelopeBase64 ([Convert]::ToBase64String($u.GetBytes(($pkg|ConvertTo-Json -Depth 30 -Compress))))
}finally{$fs.Dispose()}
`;
  return {command:directCommand(source),guestDeadlineUnixMs:nowUnixMs + guestRemainingMs};
}
export function buildWebZipStageCleanup(prepared, ticks) {
  const binding = stageBindings(prepared);
  const source = bindStage(binding,ticks) + String.raw`
$items=@(Get-ChildItem -LiteralPath $r -Force)
if($items.Count -gt 1){throw 'stage-unexpected-child'}
foreach($item in $items){
 if($item.Name -cne 'package.json' -or $item.PSIsContainer){throw 'stage-unexpected-child'}
 Check $item.FullName
 $stream=[IO.File]::Open($item.FullName,'Open','Read','None');$stream.Dispose()
 Remove-Item -LiteralPath $item.FullName -Force
}
Check $r
Remove-Item -LiteralPath $r -Force
[Console]::Out.WriteLine((@{schema=1;stageAbsent=(!(Test-Path -LiteralPath $r))}|ConvertTo-Json -Compress))
`;
  return directCommand(source);
}
const sftpQuote = value => {
  assert.equal(typeof value,'string');assert.doesNotMatch(value,/[\x00\r\n]/u,'sftp-path-invalid');
  return '"'+value.replaceAll('\\','\\\\').replaceAll('"','\\"')+'"';
};

export function encodeWebZipLogin(login) {
  exactFields(login, ['email', 'password']);
  assert.equal(typeof login.email, 'string', 'login-format-invalid');
  assert.equal(typeof login.password, 'string', 'login-format-invalid');
  assert.ok(login.email.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(login.email), 'login-format-invalid');
  assert.ok(login.password.length > 0 && login.password.length <= 1024 && !/[\u0000\r\n]/u.test(login.password), 'login-format-invalid');
  const value = login.email + '\n' + login.password + '\n';
  const bytes = Buffer.from(value, 'utf8');
  try {
    assert.ok(bytes.toString('utf8') === value, 'login-encoding-invalid');
    assert.ok(bytes.length <= MAX_LOGIN_BYTES, 'login-input-too-large');
  } catch (error) { bytes.fill(0); throw error; }
  return bytes;
}
export async function prepareWebZipRemoteTransport(adapter, prepared, {remaining, nowUnixMs = Date.now} = {}) {
  assert.equal(typeof remaining,'function');
  const setup = buildWebZipStagePreparation(prepared);
  let ticks, lastQuiescent = true, launched = false, launchCommand;
  const state = {stageCreated:false,stageAbsent:false,cleanupAttempted:false,postObservation:null};
  const run = async (command, input, timeout, trackCommand = true) => {
    try{
      const result = await adapter.execute('ssh',[...adapter.sshArguments,adapter.sshTarget,command],
        {input,timeout,terminationGraceMs:1500,maxOutputBytes:4*1024*1024,remoteCommandTransport:'openssh'});
      const quiet=result.settlement?.remoteQuiescenceObserved===true;
      if(trackCommand)lastQuiescent=quiet;
      assert.equal(quiet,true,'remote-quiescence-unconfirmed');return result;
    }catch(error){if(trackCommand)lastQuiescent=error.settlement?.remoteQuiescenceObserved===true;throw error;}
  };
  const limit = maximum => {
    const available=remaining()-STAGE_CLEANUP_RESERVE_MS;
    assert.ok(available>108000,'remaining-budget-insufficient');return Math.min(maximum,available);
  };
  const cleanup = async () => {
    if(!state.stageCreated||state.stageAbsent)return state;
    if(!lastQuiescent){
      // Read-only reconciliation is bounded and cannot turn an unknown command into a successful journey.
      if(!launchCommand||remaining()<8000)return state;
      const encodedHash=sha256(Buffer.from(launchCommand.slice(commandPrefix.length)));
      const observation=directCommand(`$ErrorActionPreference='Stop';$s='${prepared.instruction.desktop.sid}';$b='${encodedHash}'\n`+String.raw`
$found=0;$unknown=0
foreach($p in @(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(powershell|pwsh)\.exe$' -and $_.ProcessId -ne $PID})){
 if([string]::IsNullOrWhiteSpace([string]$p.CommandLine)){$unknown++;continue}
 $m=[regex]::Match([string]$p.CommandLine,'-EncodedCommand\s+([A-Za-z0-9+/=]+)','IgnoreCase');if(!$m.Success){continue}
 $a=[Security.Cryptography.SHA256]::Create();try{$h=([BitConverter]::ToString($a.ComputeHash([Text.Encoding]::ASCII.GetBytes($m.Groups[1].Value)))).Replace('-','').ToLowerInvariant()}finally{$a.Dispose()}
 if($h -ceq $b){$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $s){$unknown++};$found++}
}
[Console]::Out.WriteLine((@{schema=1;matchingProcesses=$found;unobservableProcesses=$unknown}|ConvertTo-Json -Compress))
`);
      try{
        const observed=await run(observation,'',Math.min(6000,remaining()-1000),false);
        const record=JSON.parse(observed.stdout);exactFields(record,['schema','matchingProcesses','unobservableProcesses']);
        assert.equal(record.schema,1);assert.ok(Number.isSafeInteger(record.matchingProcesses)&&record.matchingProcesses>=0);
        assert.ok(Number.isSafeInteger(record.unobservableProcesses)&&record.unobservableProcesses>=0);
        state.postObservation={matchingProcesses:record.matchingProcesses,unobservableProcesses:record.unobservableProcesses};
        if(record.matchingProcesses||record.unobservableProcesses)return state;
      }catch{return state;}
    }
    if(remaining()<5000)return state;
    state.cleanupAttempted=true;
    try{
      const cleaned=await run(buildWebZipStageCleanup(prepared,ticks),'',Math.min(12000,remaining()-1000),false);
      assert.equal(cleaned.stderr,'');const receipt=JSON.parse(cleaned.stdout);exactFields(receipt,['schema','stageAbsent']);
      assert.equal(receipt.schema,1);assert.equal(receipt.stageAbsent,true);state.stageAbsent=true;
    }catch{state.stageAbsent=false;}
    return state;
  };
  try{
    const created=await run(setup.command,'',limit(20000));assert.equal(created.stderr,'');
    const receipt=JSON.parse(created.stdout);exactFields(receipt,['schema','creationTicks']);assert.equal(receipt.schema,1);
    assert.match(receipt.creationTicks,/^[0-9]{17,19}$/u);ticks=receipt.creationTicks;state.stageCreated=true;
    const localPackage=prepared.outputDirectory+'/package.json';
    const remotePackage='/'+setup.root.replaceAll('\\','/')+'/package.json';
    const args=adapter.sshArguments.map(value=>value==='-p'?'-P':value);
    try{
      const uploaded=await adapter.execute('sftp',[...args,'-b','-',adapter.sshTarget],
        {input:`put ${sftpQuote(localPackage)} ${sftpQuote(remotePackage)}\n`,timeout:limit(30000),terminationGraceMs:1500,maxOutputBytes:16384,remoteCommandTransport:'openssh'});
      lastQuiescent=uploaded.settlement?.remoteQuiescenceObserved===true;assert.equal(lastQuiescent,true,'sftp-quiescence-unconfirmed');
    }catch(error){lastQuiescent=error.settlement?.remoteQuiescenceObserved===true;throw error;}
  }catch(error){await cleanup();error.stageCleanup=state;throw error;}
  return {
    state,
    async execute(login){
      assert.equal(launched,false,'stage-already-dispatched');launched=true;
      const bytes=encodeWebZipLogin(login);
      try {
        const timeout=limit(600000);
        launchCommand=buildWebZipStageInvocation(prepared,ticks,timeout,nowUnixMs()).command;
        return await run(launchCommand,bytes,timeout);
      } finally { bytes.fill(0); }
    },
    cleanup,
  };
}
