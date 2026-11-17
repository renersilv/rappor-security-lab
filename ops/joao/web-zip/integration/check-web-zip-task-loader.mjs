import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

const sourcePath=process.env.WEB_ZIP_TASK_LOADER_SOURCE??new URL('../source/web-zip-windows-orchestrator.ps1',import.meta.url);
const source=readFileSync(sourcePath,'utf8');
const generator=source.match(/        \$quote = [^]*?(?=        \$encoded =)/u)?.[0];
assert.ok(generator,'actual scheduled worker command generator must exist');
const quote=value=>"'"+value.replaceAll("'","''")+"'";
const digest=value=>createHash('sha256').update(value).digest('hex');
const encoded=value=>Buffer.from(value,'utf16le').toString('base64');
function fixture(){
  assert.ok(process.env.PWSH_BIN,'PWSH_BIN is required; this test has no remote fallback');
  const root=mkdtempSync(join(tmpdir(),'web-zip-task-loader-'));
  const worker=join(root,'worker.ps1');
  const content=`function Invoke-WebZipWorker { param($InstructionPath,$InstructionSha256,$OwnerSid,$AbsoluteDeadlineUnixMs) @{instruction=$InstructionPath;hash=$InstructionSha256;sid=$OwnerSid;deadline=$AbsoluteDeadlineUnixMs;scope='loaded'} | ConvertTo-Json -Compress }\n`;
  writeFileSync(worker,content);
  const build=`$ErrorActionPreference='Stop'\n$root=${quote(root)}\n$instruction=@{desktop=@{sid='S-1-5-21-100-200-300-1001'}}\n$envelope=@{workerSha256='${digest(content)}';instructionSha256='${'a'.repeat(64)}';absoluteDeadlineUnixMs=1800000000000}\nfunction Resolve-WebZipPhysicalPath($Path){return $Path}\n${generator}\n[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))`;
  const command=execFileSync(process.env.PWSH_BIN,['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded(build)],{encoding:'utf8',timeout:10000}).trim();
  return {root,worker,command,run:()=>spawnSync(process.env.PWSH_BIN,['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],{encoding:'utf8',timeout:10000}),close:()=>rmSync(root,{recursive:true,force:true})};
}
test('scheduled worker loads hash-bound bytes in caller scope without file execution or policy changes',()=>{
  const f=fixture();
  try{
    const text=Buffer.from(f.command,'base64').toString('utf16le');
    assert.match(text,/ScriptBlock\]::Create/u);
    assert.doesNotMatch(text,/Set-ExecutionPolicy|-ExecutionPolicy|login|password|loginBase64/iu);
    assert.ok(`powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ${f.command}`.length<8191);
    const result=f.run();assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');
    assert.deepEqual(JSON.parse(result.stdout),{instruction:join(f.root,'instruction.json'),hash:'a'.repeat(64),sid:'S-1-5-21-100-200-300-1001',deadline:1800000000000,scope:'loaded'});
  }finally{f.close();}
});
test('scheduled worker rejects substituted bytes before their top-level code can execute',()=>{
  const f=fixture();
  try{
    writeFileSync(f.worker,"Write-Output 'SUBSTITUTED-WORKER-EXECUTED'\nfunction Invoke-WebZipWorker { Write-Output 'SUBSTITUTED-WORKER-EXECUTED' }\n");
    const result=f.run();assert.notEqual(result.status,0);
    assert.match(result.stderr,/worker-source-hash-mismatch/u);
    assert.doesNotMatch(result.stdout,/SUBSTITUTED-WORKER-EXECUTED/u);
  }finally{f.close();}
});
