import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {buildWebZipStageInvocation,encodeWebZipLogin} from '../source/powershell-stdin-transport.mjs';

const sourceUrl=new URL('../source/powershell-stdin-transport.mjs',import.meta.url);
const prepared={requestSha256:'a'.repeat(64),instruction:{desktop:{sid:'S-1-5-21-100-200-300-1001'},parentReserveMs:15000,cleanupReserveMs:90000},
  package:{schema:1,instructionBase64:'',instructionSha256:'',archiveBase64:'',archiveSha256:'',workerBase64:'',workerSha256:'b'.repeat(64)}};
const {command}=buildWebZipStageInvocation(prepared,'638000000000000000',600000,1800000000000);
const publicSource=Buffer.from(command.split(' ').at(-1),'base64').toString('utf16le');
const start=publicSource.indexOf('$reader=[IO.StreamReader]::new([Console]');
const end=publicSource.indexOf('$parts=$null;$wire=$null',start);
assert.ok(start>=0&&end>start,'actual stdin decoder must be present in the generated public command');
const decoder=publicSource.slice(start,end);
// Execute only the actual serialization decoder. No staging, account, filesystem,
// worker loading or remote-operation statements enter this local child command.
const script=`$ErrorActionPreference='Stop'\ntry {\n${decoder}\n[Console]::Out.Write($login)\n} catch { [Console]::Error.Write('synthetic-login-frame-rejected'); exit 65 }`;
const childArgs=['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')];
const sourceHash=createHash('sha256').update(await readFile(sourceUrl)).digest('hex');
function decode(input){
  assert.ok(process.env.PWSH_BIN,'PWSH_BIN is required; only local synthetic stdin is permitted');
  const result=spawnSync(process.env.PWSH_BIN,childArgs,{input,encoding:'utf8',timeout:10000,maxBuffer:32768});
  assert.equal(result.error,undefined);
  return result;
}
const email='synthetic-login@example.invalid';
const validCases={
  'ordinary synthetic frame':{email,password:'Synthetic-only-password'},
  'maximum Unicode email and password':{email:'界'.repeat(316)+'@界.界',password:'界'.repeat(1024)},
  'control characters quotes and backslashes':{email,password:'\u0001\b\t\u000b\f\u001b\u001f"\'\\$`{} synthetic'},
  'leading password BOM':{email,password:'\ufeffSynthetic-password'},
};
for(const [name,login] of Object.entries(validCases)){
  test(`actual PowerShell login decoder preserves ${name}`,t=>{
    const bytes=encodeWebZipLogin(login);
    try{
      assert.ok(bytes.length<=4034);
      if(name==='maximum Unicode email and password'){
        assert.equal(login.email.length,320);assert.equal(login.password.length,1024);
      }
      const result=decode(bytes);
      assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');
      assert.deepEqual(JSON.parse(result.stdout),login);
      t.diagnostic(`decoderSourceSha256=${sourceHash}`);
    }finally{bytes.fill(0);}
  });
}
const invalidCases={
  'missing terminal LF':Buffer.from(`${email}\nsynthetic`),
  'missing separator LF':Buffer.from(`${email}synthetic\n`),
  'third line':Buffer.from(`${email}\nsynthetic\nextra\n`),
  'carriage return':Buffer.from(`${email}\r\nsynthetic\n`),
  'more than 4034 bytes':Buffer.from(`${email}\n${'x'.repeat(4035)}\n`),
  'invalid UTF-8':Buffer.concat([Buffer.from(`${email}\n`),Buffer.from([0xc3,0x28]),Buffer.from('\n')]),
  'UTF-16 BOM':Buffer.concat([Buffer.from([0xff,0xfe]),Buffer.from(`${email}\nsynthetic\n`,'utf16le')]),
};
for(const [name,bytes] of Object.entries(invalidCases)){
  test(`actual PowerShell login decoder rejects ${name}`,()=>{
    try{
      const result=decode(bytes);
      assert.equal(result.status,65);assert.equal(result.stdout,'');
      assert.equal(result.stderr,'synthetic-login-frame-rejected');
    }finally{bytes.fill(0);}
  });
}
