import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {runWebZipPackage,prepareWebZipPackage,SOURCE_NAMES,validateOfficialLogin} from '../source/web-zip-runner.mjs';
import {WEB_ZIP_PASS237} from '../source/web-zip-orchestrator.mjs';
import {SettlementTransport} from '../source/windows-settlement-transport.mjs';
import * as transport from '../source/powershell-stdin-transport.mjs';
const work=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const ticks='638988000000000000';
const quiet={remoteQuiescenceObserved:true,localProcessTerminated:true};
const decode=command=>Buffer.from(command.split(' ').at(-1),'base64').toString('utf16le');
async function fixture(){
 const root=await mkdtemp(join(tmpdir(),'web-zip-sftp-'));
 const sourceHashes=Object.fromEntries(await Promise.all(SOURCE_NAMES.map(async name=>[name,hash(await readFile(join(work,'source',name)))])));
 const request={schema:1,kind:'web_zip_execution_request',issue:19,authorizationId:WEB_ZIP_PASS237.authorizationId,candidate:WEB_ZIP_PASS237.candidate,
 executorPass:240,fixtureRoot:join(work,'fixture'),sourceHashes,desktop:{account:'joao',sid:'S-1-5-21-100-200-300-1001',sessionId:1},
 product:{productId:'00000000-0000-4000-8000-000000000001',analysisName:'Rappor Lab Web ZIP transport regression',environment:'Development'},
 previousReview:{path:join(root,'review.json'),sha256:'a'.repeat(64)}};
 const bytes=Buffer.from(JSON.stringify(request));const requestPath=join(root,'request.json');await writeFile(requestPath,bytes,{mode:0o600});
 return {root,args:{requestPath,requestSha256:hash(bytes),outputDirectory:join(root,'output')}};
}
const logins={unicode:{email:'a'.repeat(304)+'@example.invalid',password:'\u4e00'.repeat(1024)},escaped:{email:'\u0001'.repeat(304)+'@example.invalid',password:'\u0001'.repeat(1024)}};
for(const [name,login] of Object.entries(logins))test(`production public packet bypasses large stdin with maximum ${name} login`,async t=>{
 validateOfficialLogin(login);assert.equal(login.email.length,320);assert.equal(login.password.length,1024);
 const f=await fixture();const oldKey=process.env.RAPPOR_WINDOWS_SSH_KEY;
 const key=join(f.root,'synthetic-key');await writeFile(key,'synthetic key bytes, never used by SSH',{mode:0o600});process.env.RAPPOR_WINDOWS_SSH_KEY=key;
 const events=[];let loginEvents;let oversized=false;let launchInput;
 t.mock.method(SettlementTransport.prototype,'execute',async(file,args,options)=>{
  if(file==='sftp'){
   events.push('sftp');assert.ok(args.includes('-P'));assert.ok(!args.includes('-p'));
   assert.match(options.input,/^put ".+\/package\.json" "\/C:\/RapporLab\/runtime\/transport-web-zip-[a-f0-9]{64}\/package\.json"\n$/u);
   const packet=await readFile(join(f.args.outputDirectory,'package.json'),'utf8');assert.equal(Object.hasOwn(JSON.parse(packet),'loginBase64'),false);
   assert.equal(packet.includes(login.password),false);return {stdout:'',stderr:'',settlement:quiet};
  }
  assert.equal(file,'ssh');const source=decode(args.at(-1));assert.ok(args.at(-1).length<8191);
  if(Buffer.byteLength(options.input)>4034){oversized=true;throw new Error('synthetic-large-stdin-does-not-settle');}
  if(source.includes("throw 'stage-exists'")){events.push('setup');assert.equal(options.input,'');return {stdout:JSON.stringify({schema:1,creationTicks:ticks}),stderr:'',settlement:quiet};}
  if(source.includes('stageAbsent=')){events.push('cleanup');return {stdout:JSON.stringify({schema:1,stageAbsent:true}),stderr:'',settlement:quiet};}
  events.push('launch');launchInput=Buffer.from(options.input);assert.equal(launchInput.toString('utf8'),login.email+'\n'+login.password+'\n');
  assert.equal(source.includes(login.password),false);assert.match(source,/\. \(\[ScriptBlock\]::Create/u);
  assert.match(source,/\$hash -cne \$h/u);assert.match(source,/\$hash -cne \$w/u);
  const packet=JSON.parse(await readFile(join(f.args.outputDirectory,'package.json')));
  return {stdout:JSON.stringify({schema:1,instructionSha256:packet.instructionSha256,primary:{outcome:'inconclusive',failureCode:'synthetic_no_journey'},
   cleanup:{verified:true,ownedProcessesAbsent:true,loginMaterialAbsent:true,runtimeRootAbsent:true},taskAbsent:true,workerQuiescent:true,artifacts:{}}),stderr:'',settlement:quiet};
 });
 try{
  await assert.rejects(runWebZipPackage(f.args,{authorizeRuntime:async()=>({}),verifyHostIdentity:async()=>{},loadOfficialLogin:async()=>{loginEvents=[...events];return login;}}));
  assert.equal(oversized,false,'public-package-must-not-use-stdin');
  assert.deepEqual(loginEvents,['setup','sftp']);assert.deepEqual(events,['setup','sftp','launch','cleanup']);assert.ok(launchInput.length<=4034);
  const settled=JSON.parse(await readFile(join(f.args.outputDirectory,'cleanup.json')));
  assert.equal(settled.transportStage.stageAbsent,true);assert.equal(settled.credentialClosed,true);assert.equal(settled.cleanup.verified,true);
  const output=JSON.stringify(settled);assert.equal(output.includes(login.password),false);
 }finally{if(oldKey===undefined)delete process.env.RAPPOR_WINDOWS_SSH_KEY;else process.env.RAPPOR_WINDOWS_SSH_KEY=oldKey;await rm(f.root,{recursive:true,force:true});}
});

test('public staging rejects login fields and binds command size, generation, hashes and deadline',async()=>{
 const f=await fixture();try{
  const prepared=await prepareWebZipPackage(f.args);
  const setup=transport.buildWebZipStagePreparation(prepared);assert.equal(setup.root,'C:\\RapporLab\\runtime\\transport-web-zip-'+prepared.requestSha256);
  const invocation=transport.buildWebZipStageInvocation(prepared,ticks,500000,1800000000000);
  assert.equal(invocation.guestDeadlineUnixMs,1800000482000);
  for(const command of [setup.command,invocation.command,transport.buildWebZipStageCleanup(prepared,ticks)]){
   assert.ok(command.length<8191);const source=decode(command);assert.match(source,/stage-reparse/u);assert.match(source,/stage-acl/u);assert.match(source,/0x500D0156/u);
   assert.doesNotMatch(source,/-ExecutionPolicy|Bypass/u);
  }
  assert.match(decode(invocation.command),new RegExp(hash(Buffer.from(JSON.stringify(prepared.package)+'\n'))));
  assert.match(decode(invocation.command),/UTF8Encoding\]::new\(\$false,\$true\)/u);
  assert.throws(()=>transport.buildWebZipStageInvocation(prepared,ticks,108000),/remaining-budget-insufficient/);
  assert.throws(()=>transport.buildWebZipStageCleanup(prepared,'changed'),/stage-creation-invalid/);
  assert.throws(()=>transport.buildWebZipStagePreparation({...prepared,package:{...prepared.package,loginBase64:'synthetic'}}),/public-package-contains-login/);
 }finally{await rm(f.root,{recursive:true,force:true});}
});
for(const phase of ['upload','launch'])test(`failed ${phase} keeps primary failure and settles only owned public staging`,async()=>{
 const f=await fixture();try{
  const prepared=await prepareWebZipPackage(f.args);const calls=[];
  const adapter={sshArguments:[],sshTarget:'synthetic',async execute(file,args,options){
   const source=file==='ssh'?decode(args.at(-1)):'';
   if(source.includes("throw 'stage-exists'"))return {stdout:JSON.stringify({schema:1,creationTicks:ticks}),stderr:'',settlement:quiet};
   if(source.includes('stageAbsent=')){calls.push('cleanup');return {stdout:JSON.stringify({schema:1,stageAbsent:true}),stderr:'',settlement:quiet};}
   if((phase==='upload'&&file==='sftp')||(phase==='launch'&&file==='ssh')){const error=new Error('synthetic failure');error.settlement=quiet;throw error;}
   return {stdout:'',stderr:'',settlement:quiet};
  }};
  if(phase==='upload'){await assert.rejects(transport.prepareWebZipRemoteTransport(adapter,prepared,{remaining:()=>600000}),error=>error.stageCleanup.stageAbsent===true);}
  else{const remote=await transport.prepareWebZipRemoteTransport(adapter,prepared,{remaining:()=>600000});await assert.rejects(remote.execute(logins.unicode));assert.equal((await remote.cleanup()).stageAbsent,true);}
  assert.deepEqual(calls,['cleanup']);
 }finally{await rm(f.root,{recursive:true,force:true});}
});
for(const [matchingProcesses,unobservableProcesses,expectCleanup] of [[1,0,false],[0,1,false],[0,0,true]])test(`timeout staging reconciliation keeps uncertainty ${matchingProcesses}/${unobservableProcesses} closed`,async()=>{
 const f=await fixture();try{
  const prepared=await prepareWebZipPackage(f.args);const calls=[];
  const adapter={sshArguments:[],sshTarget:'synthetic',async execute(file,args){
   if(file==='sftp')return {stdout:'',stderr:'',settlement:quiet};
   assert.ok(args.at(-1).length<8191);const source=decode(args.at(-1));
   if(source.includes("throw 'stage-exists'"))return {stdout:JSON.stringify({schema:1,creationTicks:ticks}),stderr:'',settlement:quiet};
   if(source.includes('matchingProcesses=')){calls.push('observe');assert.doesNotMatch(source,/-EncodedCommand [A-Za-z0-9+/=]{100,}/u);return {stdout:JSON.stringify({schema:1,matchingProcesses,unobservableProcesses}),stderr:'',settlement:quiet};}
   if(source.includes('stageAbsent=')){calls.push('cleanup');return {stdout:JSON.stringify({schema:1,stageAbsent:true}),stderr:'',settlement:quiet};}
   const error=new Error('synthetic timeout');error.settlement={remoteQuiescenceObserved:false};throw error;
  }};
  const remote=await transport.prepareWebZipRemoteTransport(adapter,prepared,{remaining:()=>600000});
  await assert.rejects(remote.execute(logins.unicode));await assert.rejects(remote.execute(logins.unicode),/stage-already-dispatched/);
  const cleanup=await remote.cleanup();assert.equal(cleanup.stageAbsent,expectCleanup);
  assert.deepEqual(calls,expectCleanup?['observe','cleanup']:['observe']);
  const again=await remote.cleanup();assert.equal(again.stageAbsent,expectCleanup);
  assert.deepEqual(calls,expectCleanup?['observe','cleanup']:['observe','observe']);
 }finally{await rm(f.root,{recursive:true,force:true});}
});

for (const [name, value] of Object.entries({
  newlineEmail: {email:'x\ny@example.invalid',password:'valid'},
  newlinePassword: {email:'x@example.invalid',password:'x\ny'},
  carriageReturn: {email:'x@example.invalid',password:'x\ry'},
  nullPassword: {email:'x@example.invalid',password:'x\u0000y'},
  invalidUnicode: {email:'x@example.invalid',password:'\ud800'},
})) test(`login frame rejects ${name} before transport`,()=>{
  assert.throws(()=>transport.encodeWebZipLogin(value));
});
test('login frame preserves maximum UTF8 fields without JSON escape expansion',()=>{
  const login={email:'\u4e00'.repeat(316)+'@\u4e00.\u4e00',password:'\u4e00'.repeat(1024)};
  validateOfficialLogin(login);
  const bytes=transport.encodeWebZipLogin(login);
  assert.equal(bytes.length,4030);
  assert.equal(bytes.toString('utf8'),login.email+'\n'+login.password+'\n');
  const controls=transport.encodeWebZipLogin(logins.escaped);
  assert.equal(controls.length,1346);
  assert.equal(controls.toString('utf8'),logins.escaped.email+'\n'+logins.escaped.password+'\n');
});
