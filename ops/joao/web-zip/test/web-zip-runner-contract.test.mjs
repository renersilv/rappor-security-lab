import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {chmod, cp, mkdtemp, readFile, rm, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import test from 'node:test';
import {SOURCE_NAMES,validateRuntimeAuthority,parseOfficialLogin,validateOfficialLogin} from '../source/web-zip-runner.mjs';
import {WEB_ZIP_PASS237} from '../source/web-zip-orchestrator.mjs';
import {validateWebZipResult} from '../source/web-zip-result.mjs';
const execute=promisify(execFile);
const work=resolve(dirname(fileURLToPath(import.meta.url)), '..');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const uuid=number=>`00000000-0000-4000-8000-${String(number).padStart(12,'0')}`;
export async function makeRequest() {
  const root=await mkdtemp(join(tmpdir(),'web-zip-runner-regression-'));
  await chmod(root,0o700);
  const sourceHashes=Object.fromEntries(await Promise.all(SOURCE_NAMES.map(async name=>[name,digest(await readFile(join(work,'source',name)))])));
  const request={schema:1,kind:'web_zip_execution_request',issue:19,authorizationId:WEB_ZIP_PASS237.authorizationId,
    candidate:WEB_ZIP_PASS237.candidate,executorPass:238,fixtureRoot:join(work,'fixture'),sourceHashes,
    desktop:{account:'joao',sid:'S-1-5-21-100-200-300-1001',sessionId:1},
    product:{productId:uuid(1),analysisDefinitionId:uuid(2),revisionId:uuid(3)},
    previousReview:{path:join(root,'synthetic-previous-review.json'),sha256:'a'.repeat(64)}};
  return {root,request,async args(){const path=join(root,'request.json'); const bytes=Buffer.from(JSON.stringify(request));
    await writeFile(path,bytes,{mode:0o600}); return {requestPath:path,requestSha256:digest(bytes),outputDirectory:join(root,'output')};},
  async close(){await rm(root,{recursive:true,force:true});}};
}
async function invoke(args){return execute(process.execPath,[join(work,'source/web-zip-runner.mjs'),'prepare',
  '--request',args.requestPath,'--sha256',args.requestSha256,'--output',args.outputDirectory],{timeout:10000,maxBuffer:1024*1024});}
test('actual prepare CLI materializes exact reviewed instruction, worker and deterministic ZIP',async()=>{
  const f=await makeRequest();try{const args=await f.args();const result=await invoke(args);
    assert.equal(JSON.parse(result.stdout).outcome,'prepared');
    const packet=JSON.parse(await readFile(join(args.outputDirectory,'package.json')));
    assert.equal(digest(Buffer.from(packet.archiveBase64,'base64')),packet.archiveSha256);
    assert.equal(packet.archiveSha256,'8627e45b93043f90c664fb015901e68cb1cf82d1ba93453068e5a2f1ae508af6');
    assert.deepEqual(Buffer.from(packet.workerBase64,'base64'),await readFile(join(work,'source/web-zip-windows-orchestrator.ps1')));
    assert.equal(digest(Buffer.from(packet.instructionBase64,'base64')),packet.instructionSha256);
    const instruction=JSON.parse(Buffer.from(packet.instructionBase64,'base64'));
    assert.deepEqual(instruction.sourceHashes,f.request.sourceHashes);assert.deepEqual(instruction.desktop,f.request.desktop);
    assert.equal(instruction.totalMs,600000);
    await assert.rejects(invoke(args)); // No overwrite or second materialization.
  }finally{await f.close();}
});
for(const [name,change] of Object.entries({
  request_hash:async(f,args)=>{args.requestSha256='f'.repeat(64);},
  source_hash:async f=>{f.request.sourceHashes['web-zip-windows-orchestrator.ps1']='f'.repeat(64);},
  account:async f=>{f.request.desktop.account='unrelated';},
  session:async f=>{f.request.desktop.sessionId=0;},
  candidate:async f=>{f.request.candidate={...f.request.candidate,version:'v0.91.0'};},
  archive_bytes:async f=>{const path=join(f.root,'fixture');await cp(f.request.fixtureRoot,path,{recursive:true});
    f.request.fixtureRoot=path;await writeFile(join(path,'app.mjs'),'changed');},
  fixture_symlink:async f=>{const path=join(f.root,'fixture-link');await symlink(f.request.fixtureRoot,path);f.request.fixtureRoot=path;},
  request_symlink:async(f,args)=>{const path=join(f.root,'linked-request');await symlink(args.requestPath,path);args.requestPath=path;},
})) test(`actual prepare CLI rejects ${name} before remote execution`,async()=>{
  const f=await makeRequest();try{let args=await f.args();await change(f,args);
    if(!['request_hash','request_symlink'].includes(name))args=await f.args();
    await assert.rejects(invoke(args),error=>error.code===65 && /web_zip_error=invalid_or_unresolved/.test(error.stderr));
  }finally{await f.close();}
});
function resultFixture(){const instruction={requestSha256:'a'.repeat(64),archiveSha256:'b'.repeat(64),candidate:WEB_ZIP_PASS237.candidate,
  product:{productId:uuid(1),analysisDefinitionId:uuid(2),revisionId:uuid(3)},sourceHashes:{worker:'c'.repeat(64)}};
  const execution={id:uuid(4),...instruction.product,uploadPath:`/api/analysis-definitions/${uuid(2)}/assessments/uploaded-code`,idempotencyKey:uuid(5)};
  const primary={outcome:'completed',requestSha256:instruction.requestSha256,archiveSha256:instruction.archiveSha256,
    candidate:instruction.candidate,sourceHashes:instruction.sourceHashes,execution,selectionFingerprint:'d'.repeat(64),confirmationObserved:true,
    counts:{pickerOpens:1,fileSelections:1,uploads:1,analyses:1},rendered:{executionId:execution.id,revisionId:execution.revisionId,
      productId:execution.productId,pathname:`/executions/${execution.id}`,historyExecutionId:execution.id,coverageComplete:true,
      score:58.9,problemCount:70,executionScreenshotSha256:'e'.repeat(64),historyScreenshotSha256:'f'.repeat(64)}};
  return {instruction,primary};}
test('ZIP result binds execution/revision/history and does not require workspace consent',()=>{
  const {instruction,primary}=resultFixture();assert.equal(validateWebZipResult(primary,instruction),primary);
  assert.equal(Object.hasOwn(primary,'consent'),false);assert.equal(Object.hasOwn(primary,'operationId'),false);
});
for(const [name,mutate] of Object.entries({
  other_execution:p=>{p.rendered.executionId=uuid(99);},other_history:p=>{p.rendered.historyExecutionId=uuid(99);},
  other_revision:p=>{p.execution.revisionId=uuid(99);},workspace_endpoint:p=>{p.execution.uploadPath='/api/workspace/operations';},
  archive_as_selection:p=>{p.selectionFingerprint=p.archiveSha256;},missing_screenshot:p=>{delete p.rendered.executionScreenshotSha256;},
  unrelated_source:p=>{p.sourceHashes={worker:'0'.repeat(64)};},
}))test(`ZIP provenance rejects ${name}`,()=>{const {instruction,primary}=resultFixture();mutate(primary);
  assert.throws(()=>validateWebZipResult(primary,instruction));});

function authorityFixture(){
  const sourceHashes=Object.fromEntries(SOURCE_NAMES.map(name=>[name,'e'.repeat(64)]));
  const checkpoint={path:'/synthetic/protected/checkpoint/review.json',sha256:'b'.repeat(64)};
  const prepared={request:{executorPass:238,candidate:WEB_ZIP_PASS237.candidate,previousReview:{path:'/synthetic/protected/previous.json',sha256:'9'.repeat(64)},sourceHashes},
    requestPath:'/synthetic/protected/checkpoint/request.json',requestSha256:'c'.repeat(64),
    outputDirectory:'/synthetic/protected/checkpoint/web-zip-output-pass238'};
  const bindings=Object.fromEntries(['authorizationSha256','stageSha256','sessionSha256','candidateSha256','contractSha256'].map(name=>[name,'a'.repeat(64)]));
  const manifestRef={path:'/synthetic/protected/manifest.json',sha256:'f'.repeat(64)};
  return {prepared,authority:{campaign:{phase:'active',executorPasses:238,candidate:prepared.request.candidate,reviewCheckpoint:checkpoint,...bindings},
    receipt:{schema:1,issue:24,targetIssue:19,reviewedThroughPass:237,previousReview:prepared.request.previousReview,...bindings},
    correction:{webZipRequest:{path:prepared.requestPath,sha256:prepared.requestSha256},manifest:manifestRef,
      workContinuation:{targetObjectiveId:'web-entries',phase:'runtime',scope:'bounded_no_model',nextPass:238,runtimeCheckpoints:1,manifest:manifestRef}},
    manifest:{files:Object.fromEntries(Object.entries(sourceHashes).map(([name,hash])=>[`source/${name}`,hash]))},
    diagnosis:{verdict:'pass',scope:'bounded_no_model',cleanupAssessment:'verified',workContinuation:{targetObjectiveId:'web-entries'}}}};
}
test('runtime authority binds reviewed request, source closure and a single checkpoint intent',()=>{
  const {prepared,authority}=authorityFixture();
  assert.ok(SOURCE_NAMES.includes('protected-inputs.mjs'));
  assert.ok(SOURCE_NAMES.includes('windows-settlement-transport.mjs'));
  assert.deepEqual(validateRuntimeAuthority(prepared,authority),{intentPath:'/synthetic/protected/checkpoint/web-zip-pass238.intent.json'});
});
for(const [name,mutate] of Object.entries({
  changed_request_hash:f=>{f.prepared.requestSha256='d'.repeat(64);},
  substituted_request_path:f=>{f.prepared.requestPath='/synthetic/protected/checkpoint/unreviewed.json';},
  second_output_folder:f=>{f.prepared.outputDirectory='/synthetic/protected/checkpoint/another-output';},
  missing_reviewed_request:f=>{delete f.authority.correction.webZipRequest;},
  offline_grant:f=>{f.authority.correction.workContinuation.scope='offline';},
  unresolved_cleanup:f=>{f.authority.diagnosis.cleanupAssessment='unresolved';},
  rejected_review:f=>{f.authority.diagnosis.verdict='changes_requested';},
  changed_helper_source:f=>{f.authority.manifest.files['source/protected-inputs.mjs']='d'.repeat(64);},
  another_campaign_pass:f=>{f.authority.campaign.executorPasses=239;},
}))test(`runtime authority rejects ${name}`,()=>{const f=authorityFixture();mutate(f);assert.throws(()=>validateRuntimeAuthority(f.prepared,f.authority));});

test('official login parser treats shell metacharacters as literal synthetic data',()=>{
  const password='literal-$()-`command`-\\-!#';
  const bytes=Buffer.from(`RAPPOR_HML_EMAIL=synthetic-login@example.invalid\nRAPPOR_HML_PASSWORD='${password}'\n`);
  assert.deepEqual(parseOfficialLogin(bytes),{email:'synthetic-login@example.invalid',password});
});
for(const input of [
  'RAPPOR_HML_EMAIL=synthetic-login@example.invalid\n',
  'RAPPOR_HML_EMAIL=synthetic-login@example.invalid\nRAPPOR_HML_PASSWORD=\n',
  'RAPPOR_HML_EMAIL=synthetic-login@example.invalid\nRAPPOR_HML_PASSWORD=one\nRAPPOR_HML_PASSWORD=two\n',
  'UNRELATED_COMMAND=forbidden\nRAPPOR_HML_EMAIL=synthetic-login@example.invalid\nRAPPOR_HML_PASSWORD=one\n',
])test('missing duplicate empty or unrelated login input is refused',()=>assert.throws(()=>parseOfficialLogin(Buffer.from(input))));
test('login credential shape rejects a transport selector or control characters',()=>{
  assert.throws(()=>validateOfficialLogin({email:'synthetic-login@example.invalid',password:'one',url:'https://unrelated.invalid'}));
  assert.throws(()=>validateOfficialLogin({email:'synthetic-login@example.invalid',password:'one\nsecond'}));
});
