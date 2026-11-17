import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import test from 'node:test';
const local=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const source=process.env.WEB_ZIP_TEST_SOURCE_ROOT??join(local,'source');
const {prepareWebZipPackage,SOURCE_NAMES}=await import(pathToFileURL(join(source,'web-zip-runner.mjs')));
const {WEB_ZIP_PASS237}=await import(pathToFileURL(join(source,'web-zip-orchestrator.mjs')));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
async function prepare(change=()=>{}){
  const root=await mkdtemp(join(tmpdir(),'web-zip-first-upload-'));
  try{
    const request={schema:1,kind:'web_zip_execution_request',issue:19,authorizationId:WEB_ZIP_PASS237.authorizationId,
      candidate:WEB_ZIP_PASS237.candidate,executorPass:238,fixtureRoot:join(local,'fixture'),
      sourceHashes:Object.fromEntries(await Promise.all(SOURCE_NAMES.map(async name=>[name,hash(await readFile(join(source,name)))]))),
      desktop:{account:'joao',sid:'S-1-5-21-100-200-300-1001',sessionId:1},
      product:{productId:'00000000-0000-4000-8000-000000000001',analysisName:'Rappor Lab Web ZIP pass238',environment:'Development'},
      previousReview:{path:join(root,'previous.json'),sha256:'a'.repeat(64)}};
    change(request);
    const bytes=Buffer.from(JSON.stringify(request)),requestPath=join(root,'request.json');
    await writeFile(requestPath,bytes,{mode:0o600});
    return await prepareWebZipPackage({requestPath,requestSha256:hash(bytes),outputDirectory:join(root,'output')});
  }finally{await rm(root,{recursive:true,force:true});}
}
test('first ZIP package needs only existing product and reviewed synthetic creation details',async()=>{
  const prepared=await prepare();
  assert.deepEqual(prepared.instruction.product,{productId:'00000000-0000-4000-8000-000000000001',
    analysisName:'Rappor Lab Web ZIP pass238',environment:'Development'});
  assert.equal(prepared.instruction.totalMs,600000);
  assert.equal(Object.hasOwn(prepared.request.product,'analysisDefinitionId'),false);
  assert.equal(Object.hasOwn(prepared.request.product,'revisionId'),false);
});
for(const [name,change] of Object.entries({
  precreated_definition:r=>{r.product={productId:r.product.productId,analysisDefinitionId:'00000000-0000-4000-8000-000000000002',revisionId:'00000000-0000-4000-8000-000000000003'};},
  extra_revision:r=>{r.product.revisionId='00000000-0000-4000-8000-000000000003';},
  nonsynthetic_name:r=>{r.product.analysisName='Customer data';},
  multiline_name:r=>{r.product.analysisName='Rappor Lab Web ZIP pass238\n';},
  production_environment:r=>{r.product.environment='Production';},
}))test(`first ZIP request rejects ${name}`,async()=>{await assert.rejects(prepare(change));});
