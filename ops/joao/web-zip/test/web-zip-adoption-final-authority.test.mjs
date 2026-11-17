import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmod,mkdir,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import test from 'node:test';
const local=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sourceRoot=process.env.WEB_ZIP_ADOPTION_SOURCE_ROOT??join(local,'source');
const runtime=await import(pathToFileURL(join(sourceRoot,'web-zip-runner.mjs')).href);
const {WEB_ZIP_PASS237}=await import(pathToFileURL(join(sourceRoot,'web-zip-orchestrator.mjs')).href);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const uuid=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
async function topology({wrongPredecessor=false}={}){
  const root=await mkdtemp(join(tmpdir(),'web-zip-authority-topology-'));await chmod(root,0o700);
  const reviewRoot=join(root,'reviews');await mkdir(reviewRoot,{mode:0o700});
  const current=join(reviewRoot,'current');await mkdir(current,{mode:0o700});
  const paths={};const creation=[];
  async function put(name,value){
    const path=join(current,`${name}.json`);const bytes=Buffer.from(JSON.stringify(value)+'\n');
    await writeFile(path,bytes,{flag:'wx',mode:0o600});paths[name]=path;creation.push(name);
    return {path,sha256:hash(bytes)};
  }
  try{
    const previous=await put('previous',{schema:1,reviewedThroughPass:236});
    const otherPrevious=await put('other-previous',{schema:1,reviewedThroughPass:235});
    const sourceHashes=Object.fromEntries(await Promise.all(runtime.SOURCE_NAMES.map(async name=>[name,hash(await readFile(join(sourceRoot,name)))])));
    const request={schema:1,kind:'web_zip_execution_request',issue:19,authorizationId:WEB_ZIP_PASS237.authorizationId,
      candidate:WEB_ZIP_PASS237.candidate,executorPass:238,
      fixtureRoot:join(local,'fixture'),sourceHashes,
      desktop:{account:'joao',sid:'S-1-5-21-100-200-300-1001',sessionId:1},
      product:{productId:uuid(1),analysisName:'Rappor Lab Web ZIP pass238',environment:'Development'},
      previousReview:wrongPredecessor?otherPrevious:previous};
    const requestRef=await put('request',request);
    assert.equal(creation.includes('review'),false,'request is materialized before the current review exists');
    const prepared=await runtime.prepareWebZipPackage({requestPath:requestRef.path,requestSha256:requestRef.sha256,
      outputDirectory:join(current,'web-zip-output-pass238')});
    const manifestRef=await put('manifest',{files:Object.fromEntries(Object.entries(sourceHashes).map(([name,sha])=>[`source/${name}`,sha]))});
    const diagnosisRef=await put('diagnosis',{verdict:'pass',scope:'bounded_no_model',cleanupAssessment:'verified',workContinuation:{targetObjectiveId:'web-entries'}});
    const correction={webZipRequest:requestRef,manifest:manifestRef,workContinuation:{targetObjectiveId:'web-entries',
      phase:'runtime',scope:'bounded_no_model',nextPass:238,runtimeCheckpoints:1,manifest:manifestRef}};
    const correctionRef=await put('correction',correction);
    const bindings=Object.fromEntries(['authorizationSha256','stageSha256','sessionSha256','candidateSha256','contractSha256'].map(name=>[name,'a'.repeat(64)]));
    const receipt={schema:1,issue:24,targetIssue:19,reviewedThroughPass:237,...bindings,
      previousReview:previous,correction:correctionRef,diagnosis:diagnosisRef};
    const reviewRef=await put('review',receipt);
    const campaign={phase:'active',executorPasses:238,candidate:request.candidate,...bindings,reviewCheckpoint:reviewRef};
    const campaignRef=await put('campaign',campaign);
    return {root,current,reviewRoot,prepared,request,requestRef,paths,creation,campaign,receipt,
      authority:{campaignPath:campaignRef.path,reviewRoot},
      close:()=>rm(root,{recursive:true,force:true})};
  }catch(error){await rm(root,{recursive:true,force:true});throw error;}
}
test('acyclic materialization binds actual request correction review and campaign bytes',async()=>{
  const f=await topology();try{
    const approval=await runtime.authorizeRuntime(f.prepared,f.authority);
    assert.deepEqual(approval,{intentPath:join(f.current,'web-zip-pass238.intent.json')});
    assert.ok(f.creation.indexOf('request')<f.creation.indexOf('correction'));
    assert.ok(f.creation.indexOf('correction')<f.creation.indexOf('review'));
    assert.ok(f.creation.indexOf('review')<f.creation.indexOf('campaign'));
    assert.equal(hash(await readFile(f.requestRef.path)),f.requestRef.sha256);
    assert.equal(Object.hasOwn(f.request,'reviewCheckpoint'),false);
  }finally{await f.close();}
});
test('different protected predecessor cannot authorize the request',async()=>{
  const f=await topology({wrongPredecessor:true});try{
    await assert.rejects(runtime.authorizeRuntime(f.prepared,f.authority),/request-predecessor-mismatch/);
  }finally{await f.close();}
});
for(const name of ['previous','review','correction','diagnosis','manifest'])test(`protected ${name} byte substitution is rejected`,async()=>{
  const f=await topology();try{
    const original=await readFile(f.paths[name]);await writeFile(f.paths[name],Buffer.concat([original,Buffer.from(' ')]));
    await assert.rejects(runtime.authorizeRuntime(f.prepared,f.authority));
  }finally{await f.close();}
});
test('campaign cannot select another current review while keeping the original output authority',async()=>{
  const f=await topology();try{
    const other=join(f.reviewRoot,'other-current');await mkdir(other,{mode:0o700});
    const path=join(other,'review.json');const bytes=await readFile(f.paths.review);await writeFile(path,bytes,{mode:0o600});
    f.campaign.reviewCheckpoint={path,sha256:hash(bytes)};
    await writeFile(f.paths.campaign,JSON.stringify(f.campaign));
    await assert.rejects(runtime.authorizeRuntime(f.prepared,f.authority),/runtime-output-not-canonical/);
  }finally{await f.close();}
});
test('request still cannot choose a fresh output folder for another runtime start',async()=>{
  const f=await topology();try{
    await assert.rejects(runtime.authorizeRuntime({...f.prepared,outputDirectory:join(f.current,'new-output')},f.authority),/runtime-output-not-canonical/);
  }finally{await f.close();}
});
