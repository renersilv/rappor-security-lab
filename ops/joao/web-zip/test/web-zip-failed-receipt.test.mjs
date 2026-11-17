import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import test from 'node:test';
import {runWebZipPackage} from '../source/web-zip-runner.mjs';
import {makeRequest} from './web-zip-runner-contract.test.mjs';

const privateText='synthetic-private-receipt-content';
for(const variant of ['inconclusive','completed','unknown-diagnostics','wrong-binding','owned-processes-unconfirmed']){
  test(`failed receipt ${variant} retains only bound sanitized diagnostics without screenshots`,async()=>{
    const f=await makeRequest();
    try{
      const args=await f.args();
      await assert.rejects(runWebZipPackage(args,{
        authorizeRuntime:async()=>({}),verifyHostIdentity:async()=>{},
        loadOfficialLogin:async()=>({email:'synthetic@example.invalid',password:'Synthetic-only-password'}),
        executeRemote:async()=>{
          const packet=JSON.parse(await readFile(join(args.outputDirectory,'package.json')));
          const remote={schema:1,instructionSha256:variant==='wrong-binding'?'f'.repeat(64):packet.instructionSha256,
            workerQuiescent:true,taskAbsent:variant==='owned-processes-unconfirmed',
            primary:{schema:1,outcome:variant==='completed'?'completed':'inconclusive',
              failureCode:variant==='unknown-diagnostics'?privateText:'journey_unresolved',
              failureStage:variant==='unknown-diagnostics'?privateText:'wizard_readiness',
              arbitrary:privateText,execution:{untrusted:privateText}},
            cleanup:{schema:1,verified:['completed','owned-processes-unconfirmed'].includes(variant),failureCode:'parent_cleanup_unresolved',
              ownedProcessesAbsent:variant!=='owned-processes-unconfirmed',loginMaterialAbsent:true,
              runtimeRootAbsent:variant==='owned-processes-unconfirmed',arbitrary:privateText},
            artifacts:{'confirmation.png':{base64:Buffer.from(privateText).toString('base64'),sha256:'a'.repeat(64)}}};
          return {stdout:JSON.stringify(remote),stderr:'',settlement:{remoteQuiescenceObserved:true,localProcessTerminated:true}};
        },
      }),{message:'web_zip_unresolved'});
      const primary=JSON.parse(await readFile(join(args.outputDirectory,'primary.json')));
      const receipt=JSON.parse(await readFile(join(args.outputDirectory,'cleanup.json')));
      assert.equal(primary.outcome,'inconclusive');assert.equal(receipt.cleanup.verified,false);
      assert.equal(receipt.stage,'remote_receipt');
      assert.equal((await readdir(args.outputDirectory)).some(name=>name.endsWith('.png')),false);
      for(const value of [primary,receipt]){
        assert.equal(JSON.stringify(value).includes(privateText),false);
        assert.equal(JSON.stringify(value).includes(Buffer.from(privateText).toString('base64')),false);
      }
      if(variant==='wrong-binding'){
        assert.equal(primary.failureCode,'web_zip_unresolved');
        assert.equal(Object.hasOwn(primary,'remoteOutcome'),false);
      }else{
        assert.equal(primary.failureCode,variant==='unknown-diagnostics'?'remote_unresolved':'journey_unresolved');
        assert.equal(primary.failureStage,variant==='unknown-diagnostics'?'unknown':'wizard_readiness');
        assert.equal(primary.remoteOutcome,variant==='completed'?'completed':'inconclusive');
        assert.equal(primary.requestSha256,args.requestSha256);
        assert.equal(primary.instructionSha256,receipt.instructionSha256);
        assert.deepEqual(primary.sourceHashes,receipt.sourceHashes);
        assert.match(primary.remoteReceiptSha256,/^[a-f0-9]{64}$/u);
        assert.equal(receipt.cleanup.reportedVerified,['completed','owned-processes-unconfirmed'].includes(variant));
        assert.equal(receipt.cleanup.taskAbsent,variant==='owned-processes-unconfirmed');
        assert.equal(receipt.cleanup.workerQuiescent,true);
        assert.equal(receipt.cleanup.loginMaterialAbsent,true);
        assert.equal(receipt.cleanup.runtimeRootAbsent,variant==='owned-processes-unconfirmed');
        assert.equal(Object.hasOwn(primary,'execution'),false);
      }
    }finally{await f.close();}
  });
}
