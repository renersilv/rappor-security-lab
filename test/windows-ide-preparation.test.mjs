import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { buildPreparationSource, executePreparation, validatePreparationReceipt } from '../src/windows-ide-preparation.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const input = { guestRoot:'C:\\RapporLab\\runtime\\pass731-ide-readiness', taskName:'RapporLab-Pass731-IdeReadiness',
  minimumGuestFreeBytes:1000, interactiveBase64:Buffer.from('interactive').toString('base64'), observerBase64:Buffer.from('observer').toString('base64'),
  interactiveSha256:hash('interactive'), observerSha256:hash('observer') };
const ready = { schema:1,outcome:'ready',stage:'source_materialization',code:null,rootDisposition:'created_by_invocation',
  interactiveUserKind:'bound-joao-user',guestFreeBytes:2000,cleanupOutcome:'not_required' };
test('preparation builds only the exact pass root and matching task',()=>{
  assert.equal(typeof buildPreparationSource(input),'string');
  for(const guestRoot of ['C:\\RapporLab','C:\\RapporLab\\runtime\\pass0-ide-readiness','C:\\RapporLab\\runtime\\pass731-ide-readiness\\other','C:\\\\RapporLab\\runtime\\pass731-ide-readiness']){
    assert.throws(()=>buildPreparationSource({...input,guestRoot}));
  }
  assert.throws(()=>buildPreparationSource({...input,taskName:'RapporLab-Pass732-IdeReadiness'}));
});
test('closed receipt distinguishes verified cleanup from ownership uncertainty',()=>{
  assert.deepEqual(validatePreparationReceipt(ready,1000),ready);
  const cleaned={...ready,outcome:'failed',code:'source-write-failed',cleanupOutcome:'verified'};
  assert.deepEqual(validatePreparationReceipt(cleaned,1000),cleaned);
  const uncertain={...cleaned,rootDisposition:'unverified',cleanupOutcome:'unresolved'};
  assert.deepEqual(validatePreparationReceipt(uncertain,1000),uncertain);
  for(const receipt of [{...ready,cleanupOutcome:'verified'},{...cleaned,cleanupOutcome:'not_required'},
    {...uncertain,cleanupOutcome:'verified'},{...cleaned,rootDisposition:'preexisting'}, {...ready,rawError:'private'},
    {...ready,guestFreeBytes:999},{...ready,cleanupOutcome:true}]) assert.throws(()=>validatePreparationReceipt(receipt,1000));
});
test('failed preparation is retained before execution is rejected',async()=>{
  const receipt={...ready,outcome:'failed',code:'source-write-failed',cleanupOutcome:'verified'};
  const retained=[];
  await assert.rejects(()=>executePreparation({source:buildPreparationSource(input),minimumGuestFreeBytes:1000,
    runPowerShell:async()=>JSON.stringify(receipt),writeReceipt:async value=>retained.push(value)}),error=>error.code==='PREPARATION_REJECTED');
  assert.deepEqual(retained,[receipt]);
});
test('malformed receipt never becomes a retained approval',async()=>{
  const retained=[];
  await assert.rejects(()=>executePreparation({source:'fixture',minimumGuestFreeBytes:1000,
    runPowerShell:async()=>JSON.stringify({...ready,cleanupOutcome:'verified'}),writeReceipt:async value=>retained.push(value)}));
  assert.deepEqual(retained,[]);
});
