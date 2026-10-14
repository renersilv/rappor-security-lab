import assert from 'node:assert/strict';
import test from 'node:test';
import {reviewSummary, verifyPolicy, stoppedResult} from '../src/run-windows-agent-ai-client.mjs';

test('a timeout is not an approval refusal', () => {
  assert.equal(stoppedResult('attempt-timeout').outcome, 'failed');
  assert.equal(stoppedResult('approval-denied').outcome, 'refused');
  assert.equal(stoppedResult('human-action-required').outcome, 'failed');
});
test('only the intended approval and sandbox policy is accepted', () => {
  const policy = {approvalPolicy:'on-request',approvalsReviewer:'auto_review',sandbox:{type:'workspaceWrite',networkAccess:false}};
  verifyPolicy(policy);
  for (const override of [{approvalPolicy:'never'},{approvalsReviewer:'user'},{sandbox:{type:'dangerFullAccess'}},{sandbox:{type:'workspaceWrite',networkAccess:true}}]) {
    assert.throws(() => verifyPolicy({...policy,...override}));
  }
});
test('review notifications retain no raw rationale or identifiers', () => {
  const value = reviewSummary({reviewId:'PRIVATE_ID',action:{type:'command',command:'PRIVATE_COMMAND'},review:{status:'denied',rationale:'SSH sandbox escape PRIVATE_SECRET',riskLevel:'high',userAuthorization:'high'}});
  assert.deepEqual(value.reasons,['containment-escape','remote-execution','credential-access']);
  assert.equal(value.status,'denied');
  assert.doesNotMatch(JSON.stringify(value),/PRIVATE_/);
});
