import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const statuses = new Set(['approved', 'denied', 'timedOut', 'aborted', 'inProgress']);
const actions = new Set(['command', 'execve', 'writeStdin', 'applyPatch', 'networkAccess', 'mcpToolCall', 'requestPermissions']);
export function reviewSummary(params) {
  const text = typeof params.review?.rationale === 'string' ? params.review.rationale : '';
  const reasons = [
    ['containment-escape', /containment escape|sandbox escape|escap(?:e|ing).{0,40}sandbox/i],
    ['sandbox-conflict', /sandbox.{0,50}conflict|conflict.{0,50}sandbox/i],
    ['remote-execution', /remote (?:code |command )?execution|\bssh\b/i],
    ['missing-authorization', /(?:lack|missing|insufficient|no explicit|not explicitly).{0,45}authoriz/i],
    ['credential-access', /credential|private key|secret|token/i],
    ['network-access', /network|loopback|localhost/i],
    ['untrusted-target', /untrusted|unknown (?:host|target|destination)/i],
    ['destructive-action', /destructive|irreversible/i],
    ['policy-restriction', /policy|prohibited|disallowed/i],
  ].filter(([, pattern]) => pattern.test(text)).map(([key]) => key);
  return { event: 'approval-review', source: 'reviewer',
    status: statuses.has(params.review?.status) ? params.review.status : 'unknown',
    action: actions.has(params.action?.type) ? params.action.type : 'unknown',
    rationalePresent: Boolean(text), reasons: reasons.length ? reasons : ['unclassified'],
    risk: ['low','medium','high','critical'].includes(params.review?.riskLevel) ? params.review.riskLevel : 'unknown',
    authorization: ['unknown','low','medium','high'].includes(params.review?.userAuthorization) ? params.review.userAuthorization : 'unknown' };
}

export function verifyPolicy(thread) {
  assert.equal(thread.approvalPolicy, 'on-request');
  assert.equal(thread.approvalsReviewer, 'auto_review');
  assert.equal(thread.sandbox.type, 'workspaceWrite');
  assert.equal(thread.sandbox.networkAccess, false);
}

export function stoppedResult(reason) {
  return { outcome: reason === 'approval-denied' ? 'refused' : 'failed',
    clientPath: 'host-codex-ssh-windows-app', operationContinued: false,
    analysisCompleted: false, summaryCode: reason, scanners: [] };
}

async function main() {
  const preflight = process.argv[2] === '--preflight';
  assert.ok((preflight && process.argv.length === 3) || (process.argv[2] === '--run' && process.argv.length === 6));
  const [promptPath, resultPath, reviewPath] = process.argv.slice(3);
  if (!preflight) {
    const deadline = Number(process.env.RAPPOR_LAB_ATTEMPT_DEADLINE);
    assert.ok(Number.isInteger(deadline) && deadline > Date.now() / 1000 && deadline <= Date.now() / 1000 + 600);
  }
  const pending = new Map();
  const reviews = [];
  let sequence = 0, threadId, result, halted = false, stage = 'startup', stopReason = 'incomplete-result', turnStatus;
  let settle;
  const finished = new Promise(resolve => { settle = resolve; });
  const output = value => process.stdout.write(JSON.stringify(value) + '\n');
  const env = { HOME: '/home/linux', CODEX_HOME: '/home/linux/.codex', PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8' };
  for (const key of ['RAPPOR_WINDOWS_SSH_KEY','RAPPOR_WINDOWS_HML_BASE_URL','RAPPOR_LAB_ATTEMPT_DEADLINE']) if (process.env[key]) env[key] = process.env[key];
  // The existing account configuration is used; security policy is verified before any turn.
  const config = [];
  if (process.env.RAPPOR_WINDOWS_HML_BASE_URL) {
    const url = new URL(process.env.RAPPOR_WINDOWS_HML_BASE_URL);
    assert.ok(url.protocol === 'https:' && url.pathname === '/' && !url.username && !url.password && !url.search && !url.hash);
    config.push('-c', 'mcp_servers.rapporLabIssue18.url=' + JSON.stringify(new URL('/mcp', url).href));
  }
  const child = spawn('/home/linux/.local/bin/codex', ['app-server', '--stdio', '-c', 'approval_policy="on-request"', '-c', 'approvals_reviewer="auto_review"', '-c', 'sandbox_mode="workspace-write"', ...config],
    { cwd: root, env, detached: true, stdio: ['pipe','pipe','pipe'] });
  let stderrBytes = 0;
  child.stderr.on('data', data => { stderrBytes += data.length; });
  child.on('error', () => { halted = true; settle(); });
  child.on('exit', () => {
    for (const { reject } of pending.values()) reject(new Error('server-exited'));
    pending.clear(); settle();
  });
  const send = message => child.stdin.write(JSON.stringify(message) + '\n');
  function request(method, params) {
    const id = ++sequence;
    return new Promise((resolve, reject) => { pending.set(id, { resolve, reject }); send({ id, method, params }); });
  }
  function halt(reason = 'observer-failed') {
    stopReason = reason;
    halted = true;
    settle();
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
  }
  function stopServer() {
    halt('attempt-timeout');
    try { process.kill(-child.pid, 'SIGKILL'); } catch {}
  }
  process.once('SIGTERM', stopServer);
  process.once('SIGINT', stopServer);
  let buffer = '';
  child.stdout.on('data', data => {
    buffer += data.toString('utf8');
    if (Buffer.byteLength(buffer) > 4 * 1024 * 1024) { halt(); return; }
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
      let event;
      try { event = JSON.parse(line); } catch { halt(); continue; }
      if (event.id !== undefined && pending.has(event.id) && !event.method) {
        const target = pending.get(event.id); pending.delete(event.id);
        if (event.error) { output({ event: 'protocol-error', code: Number.isInteger(event.error.code) ? event.error.code : 0 }); target.reject(new Error('protocol-error')); }
        else target.resolve(event.result);
        continue;
      }
      if (event.method && event.id !== undefined) {
        // Never accept a human approval, tool invocation or user answer on the owner's behalf.
        output({ event: 'human-action-required', approval: /Approval|approval|requestPermissions/.test(event.method) });
        halt('human-action-required'); continue;
      }
      if (event.method === 'item/autoApprovalReview/completed' || event.method === 'item/guardianApprovalReview/completed') {
        const value = reviewSummary(event.params ?? {}); reviews.push(value); output(value);
        if (value.status !== 'approved') halt(value.status === 'denied' ? 'approval-denied' : 'approval-unavailable');
      }
      if (event.method === 'item/completed') {
        const item = event.params?.item;
        if (item?.type === 'agentMessage') {
          try { result = JSON.parse(item.text); } catch { /* No raw agent text is retained. */ }
        }
        if (['commandExecution','mcpToolCall'].includes(item?.type)) output({event:'tool-completed',tool:item.type,status:['completed','failed','declined'].includes(item.status)?item.status:'unknown'});
      }
      if (event.method === 'turn/completed') { turnStatus = event.params?.turn?.status; settle(); }
    }
  });
  const timer = setTimeout(stopServer, preflight ? 25000 : 585000);
  try {
    await request('initialize', { clientInfo: { name: 'rappor_assisted_lab', version: '1.0.0' }, capabilities: { experimentalApi: true } });
    send({ method: 'initialized', params: {} });
    stage = 'thread-start';
    const thread = await request('thread/start', { cwd: root, ephemeral: true, approvalPolicy: 'on-request', approvalsReviewer: 'auto_review', sandbox: 'workspace-write', experimentalRawEvents: false });
    verifyPolicy(thread); threadId = thread.thread.id;
    output({ event: 'policy-verified', ephemeral: true, approvalPolicy: thread.approvalPolicy, reviewer: thread.approvalsReviewer, sandbox: thread.sandbox.type, model: /^[a-zA-Z0-9._-]{1,60}$/.test(thread.model) ? thread.model : 'unknown' });
    if (preflight) return;
    const prompt = await readFile(promptPath, 'utf8');
    const outputSchema = JSON.parse(await readFile(`${root}/schemas/windows-agent-ai-result.schema.json`, 'utf8'));
    stage = 'turn-start';
    await request('turn/start', { threadId, input: [{ type: 'text', text: prompt, text_elements: [] }], outputSchema });
    await finished;
    if (halted || !result || turnStatus !== 'completed') result = stoppedResult(halted ? stopReason : 'incomplete-result');
    await writeFile(resultPath, JSON.stringify(result), { mode: 0o600 });
    await writeFile(reviewPath, JSON.stringify(reviews), { mode: 0o600 });
    output({ event:'run-ended', stopped:halted, reviewerEvents:reviews.length });
  } catch {
    output({event:'client-failed',stage});
    if (!preflight) {
      await writeFile(resultPath, JSON.stringify(stoppedResult(halted ? stopReason : 'client-failed')), {mode:0o600});
      await writeFile(reviewPath, JSON.stringify(reviews), {mode:0o600});
    }
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
    if (!child.stdin.destroyed) child.stdin.end();
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
    await new Promise(resolve => setTimeout(resolve, 1000));
    try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    output({event:'client-closed',stderrPresent:stderrBytes>0});
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
