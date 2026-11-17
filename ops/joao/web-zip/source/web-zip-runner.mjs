import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, open, realpath, lstat } from 'node:fs/promises';
import { dirname, resolve, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { captureProtectedSnapshot, captureSourceSnapshot, readProtectedJson } from './protected-inputs.mjs';
import { SettlementTransport, openStablePrivateCredential } from './windows-settlement-transport.mjs';
import { executePowerShellStdin } from './powershell-stdin-transport.mjs';
import { WEB_ZIP_PASS237, captureExactFixture } from './web-zip-orchestrator.mjs';
import { validateWebZipResult } from './web-zip-result.mjs';

export const SOURCE_NAMES = Object.freeze(['web-zip-runner.mjs', 'web-zip-orchestrator.mjs', 'web-zip-result.mjs', 'web-zip-windows-orchestrator.ps1', 'protected-inputs.mjs', 'windows-settlement-transport.mjs', 'powershell-stdin-transport.mjs', 'windows-host-identity.py']);
export const HOST_UUID = '13918e5c-5b79-4a99-9029-0aa515f5a732';
const SOURCE_ROOT = dirname(fileURLToPath(import.meta.url));
const REVIEW_ROOT = resolve(homedir(), '.config/rappor-security-lab/campaign-reviews');
const CAMPAIGN = resolve(homedir(), '.local/state/rappor-security-lab/joao/campaign.json');
const HOST_IDENTITY = resolve(SOURCE_ROOT, 'windows-host-identity.py');
const HASH = /^[a-f0-9]{64}$/u;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const closed = (value, keys, label) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), label);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), label);
};
async function writeExclusive(path, bytes) {
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  const folder = await open(dirname(path), 'r');
  try { await folder.sync(); } finally { await folder.close(); }
  return sha256(bytes);
}
async function privateDirectory(path, create = false) {
  assert.ok(isAbsolute(path));
  if (create) await mkdir(path, { mode: 0o700 });
  assert.equal(await realpath(path), path, 'output-directory-not-canonical');
  const meta = await lstat(path);
  assert.ok(meta.isDirectory() && !meta.isSymbolicLink());
  assert.equal(meta.uid, process.getuid());
  assert.equal(meta.mode & 0o777, 0o700);
}
export async function prepareWebZipPackage({ requestPath, requestSha256, outputDirectory }) {
  assert.match(requestSha256, HASH);
  const requestSnapshot = await captureProtectedSnapshot(requestPath, 'web-zip-request');
  assert.equal(requestSnapshot.sha256, requestSha256, 'request-hash-mismatch');
  const request = JSON.parse(requestSnapshot.bytes);
  closed(request, ['schema', 'kind', 'issue', 'authorizationId', 'candidate', 'executorPass', 'fixtureRoot', 'sourceHashes', 'desktop', 'product', 'previousReview'], 'request-fields');
  assert.equal(request.schema, 1); assert.equal(request.kind, 'web_zip_execution_request');
  assert.equal(request.issue, 19); assert.equal(request.authorizationId, WEB_ZIP_PASS237.authorizationId);
  assert.deepEqual(request.candidate, WEB_ZIP_PASS237.candidate);
  assert.ok(Number.isSafeInteger(request.executorPass) && request.executorPass > 237);
  closed(request.desktop, ['account', 'sid', 'sessionId'], 'desktop-fields');
  assert.equal(request.desktop.account, 'joao');
  assert.match(request.desktop.sid, /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/u);
  assert.ok(Number.isSafeInteger(request.desktop.sessionId) && request.desktop.sessionId > 0);
  closed(request.previousReview, ['path', 'sha256'], 'checkpoint-reference');
  assert.ok(isAbsolute(request.previousReview.path)); assert.match(request.previousReview.sha256, HASH);
  closed(request.product, ['productId', 'analysisName', 'environment'], 'product-fields');
  assert.match(request.product.productId, UUID);
  assert.match(request.product.analysisName, /^Rappor Lab Web ZIP [A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$/u, 'synthetic-analysis-name-required');
  assert.equal(request.product.environment, 'Development', 'synthetic-analysis-environment-required');
  closed(request.sourceHashes, SOURCE_NAMES, 'source-inventory');
  const sources = {};
  for (const name of SOURCE_NAMES) {
    const source = await captureSourceSnapshot(resolve(SOURCE_ROOT, name));
    assert.equal(source.sha256, request.sourceHashes[name], 'source-hash-mismatch');
    sources[name] = source;
  }
  const fixture = await captureExactFixture(request.fixtureRoot);
  assert.equal(fixture.archiveSha256, '8627e45b93043f90c664fb015901e68cb1cf82d1ba93453068e5a2f1ae508af6', 'deterministic-archive-mismatch');
  const identity = requestSha256.slice(0, 16);
  const guestRoot = `C:\\RapporLab\\runtime\\web-zip-${identity}`;
  const instruction = { schema: 1, kind: 'web_zip_bound_instruction', issue: 19,
    authorizationId: request.authorizationId, executorPass: request.executorPass,
    candidate: request.candidate, requestSha256, sourceHashes: request.sourceHashes,
    desktop: request.desktop, hostUuid: HOST_UUID, product: request.product,
    guestRoot, taskName: `RapporLab-WebZip-${identity}`, archiveFileName: WEB_ZIP_PASS237.fixture.archiveFileName,
    archiveSha256: fixture.archiveSha256, archiveSize: fixture.archive.length,
    totalMs: 600000, cleanupReserveMs: 90000, parentReserveMs: 15000 };
  const instructionBytes = encode(instruction);
  const package_ = { schema: 1, instructionBase64: instructionBytes.toString('base64'),
    instructionSha256: sha256(instructionBytes), archiveBase64: fixture.archive.toString('base64'),
    archiveSha256: fixture.archiveSha256,
    workerBase64: sources['web-zip-windows-orchestrator.ps1'].bytes.toString('base64'),
    workerSha256: sources['web-zip-windows-orchestrator.ps1'].sha256 };
  await privateDirectory(outputDirectory, true);
  await writeExclusive(resolve(outputDirectory, 'request.json'), requestSnapshot.bytes);
  await writeExclusive(resolve(outputDirectory, 'instruction.json'), instructionBytes);
  await writeExclusive(resolve(outputDirectory, instruction.archiveFileName), fixture.archive);
  await writeExclusive(resolve(outputDirectory, 'package.json'), encode(package_));
  return { request, instruction, package: package_, outputDirectory, requestSha256, requestPath }; 
}
export function parseOfficialLogin(bytes) {
  const values = {};
  for (const raw of new TextDecoder('utf-8', { fatal: true }).decode(bytes).split(/\r?\n/u)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^(?:export )?(RAPPOR_HML_EMAIL|RAPPOR_HML_PASSWORD)=(.*)$/u.exec(line);
    assert.ok(match && !Object.hasOwn(values, match[1]), 'login-format-invalid');
    let value = match[2];
    if (value.startsWith('"') || value.startsWith("'")) {
      assert.equal(value.at(-1), value[0], 'login-format-invalid');
      value = value.slice(1, -1);
    }
    values[match[1]] = value;
  }
  const login = { email: values.RAPPOR_HML_EMAIL, password: values.RAPPOR_HML_PASSWORD };
  validateOfficialLogin(login);
  return login;
}
export function validateOfficialLogin(login) {
  closed(login, ['email', 'password'], 'login-fields');
  assert.equal(typeof login.email, 'string', 'login-format-invalid');
  assert.equal(typeof login.password, 'string', 'login-format-invalid');
  assert.ok(login.email.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(login.email), 'login-format-invalid');
  assert.ok(login.password.length > 0 && login.password.length <= 1024 && !/[\u0000\r\n]/u.test(login.password), 'login-format-invalid');
  return login;
}
async function loadOfficialLogin() {
  const snapshot = await captureProtectedSnapshot(resolve(homedir(), '.config/rappor-security-lab/issue19-hml.env'), 'official-login', 8192);
  try { return parseOfficialLogin(snapshot.bytes); } finally { snapshot.bytes.fill(0); }
}
export function buildRemoteScript(prepared, remainingMs, nowUnixMs = Date.now(), login = null) {
  assert.ok(Number.isSafeInteger(remainingMs) && remainingMs > 100000 && remainingMs <= 600000, 'remaining-budget-insufficient');
  validateOfficialLogin(login);
  // Runtime-only stdin data: credentials never enter package.json or a receipt.
  const envelope = { ...prepared.package, absoluteDeadlineUnixMs: nowUnixMs + remainingMs, loginBase64: encode(login).toString('base64') };
  const source = Buffer.from(prepared.package.workerBase64, 'base64').toString('utf8');
  assert.equal(sha256(Buffer.from(source)), prepared.package.workerSha256);
  return `${source}\nInvoke-WebZipParent -EnvelopeBase64 '${encode(envelope).toString('base64')}'\n`;
}
export function validateRuntimeAuthority(prepared, { campaign, receipt, correction, manifest, diagnosis }) {
  assert.equal(campaign.phase, 'active', 'campaign-not-active');
  assert.equal(campaign.executorPasses, prepared.request.executorPass, 'campaign-pass-mismatch');
  assert.deepEqual(campaign.candidate, prepared.request.candidate);
  // The predecessor exists before the request; the current receipt binds the request.
  // Binding the request to the current receipt would create a circular SHA dependency.
  assert.deepEqual(receipt.previousReview, prepared.request.previousReview, 'request-predecessor-mismatch');
  assert.equal(receipt.schema, 1); assert.equal(receipt.issue, 24); assert.equal(receipt.targetIssue, 19);
  assert.equal(receipt.reviewedThroughPass + 1, prepared.request.executorPass);
  for (const name of ['authorizationSha256', 'stageSha256', 'sessionSha256', 'candidateSha256', 'contractSha256'])
    assert.equal(receipt[name], campaign[name], 'checkpoint-context-mismatch');
  assert.deepEqual(correction.webZipRequest, { path: prepared.requestPath, sha256: prepared.requestSha256 }, 'unreviewed-web-zip-request');
  const checkpointDirectory = dirname(campaign.reviewCheckpoint.path);
  assert.equal(prepared.outputDirectory, resolve(checkpointDirectory, `web-zip-output-pass${prepared.request.executorPass}`), 'runtime-output-not-canonical');
  const grant = correction.workContinuation;
  assert.equal(grant?.targetObjectiveId, 'web-entries'); assert.equal(grant?.phase, 'runtime');
  assert.equal(grant?.scope, 'bounded_no_model'); assert.equal(grant?.nextPass, prepared.request.executorPass);
  assert.equal(grant?.runtimeCheckpoints, 1);
  assert.deepEqual(grant.manifest, correction.manifest);
  assert.equal(diagnosis.verdict, 'pass'); assert.equal(diagnosis.scope, 'bounded_no_model');
  assert.equal(diagnosis.cleanupAssessment, 'verified');
  assert.deepEqual(diagnosis.workContinuation, { targetObjectiveId: 'web-entries' });
  for (const name of SOURCE_NAMES) assert.equal(manifest.files[`source/${name}`], prepared.request.sourceHashes[name], 'unreviewed-runtime-source');
  return { intentPath: resolve(checkpointDirectory, `web-zip-pass${prepared.request.executorPass}.intent.json`) };
}
export async function authorizeRuntime(prepared, { campaignPath = CAMPAIGN, reviewRoot = REVIEW_ROOT } = {}) {
  const campaign = JSON.parse((await captureProtectedSnapshot(campaignPath, 'campaign')).bytes);
  const receipt = (await readProtectedJson(campaign.reviewCheckpoint, { root: reviewRoot, label: 'checkpoint' })).value;
  await readProtectedJson(prepared.request.previousReview, { root: reviewRoot, label: 'request-predecessor' });
  const correction = (await readProtectedJson(receipt.correction, { root: reviewRoot, label: 'correction' })).value;
  const diagnosis = (await readProtectedJson(receipt.diagnosis, { root: reviewRoot, label: 'diagnosis' })).value;
  const manifestSnapshot = await captureProtectedSnapshot(correction.manifest.path, 'approved-manifest');
  assert.equal(manifestSnapshot.sha256, correction.manifest.sha256);
  const manifest = JSON.parse(manifestSnapshot.bytes);
  return validateRuntimeAuthority(prepared, { campaign, receipt, correction, manifest, diagnosis });
}
async function verifyHostIdentity(timeoutMs) {
  const source = await captureSourceSnapshot(HOST_IDENTITY, 'host-identity-source');
  assert.equal(source.sha256, '15432eec43f5405205ad92d6d22119031f118c15b1e13d5861a27f8664264730');
  const result = await new SettlementTransport('').execute('/usr/bin/python3', ['-B', HOST_IDENTITY],
    { input: '', timeout: Math.min(50000, timeoutMs), maxOutputBytes: 16384 });
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.result, 'verified');
  assert.equal(receipt.domain, 'joao-windows-x64');
  // The fixed helper validates the VM UUID and forwarding listener itself.
  assert.equal(receipt.sourceSha256, '586bb536d9cd18f576839188af71501e0042e04766b99281351e9ed5852041aa');
  assert.equal(receipt.domainUuid, HOST_UUID); assert.equal(receipt.generationStable, true);
  assert.equal(receipt.listenerOwnedByExactDomainProcess, true);
  assert.equal(receipt.listenerAddress, '127.0.0.1'); assert.equal(receipt.listenerPort, 2222);
  return receipt;
}
export async function runWebZipPackage(args, dependencies = {}) {
  const now = dependencies.now ?? (() => performance.now());
  const started = now();
  const remaining = () => Math.max(0, Math.floor(600000 - (now() - started)));
  const prepared = await prepareWebZipPackage(args);
  const authority = await (dependencies.authorizeRuntime ?? authorizeRuntime)(prepared);
  const intentPath = dependencies.authorizeRuntime ? (authority?.intentPath ?? resolve(args.outputDirectory, 'execution-intent.json')) : authority.intentPath;
  const intent = { schema: 1, requestSha256: prepared.requestSha256, sourceHashes: prepared.request.sourceHashes };
  await writeExclusive(intentPath, encode(intent));
  let credential, result, primary = null, cleanup = null, failure = null, credentialClosed = false, transportFailure = null;
  let stage = 'host_identity', remoteDispatchAttempted = false;
  try {
    await (dependencies.verifyHostIdentity ?? verifyHostIdentity)(remaining());
    let executeRemote = dependencies.executeRemote;
    if (!executeRemote) {
      stage = 'ssh_credential';
      credential = await openStablePrivateCredential(process.env.RAPPOR_WINDOWS_SSH_KEY);
      await credential.assertStable();
      const adapter = new SettlementTransport(credential.consumerPath);
      executeRemote = ({ source, timeoutMs }) => executePowerShellStdin(adapter, source,
        { timeout: timeoutMs, terminationGraceMs: 1500, maxOutputBytes: 4 * 1024 * 1024 });
    }
    stage = 'official_login';
    // Injected transport tests must supply synthetic login; never read host credentials.
    assert.ok(!dependencies.executeRemote || dependencies.loadOfficialLogin, 'test-login-loader-required');
    let login = await (dependencies.loadOfficialLogin ?? loadOfficialLogin)();
    stage = 'remote_script';
    const timeoutMs = remaining();
    const source = buildRemoteScript(prepared, timeoutMs, Date.now(), login);
    login = null;
    stage = 'remote_transport';
    // This records a local dispatch attempt, never proof of guest execution or quiescence.
    remoteDispatchAttempted = true;
    result = await executeRemote({ source, timeoutMs });
    stage = 'remote_receipt';
    if (result.stderr) {
      transportFailure = { cause: 'remote_stderr', stderrBytes: Buffer.byteLength(result.stderr), stderrSha256: sha256(Buffer.from(result.stderr)) };
      throw new Error('remote-stderr');
    }
    assert.equal(result.settlement?.remoteQuiescenceObserved, true, 'remote-quiescence-unconfirmed');
    assert.equal(result.settlement?.localProcessTerminated, true, 'local-quiescence-unconfirmed');
    const lines = result.stdout.trim().split(/\r?\n/u);
    assert.equal(lines.length, 1, 'unexpected-remote-output');
    const remote = JSON.parse(lines[0]);
    closed(remote, ['schema', 'instructionSha256', 'primary', 'cleanup', 'taskAbsent', 'workerQuiescent', 'artifacts'], 'remote-receipt-fields');
    assert.equal(remote.schema, 1); assert.equal(remote.instructionSha256, prepared.package.instructionSha256);
    assert.equal(remote.workerQuiescent, true); assert.equal(remote.taskAbsent, true);
    primary = remote.primary; cleanup = remote.cleanup;
    if (primary?.outcome === 'completed') {
      closed(remote.artifacts, ['confirmation.png', 'execution.png', 'history.png'], 'rendered-artifacts');
      const expected = { 'confirmation.png': primary.confirmationScreenshotSha256,
        'execution.png': primary.rendered.executionScreenshotSha256, 'history.png': primary.rendered.historyScreenshotSha256 };
      for (const [name, artifact] of Object.entries(remote.artifacts)) {
        const bytes = Buffer.from(artifact.base64, 'base64');
        assert.ok(bytes.length >= 100 && bytes.length <= 524288, 'screenshot-size');
        assert.equal(sha256(bytes), artifact.sha256); assert.equal(artifact.sha256, expected[name]);
        await writeExclusive(resolve(args.outputDirectory, name), bytes);
      }
    }
    assert.equal(cleanup?.verified, true, 'guest-cleanup-unconfirmed');
    assert.equal(cleanup?.loginMaterialAbsent, true, 'guest-login-material-unresolved');
    assert.equal(cleanup?.runtimeRootAbsent, true, 'guest-root-unresolved');
    if (primary?.outcome === 'completed') validateWebZipResult(primary, prepared.instruction);
    else throw new Error('web-zip-inconclusive');
    if (credential) {
      stage = 'credential_revalidation';
      await credential.assertStable();
    }
    stage = 'completed';
  } catch (error) {
    failure = 'web_zip_unresolved';
    const settlement = error?.settlement;
    if (settlement && ['timeout', 'output_limit', 'stdin_error', 'stdin_unsettled', 'ssh_transport_exit',
      'spawn_error', 'process_signal', 'nonzero_exit'].includes(settlement.cause)) {
      transportFailure = { cause: settlement.cause,
        localProcessTerminated: settlement.localProcessTerminated === true,
        remoteQuiescenceObserved: settlement.remoteQuiescenceObserved === true,
        closeObserved: settlement.closeObserved === true,
        elapsedMs: Number.isFinite(settlement.elapsedMs) ? settlement.elapsedMs : null };
      result = { settlement: transportFailure };
      // Preserve only closed, hash-bound partial receipt metadata; never raw output.
      try {
        const partial = JSON.parse(error.stdout);
        if (partial.schema === 1 && partial.instructionSha256 === prepared.package.instructionSha256) {
          primary = { outcome: 'inconclusive', failureCode: 'transport_failed',
            remoteOutcome: ['completed', 'inconclusive'].includes(partial.primary?.outcome) ? partial.primary.outcome : 'unknown' };
          cleanup = { verified: false, reportedVerified: partial.cleanup?.verified === true,
            workerQuiescent: partial.workerQuiescent === true, taskAbsent: partial.taskAbsent === true };
        }
      } catch { /* Missing partial output remains unresolved. */ }
    }
  }
  finally {
    if (credential) {
      try { await credential.close(); credentialClosed = true; }
      catch { failure = 'credential_close_failed'; stage = 'credential_close'; }
    }
    else credentialClosed = true;
    // A primary write failure cannot suppress the independent cleanup receipt.
    try { await writeExclusive(resolve(args.outputDirectory, 'primary.json'), encode(primary ?? { outcome: 'inconclusive', failureCode: failure })); }
    catch { failure = 'primary_persistence_failed'; stage = 'primary_persistence'; }
    const settled = { schema: 1, kind: 'web_zip_host_settlement', requestSha256: prepared.requestSha256,
      sourceHashes: prepared.request.sourceHashes, instructionSha256: prepared.package.instructionSha256,
      elapsedMs: Math.ceil(now() - started), stage, remoteDispatchAttempted, credentialClosed, transportFailure,
      remoteQuiescenceObserved: result?.settlement?.remoteQuiescenceObserved === true,
      cleanup: cleanup ?? { verified: false }, failureCode: failure };
    await writeExclusive(resolve(args.outputDirectory, 'cleanup.json'), encode(settled));
  }
  assert.ok(remaining() > 0, 'absolute-deadline-exhausted');
  if (failure) throw new Error(failure);
  return { outcome: 'completed', primaryPath: resolve(args.outputDirectory, 'primary.json'), cleanupPath: resolve(args.outputDirectory, 'cleanup.json') };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const [action, ...tokens] = process.argv.slice(2);
    assert.ok(['prepare', 'run'].includes(action));
    assert.deepEqual(tokens.filter((_, i) => i % 2 === 0), ['--request', '--sha256', '--output']);
    assert.equal(tokens.length, 6);
    const args = { requestPath: resolve(tokens[1]), requestSha256: tokens[3], outputDirectory: resolve(tokens[5]) };
    const result = action === 'prepare' ? await prepareWebZipPackage(args) : await runWebZipPackage(args);
    process.stdout.write(JSON.stringify({ outcome: action === 'prepare' ? 'prepared' : result.outcome, outputDirectory: args.outputDirectory }) + '\n');
  } catch { process.stderr.write('web_zip_error=invalid_or_unresolved\n'); process.exitCode = 65; }
}
