import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { buildRemoteScript, prepareWebZipPackage, runWebZipPackage, SOURCE_NAMES } from '../source/web-zip-runner.mjs';
import { WEB_ZIP_PASS237 } from '../source/web-zip-orchestrator.mjs';
import { SettlementTransport } from '../source/windows-settlement-transport.mjs';
import { executePowerShellStdin, POWERSHELL_STDIN_COMMAND } from '../source/powershell-stdin-transport.mjs';

const work = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const sensitiveError = 'synthetic-secret@example.invalid /private/synthetic-key SyntheticPassword!42';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'web-zip-host-stage-'));
  const sourceHashes = Object.fromEntries(await Promise.all(SOURCE_NAMES.map(async name =>
    [name, digest(await readFile(join(work, 'source', name)))])));
  const request = { schema: 1, kind: 'web_zip_execution_request', issue: 19,
    authorizationId: WEB_ZIP_PASS237.authorizationId, candidate: WEB_ZIP_PASS237.candidate,
    executorPass: 238, fixtureRoot: join(work, 'fixture'), sourceHashes,
    desktop: { account: 'joao', sid: 'S-1-5-21-100-200-300-1001', sessionId: 1 },
    product: { productId: '00000000-0000-4000-8000-000000000001',
      analysisName: 'Rappor Lab Web ZIP stage regression', environment: 'Development' },
    previousReview: { path: join(root, 'synthetic-review.json'), sha256: 'a'.repeat(64) } };
  const bytes = Buffer.from(JSON.stringify(request));
  const requestPath = join(root, 'request.json');
  await writeFile(requestPath, bytes, { mode: 0o600 });
  return { root, args: { requestPath, requestSha256: digest(bytes), outputDirectory: join(root, 'output') } };
}

test('real prepared worker reaches the stdin transport adapter without weakening its ASCII guard', async () => {
  const f = await fixture();
  let calls = 0;
  try {
    const prepared = await prepareWebZipPackage(f.args);
    const source = buildRemoteScript(prepared, 600000, 1800000000000,
      { email: 'synthetic-login@example.invalid', password: 'SyntheticPassword!42' });
    const adapter = { sshArguments: [], sshTarget: 'synthetic.invalid',
      async execute(file, args, options) {
        calls++;
        assert.equal(file, 'ssh');
        assert.deepEqual(args, ['synthetic.invalid', POWERSHELL_STDIN_COMMAND]);
        assert.equal(options.input, source);
        assert.equal(options.remoteCommandTransport, 'openssh');
        assert.equal(options.timeout, 600000);
        return 'synthetic-transport-observed';
      } };
    let result;
    try { result = await executePowerShellStdin(adapter, source, { timeout: 600000 }); }
    catch (error) {
      // Keep regression logs bounded; never dump the synthetic wire envelope.
      assert.fail(error.message.startsWith('powershell-source-must-be-ascii')
        ? 'powershell-source-must-be-ascii' : 'wire-framing-unresolved');
    }
    assert.equal(result, 'synthetic-transport-observed');
    assert.equal(calls, 1);
    await assert.rejects(executePowerShellStdin(adapter, source + '\n# \u00ed'), /powershell-source-must-be-ascii/);
    assert.equal(calls, 1);
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test('worker coverage expression preserves localized completed-tool matching', async () => {
  const worker = await readFile(join(work, 'source/web-zip-windows-orchestrator.ps1'), 'utf8');
  const expression = /function Get-WebZipCoverageExpression \{\s*\$script = @'\r?\n([\s\S]*?)\r?\n'@/u.exec(worker)?.[1];
  assert.ok(expression);
  function evaluate(title, count, completeness, status) {
    const metric = { innerText: title, getClientRects: () => [{}], parentElement: { children: [
      { tagName: 'P', innerText: count },
      { tagName: 'P', querySelectorAll: () => [completeness, status].map(innerText => ({ innerText })) },
    ] } };
    return runInNewContext(expression, { document: { querySelectorAll: () => [metric] } });
  }
  assert.equal(evaluate('Cobertura', '3 de 3 ferramentas', 'Completa', 'Gitleaks, Semgrep e Trivy conclu\u00edram.'), true);
  assert.equal(evaluate('Coverage', '3 of 3 tools', 'Complete', 'Gitleaks, Semgrep, and Trivy completed.'), true);
  assert.equal(evaluate('Cobertura', '3 de 3 ferramentas', 'Parcial', 'Gitleaks, Semgrep e Trivy conclu\u00edram.'), false);
  assert.equal(evaluate('Cobertura', '3 de 3 ferramentas', 'Completa', 'Gitleaks, Semgrep e Trivy concluiram.'), false);
});

for (const [scenario, expectedStage, expectedDispatch] of [
  ['identity-failed', 'host_identity', false],
  ['key-environment-missing', 'ssh_credential', false],
  ['login-failed', 'official_login', false],
  ['remote-call-failed', 'remote_transport', true],
  ['primary-write-failed', 'primary_persistence', false],
]) {
  test(`real runner preserves closed host stage: ${scenario}`, async t => {
    const f = await fixture();
    const originalKey = process.env.RAPPOR_WINDOWS_SSH_KEY;
    let identityCalls = 0, loginCalls = 0, remoteCalls = 0, transportCalls = 0;
    // No real process, credential or Windows access is permitted by this fixture.
    t.mock.method(SettlementTransport.prototype, 'execute', async () => {
      transportCalls++;
      throw new Error('real-transport-forbidden');
    });
    delete process.env.RAPPOR_WINDOWS_SSH_KEY;
    try {
      const dependencies = {
        authorizeRuntime: async () => ({}),
        verifyHostIdentity: async () => {
          identityCalls++;
          if (scenario === 'primary-write-failed') {
            await writeFile(join(f.args.outputDirectory, 'primary.json'), 'preserved synthetic evidence\n', { mode: 0o600 });
          }
          if (['identity-failed', 'primary-write-failed'].includes(scenario)) throw new Error(sensitiveError);
        },
        loadOfficialLogin: async () => {
          loginCalls++;
          if (scenario !== 'remote-call-failed') throw new Error(sensitiveError);
          return { email: 'synthetic-login@example.invalid', password: 'SyntheticPassword!42' };
        },
      };
      if (scenario !== 'key-environment-missing') dependencies.executeRemote = async () => {
        remoteCalls++;
        throw new Error(sensitiveError);
      };
      await assert.rejects(runWebZipPackage(f.args, dependencies), {
        message: scenario === 'primary-write-failed' ? 'primary_persistence_failed' : 'web_zip_unresolved',
      });
      const receipt = JSON.parse(await readFile(join(f.args.outputDirectory, 'cleanup.json')));
      assert.equal(receipt.stage, expectedStage);
      assert.equal(receipt.remoteDispatchAttempted, expectedDispatch);
      assert.equal(identityCalls, 1);
      assert.equal(loginCalls, ['login-failed', 'remote-call-failed'].includes(scenario) ? 1 : 0);
      assert.equal(remoteCalls, expectedDispatch ? 1 : 0);
      assert.equal(transportCalls, 0);
      assert.equal(receipt.credentialClosed, true);
      assert.equal(receipt.remoteQuiescenceObserved, false);
      assert.equal(receipt.transportFailure, null);
      assert.deepEqual(receipt.cleanup, { verified: false });
      assert.equal(receipt.failureCode, scenario === 'primary-write-failed' ? 'primary_persistence_failed' : 'web_zip_unresolved');
      const intentPath = join(f.args.outputDirectory, 'execution-intent.json');
      const originalIntent = await readFile(intentPath);
      await assert.rejects(runWebZipPackage(f.args, dependencies));
      assert.deepEqual(await readFile(intentPath), originalIntent);
      assert.equal(identityCalls, 1);
      for (const name of await readdir(f.args.outputDirectory)) {
        const bytes = await readFile(join(f.args.outputDirectory, name));
        for (const forbidden of [sensitiveError, 'SyntheticPassword!42', 'synthetic-login@example.invalid',
          '/private/synthetic-key', 'Error:', 'ERR_INVALID_ARG_TYPE']) {
          assert.equal(bytes.includes(Buffer.from(forbidden)), false, `diagnostic leaked into ${name}`);
        }
      }
    } finally {
      if (originalKey === undefined) delete process.env.RAPPOR_WINDOWS_SSH_KEY;
      else process.env.RAPPOR_WINDOWS_SSH_KEY = originalKey;
      await rm(f.root, { recursive: true, force: true });
    }
  });
}
