import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import { publicObservationSources, observeReviewedPublicDescriptor, validatePublicObservation }
  from "../src/public-observation-manifest.mjs";
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const legacy = process.env.RAPPOR_PUBLIC_MANIFEST_BASELINE
  ? await import(pathToFileURL(process.env.RAPPOR_PUBLIC_MANIFEST_BASELINE).href) : null;
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "public-runtime-manifest-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const request = { schema: 1, scope: "public_descriptor_only", maxDurationMs: 15000,
    endpoint: "https://lab.example.invalid/downloads/rappor-windows-delivery.json",
    outputDirectory: join(root, "observation"), policy: { revision: "a".repeat(40), protocolVersion: 7,
      runtimePlatform: "linux/amd64", hostArchitecture: "x64", trustedImageRepositories: ["ghcr.io/example/lab-agent"] },
    reviewBinding: { issue: 19, executorPass: 7, reviewSha256: "b".repeat(64), incident: "c".repeat(64) },
    context: { issue: 19, executorPass: 8, objectiveId: "ide-mcp", authorizationId: "synthetic",
      candidate: { sha: "a".repeat(40), version: "v0.1.0", origin: "https://lab.example.invalid" } },
    sourceHashes: await publicObservationSources() };
  const requestPath = join(root, "request.json"), bytes = JSON.stringify(request);
  await writeFile(requestPath, bytes, { mode: 0o600 });
  const args = { requestPath, requestSha256: digest(bytes), protectedRoot: root };
  const body = { schemaVersion: 1, protocolVersion: 7, revision: request.policy.revision,
    imageRepository: "ghcr.io/example/lab-agent", imageDigest: `sha256:${"d".repeat(64)}`,
    runtimePlatform: "linux/amd64", supportedHostArchitectures: ["x64"], expiresAtUtc: "2026-01-01T00:05:00Z" };
  let calls = 0;
  const dependencies = { observedAt: () => "2026-01-01T00:00:00Z", fetchImpl: async (_url, options) => {
    calls++; assert.equal(options.method, "GET"); assert.equal(options.credentials, "omit");
    assert.equal(options.redirect, "error"); assert.deepEqual(options.headers, { accept: "application/json" });
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  } };
  const observed = await observeReviewedPublicDescriptor(args, dependencies);
  const manifestPath = join(request.outputDirectory, "runtime-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const reference = { path: manifestPath, sha256: observed.manifestSha256 };
  return { request, args, manifest, reference, dependencies, calls: () => calls,
    rewrite: async () => { const raw = JSON.stringify(manifest); await writeFile(manifestPath, raw); reference.sha256 = digest(raw); } };
}
// The pass206 adapter receives its valid receipt/context and the actual outer manifest.
// It demonstrates the missing check without executing the historical Windows collector.
function validate(f) {
  if (!legacy) return validatePublicObservation(f.args, f.reference);
  const sha = "d".repeat(64), candidate = { sha: "a".repeat(40), version: "v0.1.0", origin: "https://lab.example.invalid" };
  const context = { issue: 19, executorPass: 7, authorizationId: "synthetic", candidate, reviewSha256: sha };
  const receipt = { schema: 1, observationType: "public_contract", ...context, reviewCheckpoint: { sha256: sha },
    newLiveActivity: true, manifest: { newLiveActivity: true }, outcome: "runtime_delivery_v1_valid",
    executionFingerprint: sha, operationFingerprint: sha, runtimeIdentityFingerprint: sha, screenshotSha256: sha,
    inferenceStarted: false, scanStarted: false, reauthorizationStarted: false,
    reservationSequence23Consumed: false, windowsAccessed: false, artifacts: { "receipt.json": sha } };
  return Promise.resolve().then(() => legacy.validatePublicContractReceipt(receipt, context, {
    fileName: "live-pass7-public-descriptor.json", requiredArtifacts: ["receipt.json"],
    materializedArtifacts: receipt.artifacts, outerManifest: f.manifest }));
}
test("actual GET produces an independently validated outer manifest and cannot repeat", async t => {
  const f = await fixture(t); assert.equal(f.calls(), 1);
  assert.equal((await validatePublicObservation(f.args, f.reference)).observationVerified, true);
  if (legacy) await validate(f);
  assert.equal(f.manifest.newLiveActivity, true); assert.equal(f.manifest.windowsAccessed, false);
  await assert.rejects(observeReviewedPublicDescriptor(f.args, f.dependencies), /EEXIST/u);
  assert.equal(f.calls(), 1);
});
test("false outer activity cannot be replaced by receipt self-attestation", async t => {
  const f = await fixture(t); f.manifest.newLiveActivity = false; await f.rewrite(); await assert.rejects(validate(f));
});
test("missing actual outer activity is rejected", async t => {
  const f = await fixture(t); delete f.manifest.newLiveActivity; await f.rewrite(); await assert.rejects(validate(f));
});
test("actual receipt drift is rejected despite nested validity claims", async t => {
  const f = await fixture(t); await writeFile(join(f.request.outputDirectory, "public-descriptor.json"), '{"altered":true}');
  await assert.rejects(validate(f));
});
test("review, source and request mismatches fail independent verification", async t => {
  const f = await fixture(t), original = structuredClone(f.manifest);
  for (const mutate of [m => { m.reviewBinding.executorPass++; }, m => { m.requestSha256 = "0".repeat(64); },
    m => { m.sourceHashes["protected-inputs.mjs"] = "0".repeat(64); }]) {
    Object.assign(f.manifest, structuredClone(original)); mutate(f.manifest); await f.rewrite();
    await assert.rejects(validatePublicObservation(f.args, f.reference));
  }
});
test("manifest drift is rejected against an externally retained hash", async t => {
  const f = await fixture(t); await writeFile(f.reference.path, JSON.stringify({ ...f.manifest, newLiveActivity: false }));
  await assert.rejects(validatePublicObservation(f.args, f.reference), /hash-mismatch/u);
});

test("projection-only or incorrect raw-body hashes never prove independent body verification", async t => {
  const f = await fixture(t), path = join(f.request.outputDirectory, "public-descriptor.json");
  const original = JSON.parse(await readFile(path, "utf8"));
  for (const changes of [{ retainedBodyUtf8: null }, { bodySha256: "incorrect-body-hash" }, { bodyBytes: 1 }]) {
    const bytes = JSON.stringify({ ...original, ...changes });
    await writeFile(path, bytes);
    f.manifest.files["public-descriptor.json"] = digest(bytes); await f.rewrite();
    await assert.rejects(validatePublicObservation(f.args, f.reference), /body/u);
  }
});

test("existing objective verifier recognizes only the linked public observation, without accepting the journey", async t => {
  const f = await fixture(t);
  const program = `import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('objective_verifier',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2]);manifest=json.loads((root/'runtime-manifest.json').read_text())
actual={name:(root/name).read_bytes() for name in manifest['files']}
bundle={'executorPass':manifest['executorPass'],'candidate':manifest['candidate']}
verdict={'evidenceLevel':'runtime_observation','objectiveId':'ide-mcp','evidence':[name for name in actual if name.startswith('live-')]}
hashes,identities=module._runtime_artifacts(bundle,manifest,actual,verdict)
print(json.dumps({'hashes':sorted(hashes),'identities':sorted(identities)}))`;
  const checked = JSON.parse(execFileSync("python3", ["-B", "-c", program,
    fileURLToPath(new URL("../ops/joao/objectives.py", import.meta.url)), f.request.outputDirectory], { encoding: "utf8" }));
  assert.deepEqual(checked.hashes, [f.manifest.files["public-observation.json"]]);
  const operation = JSON.parse(await readFile(join(f.request.outputDirectory, "public-observation.json"), "utf8"));
  assert.deepEqual(checked.identities, [operation.operationFingerprint]);
  const repeated = await fixture(t);
  const another = JSON.parse(await readFile(join(repeated.request.outputDirectory, "public-observation.json"), "utf8"));
  assert.equal(another.operationFingerprint, operation.operationFingerprint, "new request metadata cannot fabricate novel runtime identity");
});
