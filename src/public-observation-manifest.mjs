import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { observePublicDescriptor } from "./observe-public-descriptor.mjs";
import { captureSourceSnapshot, readProtectedJson, rebuildPrivateArtifactMap } from "./protected-inputs.mjs";
import { validateDeliveryDescriptor } from "./windows-delivery-contract.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const sourceNames = ["public-observation-manifest.mjs", "observe-public-descriptor.mjs",
  "protected-inputs.mjs", "windows-delivery-contract.mjs"];
const requireValue = (value, code) => { if (!value) throw new Error(code); };
const operationIdentity = receipt => hash(Buffer.from(JSON.stringify(Object.fromEntries(
  ["revision", "protocolVersion", "imageRepository", "imageDigest", "runtimePlatform", "supportedHostArchitectures"]
    .map(key => [key, receipt.sanitizedBody[key]])))));
async function writeJson(path, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`), file = await open(path, "wx", 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  return hash(bytes);
}

export async function publicObservationSources() {
  const result = {};
  for (const name of sourceNames) {
    result[name] = (await captureSourceSnapshot(fileURLToPath(new URL(name, import.meta.url)))).sha256;
  }
  return result;
}

async function boundRequest(args) {
  const { value: request } = await readProtectedJson({ path: args.requestPath, sha256: args.requestSha256 },
    { root: args.protectedRoot, label: "observation-request" });
  requireValue(request.schema === 1 && request.scope === "public_descriptor_only", "observation-scope-invalid");
  requireValue(request.maxDurationMs === 15000, "observation-duration-invalid");
  const binding = request.reviewBinding;
  requireValue(binding && Number.isSafeInteger(binding.issue) && binding.issue > 0 &&
    Number.isSafeInteger(binding.executorPass) && binding.executorPass > 0 &&
    /^[a-f0-9]{64}$/u.test(binding.reviewSha256) && /^[a-f0-9]{64}$/u.test(binding.incident),
  "observation-review-binding-invalid");
  const context = request.context;
  requireValue(context && context.issue === binding.issue && context.executorPass === binding.executorPass + 1 &&
    context.objectiveId === "ide-mcp" && typeof context.authorizationId === "string" &&
    /^[a-z0-9-]{1,100}$/u.test(context.authorizationId) && context.candidate?.sha === request.policy.revision &&
    context.candidate.origin === new URL(request.endpoint).origin && /^v\d+\.\d+\.\d+$/u.test(context.candidate.version),
  "observation-context-invalid");
  assert.deepEqual(request.sourceHashes, await publicObservationSources(), "observation-source-binding-mismatch");
  return request;
}

// Read the actual outer manifest and actual receipt independently; nested self-attestation is insufficient.
export async function validatePublicObservation(args, manifestReference) {
  const request = await boundRequest(args);
  requireValue(manifestReference.path === resolve(request.outputDirectory, "runtime-manifest.json"),
    "observation-manifest-path-invalid");
  const { value: manifest } = await readProtectedJson(manifestReference,
    { root: args.protectedRoot, label: "observation-manifest" });
  requireValue(manifest.schema === 1 && manifest.observationType === "public_contract" &&
    manifest.newLiveActivity === true && manifest.inferenceStarted === false &&
    manifest.windowsAccessed === false && manifest.scanStarted === false && manifest.maxDurationMs === request.maxDurationMs,
  "observation-manifest-activity-invalid");
  assert.deepEqual(manifest.reviewBinding, request.reviewBinding, "observation-review-mismatch");
  assert.deepEqual(manifest.sourceHashes, request.sourceHashes, "observation-source-mismatch");
  requireValue(manifest.requestSha256 === args.requestSha256 && manifest.revision === request.policy.revision,
    "observation-request-mismatch");
  for (const [key, value] of Object.entries(request.context)) assert.deepEqual(manifest[key], value, "observation-context-mismatch");
  const liveName = `live-pass${request.context.executorPass}-public-descriptor.json`;
  assert.deepEqual(Object.keys(manifest.files), ["public-descriptor.json", "public-observation.json", liveName],
    "observation-artifact-set-invalid");
  await rebuildPrivateArtifactMap(request.outputDirectory, manifest.files);
  const { value: receipt } = await readProtectedJson({ path: resolve(request.outputDirectory, "public-descriptor.json"),
    sha256: manifest.files["public-descriptor.json"] }, { root: args.protectedRoot, label: "observation-receipt" });
  requireValue(receipt.requestSha256 === args.requestSha256 && receipt.endpoint === request.endpoint &&
    receipt.status === 200 && receipt.bodyComplete === true && receipt.inferenceStarted === false &&
    receipt.installedPackageIdentityEvaluated === false && receipt.hashScope === "complete_body",
  "observation-receipt-binding-invalid");
  requireValue(typeof receipt.retainedBodyUtf8 === "string" &&
    receipt.bodyRetention === "complete_safe_public_json", "observation-complete-body-required");
  const body = Buffer.from(receipt.retainedBodyUtf8);
  requireValue(body.length === receipt.bodyBytes && hash(body) === receipt.bodySha256, "observation-body-hash-mismatch");
  assert.deepEqual(JSON.parse(receipt.retainedBodyUtf8), receipt.sanitizedBody, "observation-body-projection-mismatch");
  validateDeliveryDescriptor(receipt.sanitizedBody, request.policy, receipt.observedAtUtc);
  for (const name of ["public-observation.json", liveName]) {
    const { value: artifact } = await readProtectedJson({ path: resolve(request.outputDirectory, name), sha256: manifest.files[name] },
      { root: args.protectedRoot, label: "observation-artifact" });
    for (const [key, value] of Object.entries(request.context)) assert.deepEqual(artifact[key], value, "observation-artifact-context-mismatch");
    requireValue(artifact.observationType === "public_contract" && artifact.operationFingerprint === operationIdentity(receipt),
      "observation-runtime-identity-mismatch");
    assert.deepEqual(artifact.artifacts, name === liveName
      ? { "public-observation.json": manifest.files["public-observation.json"] }
      : { "public-descriptor.json": manifest.files["public-descriptor.json"] }, "observation-artifact-binding-mismatch");
  }
  return { observationVerified: true, manifestSha256: manifestReference.sha256 };
}

export async function observeReviewedPublicDescriptor(args, dependencies) {
  const request = await boundRequest(args);
  const result = await observePublicDescriptor(args, dependencies);
  const receipt = await captureSourceSnapshot(result.receiptPath, "observation-receipt");
  const operation = { ...request.context, observationType: "public_contract",
    operationFingerprint: operationIdentity(JSON.parse(receipt.bytes)), inferenceStarted: false, windowsAccessed: false,
    artifacts: { "public-descriptor.json": receipt.sha256 } };
  const operationHash = await writeJson(resolve(request.outputDirectory, "public-observation.json"), operation);
  const liveName = `live-pass${request.context.executorPass}-public-descriptor.json`;
  const liveHash = await writeJson(resolve(request.outputDirectory, liveName), {
    ...operation, artifacts: { "public-observation.json": operationHash } });
  const manifest = { schema: 1, ...request.context, observationType: "public_contract", newLiveActivity: true,
    inferenceStarted: false, windowsAccessed: false, scanStarted: false, maxDurationMs: request.maxDurationMs,
    revision: request.policy.revision, requestSha256: args.requestSha256,
    reviewBinding: request.reviewBinding, sourceHashes: request.sourceHashes,
    files: { "public-descriptor.json": receipt.sha256, "public-observation.json": operationHash, [liveName]: liveHash } };
  const path = resolve(request.outputDirectory, "runtime-manifest.json");
  return validatePublicObservation(args, { path, sha256: await writeJson(path, manifest) });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    requireValue(process.argv.length === 5, "usage-request-path-sha256-protected-root");
    const [requestPath, requestSha256, protectedRoot] = process.argv.slice(2);
    const result = await observeReviewedPublicDescriptor({ requestPath, requestSha256, protectedRoot });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch { process.stderr.write("reviewed-public-observation-failed\n"); process.exitCode = 1; }
}
