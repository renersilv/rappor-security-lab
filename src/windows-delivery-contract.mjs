import nodeAssert from "node:assert/strict";

const assert = {
  ok(value, code) { if (!value) throw new Error(code); },
  equal(actual, expected, code) { if (actual !== expected) throw new Error(code); },
  match(value, pattern, code) { if (typeof value !== "string" || !pattern.test(value)) throw new Error(code); },
  deepEqual(actual, expected, code) {
    try { nodeAssert.deepEqual(actual, expected); } catch { throw new Error(code); }
  },
};
import { createHash } from "node:crypto";

export const DELIVERY_FIELDS = Object.freeze([
  "expiresAtUtc", "imageDigest", "imageRepository", "protocolVersion", "revision",
  "runtimePlatform", "schemaVersion", "supportedHostArchitectures",
]);
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/u;
const MAX_DELIVERY_BYTES = 65536;

function safeProjection(value, policy) {
  const result = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return result;
  for (const key of DELIVERY_FIELDS) {
    if (!Object.hasOwn(value, key)) continue;
    const item = value[key];
    let safe = false;
    if (["schemaVersion", "protocolVersion"].includes(key)) safe = Number.isSafeInteger(item);
    if (key === "revision") safe = typeof item === "string" && /^[a-f0-9]{40}$/u.test(item);
    if (key === "imageDigest") safe = typeof item === "string" && /^sha256:[a-f0-9]{64}$/u.test(item);
    if (key === "imageRepository") safe = policy.trustedImageRepositories.includes(item);
    if (key === "runtimePlatform") safe = ["linux/amd64", "linux/arm64"].includes(item);
    if (key === "expiresAtUtc") safe = typeof item === "string" && UTC.test(item) && Number.isFinite(Date.parse(item));
    if (key === "supportedHostArchitectures") safe = Array.isArray(item) && item.length <= 2 &&
      item.every(entry => ["x64", "arm64"].includes(entry));
    result[key] = safe ? item : "[invalid]";
  }
  return result;
}

export function validateDeliveryDescriptor(value, policy, observedAtUtc) {
  validatePolicy(policy);
  assert.ok(value && typeof value === "object" && !Array.isArray(value), "delivery-object-required");
  assert.deepEqual(Object.keys(value).sort(), DELIVERY_FIELDS, "delivery-field-set-mismatch");
  assert.equal(value.schemaVersion, 1, "delivery-schema-mismatch");
  assert.equal(value.protocolVersion, policy.protocolVersion, "delivery-protocol-mismatch");
  assert.match(value.revision, /^[a-f0-9]{40}$/u, "delivery-revision-invalid");
  assert.equal(value.revision, policy.revision, "delivery-revision-mismatch");
  assert.ok(policy.trustedImageRepositories.includes(value.imageRepository), "delivery-repository-mismatch");
  assert.match(value.imageDigest, /^sha256:[a-f0-9]{64}$/u, "delivery-image-digest-invalid");
  assert.equal(value.runtimePlatform, policy.runtimePlatform, "delivery-runtime-platform-mismatch");
  assert.ok(Array.isArray(value.supportedHostArchitectures) && value.supportedHostArchitectures.length <= 2 &&
    value.supportedHostArchitectures.includes(policy.hostArchitecture) &&
    value.supportedHostArchitectures.every(entry => ["x64", "arm64"].includes(entry)) &&
    new Set(value.supportedHostArchitectures).size === value.supportedHostArchitectures.length,
  "delivery-host-architectures-invalid");
  assert.match(value.expiresAtUtc, UTC, "delivery-expiry-invalid");
  assert.ok(Number.isFinite(Date.parse(observedAtUtc)) && Date.parse(value.expiresAtUtc) > Date.parse(observedAtUtc),
    "delivery-expired");
  return Object.freeze({ ...value });
}

// Persist transport evidence before any descriptor assertion; retain only bounded safe public data.
export async function observeDeliveryResponse(response, context, persistReceipt, observedAtUtc = new Date().toISOString()) {
  validatePolicy(context.policy);
  const chunks = [];
  let size = 0;
  let bodyComplete = true;
  let readFailure = null;
  const reader = response.body?.getReader();
  if (!reader) { bodyComplete = false; readFailure = "missing_body"; }
  try {
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > MAX_DELIVERY_BYTES) {
        chunks.push(Buffer.from(value).subarray(0, MAX_DELIVERY_BYTES - size));
        size = MAX_DELIVERY_BYTES;
        bodyComplete = false;
        readFailure = "body_limit";
        await reader.cancel();
        break;
      }
      chunks.push(Buffer.from(value));
      size += value.byteLength;
    }
  } catch {
    bodyComplete = false; readFailure = "body_read_failed";
  } finally {
    reader?.releaseLock();
  }
  const bytes = Buffer.concat(chunks);
  let value = null;
  let text = null;
  let parseFailure = null;
  if (bodyComplete) {
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); value = JSON.parse(text); }
    catch { parseFailure = "invalid_json"; }
  }
  const keys = value && typeof value === "object" && !Array.isArray(value) ? Object.keys(value) : [];
  const knownKeys = keys.filter(key => DELIVERY_FIELDS.includes(key)).sort();
  const projection = safeProjection(value, context.policy);
  const safeBody = bodyComplete && !parseFailure && keys.length === DELIVERY_FIELDS.length &&
    keys.every(key => DELIVERY_FIELDS.includes(key)) && !Object.values(projection).includes("[invalid]") &&
    text.trim() === JSON.stringify(value);
  const contentType = response.headers.get("content-type") ?? "";
  const receipt = {
    schema: 1,
    observationType: "public_contract", observedAtUtc,
    revision: context.policy.revision,
    status: response.status,
    contentType: /^[a-z0-9.+/-]+(?:;\s*charset=[a-z0-9-]+)?$/iu.test(contentType) && contentType.length <= 128
      ? contentType : "[invalid]",
    bodyBytes: bytes.length, bodyComplete, bodySha256: hash(bytes),
    hashScope: bodyComplete ? "complete_body" : "bounded_prefix",
    knownKeys, unknownKeyCount: keys.length - knownKeys.length,
    packageIdentityPresent: keys.includes("packageIdentity"),
    sanitizedBody: projection, retainedBodyUtf8: safeBody ? text : null,
    bodyRetention: safeBody ? "complete_safe_public_json" : "sanitized_projection_only",
    readFailure, parseFailure,
    inferenceStarted: false, installedPackageIdentityEvaluated: false,
  };
  await persistReceipt(receipt);
  assert.equal(bodyComplete, true, "delivery-body-incomplete");
  assert.equal(response.status, 200, "delivery-http-status");
  assert.match(contentType, /^application\/json(?:;\s*charset=utf-8)?$/iu, "delivery-content-type");
  assert.equal(parseFailure, null, "delivery-invalid-json");
  const delivery = validateDeliveryDescriptor(value, context.policy, observedAtUtc);
  return { delivery, receipt };
}

function validatePolicy(policy) {
  assert.ok(policy && typeof policy === "object", "delivery-reviewed-policy-required");
  assert.match(policy.revision, /^[a-f0-9]{40}$/u, "delivery-policy-revision-invalid");
  assert.ok(Number.isSafeInteger(policy.protocolVersion) && policy.protocolVersion > 0,
    "delivery-policy-protocol-invalid");
  assert.ok(Array.isArray(policy.trustedImageRepositories) && policy.trustedImageRepositories.length > 0 &&
    policy.trustedImageRepositories.length <= 16 && policy.trustedImageRepositories.every(value =>
      typeof value === "string" && /^[a-z0-9.-]+(?:\/[a-z0-9._-]+)+$/u.test(value)),
    "delivery-policy-repositories-invalid");
  assert.ok(["linux/amd64", "linux/arm64"].includes(policy.runtimePlatform), "delivery-policy-runtime-invalid");
  assert.ok(["x64", "arm64"].includes(policy.hostArchitecture), "delivery-policy-host-invalid");
}
