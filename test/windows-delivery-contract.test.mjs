import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { DELIVERY_FIELDS, observeDeliveryResponse, validateDeliveryDescriptor } from "../src/windows-delivery-contract.mjs";

const now = "2026-01-01T00:00:00Z";
const policy = { revision: "a".repeat(40), protocolVersion: 7,
  trustedImageRepositories: ["ghcr.io/example/lab-agent"], runtimePlatform: "linux/amd64", hostArchitecture: "x64" };
const descriptor = () => ({ schemaVersion: 1, protocolVersion: 7, revision: policy.revision,
  imageRepository: policy.trustedImageRepositories[0], imageDigest: `sha256:${"b".repeat(64)}`,
  runtimePlatform: "linux/amd64", supportedHostArchitectures: ["x64", "arm64"], expiresAtUtc: "2026-01-01T00:05:00Z" });
const digest = bytes => createHash("sha256").update(bytes).digest("hex");

async function observe(body, options = {}) {
  const receipts = [];
  let error;
  let result;
  try {
    result = await observeDeliveryResponse(new Response(body, { status: options.status ?? 200,
      headers: { "content-type": options.contentType ?? "application/json" } }), { policy },
    async receipt => receipts.push(receipt), now);
  } catch (caught) { error = caught; }
  assert.equal(receipts.length, 1, "transport receipt must survive validation failure");
  return { receipt: receipts[0], error, result };
}

test("Windows delivery describes the agent image without inventing an MSIX identity or release version", async () => {
  const body = JSON.stringify(descriptor());
  const { result, receipt, error } = await observe(body);
  assert.equal(error, undefined);
  assert.deepEqual(Object.keys(result.delivery).sort(), DELIVERY_FIELDS);
  assert.equal(Object.hasOwn(result.delivery, "packageIdentity"), false);
  assert.equal(receipt.installedPackageIdentityEvaluated, false);
  assert.equal(receipt.bodySha256, digest(body));
  assert.equal(receipt.retainedBodyUtf8, body);
});

for (const [name, change, code] of [
  ["missing required field", value => { delete value.imageDigest; }, "delivery-field-set-mismatch"],
  ["different candidate", value => { value.revision = "c".repeat(40); }, "delivery-revision-mismatch"],
  ["expired descriptor", value => { value.expiresAtUtc = now; }, "delivery-expired"],
  ["wrong protocol", value => { value.protocolVersion++; }, "delivery-protocol-mismatch"],
  ["unsupported host", value => { value.supportedHostArchitectures = ["arm64"]; }, "delivery-host-architectures-invalid"],
  ["duplicate hosts", value => { value.supportedHostArchitectures = ["x64", "x64"]; }, "delivery-host-architectures-invalid"],
]) {
  test(`receipt precedes rejection of ${name}`, async () => {
    const value = descriptor(); change(value);
    const { receipt, error } = await observe(JSON.stringify(value));
    assert.equal(error.message, code);
    assert.equal(receipt.status, 200);
    assert.equal(receipt.bodyComplete, true);
    assert.equal(receipt.bodySha256, digest(JSON.stringify(value)));
  });
}

test("malformed, unauthorized, and non-JSON responses retain bounded factual transport receipts", async () => {
  for (const [body, options, code] of [
    ["malformed", {}, "delivery-invalid-json"],
    [JSON.stringify(descriptor()), { status: 401 }, "delivery-http-status"],
    [JSON.stringify(descriptor()), { contentType: "text/plain" }, "delivery-content-type"],
  ]) {
    const { receipt, error } = await observe(body, options);
    assert.equal(error.message, code);
    assert.equal(receipt.bodySha256, digest(body));
    assert.equal(receipt.status, options.status ?? 200);
  }
});

test("unknown fields and unsafe field values never enter the receipt or error", async () => {
  const secret = "sensitive-test-value";
  for (const value of [{ ...descriptor(), token: secret }, { ...descriptor(), imageRepository: secret }]) {
    const { receipt, error } = await observe(JSON.stringify(value));
    assert.ok(error);
    assert.equal(JSON.stringify(receipt).includes(secret), false);
    assert.equal(String(error).includes(secret), false);
    assert.equal(receipt.retainedBodyUtf8, null);
  }
});

test("oversize response is cancelled and only its bounded prefix is hashed", async () => {
  const body = "x".repeat(65537);
  const { receipt, error } = await observe(body);
  assert.equal(error.message, "delivery-body-incomplete");
  assert.equal(receipt.bodyBytes, 65536);
  assert.equal(receipt.hashScope, "bounded_prefix");
  assert.equal(receipt.bodySha256, digest(body.slice(0, 65536)));
  assert.equal(receipt.retainedBodyUtf8, null);
});

test("caller policy is explicit and cannot be derived from untrusted descriptor values", () => {
  assert.throws(() => validateDeliveryDescriptor(descriptor(), undefined, now), /reviewed-policy-required/u);
  assert.throws(() => validateDeliveryDescriptor(descriptor(), { ...policy, protocolVersion: true }, now), /policy-protocol/u);
  assert.throws(() => validateDeliveryDescriptor(descriptor(), { ...policy, trustedImageRepositories: [] }, now), /policy-repositories/u);
});

test("receipt persistence failure prevents successful descriptor acceptance", async () => {
  await assert.rejects(observeDeliveryResponse(new Response(JSON.stringify(descriptor()),
    { headers: { "content-type": "application/json" } }), { policy },
  async () => { throw new Error("storage-unavailable"); }, now), /storage-unavailable/u);
});
