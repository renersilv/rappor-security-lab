import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { observePublicDescriptor } from "../src/observe-public-descriptor.mjs";

const digest = value => createHash("sha256").update(value).digest("hex");
const fixture = async () => {
  const root = await mkdtemp(join(tmpdir(), "public-descriptor-entry-"));
  const requestPath = join(root, "request.json");
  const request = { schema: 1, scope: "public_descriptor_only",
    endpoint: "https://lab.example.invalid/downloads/rappor-windows-delivery.json",
    outputDirectory: join(root, "observation"), policy: { revision: "a".repeat(40), protocolVersion: 7,
      trustedImageRepositories: ["ghcr.io/example/lab-agent"], runtimePlatform: "linux/amd64", hostArchitecture: "x64" } };
  const body = { schemaVersion: 1, protocolVersion: 7, revision: request.policy.revision,
    imageRepository: "ghcr.io/example/lab-agent", imageDigest: `sha256:${"b".repeat(64)}`,
    runtimePlatform: "linux/amd64", supportedHostArchitectures: ["x64"], expiresAtUtc: "2026-01-01T00:05:00Z" };
  const save = async () => {
    const bytes = JSON.stringify(request);
    await writeFile(requestPath, bytes, { mode: 0o600 });
    return { requestPath, requestSha256: digest(bytes), protectedRoot: root };
  };
  return { root, request, body, save };
};

test("versioned entrypoint makes one bounded passive request and saves a private receipt", async () => {
  const f = await fixture(); let calls = 0;
  try {
    const args = await f.save();
    const result = await observePublicDescriptor(args, { observedAt: () => "2026-01-01T00:00:00Z",
      fetchImpl: async (url, options) => {
        calls++;
        assert.equal(url, f.request.endpoint);
        assert.equal(options.method, "GET");
        assert.equal(options.credentials, "omit");
        assert.equal(options.redirect, "error");
        assert.ok(options.signal instanceof AbortSignal);
        assert.deepEqual(options.headers, { accept: "application/json" });
        return new Response(JSON.stringify(f.body), { headers: { "content-type": "application/json" } });
      } });
    assert.equal(calls, 1);
    assert.equal(result.descriptorValidated, true);
    const receipt = JSON.parse(await readFile(result.receiptPath, "utf8"));
    assert.equal(receipt.requestSha256, args.requestSha256);
    assert.equal(receipt.installedPackageIdentityEvaluated, false);
    assert.equal((await stat(result.receiptPath)).mode & 0o777, 0o600);
    assert.equal((await stat(f.request.outputDirectory)).mode & 0o777, 0o700);
    await assert.rejects(observePublicDescriptor(args, { fetchImpl: async () => { calls++; } }), /EEXIST/u);
    assert.equal(calls, 1, "existing output cannot cause another observation");
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("entrypoint persists HTTP rejection before failing and never retries", async () => {
  const f = await fixture(); let calls = 0;
  try {
    await assert.rejects(observePublicDescriptor(await f.save(), { fetchImpl: async () => {
      calls++; return new Response('{"error":"unauthorized"}', { status: 401, headers: { "content-type": "application/json" } });
    } }), /delivery-http-status/u);
    const receipt = JSON.parse(await readFile(join(f.request.outputDirectory, "public-descriptor.json"), "utf8"));
    assert.equal(receipt.status, 401);
    assert.equal(calls, 1);
    assert.equal(receipt.retainedBodyUtf8, null);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("unbound requests, credential-bearing URLs, and wrong scopes fail before network", async () => {
  const f = await fixture(); let calls = 0;
  const options = { fetchImpl: async () => { calls++; } };
  try {
    const args = await f.save();
    await assert.rejects(observePublicDescriptor({ ...args, requestSha256: "0".repeat(64) }, options), /hash-mismatch/u);
    f.request.endpoint = "https://user:password@lab.example.invalid/downloads/rappor-windows-delivery.json";
    await assert.rejects(observePublicDescriptor(await f.save(), options), /endpoint-invalid/u);
    f.request.scope = "start_analysis";
    await assert.rejects(observePublicDescriptor(await f.save(), options), /scope-invalid/u);
    assert.equal(calls, 0);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
