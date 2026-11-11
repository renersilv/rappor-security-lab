import { mkdir, open } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { readProtectedJson } from "./protected-inputs.mjs";
import { observeDeliveryResponse } from "./windows-delivery-contract.mjs";

const requireValue = (condition, code) => { if (!condition) throw new Error(code); };
const within = (root, path) => {
  const child = relative(root, path);
  return isAbsolute(path) && child && child !== ".." && !child.startsWith("../") && !isAbsolute(child);
};

// The independently reviewed request binds the public endpoint, candidate policy and new output directory.
// It contains no credentials or AI ledger: public metadata observation does not consume an AI reservation.
export async function observePublicDescriptor({ requestPath, requestSha256, protectedRoot },
  { fetchImpl = globalThis.fetch, observedAt = () => new Date().toISOString() } = {}) {
  const { value: request } = await readProtectedJson({ path: requestPath, sha256: requestSha256 },
    { root: protectedRoot, label: "descriptor-request" });
  requireValue(request?.schema === 1 && request.scope === "public_descriptor_only", "descriptor-request-scope-invalid");
  const endpoint = new URL(request.endpoint);
  requireValue(endpoint.protocol === "https:" && !endpoint.username && !endpoint.password &&
    !endpoint.search && !endpoint.hash && endpoint.pathname === "/downloads/rappor-windows-delivery.json",
  "descriptor-request-endpoint-invalid");
  requireValue(typeof request.outputDirectory === "string" && within(protectedRoot, request.outputDirectory),
    "descriptor-output-outside-root");
  // A direct child prevents following a mutable intermediate output-directory chain.
  requireValue(resolve(request.outputDirectory, "..") === protectedRoot, "descriptor-output-must-be-direct-child");
  await mkdir(request.outputDirectory, { mode: 0o700 });
  const receiptPath = resolve(request.outputDirectory, "public-descriptor.json");
  const response = await fetchImpl(endpoint.href, {
    method: "GET", redirect: "error", credentials: "omit", signal: AbortSignal.timeout(15000),
    headers: { accept: "application/json" },
  });
  const result = await observeDeliveryResponse(response, { policy: request.policy }, async receipt => {
    const retained = { ...receipt, requestSha256, endpoint: endpoint.href };
    const file = await open(receiptPath, "wx", 0o600);
    try { await file.writeFile(`${JSON.stringify(retained, null, 2)}\n`); await file.sync(); }
    finally { await file.close(); }
  }, observedAt());
  return { receiptPath, bodySha256: result.receipt.bodySha256, descriptorValidated: true };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    requireValue(process.argv.length === 5, "usage-request-path-sha256-protected-root");
    const [requestPath, requestSha256, protectedRoot] = process.argv.slice(2);
    const result = await observePublicDescriptor({ requestPath, requestSha256, protectedRoot });
    process.stdout.write(`${JSON.stringify({ descriptorValidated: result.descriptorValidated })}\n`);
  } catch {
    // Request/transport errors can contain sensitive host metadata; the persisted receipt holds bounded facts.
    process.stderr.write("public-descriptor-observation-failed\n");
    process.exitCode = 1;
  }
}
