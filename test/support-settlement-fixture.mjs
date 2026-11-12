import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { settlementSources } from "../src/windows-resource-settlement.mjs";
export const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const encode = value => `${JSON.stringify(value)}\n`;
export async function settlementFixture(options = {}) {
  const root = await mkdtemp(resolve(tmpdir(), "settlement-test-"));
  const protectedRoot = resolve(root, "reviews"), stateRoot = resolve(root, "state");
  await mkdir(protectedRoot, { mode: 0o700 }); await mkdir(stateRoot, { mode: 0o700 });
  await mkdir(resolve(stateRoot, "tmp"), { mode: 0o700 });
  const put = async (name, value, directory = protectedRoot) => {
    const path = resolve(directory, name), bytes = encode(value);
    await writeFile(path, bytes, { mode: 0o600 }); return { path, sha256: digest(bytes) };
  };
  const candidate = { origin: "https://lab.example.invalid", sha: "a".repeat(40), version: "v0.1.0" };
  const context = { issue: 19, executorPass: 220, authorizationId: "issue19-native-windows-20261023", candidate };
  const runtime = { ...context, artifacts: { "runtime/interactive.ps1": "b".repeat(64), "runtime/observe.ps1": "c".repeat(64) } };
  const runtimeHash = digest(encode(runtime));
  const origin = { ...context, files: { "live-pass220-ide-mcp-discovery.json": runtimeHash } };
  const originHash = digest(encode(origin));
  const originCorrection = await put("origin-correction.json", { manifest: { path: "/historical/manifest.json",
    sha256: options.unreviewedOrigin ? "d".repeat(64) : originHash } });
  const previousReview = await put("origin-review.json", { reviewedThroughPass: 220, correction: originCorrection });
  const plan = { schema: 1, kind: "windows_task_settlement", ...context, executorPass: 223, originPass: 220,
    incident: "e".repeat(64), originManifest: { file: "origin-manifest.json", sha256: originHash },
    originRuntimeReceipt: { file: "origin-runtime.json", sha256: runtimeHash, manifestName: "live-pass220-ide-mcp-discovery.json" },
    taskName: "RapporLab-Pass220-IdeReadiness", guestRoot: "C:\\RapporLab\\runtime\\pass220-ide-readiness",
    ownershipFiles: ["owned-processes.json", "observer-ownership.json"], maxDurationMs: 55000, sourceHashes: await settlementSources() };
  options.mutatePlan?.(plan);
  const planRef = await put("settlement-plan.json", plan);
  const source = value => ({ content: encode(value), sha256: digest(encode(value)), omitted: false });
  const manifest = { path: "/reviewed/manifest.json", sha256: "f".repeat(64) };
  const packet = { planName: "settlement-plan.json", bundle: { executorPass: 222, candidate, manifest,
    sources: { "settlement-plan.json": source(plan), "origin-manifest.json": source(origin), "origin-runtime.json": source(runtime) } } };
  const correction = await put("correction.json", { scope: "settlement_only", manifest,
    technicalRoute: { phase: "settlement", incident: plan.incident, settlementPlan: planRef,
      cleanupOrigin: { executorPass: 220, manifestSha256: originHash } },
    settlementBundle: await put("bundle.json", packet) });
  const diagnosis = await put("diagnosis.json", { scope: "settlement_only", verdict: "pass", findings: [], ownerRequest: null });
  const checkpoint = await put("checkpoint.json", { schema: 1, issue: 24, targetIssue: 19,
    reviewedThroughPass: 222, correction, diagnosis, previousReview });
  const campaign = { reviewCheckpoint: checkpoint, phase: "active", executorPasses: 223, lastFinishedPass: 222 };
  options.mutateCampaign?.(campaign);
  await put("campaign.json", campaign, stateRoot);
  const outputDirectory = resolve(stateRoot, "tmp", "output");
  const request = { schema: 1, scope: "settlement_only", checkpoint, plan: planRef, outputDirectory };
  const requestRef = await put("request.json", request);
  let closed = false, calls = 0, stabilityChecks = 0;
  const dependencies = { protectedRoot, stateRoot,
    runHostIdentity: async timeout => {
      await options.onHostIdentity?.(timeout);
      const value = { schemaVersion: 1, result: "verified", domain: "joao-windows-x64",
        domainUuid: "13918e5c-5b79-4a99-9029-0aa515f5a732",
        sourceSha256: "586bb536d9cd18f576839188af71501e0042e04766b99281351e9ed5852041aa",
        executable: "/usr/bin/qemu-system-x86_64", generationStable: true, listenerOwnedByExactDomainProcess: true,
        listenerAddress: "127.0.0.1", listenerPort: 2222, guestPort: 22,
        guestCommandExecuted: false, vmMutated: false, permissionsChanged: false };
      options.mutateHostIdentity?.(value);
      return { stdout: JSON.stringify(value), stderr: "", exitCode: 0,
        settlement: { cause: "accepted", remoteQuiescenceObserved: true, closeObserved: true, stdinEndCallbackObserved: true } };
    },
    openCredential: async () => { await options.onOpen?.(); return { consumerPath: "/fixture/key", assertStable: async () => { await options.onStable?.(++stabilityChecks); },
      close: async () => { closed = true; await options.onClose?.(); } }; },
    createTransport: () => ({ sshArguments: [], sshTarget: "fixture",
      async execute(_file, _args, execution) {
        calls++;
        await options.onExecute?.(execution, calls);
        const probe = execution.input.match(/probe = '([a-f0-9]+)'/u);
        const value = probe ? { schema: 1, probe: probe[1], domainUuid: "13918e5c-5b79-4a99-9029-0aa515f5a732" } : { schema: 1, kind: "windows_task_settlement_guest",
          taskAbsent: true, rootAbsent: true, ownershipVerified: true, remainingOwnedProcesses: 0 };
        const result = { stdout: JSON.stringify(value), stderr: "", exitCode: 0,
          settlement: { cause: "accepted", remoteQuiescenceObserved: true, closeObserved: true, stdinEndCallbackObserved: true } };
        options.mutateResult?.(result, calls);
        return result;
      } }),
  };
  return { root, protectedRoot, stateRoot, put, plan, request, outputDirectory, dependencies,
    args: { requestPath: requestRef.path, requestSha256: requestRef.sha256, protectedRoot },
    get closed() { return closed; }, get calls() { return calls; },
    unresolved: async () => JSON.parse(await readFile(resolve(outputDirectory, "settlement-unresolved.json"))),
    receipt: async () => JSON.parse(await readFile(resolve(outputDirectory, "settlement-result.json"))),
    exists: async name => access(resolve(outputDirectory, name)).then(() => true, () => false),
  };
}
