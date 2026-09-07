#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  OPERATIONS,
  STATE_ORDER,
  STATES,
} from "../targets/connected/supabase-authorization/lib/states.mjs";
import { verifySupabaseTarget } from "./verify-supabase-target.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const PROFILE_PATH = "scanner-profiles/supabase-connected.json";

function expectedPresence(operation, allowed) {
  return operation.presentWhenAllowed ? allowed : !allowed;
}

export async function buildSupabaseManifest(repositoryRoot = REPOSITORY_ROOT) {
  const verified = await verifySupabaseTarget(repositoryRoot);
  const profile = await readFile(resolve(repositoryRoot, PROFILE_PATH));
  const rulesetDigest = `sha256:${createHash("sha256").update(profile).digest("hex")}`;
  const targets = [];
  const cases = [];

  for (const stateName of STATE_ORDER) {
    const state = STATES[stateName];
    const targetId = `supabase-authorization-${stateName}`;
    const targetRevision = verified[stateName].revision;
    targets.push({
      id: targetId,
      control: "controlled",
      layer: "connected",
      revision: targetRevision,
      accessControl: verified[stateName].accessControl,
    });

    for (const operation of Object.values(OPERATIONS)) {
      const allowed = state.expectedAccess[operation.actor][operation.operation];
      const presence = expectedPresence(operation, allowed);
      cases.push({
        id: `supabase-${operation.id}-${stateName}`,
        targetId,
        targetRevision,
        state: stateName,
        scanner: "connected-scan",
        capability: operation.capability,
        ruleFamily: operation.ruleFamily,
        expectedPresence: presence,
        expectedSeverity: presence ? operation.severity : null,
        groupingKey: presence ? operation.groupingKey : null,
        safeEvidence: presence ? operation.positiveEvidence : operation.negativeEvidence,
        fixedCaseId: `supabase-${operation.id}-fixed`,
        functionalAssertion: operation.functionalAssertion,
        scannerProfile: "supabase-connected@1",
        rulesetDigest,
      });
    }
  }

  return { benchmarkVersion: "1.0.0", targets, cases };
}

async function main() {
  const output = process.argv[2]
    ? resolve(process.cwd(), process.argv[2])
    : resolve(REPOSITORY_ROOT, "manifests", "supabase-authorization.json");
  const manifest = await buildSupabaseManifest();
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Supabase manifest generation failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
