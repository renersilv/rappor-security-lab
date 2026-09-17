#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  STATE_ORDER,
  SUPABASE_RULES,
  SUPABASE_STATES,
  VERCEL_RULE,
  VERCEL_STATES,
} from "../targets/connected/provider-configuration/lib/states.mjs";
import { verifyProviderConfigurationTarget } from "./verify-provider-configuration-target.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const PROFILES = {
  supabase: "scanner-profiles/supabase-security-advisor.json",
  vercel: "scanner-profiles/vercel-project-configuration.json",
};

function digest(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

export async function buildProviderConfigurationManifest(repositoryRoot = REPOSITORY_ROOT) {
  const verified = await verifyProviderConfigurationTarget(repositoryRoot);
  const [supabaseProfileContent, vercelProfileContent] = await Promise.all([
    readFile(resolve(repositoryRoot, PROFILES.supabase)),
    readFile(resolve(repositoryRoot, PROFILES.vercel)),
  ]);
  const targets = [];
  const cases = [];

  for (const stateName of STATE_ORDER) {
    const supabaseTargetId = `supabase-provider-configuration-${stateName}`;
    const supabaseRevision = verified.supabase[stateName].revision;
    targets.push({
      id: supabaseTargetId,
      control: "controlled",
      layer: "connected",
      revision: supabaseRevision,
    });
    for (const [key, rule] of Object.entries(SUPABASE_RULES)) {
      const expectedPresence = SUPABASE_STATES[stateName].findings[key];
      cases.push({
        id: `supabase-${rule.id}-${stateName}`,
        targetId: supabaseTargetId,
        targetRevision: supabaseRevision,
        state: stateName,
        scanner: "connected-scan",
        capability: "provider-configuration",
        ruleFamily: rule.ruleFamily,
        expectedPresence,
        expectedSeverity: expectedPresence ? rule.severity : null,
        groupingKey: expectedPresence ? rule.groupingKey : null,
        safeEvidence: expectedPresence ? rule.positiveEvidence : rule.negativeEvidence,
        fixedCaseId: `supabase-${rule.id}-fixed`,
        functionalAssertion: "The state is proven from bounded PostgreSQL catalog predicates and retains no row, user or credential value.",
        scannerProfile: "supabase-security-advisor@2026.08.0",
        rulesetDigest: digest(supabaseProfileContent),
      });
    }

    const vercelTargetId = `vercel-project-configuration-${stateName}`;
    const vercelRevision = verified.vercel[stateName].revision;
    const expectedPresence = !VERCEL_STATES[stateName].gitForkProtection;
    targets.push({
      id: vercelTargetId,
      control: "controlled",
      layer: "connected",
      revision: vercelRevision,
    });
    cases.push({
      id: `vercel-${VERCEL_RULE.id}-${stateName}`,
      targetId: vercelTargetId,
      targetRevision: vercelRevision,
      state: stateName,
      scanner: "connected-scan",
      capability: "provider-configuration",
      ruleFamily: VERCEL_RULE.ruleFamily,
      expectedPresence,
      expectedSeverity: expectedPresence ? VERCEL_RULE.severity : null,
      groupingKey: expectedPresence ? VERCEL_RULE.groupingKey : null,
      safeEvidence: expectedPresence ? VERCEL_RULE.positiveEvidence : VERCEL_RULE.negativeEvidence,
      fixedCaseId: `vercel-${VERCEL_RULE.id}-fixed`,
      functionalAssertion: "The official project API reports the requested boolean after each mutation and every controlled project is restored to true in cleanup.",
      scannerProfile: "vercel-project-configuration@1",
      rulesetDigest: digest(vercelProfileContent),
    });
  }

  return { benchmarkVersion: "3.0.0", targets, cases };
}

async function main() {
  const output = process.argv[2]
    ? resolve(process.cwd(), process.argv[2])
    : resolve(REPOSITORY_ROOT, "manifests", "provider-configuration.json");
  const manifest = await buildProviderConfigurationManifest();
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Provider configuration manifest generation failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
