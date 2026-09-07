#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CASE_DEFINITIONS,
  EXPECTED_OBSERVATIONS,
  verifyPublicTarget,
} from "./verify-public-target.mjs";

export const CASE_METADATA = {
  nextjs: {
    capability: "technology-identification",
    ruleFamily: "nextjs-technology",
    severity: "info",
    groupingKey: "technology-nextjs",
    positiveEvidence: "The controlled response exposes matching Next.js HTTP and DOM signals.",
    negativeEvidence: "The controlled response does not expose the declared Next.js signals.",
    functionalAssertion: "GET / returns HTTP 200 and matching Next.js HTTP and DOM markers.",
  },
  vercel: {
    capability: "hosting-identification",
    ruleFamily: "vercel-host-profile",
    severity: "info",
    groupingKey: "hosting-vercel",
    positiveEvidence: "The controlled response declares the Vercel host profile in HTTP and DOM metadata.",
    negativeEvidence: "The controlled response does not declare the Vercel host profile.",
    functionalAssertion: "GET / returns HTTP 200 and matching Vercel profile markers without deployment access.",
  },
  lovable: {
    capability: "technology-identification",
    ruleFamily: "lovable-generator",
    severity: "info",
    groupingKey: "technology-lovable",
    positiveEvidence: "The controlled DOM contains the declared Lovable generator marker.",
    negativeEvidence: "The controlled DOM does not contain the Lovable generator marker.",
    functionalAssertion: "GET / returns HTTP 200 and a deterministic generator meta element.",
  },
  supabaseClient: {
    capability: "technology-identification",
    ruleFamily: "supabase-client",
    severity: "info",
    groupingKey: "technology-supabase",
    positiveEvidence: "The DOM and public resource declare a network-disabled Supabase client.",
    negativeEvidence: "The DOM and public resource do not declare a Supabase client.",
    functionalAssertion: "The Supabase fixture disables persistence and network access while its public resource returns HTTP 200.",
  },
  supabasePublicKeys: {
    capability: "public-secret-classification",
    ruleFamily: "supabase-public-keys",
    severity: "high",
    groupingKey: "public-secret",
    positiveEvidence: "A Supabase public key was incorrectly classified as an elevated secret.",
    negativeEvidence: "Explicitly synthetic Supabase publishable and anon values remain public non-secret configuration.",
    functionalAssertion: "The public resource exposes only non-functional publishable and anon values and performs no Supabase request.",
  },
  header: {
    capability: "public-header-analysis",
    ruleFamily: "missing-content-security-policy",
    severity: "low",
    groupingKey: "security-header",
    positiveEvidence: "The controlled root response omits Content-Security-Policy.",
    negativeEvidence: "The controlled root response includes the pinned Content-Security-Policy.",
    functionalAssertion: "GET / returns HTTP 200 independently of the security-header state.",
  },
  cookie: {
    capability: "public-cookie-analysis",
    ruleFamily: "insecure-cookie-attributes",
    severity: "medium",
    groupingKey: "cookie-attributes",
    positiveEvidence: "The synthetic response cookie omits Secure, HttpOnly and SameSite.",
    negativeEvidence: "The synthetic response cookie includes Secure, HttpOnly and SameSite=Strict.",
    functionalAssertion: "The cookie contains only a fixed synthetic value and stores no visitor data.",
  },
  form: {
    capability: "public-form-analysis",
    ruleFamily: "password-form-uses-get",
    severity: "medium",
    groupingKey: "form-transport",
    positiveEvidence: "The inert password-form fixture declares the GET method.",
    negativeEvidence: "The inert password-form fixture declares POST and has no enabled or named controls.",
    functionalAssertion: "All form controls are inert and every mutation method returns HTTP 405 without reading a body.",
  },
  mixedContent: {
    capability: "public-resource-analysis",
    ruleFamily: "mixed-content",
    severity: "medium",
    groupingKey: "mixed-content",
    positiveEvidence: "The controlled DOM references an HTTP resource below the reserved invalid domain.",
    negativeEvidence: "The controlled DOM uses an inline data resource instead of an HTTP resource.",
    functionalAssertion: "GET / remains functional and the mixed-content hostname cannot resolve externally.",
  },
  elevatedSecret: {
    capability: "synthetic-secret-detection",
    ruleFamily: "synthetic-elevated-secret",
    severity: "high",
    groupingKey: "synthetic-secret-marker",
    positiveEvidence: "The public resource contains a documented non-functional Rappor elevated marker.",
    negativeEvidence: "The public resource contains the no-secret control marker only.",
    functionalAssertion: "GET /lab-resource.js returns deterministic public JavaScript without a functioning credential.",
  },
};

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const PROFILE_PATH = "scanner-profiles/public-passive.json";

export async function buildPublicManifest(repositoryRoot = REPOSITORY_ROOT) {
  const results = await verifyPublicTarget(repositoryRoot);
  const profile = await readFile(resolve(repositoryRoot, PROFILE_PATH));
  const rulesetDigest = `sha256:${createHash("sha256").update(profile).digest("hex")}`;
  const targets = [];
  const cases = [];
  const observations = [];

  for (const [state, expected] of Object.entries(EXPECTED_OBSERVATIONS)) {
    const targetId = `public-vibe-coding-${state}`;
    const targetRevision = results[state].revision;
    targets.push({
      id: targetId,
      control: "controlled",
      layer: "public",
      revision: targetRevision,
    });

    for (const [key, expectedPresence] of Object.entries(expected)) {
      const definition = CASE_DEFINITIONS[key];
      const metadata = CASE_METADATA[key];
      const id = `public-${definition.id}-${state}`;
      cases.push({
        id,
        targetId,
        targetRevision,
        state,
        scanner: "public-scan",
        capability: metadata.capability,
        ruleFamily: metadata.ruleFamily,
        expectedPresence,
        expectedSeverity: expectedPresence ? metadata.severity : null,
        groupingKey: expectedPresence ? metadata.groupingKey : null,
        safeEvidence: expectedPresence ? metadata.positiveEvidence : metadata.negativeEvidence,
        fixedCaseId: `public-${definition.id}-fixed`,
        functionalAssertion: metadata.functionalAssertion,
        scannerProfile: "public-passive@2",
        rulesetDigest,
      });
      observations.push({ caseId: id, present: expectedPresence });
    }
  }

  return {
    benchmarkVersion: "1.0.0",
    targets,
    cases,
    exampleRun: { status: "completed", observations },
  };
}

async function main() {
  const output = process.argv[2]
    ? resolve(process.cwd(), process.argv[2])
    : resolve(REPOSITORY_ROOT, "manifests", "public-vibe-coding.json");
  const manifest = await buildPublicManifest();
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Public manifest generation failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
