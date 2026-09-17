#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  STATE_ORDER,
  SUPABASE_RULES,
  SUPABASE_STATES,
  VERCEL_STATES,
} from "../targets/connected/provider-configuration/lib/states.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const TARGET_PATH = "targets/connected/provider-configuration";
const SUPABASE_SCHEMA = "supabase/migrations/001_schema.sql";
const SUPABASE_RESET = "supabase/migrations/900_reset.sql";
const STATE_SOURCE = "lib/states.mjs";
const FORBIDDEN_SECRET = /(?:sb_secret_|service_role|postgres(?:ql)?:\/\/|bearer\s+[a-z0-9._-]+)/i;

function digestFiles(files, selectedState) {
  const digest = createHash("sha256");
  for (const [path, content] of files) {
    digest.update(`${path}\0`);
    digest.update(content);
    digest.update("\0");
  }
  digest.update(`selected-state\0${selectedState}\0`);
  return `sha256:${digest.digest("hex")}`;
}

function normalizeSql(sql) {
  return sql.replaceAll(/--[^\n]*/g, " ").replaceAll(/\s+/g, " ").trim().toLowerCase();
}

function assertFindingSql(stateName, sql, key, expected) {
  const checks = {
    policyExistsRlsDisabled: /alter table public\.rappor_lab_policy_without_rls disable row level security;/,
    rlsEnabledNoPolicy: /drop policy rappor_lab_no_policy_deny on public\.rappor_lab_no_policy;/,
    securityDefinerView: /alter view public\.rappor_lab_security_view reset \(security_invoker\);/,
    rlsDisabledInPublic: /alter table public\.rappor_lab_rls_disabled disable row level security;/,
    sensitiveColumnsExposed: /alter table public\.rappor_lab_sensitive_profiles disable row level security;/,
    permissiveRlsPolicy: /create policy rappor_lab_permissive_policy_owner on public\.rappor_lab_permissive_policy for update to authenticated using \(true\) with check \(true\);/,
    publicBucketAllowsListing: /create policy rappor_lab_public_bucket_list on storage\.objects for select to authenticated using \(bucket_id = 'rappor-lab-public-listing'\);/,
  };
  if (expected) assert.match(sql, checks[key], `${stateName} must create ${key}`);
  else assert.doesNotMatch(sql, checks[key], `${stateName} must not create ${key}`);
}

export async function verifyProviderConfigurationTarget(repositoryRoot = REPOSITORY_ROOT) {
  const targetDirectory = resolve(repositoryRoot, TARGET_PATH);
  const [schema, reset, stateSource] = await Promise.all([
    readFile(resolve(targetDirectory, SUPABASE_SCHEMA), "utf8"),
    readFile(resolve(targetDirectory, SUPABASE_RESET), "utf8"),
    readFile(resolve(targetDirectory, STATE_SOURCE), "utf8"),
  ]);
  for (const content of [schema, reset, stateSource]) assert.doesNotMatch(content, FORBIDDEN_SECRET);

  const normalizedSchema = normalizeSql(schema);
  assert.match(normalizedSchema, /create view public\.rappor_lab_security_view with \(security_invoker = true\)/);
  assert.match(normalizedSchema, /insert into storage\.buckets \(id, name, public\) values \('rappor-lab-public-listing', 'rappor laboratory empty bucket', false\);/);
  assert.match(normalizedSchema, /create table public\.rappor_lab_sensitive_profiles \([^;]*password text/);
  assert.match(normalizeSql(reset), /delete from storage\.buckets where id = 'rappor-lab-public-listing';/);

  assert.deepEqual(Object.keys(SUPABASE_RULES), [
    "policyExistsRlsDisabled",
    "rlsEnabledNoPolicy",
    "securityDefinerView",
    "rlsDisabledInPublic",
    "sensitiveColumnsExposed",
    "permissiveRlsPolicy",
    "publicBucketAllowsListing",
  ]);

  const supabase = {};
  const vercel = {};
  for (const stateName of STATE_ORDER) {
    const state = SUPABASE_STATES[stateName];
    const migration = await readFile(resolve(targetDirectory, state.migration), "utf8");
    assert.doesNotMatch(migration, FORBIDDEN_SECRET);
    const normalizedMigration = normalizeSql(migration);
    for (const [key, expected] of Object.entries(state.findings)) {
      assertFindingSql(stateName, normalizedMigration, key, expected);
    }
    supabase[stateName] = {
      revision: digestFiles([
        [SUPABASE_SCHEMA, schema],
        [state.migration, migration],
      ], stateName),
      findings: structuredClone(state.findings),
    };

    const vercelState = VERCEL_STATES[stateName];
    assert.match(vercelState.project, /^rappor-lab-[a-z-]+$/);
    assert.equal(typeof vercelState.gitForkProtection, "boolean");
    vercel[stateName] = {
      revision: digestFiles([[STATE_SOURCE, stateSource]], `vercel-${stateName}`),
      gitForkProtection: vercelState.gitForkProtection,
    };
  }

  assert.equal(new Set(Object.values(supabase).map((item) => item.revision)).size, 4);
  assert.equal(new Set(Object.values(vercel).map((item) => item.revision)).size, 4);
  assert.equal(Object.values(VERCEL_STATES).every((item) => item.project.startsWith("rappor-lab-")), true);
  return { supabase, vercel };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyProviderConfigurationTarget()
    .then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`Provider configuration target verification failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
