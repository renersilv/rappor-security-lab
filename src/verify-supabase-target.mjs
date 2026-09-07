#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  STATE_ORDER,
  STATES,
  TABLE,
} from "../targets/connected/supabase-authorization/lib/states.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const TARGET_PATH = "targets/connected/supabase-authorization";
const SCHEMA_PATH = "migrations/001_schema.sql";
const RESET_PATH = "migrations/900_reset.sql";
const FORBIDDEN_SECRET = /(?:sb_secret_|service_role_key|postgres(?:ql)?:\/\/)/i;

function normalizeSql(sql) {
  return sql
    .replaceAll(/--[^\n]*/g, " ")
    .replaceAll(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function expectedGrantStatements(accessControl) {
  const grouped = new Map();
  for (const role of ["anon", "authenticated"]) {
    const privileges = accessControl.grants[role].join(", ");
    if (!privileges) continue;
    const roles = grouped.get(privileges) ?? [];
    roles.push(role);
    grouped.set(privileges, roles);
  }
  return [...grouped.entries()]
    .map(([privileges, roles]) => `grant ${privileges} on table ${TABLE} to ${roles.join(", ")};`)
    .sort();
}

function expectedPolicyStatements(accessControl) {
  return accessControl.policies.map((policy) => {
    const clauses = [
      `create policy ${policy.name}`,
      `on ${TABLE}`,
      `for ${policy.command}`,
      `to ${policy.roles.join(", ")}`,
    ];
    if (policy.using !== null) clauses.push(`using (${policy.using})`);
    if (policy.withCheck !== null) clauses.push(`with check (${policy.withCheck})`);
    return `${clauses.join(" ")};`;
  }).sort();
}

function assertStateSql(stateName, sql, accessControl) {
  assert.doesNotMatch(sql, FORBIDDEN_SECRET, `${stateName} migration must not contain an elevated credential`);
  const normalized = normalizeSql(sql);
  assert.match(normalized, /revoke all on table public\.rappor_lab_documents from public, anon, authenticated;/);
  assert.match(
    normalized,
    new RegExp(`alter table public\\.rappor_lab_documents ${accessControl.rlsEnabled ? "enable" : "disable"} row level security;`),
  );

  const grants = [...normalized.matchAll(/grant [^;]+;/g)].map(([statement]) => statement).sort();
  assert.deepEqual(grants, expectedGrantStatements(accessControl), `${stateName} grants must match its declared contract`);

  const policies = [...normalized.matchAll(/create policy [^;]+;/g)].map(([statement]) => statement).sort();
  assert.deepEqual(policies, expectedPolicyStatements(accessControl), `${stateName} policies must match its declared contract`);
}

export async function verifySupabaseTarget(repositoryRoot = REPOSITORY_ROOT) {
  const targetDirectory = resolve(repositoryRoot, TARGET_PATH);
  const schema = await readFile(resolve(targetDirectory, SCHEMA_PATH), "utf8");
  const reset = await readFile(resolve(targetDirectory, RESET_PATH), "utf8");
  assert.doesNotMatch(schema, FORBIDDEN_SECRET);
  assert.doesNotMatch(reset, FORBIDDEN_SECRET);
  assert.match(schema, /RAPPOR_LAB_DUMMY_SEED/);
  assert.match(schema, /revoke all on table public\.rappor_lab_documents from public, anon, authenticated;/i);
  assert.match(reset, /drop table if exists public\.rappor_lab_documents cascade;/i);

  const results = {};
  for (const stateName of STATE_ORDER) {
    const state = STATES[stateName];
    const migration = await readFile(resolve(targetDirectory, state.migration), "utf8");
    assertStateSql(stateName, migration, state.accessControl);

    const digest = createHash("sha256");
    for (const [path, content] of [
      [SCHEMA_PATH, schema],
      [state.migration, migration],
    ]) {
      digest.update(`${path}\0`);
      digest.update(content);
      digest.update("\0");
    }
    digest.update(`selected-state\0${stateName}\0`);
    results[stateName] = {
      revision: `sha256:${digest.digest("hex")}`,
      accessControl: JSON.parse(JSON.stringify(state.accessControl)),
      expectedAccess: JSON.parse(JSON.stringify(state.expectedAccess)),
    };
  }

  assert.equal(new Set(Object.values(results).map((result) => result.revision)).size, STATE_ORDER.length);
  return results;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifySupabaseTarget()
    .then((results) => process.stdout.write(`${JSON.stringify(results, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`Supabase target verification failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
