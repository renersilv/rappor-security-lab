#!/usr/bin/env node

import { execFile as execFileCallback } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import { compare } from "./compare.mjs";
import { buildSupabaseManifest } from "./generate-supabase-manifest.mjs";
import {
  OPERATIONS,
  STATE_ORDER,
  STATES,
} from "../targets/connected/supabase-authorization/lib/states.mjs";
import { createPublicSupabaseConfig } from "../targets/connected/supabase-authorization/browser/public-config.mjs";

const execFile = promisify(execFileCallback);
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const TARGET_DIRECTORY = resolve(REPOSITORY_ROOT, "targets", "connected", "supabase-authorization");
const READ_STATUSES = new Set([200, 206]);
const DENIED_STATUSES = new Set([401, 403]);

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

export function loadPublicEnvironment(environment = process.env) {
  return createPublicSupabaseConfig({
    url: required(environment, "SUPABASE_LAB_URL"),
    publishableKey: required(environment, "SUPABASE_LAB_PUBLISHABLE_KEY"),
  });
}

function loadAuthenticatedEnvironment(environment = process.env) {
  return {
    ...loadPublicEnvironment(environment),
    email: required(environment, "SUPABASE_LAB_AUTH_EMAIL"),
    password: required(environment, "SUPABASE_LAB_AUTH_PASSWORD"),
  };
}

async function safeFetch(request, url, options) {
  try {
    return await request(url, {
      ...options,
      signal: options.signal ?? AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error("the bounded Supabase request did not complete");
  }
}

async function authenticate(config, request) {
  const response = await safeFetch(
    request,
    `${config.url}/auth/v1/token?grant_type=password`,
    {
      method: "POST",
      headers: {
        apikey: config.publishableKey,
        "content-type": "application/json",
      },
      body: JSON.stringify({ email: config.email, password: config.password }),
    },
  );
  if (!response.ok) throw new Error("the disposable authenticated user could not sign in");
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("the authentication response was not valid JSON");
  }
  if (typeof payload.access_token !== "string" || payload.access_token.length === 0) {
    throw new Error("the authentication response did not contain a user access token");
  }
  return payload.access_token;
}

function headers(config, accessToken) {
  const result = { apikey: config.publishableKey };
  if (accessToken) result.authorization = `Bearer ${accessToken}`;
  return result;
}

function totalFromContentRange(value) {
  const match = value?.match(/\/(\d+)$/);
  return match ? Number.parseInt(match[1], 10) : null;
}

async function checkRead(config, accessToken, request) {
  const response = await safeFetch(
    request,
    `${config.url}/rest/v1/rappor_lab_documents?select=id&marker=eq.RAPPOR_LAB_DUMMY_SEED`,
    {
      method: "HEAD",
      headers: {
        ...headers(config, accessToken),
        prefer: "count=exact",
        range: "0-0",
        "range-unit": "items",
      },
    },
  );
  if (DENIED_STATUSES.has(response.status)) return false;
  if (!READ_STATUSES.has(response.status)) throw new Error("a read assertion returned an unexpected status class");
  const total = totalFromContentRange(response.headers.get("content-range"));
  if (total === null) throw new Error("a read assertion did not return an exact count");
  return total > 0;
}

async function checkWrite(config, accessToken, stateName, actor, request) {
  const markerState = stateName.replaceAll("-", "_").toUpperCase();
  const response = await safeFetch(
    request,
    `${config.url}/rest/v1/rappor_lab_documents`,
    {
      method: "POST",
      headers: {
        ...headers(config, accessToken),
        "content-type": "application/json",
        prefer: "return=minimal",
      },
      body: JSON.stringify({ marker: `RAPPOR_LAB_DUMMY_${markerState}_${actor.toUpperCase()}` }),
    },
  );
  if (response.status === 201) return true;
  if (DENIED_STATUSES.has(response.status)) return false;
  throw new Error("a write assertion returned an unexpected status class");
}

export async function checkSupabaseState(stateName, config, request = fetch) {
  if (!STATES[stateName]) throw new Error(`unknown Supabase target state: ${stateName}`);
  const accessToken = await authenticate(config, request);
  const access = {
    anon: {
      read: await checkRead(config, null, request),
      write: false,
    },
    authenticated: {
      read: await checkRead(config, accessToken, request),
      write: false,
    },
  };
  access.anon.write = await checkWrite(config, null, stateName, "anon", request);
  access.authenticated.write = await checkWrite(config, accessToken, stateName, "authenticated", request);

  const observations = Object.values(OPERATIONS).map((operation) => {
    const allowed = access[operation.actor][operation.operation];
    return {
      caseId: `supabase-${operation.id}-${stateName}`,
      present: operation.presentWhenAllowed ? allowed : !allowed,
    };
  });
  return { status: "completed", observations };
}

async function applySqlFiles(files, pgService, runner = execFile) {
  const arguments_ = ["--no-psqlrc", "--set=ON_ERROR_STOP=on", "--quiet"];
  for (const file of files) arguments_.push("--file", resolve(TARGET_DIRECTORY, file));
  try {
    await runner("psql", arguments_, {
      env: { ...process.env, PGSERVICE: pgService },
      maxBuffer: 1024 * 1024,
    });
  } catch {
    throw new Error("the administrative database migration command failed");
  }
}

export async function runSupabaseLifecycle({ config, pgService, request = fetch, applyState, cleanup } = {}) {
  if (!pgService) throw new Error("SUPABASE_LAB_PGSERVICE is required for lifecycle execution");
  const apply = applyState ?? (async (stateName) => {
    await applySqlFiles(["migrations/001_schema.sql", STATES[stateName].migration], pgService);
  });
  const clean = cleanup ?? (async () => {
    await resetSupabaseLab(pgService);
  });
  const observations = [];
  try {
    for (const stateName of STATE_ORDER) {
      await apply(stateName);
      const stateRun = await checkSupabaseState(stateName, config, request);
      observations.push(...stateRun.observations);
    }
    return { status: "completed", observations };
  } finally {
    await clean();
  }
}

export async function resetSupabaseLab(pgService, runner = execFile) {
  if (!pgService) throw new Error("SUPABASE_LAB_PGSERVICE is required for reset");
  await applySqlFiles(["migrations/900_reset.sql"], pgService, runner);
  let output;
  try {
    ({ stdout: output } = await runner(
      "psql",
      [
        "--no-psqlrc",
        "--set=ON_ERROR_STOP=on",
        "--tuples-only",
        "--no-align",
        "--command=select to_regclass('public.rappor_lab_documents') is null;",
      ],
      { env: { ...process.env, PGSERVICE: pgService }, maxBuffer: 1024 * 1024 },
    ));
  } catch {
    throw new Error("the administrative reset verification command failed");
  }
  if (output.trim() !== "t") throw new Error("the laboratory relation remains after reset");
  return { status: "completed", reset: true, relation: "public.rappor_lab_documents" };
}

function parseArguments(arguments_) {
  const options = { output: null, state: null, lifecycle: false, reset: false };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--lifecycle") options.lifecycle = true;
    else if (argument === "--reset") options.reset = true;
    else if (argument === "--state" && arguments_[index + 1]) options.state = arguments_[++index];
    else if (argument === "--output" && arguments_[index + 1]) options.output = arguments_[++index];
    else throw new Error("usage: run-supabase-authorization.mjs (--state STATE | --lifecycle | --reset) [--output PATH]");
  }
  if ([Boolean(options.state), options.lifecycle, options.reset].filter(Boolean).length !== 1) {
    throw new Error("exactly one of --state, --lifecycle or --reset is required");
  }
  return options;
}

async function emit(value, output) {
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (output) await writeFile(resolve(process.cwd(), output), serialized, "utf8");
  else process.stdout.write(serialized);
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
    if (options.reset) {
      await emit(await resetSupabaseLab(required(process.env, "SUPABASE_LAB_PGSERVICE")), options.output);
      return;
    }
    const config = loadAuthenticatedEnvironment();
    const run = options.lifecycle
      ? await runSupabaseLifecycle({
          config,
          pgService: required(process.env, "SUPABASE_LAB_PGSERVICE"),
        })
      : await checkSupabaseState(options.state, config);
    if (options.lifecycle) {
      const manifest = await buildSupabaseManifest();
      compare(manifest, run);
    }
    await emit(run, options.output);
  } catch (error) {
    if (options?.output) await emit({ status: "failed", observations: [] }, options.output);
    process.stderr.write(`Supabase authorization run failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
