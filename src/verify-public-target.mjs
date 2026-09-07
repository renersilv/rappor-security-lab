#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  STATES,
  SUPABASE_ANON_KEY,
  SUPABASE_PUBLISHABLE_KEY,
  SUPABASE_URL,
  cookieOptions,
  renderPublicResource,
  responseHeaders,
} from "../targets/public/vibe-coding/lib/states.mjs";

export const EXPECTED_OBSERVATIONS = {
  vulnerable: {
    nextjs: true,
    vercel: true,
    lovable: true,
    supabaseClient: true,
    supabasePublicKeys: false,
    header: true,
    cookie: true,
    form: true,
    mixedContent: true,
    elevatedSecret: true,
  },
  "partially-fixed": {
    nextjs: true,
    vercel: true,
    lovable: true,
    supabaseClient: true,
    supabasePublicKeys: false,
    header: false,
    cookie: false,
    form: true,
    mixedContent: true,
    elevatedSecret: true,
  },
  fixed: {
    nextjs: true,
    vercel: true,
    lovable: true,
    supabaseClient: true,
    supabasePublicKeys: false,
    header: false,
    cookie: false,
    form: false,
    mixedContent: false,
    elevatedSecret: false,
  },
  reintroduced: {
    nextjs: true,
    vercel: true,
    lovable: true,
    supabaseClient: true,
    supabasePublicKeys: false,
    header: true,
    cookie: true,
    form: true,
    mixedContent: true,
    elevatedSecret: true,
  },
};

export const CASE_DEFINITIONS = {
  nextjs: { id: "nextjs", assertion: "http-and-dom" },
  vercel: { id: "vercel", assertion: "http-and-dom" },
  lovable: { id: "lovable", assertion: "dom" },
  supabaseClient: { id: "supabase-client", assertion: "http-and-dom" },
  supabasePublicKeys: { id: "supabase-public-keys", assertion: "http" },
  header: { id: "header", assertion: "http" },
  cookie: { id: "cookie", assertion: "http" },
  form: { id: "form", assertion: "dom" },
  mixedContent: { id: "mixed-content", assertion: "dom" },
  elevatedSecret: { id: "secret", assertion: "http" },
};

const TARGET_FILES = [
  "package.json",
  "package-lock.json",
  "next.config.mjs",
  "vercel.json",
  "proxy.js",
  "app/globals.css",
  "app/lab-client.jsx",
  "app/lab-resource.js/route.js",
  "app/layout.jsx",
  "app/page.jsx",
  "lib/states.mjs",
];
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const ELEVATED_MARKER = /RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_[A-Z0-9]{16}/;

function escapeAttribute(value) {
  return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
}

function renderDocument(state) {
  return `<!doctype html>
<html lang="en">
  <head><meta name="generator" content="Lovable"><title>Controlled public security target</title></head>
  <body>
    <main data-framework="Next.js" data-generator="Lovable" data-host-profile="Vercel" data-lab-state="${state.id}">
      <form action="/not-accepted" method="${state.formMethod}" data-lab-inert="true">
        <input id="lab-password" type="password" autocomplete="off" disabled>
        <button type="button" disabled>Submission disabled</button>
      </form>
      <img alt="" data-lab-mixed-content="true" src="${escapeAttribute(state.mixedContentUrl)}">
      <output data-supabase-client="configured">Supabase client configured without network or persistence</output>
      <script src="/lab-resource.js"></script>
    </main>
  </body>
</html>`;
}

function serializeCookie(state) {
  const options = cookieOptions(state);
  const attributes = ["rappor_lab_notice=synthetic"];
  if (options.path) attributes.push(`Path=${options.path}`);
  if (options.httpOnly) attributes.push("HttpOnly");
  if (options.secure) attributes.push("Secure");
  if (options.sameSite) attributes.push(`SameSite=${options.sameSite[0].toUpperCase()}${options.sameSite.slice(1)}`);
  return attributes.join("; ");
}

function createFixtureServer(state) {
  return createServer((request, response) => {
    if (!["GET", "HEAD"].includes(request.method)) {
      response.writeHead(405, { allow: "GET, HEAD", "cache-control": "no-store" });
      response.end();
      return;
    }
    if (request.url === "/lab-resource.js") {
      response.writeHead(200, {
        ...responseHeaders(state),
        "content-type": "application/javascript; charset=utf-8",
      });
      response.end(request.method === "HEAD" ? undefined : renderPublicResource(state));
      return;
    }
    if (request.url !== "/") {
      response.writeHead(404, { "cache-control": "no-store" });
      response.end();
      return;
    }
    response.writeHead(200, {
      ...responseHeaders(state),
      "content-type": "text/html; charset=utf-8",
      "set-cookie": serializeCookie(state),
    });
    response.end(request.method === "HEAD" ? undefined : renderDocument(state));
  });
}

function listen(server) {
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolvePromise();
    });
  });
}

function close(server) {
  return new Promise((resolvePromise, reject) => {
    server.close((error) => error ? reject(error) : resolvePromise());
  });
}

function tag(document, name, attribute) {
  const expression = new RegExp(`<${name}\\b[^>]*\\b${attribute}=(?:"[^"]*"|'[^']*')[^>]*>`, "i");
  return document.match(expression)?.[0] ?? "";
}

function attribute(element, name) {
  const match = element.match(new RegExp(`\\b${name}=(?:"([^"]*)"|'([^']*)')`, "i"));
  return match?.[1] ?? match?.[2] ?? null;
}

export async function inspectPublicState(stateName, repositoryRoot = REPOSITORY_ROOT) {
  const state = STATES[stateName];
  if (!state) throw new Error(`unknown public target state: ${stateName}`);

  const targetDirectory = resolve(repositoryRoot, "targets", "public", "vibe-coding");
  const digest = createHash("sha256");
  for (const file of TARGET_FILES) {
    const content = await readFile(resolve(targetDirectory, file));
    digest.update(`${file}\0`);
    digest.update(content);
    digest.update("\0");
  }
  digest.update(`selected-state\0${stateName}\0`);

  const server = createFixtureServer(state);
  await listen(server);
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    const rootResponse = await fetch(`${baseUrl}/`);
    const document = await rootResponse.text();
    const resourceResponse = await fetch(`${baseUrl}/lab-resource.js`);
    const resource = await resourceResponse.text();
    const rejectedMutation = await fetch(`${baseUrl}/not-accepted`, {
      method: "POST",
      redirect: "manual",
    });

    const main = tag(document, "main", "data-framework");
    const generator = tag(document, "meta", "name");
    const form = tag(document, "form", "data-lab-inert");
    const password = tag(document, "input", "type");
    const image = tag(document, "img", "data-lab-mixed-content");
    const supabaseOutput = tag(document, "output", "data-supabase-client");
    const publicScript = tag(document, "script", "src");
    const cookie = rootResponse.headers.get("set-cookie") ?? "";
    const publicKeyValues = [SUPABASE_PUBLISHABLE_KEY, SUPABASE_ANON_KEY];

    assert.equal(rootResponse.status, 200, `${stateName} root must return HTTP 200`);
    assert.equal(resourceResponse.status, 200, `${stateName} public resource must return HTTP 200`);
    assert.equal(rejectedMutation.status, 405, `${stateName} must reject mutation methods`);
    assert.match(rejectedMutation.headers.get("allow") ?? "", /^GET, HEAD$/);
    assert.match(form, /\bdata-lab-inert="true"/i);
    assert.match(password, /\bdisabled\b/i);
    assert.doesNotMatch(password, /\bname=/i);
    assert.ok(publicKeyValues.every((value) => resource.includes(value)), `${stateName} must expose both public-key controls`);

    const observations = {
      nextjs:
        rootResponse.headers.get("x-powered-by") === "Next.js" &&
        attribute(main, "data-framework") === "Next.js",
      vercel:
        rootResponse.headers.get("x-rappor-lab-host-profile") === "Vercel" &&
        attribute(main, "data-host-profile") === "Vercel",
      lovable:
        attribute(generator, "name") === "generator" &&
        attribute(generator, "content") === "Lovable",
      supabaseClient:
        attribute(supabaseOutput, "data-supabase-client") === "configured" &&
        attribute(publicScript, "src") === "/lab-resource.js" &&
        resource.includes(SUPABASE_URL),
      supabasePublicKeys: publicKeyValues.some((value) => ELEVATED_MARKER.test(value)),
      header: !rootResponse.headers.has("content-security-policy"),
      cookie:
        !/;\s*HttpOnly(?:;|$)/i.test(cookie) ||
        !/;\s*Secure(?:;|$)/i.test(cookie) ||
        !/;\s*SameSite=Strict(?:;|$)/i.test(cookie),
      form: attribute(form, "method") === "get",
      mixedContent: attribute(image, "src")?.startsWith("http://") ?? false,
      elevatedSecret: ELEVATED_MARKER.test(resource),
    };

    assert.deepEqual(observations, EXPECTED_OBSERVATIONS[stateName]);
    return {
      revision: `sha256:${digest.digest("hex")}`,
      observations,
      functional: {
        inertForm: true,
        mutationRejected: true,
        publicResourceAvailable: true,
        rootAvailable: true,
      },
    };
  } finally {
    await close(server);
  }
}

export async function verifyPublicTarget(repositoryRoot = REPOSITORY_ROOT) {
  const results = {};
  for (const stateName of Object.keys(EXPECTED_OBSERVATIONS)) {
    results[stateName] = await inspectPublicState(stateName, repositoryRoot);
  }
  return results;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyPublicTarget()
    .then((results) => process.stdout.write(`${JSON.stringify(results, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`Public target verification failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
