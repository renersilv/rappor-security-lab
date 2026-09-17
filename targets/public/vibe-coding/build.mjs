#!/usr/bin/env node

import { mkdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  PUBLIC_SCRIPT_PATH,
  STATES,
  getState,
  renderDocument,
  renderPublicResource,
  responseHeaders,
  serializeCookie,
} from "./lib/states.mjs";

function serverModule(state) {
  const headers = {
    ...responseHeaders(state),
    "content-type": "text/html; charset=utf-8",
    "set-cookie": serializeCookie(state),
  };
  return `const document = ${JSON.stringify(renderDocument(state))};
const headers = ${JSON.stringify(headers)};

export default function handler(request, response) {
  if (!["GET", "HEAD"].includes(request.method)) {
    response.statusCode = 405;
    response.setHeader("allow", "GET, HEAD");
    response.setHeader("cache-control", "no-store");
    response.end();
    return;
  }
  response.statusCode = 200;
  for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
  response.end(request.method === "HEAD" ? undefined : document);
}
`;
}

function vercelConfiguration(state) {
  return {
    $schema: "https://openapi.vercel.sh/vercel.json",
    headers: [
      {
        source: PUBLIC_SCRIPT_PATH,
        headers: Object.entries(responseHeaders(state)).map(([key, value]) => ({ key, value })),
      },
    ],
    rewrites: [
      { source: "/", destination: "/api/target.mjs" },
      { source: "/not-accepted", destination: "/api/target.mjs" },
    ],
  };
}

export async function buildPublicTarget(stateName, outputDirectory) {
  const state = getState(stateName);
  const absoluteOutput = resolve(outputDirectory);
  await rm(absoluteOutput, { force: true, recursive: true });
  await Promise.all([
    mkdir(resolve(absoluteOutput, "api"), { recursive: true }),
    mkdir(resolve(absoluteOutput, "public", "_next", "static", "chunks"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(resolve(absoluteOutput, "api", "target.mjs"), serverModule(state), "utf8"),
    writeFile(resolve(absoluteOutput, "public", PUBLIC_SCRIPT_PATH.slice(1)), renderPublicResource(state), "utf8"),
    writeFile(resolve(absoluteOutput, "vercel.json"), `${JSON.stringify(vercelConfiguration(state), null, 2)}\n`, "utf8"),
  ]);
  return { outputDirectory: absoluteOutput, state: state.id };
}

function parseArguments(arguments_) {
  const stateIndex = arguments_.indexOf("--state");
  const outputIndex = arguments_.indexOf("--output");
  const state = stateIndex >= 0 ? arguments_[stateIndex + 1] : null;
  const output = outputIndex >= 0 ? arguments_[outputIndex + 1] : null;
  if (!state || !Object.hasOwn(STATES, state) || !output) {
    throw new Error("usage: build.mjs --state <vulnerable|partially-fixed|fixed|reintroduced> --output <directory>");
  }
  return { output, state };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const options = parseArguments(process.argv.slice(2));
  buildPublicTarget(options.state, options.output)
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error) => {
      process.stderr.write(`Public target build failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
