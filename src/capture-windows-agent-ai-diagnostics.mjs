import { constants, closeSync, fchmodSync, openSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const maximumLineBytes = 65536;
const schemaFieldNames = new Set([
  "properties", "items", "required", "additionalProperties", "type", "enum", "const", "anyOf", "oneOf",
  "outcome", "clientPath", "operationContinued", "analysisCompleted", "summaryCode", "scanners",
  "key", "version", "state", "productId", "computerId", "operationId", "workspace", "controlPlane",
  "protocolVersion", "cursor", "limit", "error", "nextCursor", "securityScore", "limitedRiskScoreBound",
]);
const eventTypes = new Set([
  "thread.started", "turn.started", "turn.completed", "turn.failed",
  "item.started", "item.updated", "item.completed", "error",
]);
const failurePatterns = [
  ["missing-prompt", /no prompt provided via stdin/i],
  ["schema-rejected", /invalid.{0,40}schema|schema.{0,80}(?:invalid|unsupported|not supported)|failed to read output schema/i],
  ["authentication-failed", /unauthorized|authentication.{0,30}(?:failed|required)|\binvalid\s+(?:(?:access|refresh)\s+)?(?:token|api key)|\b401\b/i],
  ["quota-or-rate-limit", /rate limit|quota|\b429\b/i],
  ["model-unavailable", /model.{0,80}(?:not found|not supported|unavailable|does not exist)/i],
  ["network-failed", /connection (?:refused|reset)|failed to connect|dns|certificate|tls|stream disconnected|error sending request/i],
  ["timeout", /timed out|timeout/i],
  ["permission-refused", /containment escape|operation not permitted|permission denied|approval.{0,30}(?:denied|refused|rejected)|(?:auto(?:matic)?[- ]review).{0,30}(?:denied|refused|rejected)|sandbox.{0,30}(?:failed|denied|conflict)/i],
  ["automatic-review-denied", /auto(?:matic)?[- ]review.{0,30}(?:denied|refused|rejected)/i],
  ["sandbox-conflict", /sandbox.{0,30}conflict|conflict.{0,30}sandbox/i],
  ["mcp-failed", /mcp.{0,80}(?:failed|error)|failed.{0,80}mcp/i],
  ["cli-rejected", /unexpected argument|unrecognized (?:option|argument)/i],
];

// Only closed categories leave memory. Never retain event bodies, paths or IDs.
export async function captureDiagnostics(input, persist) {
  const startedAt = performance.now();
  const counts = Object.fromEntries([...eventTypes].map((key) => [key, 0]));
  const failures = new Set();
  const agentReportedFailures = new Set();
  const failedTools = new Set();
  const schemaTargets = new Set();
  const schemaContexts = new Set();
  const schemaReasons = new Set();
  let lastEvent = "none";
  let oversizedLine = false;
  let pending = Buffer.alloc(0);
  let dropping = false;
  const report = (streamClosed) => ({
    schemaVersion: "1.0.0",
    rawOutputRetained: false,
    streamClosed,
    elapsedMs: Math.round(performance.now() - startedAt),
    oversizedLine,
    lastEvent,
    eventCounts: { ...counts },
    failureClasses: [...failures].sort(),
    agentReportedFailureClasses: [...agentReportedFailures].sort(),
    failedToolTypes: [...failedTools].sort(),
    schemaTargets: [...schemaTargets].sort(),
    schemaContexts: [...schemaContexts].sort(),
    schemaReasons: [...schemaReasons].sort(),
  });
  const classify = (message, recordUnknown = true) => {
    if (typeof message !== "string") return;
    if (/invalid.{0,40}schema|schema.{0,80}(?:invalid|unsupported|not supported)/i.test(message)) {
      if (/response_format|text\.format|output.schema/i.test(message)) schemaTargets.add("final-response");
      else if (/function|tool/i.test(message)) schemaTargets.add("tool");
      else schemaTargets.add("unknown");
      if (/must have.{0,20}["']type["']|type.{0,20}(?:missing|required)/i.test(message)) schemaReasons.add("missing-type");
      if (/additionalProperties/i.test(message)) schemaReasons.add("additional-properties-contract");
      if (/required/i.test(message)) schemaReasons.add("required-fields-contract");
      if (/not supported|unsupported/i.test(message)) schemaReasons.add("unsupported-keyword");
      for (const match of message.matchAll(/["']([A-Za-z][A-Za-z0-9]*)["']/g)) {
        if (schemaFieldNames.has(match[1])) schemaContexts.add(match[1]);
      }
    }
    let recognized = false;
    for (const [category, pattern] of failurePatterns) {
      if (pattern.test(message)) {
        failures.add(category);
        recognized = true;
      }
    }
    if (!recognized && recordUnknown) failures.add("unclassified-error");
  };
  const line = (buffer) => {
    const value = buffer.toString("utf8").trim();
    if (!value) return;
    let event;
    try { event = JSON.parse(value); } catch {
      // Stderr is not JSONL; classify it without persisting its text.
      classify(value);
      return;
    }
    if (event?.event === "approval-review" && event.source === "reviewer" && event.status === "denied") {
      failures.add("automatic-review-denied");
      failures.add("permission-refused");
      return;
    }
    if (event?.event === "tool-completed" && ["failed", "declined"].includes(event.status)) {
      const tools = { commandExecution: "command_execution", mcpToolCall: "mcp_tool_call" };
      if (Object.hasOwn(tools, event.tool)) failedTools.add(tools[event.tool]);
      return;
    }
    if (event?.event === "client-failed") { failures.add("unclassified-error"); return; }
    if (!event || !eventTypes.has(event.type)) return;
    lastEvent = event.type;
    counts[event.type] = Math.min(counts[event.type] + 1, 1000000);
    if (event.type === "item.completed" && event.item?.type === "command_execution" &&
      (event.item.status === "failed" || (Number.isInteger(event.item.exit_code) && event.item.exit_code !== 0))) {
      failedTools.add("command_execution");
      classify(event.item.aggregated_output, false);
    }
    if (event.type === "item.completed" && event.item?.type === "mcp_tool_call" && event.item.error) {
      failedTools.add("mcp_tool_call");
      classify(event.item.error.message, false);
    }
    // A model's final summary is not a reviewer decision or a tool observation.
    if (event.type === "item.completed" && event.item?.type === "agent_message") {
      let summary;
      try { summary = JSON.parse(event.item.text); } catch { /* Ignore prose. */ }
      if ((summary?.outcome === "refused" || summary?.outcome === "failed") &&
        typeof summary.summaryCode === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(summary.summaryCode) &&
        summary.summaryCode.length <= 80) {
        for (const [category, pattern] of failurePatterns) {
          if (pattern.test(summary.summaryCode)) agentReportedFailures.add(category);
        }
      }
    }
    if (event.type === "error" || event.type === "turn.failed") {
      classify(event.message ?? event.error?.message ?? "");
    }
  };
  await persist(report(false));
  for await (const chunk of input) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let start = 0;
    while (start < bytes.length) {
      const newline = bytes.indexOf(10, start);
      const end = newline < 0 ? bytes.length : newline;
      if (!dropping) {
        if (pending.length + end - start > maximumLineBytes) {
          oversizedLine = true;
          dropping = true;
          pending = Buffer.alloc(0);
        } else {
          pending = Buffer.concat([pending, bytes.subarray(start, end)]);
        }
      }
      if (newline < 0) break;
      if (!dropping) line(pending);
      pending = Buffer.alloc(0);
      dropping = false;
      start = newline + 1;
    }
    await persist(report(false));
  }
  if (!dropping && pending.length) line(pending);
  const result = report(true);
  await persist(result);
  return result;
}

// The caller creates a private regular file before launching the one-shot child.
// O_NOFOLLOW prevents accidentally following a substituted symlink.
function persistReport(path, report) {
  const descriptor = openSync(path, constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW);
  try {
    fchmodSync(descriptor, 0o600);
    writeSync(descriptor, JSON.stringify(report) + "\n");
  } finally {
    closeSync(descriptor);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 3) throw new Error("invalid arguments");
    await captureDiagnostics(process.stdin, (report) => persistReport(process.argv[2], report));
  } catch {
    // Exception messages can include private filenames or input contents.
    writeSync(2, "ai_diagnostic_capture=failed\n");
    process.exitCode = 1;
  }
}
