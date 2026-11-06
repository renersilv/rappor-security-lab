# Typed IDE readiness observations

Use `python3 -B ops/joao/ide-readiness.py --input-file ABSOLUTE_PRIVATE_JSON` on a
bounded private observation (0600, at most 256 KiB). This helper parses evidence;
it does not collect evidence, contact MCP, start an IDE or model, or grant a login.

Input shape:

```json
{
  "schemaVersion": 1,
  "candidateOrigin": "https://linux-ai2.taile60a95.ts.net:8443",
  "mcpStatus": [{
    "name": "rapporLabIssue19Windows",
    "enabled": true,
    "transport": {"type": "streamable_http", "url": "https://linux-ai2.taile60a95.ts.net:8443/mcp"},
    "auth_status": "oAuth"
  }],
  "appxPackages": [{"Name": "Rappor.RapporSecurity", "Status": "Ok"}],
  "windowObservation": {
    "mode": "interactive",
    "observerSessionId": 1,
    "interactiveSessionId": 1,
    "visibleCodeWindows": 1
  },
  "rendererStatus": "unknown"
}
```

Values above illustrate shape, not current evidence. Populate them from a fresh,
identity-checked official client observation. MCP selection uses exactly one
enabled streamable HTTP endpoint matching the candidate's `/mcp`, not an assumed
server alias. Disabled, ambiguous, wrong path, query, credential-bearing and
unexpected-origin endpoints fail selection. Never read or publish auth.json,
authorization headers, tokens or full client configuration. Preserve only the
shown MCP fields in evidence; do not copy unfiltered CLI output into a manifest.

The official app-server schema supplied by the installed CLI uses authStatus
`unknown`, `unsupported`, `notLoggedIn`, `bearerToken` and `oAuth`.
`oAuth` means configured, not authenticated. Unknown or conflicting auth fields
remain unknown; file presence does not prove a session. Use literal status values,
never substring checks. `authenticated` is not accepted as an invented positive
enum. An optional `mcpRuntimeStatus` contains the official `mcpServerStatus/list`
response, shaped as `{data:[...],nextCursor:null}`. Bind its row by the server name
actually selected from the exact endpoint configuration. This observed schema uses
`runtimeStatus`, not a guessed `connectionStatus`; unknown Windows/client schemas
remain unconfirmed. Only `runtimeStatus:"connected"`, `authStatus:"oAuth"` or
`"bearerToken"`, explicit `toolsError:null` and a nonempty valid tools dictionary
show an available catalog in a connected runtime. The catalog may be cached; this
does not claim a new tools/list request. Each tool has matching name and inputSchema. Cached
tools with null/notStarted/starting runtime do not prove a live connection. Tool
discovery still does not prove a successful tool call or a remediation cycle.
No AI turn is necessary to inspect this official status contract. The installed package is `Rappor.RapporSecurity`.

SSH process/window observations use mode `ssh` and cannot prove interactive
visibility even when MainWindowHandle is zero. Interactive visibility requires an
observation performed in the matching positive interactive session. A renderer
ready timeout is a technical failure, regardless of MCP configuration. No parser
result by itself proves that the owner must act or that MCP tools work.

Bind this exact helper, focused test outcomes, fresh sanitized inputs/output and
actual collector source to the next current-pass manifest. Preserve pass175 and
other historical receipts unchanged. Recheck listener/guest identity, candidate,
authorization, deadlines and cleanup before any new live observation. The existing
no-remediation-inference/no-new-VM/no-API-key limits remain unchanged.
