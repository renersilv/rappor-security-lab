#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPOSITORY_ROOT
readonly PRIVATE_STATE_ROOT="/home/linux/.local/state/rappor-security-lab/joao/tmp"
readonly LIVE_MARKER="$PRIVATE_STATE_ROOT/issue-18-codex-mcp.once"
readonly LIVE_LOCK="$PRIVATE_STATE_ROOT/issue-18-codex-mcp.lock"
readonly RESULT_SCHEMA="$REPOSITORY_ROOT/schemas/windows-agent-ai-result.schema.json"
readonly REMOTE_ADAPTER="$REPOSITORY_ROOT/ops/windows-agent-lab/rappor-remote.sh"
readonly INTERACTIVE_CLIENT="$REPOSITORY_ROOT/src/run-windows-agent-ai-client.mjs"
readonly DIAGNOSTIC_CAPTURE="$REPOSITORY_ROOT/src/capture-windows-agent-ai-diagnostics.mjs"
readonly CODEX_HOME_PATH="/home/linux/.codex"
readonly CODEX_BIN="/home/linux/.local/bin/codex"
# Automatic review already selects workspace-write; an explicit --sandbox conflicts.
readonly -a CODEX_EXEC_OPTIONS=(exec --ephemeral --config 'approval_policy="on-request"' --ignore-user-config --approve-for-me)

cli_preflight() (
  local directory status=0
  umask 077
  directory="$(mktemp -d /tmp/rappor-codex-cli-check.XXXXXX)"
  trap 'rm -rf -- "$directory"' EXIT
  # Deliberately stop at a missing schema, before authentication, MCP or inference.
  # An empty home and environment keep this parser check independent of credentials.
  timeout 10s env -i HOME="$directory" CODEX_HOME="$directory" \
    PATH=/usr/bin:/bin LANG=C.UTF-8 \
    "$CODEX_BIN" "${CODEX_EXEC_OPTIONS[@]}" --json --skip-git-repo-check \
    --output-schema "$directory/missing-schema.json" \
    --output-last-message "$directory/result.json" - \
    <<<'Inert schema validation; do not run a task.' >"$directory/stdout" 2>"$directory/stderr" || status=$?
  [[ $status -eq 1 && ! -e $directory/result.json ]] ||
    fail "the inert CLI preflight did not stop at schema validation"
  grep -Fq "Failed to read output schema file $directory/missing-schema.json:" "$directory/stderr" ||
    fail "the Codex invocation was rejected before schema validation"
)

fail() {
  printf 'One-shot Codex control failed: %s\n' "$1" >&2
  exit 1
}

run_bounded_once() {
  local marker="$1"
  local lock="$2"
  local soft_limit="$3"
  local kill_grace="$4"
  shift 4

  umask 077
  mkdir -p -- "$(dirname "$marker")"
  exec 9>"$lock"
  flock -n 9 || fail "another Issue #18 AI execution is active"
  if ! (set -o noclobber; printf 'consumed-at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$marker") 2>/dev/null; then
    fail "the persistent Issue #18 AI attempt was already consumed"
  fi

  # Background commands otherwise receive /dev/null instead of the prompt pipe.
  setsid "$@" <&0 &
  local command_pid=$!
  # A separate group lets cleanup terminate both the timer shell and its sleep.
  # shellcheck disable=SC2016
  setsid bash -c '
    sleep "$2"
    kill -TERM -- "-$1" 2>/dev/null || exit 0
    sleep "$3"
    kill -KILL -- "-$1" 2>/dev/null || true
  ' -- "$command_pid" "$soft_limit" "$kill_grace" </dev/null >/dev/null 2>&1 &
  local watchdog_pid=$!
  local status=0
  wait "$command_pid" || status=$?
  if kill -0 -- "-$command_pid" 2>/dev/null; then
    wait "$watchdog_pid" || true
  else
    # A fast command can exit before setsid creates the watchdog's process group.
    # Wait for that group before terminating it, so its timer cannot retain the lock.
    local watchdog_ready=false
    for _ in {1..100}; do
      if kill -0 -- "-$watchdog_pid" 2>/dev/null; then watchdog_ready=true; break; fi
      if ! kill -0 "$watchdog_pid" 2>/dev/null; then break; fi
      sleep 0.01
    done
    if [[ $watchdog_ready == true ]]; then
      kill -TERM -- "-$watchdog_pid" 2>/dev/null || true
    else
      kill -TERM "$watchdog_pid" 2>/dev/null || true
    fi
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  return "$status"
}

self_test() {
  local directory marker lock diagnostic_file first_status second_status
  directory="$(mktemp -d /tmp/rappor-issue-18-once.XXXXXX)"
  marker="$directory/attempt.once"
  lock="$directory/attempt.lock"
  diagnostic_file="$directory/diagnostic.json"
  (umask 077; : >"$diagnostic_file")
  trap 'rm -f -- "$marker" "$lock" "$diagnostic_file"; rmdir -- "$directory"' RETURN

  first_status=0
  run_with_diagnostics "$diagnostic_file" run_bounded_once "$marker" "$lock" 1 1 \
    bash -c 'trap "" TERM; sleep 30 & wait' || first_status=$?
  [[ $first_status -eq 124 || $first_status -eq 137 ]] || fail "the reduced timeout did not terminate its process group"
  [[ -f $marker && $(stat -c '%a' "$marker") == 600 ]] || fail "the private marker was not consumed safely"

  second_status=0
  (run_bounded_once "$marker" "$lock" 1 1 /bin/true) >/dev/null 2>&1 || second_status=$?
  [[ $second_status -ne 0 ]] || fail "the consumed marker allowed an automatic retry"
  printf 'one_shot_control=passed\n'
}

run_with_diagnostics() {
  local diagnostic_file="$1"
  shift
  local -a pipeline_status=(0 0)
  "$@" 2>&1 | node "$DIAGNOSTIC_CAPTURE" "$diagnostic_file" || pipeline_status=("${PIPESTATUS[@]}")
  printf 'codex_process_exit=%s diagnostic_capture_exit=%s\n' "${pipeline_status[0]}" "${pipeline_status[1]}" >&2
  if [[ ${pipeline_status[1]} -ne 0 ]]; then
    return 1
  fi
  return "${pipeline_status[0]}"
}

diagnostic_self_test() (
  local directory diagnostic_file status=0
  umask 077
  directory="$(mktemp -d /tmp/rappor-ai-diagnostic-check.XXXXXX)"
  diagnostic_file="$directory/diagnostic.json"
  : >"$diagnostic_file"
  trap 'rm -f -- "$diagnostic_file" "$directory/attempt.once" "$directory/attempt.lock"; rmdir -- "$directory"' EXIT
  # The child shell, not this shell, expands the synthetic input variable.
  # shellcheck disable=SC2016
  run_with_diagnostics "$diagnostic_file" run_bounded_once "$directory/attempt.once" "$directory/attempt.lock" 30 1 bash -c \
    'IFS= read -r input; [[ $input == "synthetic diagnostic prompt" ]] || exit 18; printf "%s\n" "Invalid schema: synthetic diagnostic probe" >&2; exit 17' <<<'synthetic diagnostic prompt' || status=$?
  [[ $status -eq 17 ]] || fail "diagnostic capture lost the child exit status"
  timeout 2s flock "$directory/attempt.lock" /bin/true || fail "the completed command left its one-shot lock held"
  node --input-type=module - "$diagnostic_file" <<'NODE'
import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
const result = JSON.parse(readFileSync(process.argv[2], "utf8"));
assert.equal(result.streamClosed, true);
assert.deepEqual(result.failureClasses, ["schema-rejected"]);
assert.equal(result.rawOutputRetained, false);
assert.equal(statSync(process.argv[2]).mode & 0o777, 0o600);
NODE
  printf 'diagnostic_capture=passed\n'
)

live_preflight() {
  [[ ${RAPPOR_WINDOWS_HML_BASE_URL:-} ]] || fail "RAPPOR_WINDOWS_HML_BASE_URL is required"
  [[ ${RAPPOR_WINDOWS_SSH_KEY:-} ]] || fail "RAPPOR_WINDOWS_SSH_KEY is required"
  [[ $RAPPOR_WINDOWS_HML_BASE_URL =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] ||
    fail "RAPPOR_WINDOWS_HML_BASE_URL must be a credential-free HTTPS origin"
  [[ -f $RAPPOR_WINDOWS_SSH_KEY ]] || fail "the protected SSH key is unavailable"
  [[ $(stat -c '%a' "$RAPPOR_WINDOWS_SSH_KEY") == 600 ]] || fail "the protected SSH key must have mode 0600"
  [[ -x $REMOTE_ADAPTER ]] || fail "the restricted Windows adapter is not executable"
  [[ -f $RESULT_SCHEMA ]] || fail "the sanitized result schema is unavailable"
  [[ -x $CODEX_BIN ]] || fail "the pinned Codex executable is unavailable"
  cli_preflight
  "$CODEX_BIN" mcp list --json | node --input-type=module -e '
    let input = "";
    for await (const chunk of process.stdin) input += chunk;
    const servers = JSON.parse(input);
    const expected = new URL("/mcp", process.env.RAPPOR_WINDOWS_HML_BASE_URL).href;
    if (!servers.some(server => server.name === "rapporLabIssue18" && server.enabled === true &&
      server.transport?.type === "streamable_http" && server.transport.url === expected && server.auth_status === "o_auth")) process.exit(1);
  ' || fail "the exact temporary laboratory MCP OAuth connection is not ready"
  node "$INTERACTIVE_CLIENT" --preflight >/dev/null
  diagnostic_self_test >/dev/null
  "$CODEX_BIN" login status >/dev/null 2>&1 || fail "the existing ChatGPT login is unavailable"
}

live_run() {
  live_preflight

  local result_file prompt_file diagnostic_file review_file status
  result_file="$(mktemp "$PRIVATE_STATE_ROOT/issue-18-ai-result.XXXXXX")"
  prompt_file="$(mktemp "$PRIVATE_STATE_ROOT/issue-18-ai-prompt.XXXXXX")"
  diagnostic_file="$(mktemp "$PRIVATE_STATE_ROOT/issue-18-ai-diagnostic.XXXXXX")"
  review_file="$(mktemp "$PRIVATE_STATE_ROOT/issue-18-approval-review.XXXXXX")"
  chmod 600 "$result_file" "$prompt_file" "$diagnostic_file" "$review_file"
  trap 'rm -f -- "$result_file" "$prompt_file"' RETURN
  [[ ${RAPPOR_LAB_ATTEMPT_DEADLINE:-} =~ ^[0-9]{10}$ ]] || fail "the prepared UI deadline is required"
  (( RAPPOR_LAB_ATTEMPT_DEADLINE > $(date +%s) + 10 )) || fail "the prepared UI deadline expired"
  (( RAPPOR_LAB_ATTEMPT_DEADLINE <= $(date +%s) + 590 )) || fail "the prepared UI deadline exceeds the attempt budget"

  cat >"$prompt_file" <<EOF
Perform exactly one owner-authorized Rappor Security laboratory analysis of the synthetic local folder for the existing product named Windows Agent Laboratory through the configured rapporLabIssue18 MCP server.

Use the MCP workflow to request analysis of the local synthetic workspace. When the MCP server returns the public Rappor.LocalClient continuation command, invoke only this restricted adapter, preserving the returned operation, control-plane and protocol values:

$REMOTE_ADAPTER workspace continue --operation <operationId> --control-plane <controlPlane> --protocol <protocolVersion> --workspace 'C:\RapporLab\corpus'

The restricted adapter requires a loopback SSH connection to the existing laboratory VM. Before invoking that exact adapter command, request the normal scoped shell-tool approval for its network access. Keep automatic review and the sandbox enabled. If approval is denied or unavailable, stop and report refused; do not change the route, permissions, command or target to get around the decision.

The adapter launches the official client in the existing Windows desktop session. The prepared laboratory UI adapter handles the actual native and browser confirmations only for this exact synthetic folder, computer and operation; do not bypass them.

Do not run any other shell command. Do not read files, environment variables, credentials, Git data, source contents or private paths. Do not start another Codex process. Do not edit anything. Wait for the MCP workflow to reach a terminal state. Return only the JSON object required by the supplied output schema. Classify an actual permission denial as refused and an unavailable operation or timeout as failed. Stop without retrying it in a different form.
EOF

  status=0
  run_with_diagnostics "$diagnostic_file" run_bounded_once "$LIVE_MARKER" "$LIVE_LOCK" 589 10 \
    env -i \
      HOME=/home/linux \
      CODEX_HOME="$CODEX_HOME_PATH" \
      PATH=/usr/local/bin:/usr/bin:/bin \
      LANG=C.UTF-8 \
      RAPPOR_WINDOWS_SSH_KEY="$RAPPOR_WINDOWS_SSH_KEY" \
      RAPPOR_WINDOWS_HML_BASE_URL="$RAPPOR_WINDOWS_HML_BASE_URL" \
      RAPPOR_LAB_ATTEMPT_DEADLINE="$RAPPOR_LAB_ATTEMPT_DEADLINE" \
      node "$INTERACTIVE_CLIENT" --run "$prompt_file" "$result_file" "$review_file" || status=$?
  printf 'approval_review_file=%s\n' "${review_file##*/}" >&2
  printf 'ai_diagnostic_file=%s\n' "${diagnostic_file##*/}" >&2

  if [[ $status -ne 0 ]]; then
    printf 'codex_process_exit=%s\n' "$status" >&2
    printf '{"outcome":"failed","clientPath":"host-codex-ssh-windows-app","operationContinued":false,"analysisCompleted":false,"summaryCode":"codex-process-failed","scanners":[]}\n'
    return "$status"
  fi
  node "$REPOSITORY_ROOT/src/verify-windows-agent-ai-result.mjs" "$result_file"
}

case "${1:-}" in
  --self-test) self_test ;;
  --check-diagnostics) diagnostic_self_test ;;
  --check-interactive) node "$INTERACTIVE_CLIENT" --preflight ;;
  --check-cli) cli_preflight; printf 'cli_preflight=passed\n' ;;
  --preflight) live_preflight; printf 'live_preflight=passed\n' ;;
  --run) live_run ;;
  *) fail "expected --self-test, --check-cli, --check-diagnostics, --preflight or --run" ;;
esac
