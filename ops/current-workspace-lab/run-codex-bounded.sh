#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPOSITORY_ROOT
readonly PRIVATE_STATE_ROOT="/home/linux/.local/state/rappor-security-lab/joao/tmp"
readonly AUTHORIZATION_RECEIPT="/home/linux/.config/rappor-security-lab/issue19-ai-authorization-20261016.json"
readonly AUTHORIZATION_EXTENSION_RECEIPT="/home/linux/.config/rappor-security-lab/issue19-ai-authorization-20261016-extension-1.json"
readonly PREPARATION_RECEIPT="/home/linux/.config/rappor-security-lab/issue19-preparation.json"
readonly LINUX_PREPARATION_RECEIPT="/home/linux/.config/rappor-security-lab/issue19-linux-preparation-completed.json"
readonly OAUTH_RECOVERY_RECEIPT="/home/linux/.config/rappor-security-lab/issue19-oauth-expiry-recovery-20261017.json"
readonly CONSUMPTION_STATE="$PRIVATE_STATE_ROOT/issue-19-ai-consumption.json"
readonly CONSUMPTION_LOCK="$PRIVATE_STATE_ROOT/issue-19-ai-consumption.lock"
readonly WORKSPACE="$PRIVATE_STATE_ROOT/issue-19-current-workspace"
readonly CONSUMPTION_CONTROL="$REPOSITORY_ROOT/src/issue19-ai-consumption.mjs"
readonly FIXTURE_CONTROL="$REPOSITORY_ROOT/src/current-workspace-fixture.mjs"
readonly INTERACTIVE_CLIENT="$REPOSITORY_ROOT/src/run-current-workspace-ai-client.mjs"
readonly DIAGNOSTIC_CAPTURE="$REPOSITORY_ROOT/src/capture-windows-agent-ai-diagnostics.mjs"
readonly RESULT_VERIFIER="$REPOSITORY_ROOT/src/verify-current-workspace-ai-result.mjs"
readonly PROFILE="$REPOSITORY_ROOT/scanner-profiles/current-workspace-ai.json"
readonly CODEX_BIN="/home/linux/.local/bin/codex"

fail() {
  printf 'Issue #19 bounded Codex control failed: %s\n' "$1" >&2
  exit 1
}

read_profile() {
  node --input-type=module - "$PROFILE" "$1" <<'NODE'
import {readFileSync} from 'node:fs';
const profile=JSON.parse(readFileSync(process.argv[2],'utf8'));
const path=process.argv[3].split('.');
let value=profile;
for(const key of path) value=value?.[key];
if(!['string','number'].includes(typeof value)) process.exit(1);
process.stdout.write(String(value));
NODE
}

read_preparation_override() {
  node --input-type=module - "$PREPARATION_RECEIPT" <<'NODE'
import {readFileSync,statSync} from 'node:fs';
const path=process.argv[2];
if((statSync(path).mode&0o777)!==0o600) process.exit(1);
const receipt=JSON.parse(readFileSync(path,'utf8'));
if(!/^mcp_servers\.rapporLabIssue19\.url="https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?\/mcp"$/u.test(receipt.oauthConfigOverride)) process.exit(1);
process.stdout.write(receipt.oauthConfigOverride);
NODE
}

verify_live_preparation() {
  node --input-type=module - "$PREPARATION_RECEIPT" "$LINUX_PREPARATION_RECEIPT" \
    "$OAUTH_RECOVERY_RECEIPT" <<'NODE'
import assert from 'node:assert/strict';
import {readFileSync,statSync} from 'node:fs';
const readPrivate=(path)=>{
  assert.equal(statSync(path).mode&0o777,0o600);
  return JSON.parse(readFileSync(path,'utf8'));
};
const preparation=readPrivate(process.argv[2]);
const linux=readPrivate(process.argv[3]);
const recovery=readPrivate(process.argv[4]);
assert.equal(preparation.oauthRefreshPersistenceVerified,true);
assert.equal(recovery.confirmedCause,'refresh_token_expired_after_eight_hour_inactivity');
assert.equal(recovery.authorizationWasRevoked,false);
assert.equal(recovery.recoveryUsedOfficialCli,true);
assert.equal(recovery.recoveryUsedPublicConsentUi,true);
assert.equal(recovery.credentialScopeChanged,false);
assert.equal(recovery.productTokenLifetimeChanged,false);
assert.equal(recovery.inferenceStarts,0);
assert.equal(recovery.postAccessExpiryRefreshVerified,true);
assert.equal(recovery.refreshedCredentialPersistenceVerified,true);
assert.ok(recovery.independentPreflightsPassed>=2);
assert.equal(linux.productVersion,'v0.79.0');
assert.equal(linux.sourceRevision,'1c6412c0e813f4a3f95b125871b4338b6f168356');
assert.equal(linux.clientArchiveSha256,'9fd7775aacb84fcfd9d638a61397119389757fce1b4e7b02502476054b2f0ed5');
assert.equal(linux.localClientInstalled,true);
assert.equal(linux.localClientProtocolVersion,1);
assert.equal(linux.computerApproved,true);
assert.equal(linux.computerOnline,true);
assert.ok(linux.computerCapabilities.includes('source.current-workspace.v1'));
assert.ok(linux.computerCapabilities.includes('source.local-folder.v1'));
assert.equal(linux.registeredWorkspaceCount,0);
assert.equal(linux.inferenceStartsDuringPreparation,0);
assert.equal(linux.totalInferenceStartsConsumed,2);
assert.equal(linux.linuxCliStartsConsumed,2);
assert.equal(linux.ideWindowsStartsReserved,2);
assert.equal(linux.folderConsentGranted,false);
assert.equal(linux.baselineCompleted,false);
assert.equal(linux.originalFirstUseEvidencePreserved,true);
NODE
}

prepare_workspace() {
  mkdir -p -- "$PRIVATE_STATE_ROOT"
  chmod 0700 -- "$PRIVATE_STATE_ROOT"
  node "$FIXTURE_CONTROL" prepare "$WORKSPACE"
}

live_preflight() {
  [[ ! ${OPENAI_API_KEY:-} ]] || fail "OPENAI_API_KEY must not be present"
  [[ -x $CODEX_BIN ]] || fail "the pinned Codex executable is unavailable"
  [[ -f $AUTHORIZATION_RECEIPT && $(stat -c '%a' "$AUTHORIZATION_RECEIPT") == 600 ]] ||
    fail "the private authorization receipt is unavailable"
  [[ -f $AUTHORIZATION_EXTENSION_RECEIPT && $(stat -c '%a' "$AUTHORIZATION_EXTENSION_RECEIPT") == 600 ]] ||
    fail "the private authorization extension is unavailable"
  [[ -f $PREPARATION_RECEIPT && $(stat -c '%a' "$PREPARATION_RECEIPT") == 600 ]] ||
    fail "the private preparation receipt is unavailable"
  [[ -f $LINUX_PREPARATION_RECEIPT && $(stat -c '%a' "$LINUX_PREPARATION_RECEIPT") == 600 ]] ||
    fail "the private Linux preparation receipt is unavailable"
  [[ -f $OAUTH_RECOVERY_RECEIPT && $(stat -c '%a' "$OAUTH_RECOVERY_RECEIPT") == 600 ]] ||
    fail "the private OAuth recovery receipt is unavailable"
  [[ -d $WORKSPACE ]] || fail "the controlled current workspace is not prepared"
  command -v rappor >/dev/null || fail "the official Linux client is unavailable"
  verify_live_preparation || fail "the bounded Linux or OAuth preparation changed"
  node "$CONSUMPTION_CONTROL" status --authorization "$AUTHORIZATION_RECEIPT" \
    --extension "$AUTHORIZATION_EXTENSION_RECEIPT" --state "$CONSUMPTION_STATE" >/dev/null ||
    fail "the authorization extension or preserved history changed"
  local override
  override="$(read_preparation_override)" || fail "the isolated MCP override changed"
  "$CODEX_BIN" login status >/dev/null 2>&1 || fail "the existing ChatGPT login is unavailable"
  "$CODEX_BIN" --config "$override" mcp list --json | node --input-type=module -e '
    let input=""; for await (const chunk of process.stdin) input+=chunk;
    const target=JSON.parse(input).find(item=>item.name==="rapporLabIssue19");
    if(!target||target.enabled!==true||target.auth_status!=="o_auth") process.exit(1);
  ' || fail "the isolated Issue #19 MCP OAuth connection is not ready"
  RAPPOR_CURRENT_WORKSPACE="$WORKSPACE" RAPPOR_ISSUE19_MCP_OVERRIDE="$override" \
    "$CODEX_BIN" --version >/dev/null
  RAPPOR_CURRENT_WORKSPACE="$WORKSPACE" RAPPOR_ISSUE19_MCP_OVERRIDE="$override" \
    node "$INTERACTIVE_CLIENT" --preflight >/dev/null
  node "$FIXTURE_CONTROL" inspect "$WORKSPACE" >/dev/null
}

run_bounded() {
  local timeout_flag="$1"
  local soft_limit="$2"
  local kill_grace="$3"
  shift 3
  setsid "$@" &
  local command_pid=$!
  # The child shell expands the positional parameters after setsid.
  # shellcheck disable=SC2016
  setsid bash -c '
    sleep "$2"
    : >"$4"
    kill -TERM -- "-$1" 2>/dev/null || exit 0
    sleep "$3"
    kill -KILL -- "-$1" 2>/dev/null || true
  ' -- "$command_pid" "$soft_limit" "$kill_grace" "$timeout_flag" </dev/null >/dev/null 2>&1 &
  local watchdog_pid=$!
  local status=0
  wait "$command_pid" || status=$?
  if kill -0 -- "-$command_pid" 2>/dev/null; then
    kill -TERM -- "-$command_pid" 2>/dev/null || true
  fi
  if kill -0 -- "-$watchdog_pid" 2>/dev/null; then
    kill -TERM -- "-$watchdog_pid" 2>/dev/null || true
  else
    kill -TERM "$watchdog_pid" 2>/dev/null || true
  fi
  wait "$watchdog_pid" 2>/dev/null || true
  [[ -e $timeout_flag ]] && return 124
  return "$status"
}

run_with_diagnostics() {
  local diagnostic_file="$1"
  shift
  local -a pipeline_status=(0 0)
  "$@" 2>&1 | node "$DIAGNOSTIC_CAPTURE" "$diagnostic_file" || pipeline_status=("${PIPESTATUS[@]}")
  printf 'codex_process_exit=%s diagnostic_capture_exit=%s\n' "${pipeline_status[0]}" "${pipeline_status[1]}" >&2
  [[ ${pipeline_status[1]} -eq 0 ]] || return 1
  return "${pipeline_status[0]}"
}

run_live() {
  prepare_workspace >/dev/null
  live_preflight
  umask 077
  exec 9>"$CONSUMPTION_LOCK"
  flock -n 9 || fail "another Issue #19 AI execution is active"
  local sequence
  sequence="$(node "$CONSUMPTION_CONTROL" reserve --authorization "$AUTHORIZATION_RECEIPT" \
    --extension "$AUTHORIZATION_EXTENSION_RECEIPT" --state "$CONSUMPTION_STATE" \
    --client cli-linux)" || fail "the AI start could not be reserved"

  local prompt follow_up baseline result review diagnostic timeout_flag override deadline status=0 outcome=failed
  prompt="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-prompt.XXXXXX")"
  follow_up="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-follow-up.XXXXXX")"
  baseline="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-baseline.XXXXXX")"
  result="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-result.XXXXXX")"
  review="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-review.XXXXXX")"
  diagnostic="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-diagnostic.XXXXXX")"
  timeout_flag="$(mktemp "$PRIVATE_STATE_ROOT/issue-19-ai-timeout.XXXXXX")"
  rm -f -- "$timeout_flag"
  chmod 0600 -- "$prompt" "$follow_up" "$baseline" "$result" "$review" "$diagnostic"
  printf '%s\n' "$(read_profile prompt)" >"$prompt"
  printf '%s\n' "$(read_profile followUpPrompt)" >"$follow_up"
  override="$(read_preparation_override)" || fail "the isolated MCP override changed"
  deadline=$(( $(date +%s) + 599 ))
  run_with_diagnostics "$diagnostic" run_bounded "$timeout_flag" 589 10 \
    env -u OPENAI_API_KEY \
      RAPPOR_CURRENT_WORKSPACE="$WORKSPACE" \
      RAPPOR_ISSUE19_MCP_OVERRIDE="$override" \
      RAPPOR_LAB_ATTEMPT_DEADLINE="$deadline" \
      node "$INTERACTIVE_CLIENT" --run "$prompt" "$follow_up" "$baseline" "$result" "$review" || status=$?
  rm -f -- "$prompt" "$follow_up" "$timeout_flag"

  if [[ $status -eq 124 ]]; then
    outcome=timed-out
  elif node "$RESULT_VERIFIER" "$result" >/dev/null 2>&1; then
    outcome="$(node --input-type=module -e 'import{readFileSync}from"node:fs";process.stdout.write(JSON.parse(readFileSync(process.argv[1],"utf8")).outcome)' "$result")"
  else
    outcome=failed
    status=1
  fi
  node "$CONSUMPTION_CONTROL" finish --authorization "$AUTHORIZATION_RECEIPT" \
    --extension "$AUTHORIZATION_EXTENSION_RECEIPT" --state "$CONSUMPTION_STATE" \
    --sequence "$sequence" --outcome "$outcome" --process-exit "$status" >/dev/null
  printf 'attempt_sequence=%s\n' "$sequence"
  printf 'attempt_outcome=%s\n' "$outcome"
  printf 'baseline_result_file=%s\n' "${baseline##*/}"
  printf 'ai_result_file=%s\n' "${result##*/}"
  printf 'approval_review_file=%s\n' "${review##*/}"
  printf 'ai_diagnostic_file=%s\n' "${diagnostic##*/}"
  node "$FIXTURE_CONTROL" inspect "$WORKSPACE"
  node "$RESULT_VERIFIER" "$result" || true
  return "$status"
}

self_test() (
  umask 077
  local directory authorization extension state lock timeout_flag sequence status=0
  directory="$(mktemp -d /tmp/rappor-issue19-control.XXXXXX)"
  trap 'rm -rf -- "$directory"' EXIT
  authorization="$directory/authorization.json"
  extension="$directory/authorization-extension.json"
  state="$directory/state.json"
  lock="$directory/state.lock"
  timeout_flag="$directory/timed-out"
  node --input-type=module - "$authorization" <<'NODE'
import{writeFileSync}from'node:fs';
writeFileSync(process.argv[2],JSON.stringify({authorizationId:'issue19-ai-20261016',issue:19,maxStarts:4,maxSecondsPerRun:600,sequentialOnly:true,consumeBeforeStart:true,countFailedStarts:true,persistentConsumptionRequired:true,allowOpenAiApiKey:false,allowNewVm:false,doesNotResetIssue18:true}),{mode:0o600});
NODE
  exec 8>"$lock"
  flock -n 8 || fail "the self-test lock was unavailable"
  for expected_sequence in 1 2; do
    sequence="$(node "$CONSUMPTION_CONTROL" reserve --authorization "$authorization" \
      --state "$state" --client cli-linux)"
    [[ $sequence -eq $expected_sequence ]] || fail "the original history sequence changed"
    node "$CONSUMPTION_CONTROL" finish --authorization "$authorization" --state "$state" \
      --sequence "$sequence" --outcome failed --process-exit 1 >/dev/null
  done
  node --input-type=module - "$authorization" "$state" "$extension" <<'NODE'
import{createHash}from'node:crypto';import{readFileSync,writeFileSync}from'node:fs';
const original=readFileSync(process.argv[2]);const state=readFileSync(process.argv[3]);
const hash=(value)=>createHash('sha256').update(value).digest('hex');
writeFileSync(process.argv[4],JSON.stringify({schemaVersion:1,amendmentId:'issue19-ai-20261016-extension-1',authorizationId:'issue19-ai-20261016',issue:19,authorizedAtUtc:'2026-10-17T15:00:00Z',authorizationSource:'bounded-self-test',originalAuthorizationReceiptSha256:hash(original),consumptionStateSha256AtAuthorization:hash(state),consumedStartsAtAuthorization:2,additionalStarts:1,maxStarts:5,maxCliLinuxStarts:3,reservedIdeWindowsStarts:2,maxSecondsPerRun:600,sequentialOnly:true,allowOpenAiApiKey:false,allowNewVm:false,consumeBeforeStart:true,countFailedStarts:true,persistentConsumptionRequired:true,doesNotResetIssue18:true,preserveOriginalReceiptAndAttempts:true}),{mode:0o600});
NODE
  sequence="$(node "$CONSUMPTION_CONTROL" reserve --authorization "$authorization" \
    --extension "$extension" --state "$state" --client cli-linux)"
  [[ $sequence -eq 3 ]] || fail "the extension did not preserve the original history"
  run_bounded "$timeout_flag" 1 1 bash -c 'trap "" TERM; sleep 30 & wait' || status=$?
  [[ $status -eq 124 ]] || fail "the reduced timeout did not terminate the process tree"
  node "$CONSUMPTION_CONTROL" finish --authorization "$authorization" --extension "$extension" \
    --state "$state" --sequence "$sequence" --outcome timed-out --process-exit 124 >/dev/null
  if node "$CONSUMPTION_CONTROL" reserve --authorization "$authorization" --extension "$extension" \
      --state "$state" --client cli-linux >/dev/null 2>&1; then
    fail "the extension allowed a fourth CLI start"
  fi
  for expected_sequence in 4 5; do
    sequence="$(node "$CONSUMPTION_CONTROL" reserve --authorization "$authorization" \
      --extension "$extension" --state "$state" --client ide-windows)"
    [[ $sequence -eq $expected_sequence ]] || fail "the IDE reservation changed"
    node "$CONSUMPTION_CONTROL" finish --authorization "$authorization" --extension "$extension" \
      --state "$state" --sequence "$sequence" --outcome failed --process-exit 1 >/dev/null
  done
  node "$CONSUMPTION_CONTROL" status --authorization "$authorization" --extension "$extension" \
    --state "$state" | node --input-type=module -e '
      let input="";for await(const chunk of process.stdin)input+=chunk;const value=JSON.parse(input);
      if(value.maxStarts!==5||value.maxCliLinuxStarts!==3||value.maxIdeWindowsStarts!==2||
        value.consumedStarts!==5||value.cliLinuxStarts!==3||value.ideWindowsStarts!==2||
        value.extensionActive!==true||value.active!==false)process.exit(1);
    ' || fail "the extended status changed"
  [[ $(stat -c '%a' "$state") == 600 ]] || fail "the persistent history is not private"
  flock -u 8
  timeout 2s flock "$lock" /bin/true || fail "the self-test left the serialization lock held"
  printf 'issue19_bounded_control=passed\n'
)

case "${1:-}" in
  --prepare) prepare_workspace ;;
  --preflight) prepare_workspace >/dev/null; live_preflight; printf 'issue19_live_preflight=passed\n' ;;
  --run) run_live ;;
  --status) node "$CONSUMPTION_CONTROL" status --authorization "$AUTHORIZATION_RECEIPT" \
    --extension "$AUTHORIZATION_EXTENSION_RECEIPT" --state "$CONSUMPTION_STATE" ;;
  --self-test) self_test ;;
  *) fail "expected --prepare, --preflight, --run, --status or --self-test" ;;
esac
