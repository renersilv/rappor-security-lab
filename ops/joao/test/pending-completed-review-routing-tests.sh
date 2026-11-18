#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091,SC2034,SC2329
# Preserve real gate ordering; model and protected admission are offline doubles.
set -euo pipefail
ROOT=${JOAO_TEST_SOURCE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export JOAO_STATE_ROOT="$TEST_ROOT/state" JOAO_SOURCE_ONLY=1
mkdir -p "$JOAO_STATE_ROOT"
source "$ROOT/ops/joao/run.sh"
STATE_ROOT=$JOAO_STATE_ROOT
record() { printf '%s\n' "$1" >> "$STATE_ROOT/trace"; }
log() { :; }
campaign_enabled() { return 0; }
campaign_review_command() {
  case $1 in
    transport-status) printf 'pending\n' ;;
    pending-completed-review) [[ $ADMISSION != invalid ]] || return 65; printf '%s\n' "$ADMISSION" ;;
    *) record "forbidden-review-operation:$1"; return 99 ;;
  esac
}
candidate_repair_dispatch() { record old-candidate-gate; return 75; }
run_campaign_review() {
  record review
  local attempts=0
  [[ ! -f $STATE_ROOT/attempts ]] || attempts=$(cat "$STATE_ROOT/attempts")
  (( attempts < 3 )) || return 70
  printf '%s\n' "$((attempts + 1))" > "$STATE_ROOT/attempts"
  return "$REVIEW_RESULT"
}
recover_campaign_failure() { record forbidden-recovery; return 99; }
clear_issue_retry() { record forbidden-clear; return 99; }
run_codex() { record forbidden-executor; return 99; }
printf 'old suspended executor gate\n' > "$STATE_ROOT/issue-retry"
printf 'consumed runtime ledger\n' > "$STATE_ROOT/ledger"
cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/retry-before"
cp "$STATE_ROOT/ledger" "$STATE_ROOT/ledger-before"
ADMISSION=yes REVIEW_RESULT=70
: > "$STATE_ROOT/trace"
for _ in 1 2 3 4; do
  actual=0
  check_issue_retry_gate 19 joao/batch-synthetic /synthetic/worktree || actual=$?
  [[ $actual == 75 ]]
done
[[ $(grep -c '^review$' "$STATE_ROOT/trace" || :) == 4 ]] || {
  printf 'FAIL completed evidence never reached review; observed trace: %s\n' "$(cat "$STATE_ROOT/trace")" >&2
  exit 1
}
[[ $(cat "$STATE_ROOT/attempts") == 3 ]]
[[ $(grep -c -E 'old-candidate-gate|forbidden-' "$STATE_ROOT/trace" || :) == 0 ]]
cmp -s "$STATE_ROOT/retry-before" "$STATE_ROOT/issue-retry"
cmp -s "$STATE_ROOT/ledger-before" "$STATE_ROOT/ledger"
printf 'PASS completed evidence review precedes stale gates and preserves consumed authority\n'
for REVIEW_RESULT in 0 65 1; do
  : > "$STATE_ROOT/trace"
  printf '0\n' > "$STATE_ROOT/attempts"
  actual=0
  check_issue_retry_gate 19 joao/batch-synthetic /synthetic/worktree || actual=$?
  if (( REVIEW_RESULT == 0 )); then [[ $actual == 75 ]]; else [[ $actual == "$REVIEW_RESULT" ]]; fi
  [[ $(cat "$STATE_ROOT/trace") == review ]]
  cmp -s "$STATE_ROOT/retry-before" "$STATE_ROOT/issue-retry"
done
printf 'PASS review success preserves authority and fatal failures retain their exit status\n'
ADMISSION=no
: > "$STATE_ROOT/trace"
actual=0
check_issue_retry_gate 19 joao/batch-synthetic /synthetic/worktree || actual=$?
[[ $actual == 75 && $(cat "$STATE_ROOT/trace") == old-candidate-gate ]]
ADMISSION=invalid
: > "$STATE_ROOT/trace"
actual=0
check_issue_retry_gate 19 joao/batch-synthetic /synthetic/worktree || actual=$?
[[ $actual == 65 && ! -s $STATE_ROOT/trace ]]
printf 'PASS inactive or unbound evidence does not bypass existing gates\n'

queue_comment() { printf '%s\n' "$3" > "$STATE_ROOT/notice-body"; }
for phase in continued operator_reviewed; do
  campaign_review_notice "$phase"
  grep -q 'bloqueio técnico anterior permanece em reconciliação' "$STATE_ROOT/notice-body"
  if grep -q -E 'retoma|cinco minutos|Preciso de você' "$STATE_ROOT/notice-body"; then exit 1; fi
done
rm "$STATE_ROOT/issue-retry"
campaign_review_notice continued
grep -q 'retoma a mesma tarefa automaticamente' "$STATE_ROOT/notice-body"
printf 'PASS review notices do not promise executor restart while its gate remains\n'

(
  touch "$STATE_ROOT/campaign.json"
  python3() {
    case $1 in
      */campaign-review.py)
        case $2 in
          phase) printf 'review_pending\n' ;;
          transport-status) [[ $CONTROL_TRANSPORT != invalid ]] || return 65; printf '%s\n' "$CONTROL_TRANSPORT" ;;
          *) printf 'synthetic_review_status\n' ;;
        esac ;;
      *) printf 'synthetic_status\n' ;;
    esac
  }
  export -f python3
  for CONTROL_TRANSPORT in pending exhausted hard_limit; do
    export CONTROL_TRANSPORT
    JOAO_STATE_ROOT="$STATE_ROOT" bash "$ROOT/ops/joao/control.sh" status > "$STATE_ROOT/control-status"
    grep -Fxq "campaign_review_transport=$CONTROL_TRANSPORT" "$STATE_ROOT/control-status"
  done
  CONTROL_TRANSPORT=invalid
  result=0
  JOAO_STATE_ROOT="$STATE_ROOT" bash "$ROOT/ops/joao/control.sh" status > "$STATE_ROOT/control-status" || result=$?
  [[ $result == 65 ]]
  printf 'PASS control status distinguishes pending and exhausted transport and preserves validation errors\n'
)
