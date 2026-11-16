#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091,SC2034,SC2329
# Exercise the real campaign dispatcher with protected-command fixture boundaries.
set -euo pipefail
ROOT=${JOAO_TEST_SOURCE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export JOAO_STATE_ROOT="$TEST_ROOT/state" JOAO_SOURCE_ONLY=1
mkdir -p "$JOAO_STATE_ROOT"
source "$ROOT/ops/joao/run.sh"
record() { printf '%s\n' "$1" >> "$TEST_ROOT/trace"; }
log() { :; }
campaign_review_flush_notice() { :; }
issue_operational_state() { cat "$TEST_ROOT/operational"; }
run_codex() { record forbidden-model; return 99; }
campaign_command() {
  case $1 in
    phase) cat "$TEST_ROOT/phase" ;;
    begin|finish) record "forbidden-model-$1"; return 99 ;;
    *) return 98 ;;
  esac
}
campaign_review_command() {
  case $1 in
    phase) printf 'continued\n' ;;
    settlement-mode) printf 'none\n' ;;
    web-zip-reconcile)
      if [[ -f $TEST_ROOT/consumed-launch ]]; then
        record protected-interruption-reconciled
        printf 'review_pending\n' > "$TEST_ROOT/phase"
      fi ;;
    web-zip-mode)
      record protected-checkpoint-checked
      if [[ -f $TEST_ROOT/invalid-checkpoint ]]; then return 65; fi
      printf 'pending\n' ;;
    execute-web-zip)
      record protected-host-execute
      if [[ -f $TEST_ROOT/interrupted ]]; then return 70; fi
      printf 'review_pending\n' > "$TEST_ROOT/phase" ;;
    *) record "forbidden-$1"; return 98 ;;
  esac
}
run_campaign_review() { record independent-review; printf 'review_pending\n' > "$TEST_ROOT/phase"; }
fresh_case() {
  : > "$TEST_ROOT/trace"
  printf 'active\n' > "$TEST_ROOT/phase"
  printf 'doing\n' > "$TEST_ROOT/operational"
  rm -f "$TEST_ROOT/invalid-checkpoint" "$TEST_ROOT/interrupted" "$TEST_ROOT/consumed-launch"
}
run_case() {
  local expected=$1 actual=0
  execute_campaign_item 19 "$TEST_ROOT/worktree" joao/batch-fixture || actual=$?
  [[ $actual == "$expected" ]] || { cat "$TEST_ROOT/trace" >&2; return 1; }
  ! grep -q forbidden "$TEST_ROOT/trace"
}
assert_trace() { diff -u <(printf '%s\n' "$@") "$TEST_ROOT/trace"; }
fresh_case
run_case 0
assert_trace protected-checkpoint-checked protected-host-execute independent-review
printf 'PASS approved Web ZIP host dispatch reaches independent review without a model\n'
fresh_case
touch "$TEST_ROOT/invalid-checkpoint"
run_case 65
assert_trace protected-checkpoint-checked
printf 'PASS invalid protected checkpoint cannot launch or fall back to a model\n'
fresh_case
touch "$TEST_ROOT/interrupted"
run_case 70
assert_trace protected-checkpoint-checked protected-host-execute
printf 'PASS interrupted host dispatch preserves failure without another model or review claim\n'
fresh_case
printf 'blocked\n' > "$TEST_ROOT/operational"
run_case 0
[[ ! -s $TEST_ROOT/trace ]]
printf 'PASS owner-blocked work cannot dispatch the host runtime\n'

fresh_case
touch "$TEST_ROOT/consumed-launch"
run_case 0
assert_trace protected-interruption-reconciled independent-review
printf 'PASS interrupted consumed launch reconciles before the phase gate without another runtime or model\n'
