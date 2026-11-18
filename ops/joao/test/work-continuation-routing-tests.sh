#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091,SC2034,SC2329
# Real retry gate, work-review dispatcher and executor dispatch; protected Python boundaries are fixture doubles.
set -euo pipefail
ROOT=${JOAO_TEST_SOURCE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export JOAO_STATE_ROOT="$TEST_ROOT/initial" JOAO_SOURCE_ONLY=1
mkdir -p "$JOAO_STATE_ROOT"
source "$ROOT/ops/joao/run.sh"
BRANCH=joao/batch-20261116T000000Z-19-19
record() { printf '%s\n' "$1" >> "$STATE_ROOT/trace"; }
log() { :; }
campaign_enabled() { return 0; }
candidate_repair_dispatch() { record candidate-repair-check; }
record_issue_failure() { record forbidden-generic-retry-inflation; return 99; }
recover_campaign_failure() { record existing-recovery; return 0; }
run_codex() { record executor; }
issue_operational_state() { printf 'doing\n'; }
campaign_review_flush_notice() { :; }
publication_ready() { :; }
campaign_command() {
  case $1 in
    phase) cat "$STATE_ROOT/campaign-phase" ;;
    begin) record begin ;;
    finish) record finish; cat "$STATE_ROOT/campaign-phase" ;;
    *) return 98 ;;
  esac
}
campaign_review_command() {
  case $1 in
    pending-completed-review) printf 'no\n' ;;
    work-stop) printf 'none\n' ;;
    phase) cat "$STATE_ROOT/review-phase" ;;
    transport-status)
      if [[ $(cat "$STATE_ROOT/review-phase") == stalled ]]; then printf 'not_pending\n'; else printf 'pending\n'; fi ;;
    settlement-mode|web-zip-mode) printf 'none\n' ;;
    web-zip-reconcile) : ;;
    resume-correction)
      record protected-release-check
      if [[ $(cat "$STATE_ROOT/review-phase") == stalled && -f $STATE_ROOT/active-offline-correction ]]; then
        [[ -f $STATE_ROOT/archived-retry && -f $STATE_ROOT/issue-retry ]] || return 65
        cmp -s "$STATE_ROOT/archived-retry" "$STATE_ROOT/issue-retry" || return 65
        printf 'continued\n' > "$STATE_ROOT/review-phase"
        printf 'active\n' > "$STATE_ROOT/campaign-phase"
        record protected-existing-grant-correction
      fi
      if [[ $(cat "$STATE_ROOT/review-phase") == continued && -f $STATE_ROOT/issue-retry ]]; then
        [[ -f $STATE_ROOT/archived-retry ]] || return 65
        cmp -s "$STATE_ROOT/archived-retry" "$STATE_ROOT/issue-retry" || return 65
        cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/released-retry"
        rm "$STATE_ROOT/issue-retry"
        record protected-gate-released
        printf 'continued\n'
      else
        printf 'not_eligible\n'
      fi ;;
    prepare-work-review)
      record protected-prepare-work-review
      if [[ -f $STATE_ROOT/not-eligible ]]; then printf 'not_eligible\n'; return 0; fi
      [[ -f $STATE_ROOT/issue-retry ]]
      cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/archived-retry"
      printf 'same-protected-review-job\n' > "$STATE_ROOT/job-id"
      printf 'review_pending\n' > "$STATE_ROOT/review-phase"
      printf '%s\n' "$STATE_ROOT/job-id" ;;
    *) printf 'unexpected fixture review command %s\n' "$1" >&2; return 98 ;;
  esac
}
run_campaign_review() {
  [[ $1 == "$STATE_ROOT/worktree" ]]
  record "review:$(cat "$STATE_ROOT/job-id")"
  case $(cat "$STATE_ROOT/review-result") in
    transport-failed) return 70 ;;
    rejected) printf 'stalled\n' > "$STATE_ROOT/review-phase"; return 70 ;;
    approved)
      printf 'continued\n' > "$STATE_ROOT/review-phase"
      printf 'active\n' > "$STATE_ROOT/campaign-phase"
      record independently-approved
      if [[ -f $STATE_ROOT/change-retry-after-review ]]; then
        printf '# unrelated changed retry\n' >> "$STATE_ROOT/issue-retry"
      fi ;;
    *) return 98 ;;
  esac
}
fresh_case() {
  STATE_ROOT="$TEST_ROOT/$1"
  mkdir -p "$STATE_ROOT/worktree"
  : > "$STATE_ROOT/trace"
  printf 'stalled\n' > "$STATE_ROOT/review-phase"
  printf 'review_pending\n' > "$STATE_ROOT/campaign-phase"
  printf 'approved\n' > "$STATE_ROOT/review-result"
  ISSUE_RETRY_ISSUE=19 ISSUE_RETRY_BRANCH=$BRANCH ISSUE_RETRY_ERROR_CLASS=codex_exit
  ISSUE_RETRY_FINGERPRINT=$(printf '%064d' 1)
  ISSUE_RETRY_ATTEMPTS=3 ISSUE_RETRY_SUSPENDED=true
  write_issue_retry
  cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/original-retry"
}
cycle_once() {
  local expected=$1 actual=0
  check_issue_retry_gate 19 "$BRANCH" "$STATE_ROOT/worktree" || actual=$?
  [[ $actual == "$expected" ]] || {
    printf 'gate expected %s actual %s\n' "$expected" "$actual" >&2
    cat "$STATE_ROOT/trace" >&2
    return 1
  }
  if (( actual == 0 )); then execute_campaign_item 19 "$STATE_ROOT/worktree" "$BRANCH"; fi
}
assert_trace() {
  python3 - "$STATE_ROOT/trace" "$@" <<'PY'
from pathlib import Path
import sys
values = Path(sys.argv[1]).read_text().splitlines()
assert 'forbidden-generic-retry-inflation' not in values, values
for expression in sys.argv[2:]:
    if '=' in expression:
        name, count = expression.rsplit('=', 1)
        assert values.count(name) == int(count), (expression, values)
    else:
        first, last = expression.split('<', 1)
        assert values.index(first) < values.index(last), (expression, values)
PY
}

fresh_case approved
cycle_once 0
assert_trace 'protected-prepare-work-review=1' 'review:same-protected-review-job=1' \
  'protected-prepare-work-review<review:same-protected-review-job' \
  'independently-approved<protected-gate-released' 'protected-gate-released<executor' 'executor=1'
cmp -s "$STATE_ROOT/released-retry" "$STATE_ROOT/original-retry"
[[ ! -e $STATE_ROOT/issue-retry ]]
printf 'PASS eligible stalled work reaches independent review before the suspended gate\n'

fresh_case rejected
printf 'rejected\n' > "$STATE_ROOT/review-result"
cycle_once 75
assert_trace 'review:same-protected-review-job=1' 'executor=0' 'protected-gate-released=0'
cmp -s "$STATE_ROOT/issue-retry" "$STATE_ROOT/original-retry"
printf 'PASS rejected review retains the operational gate without executor\n'

fresh_case interrupted_review
printf 'transport-failed\n' > "$STATE_ROOT/review-result"
cycle_once 75
assert_trace 'protected-prepare-work-review=1' 'review:same-protected-review-job=1' 'executor=0'
cmp -s "$STATE_ROOT/issue-retry" "$STATE_ROOT/original-retry"
[[ $(cat "$STATE_ROOT/review-phase") == review_pending ]]
printf 'approved\n' > "$STATE_ROOT/review-result"
cycle_once 0
assert_trace 'protected-prepare-work-review=1' 'review:same-protected-review-job=2' 'executor=1' 'protected-gate-released=1'
printf 'PASS failed review transport resumes the same job without generic retry inflation\n'

fresh_case completed_before_release
cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/archived-retry"
printf 'continued\n' > "$STATE_ROOT/review-phase"
printf 'active\n' > "$STATE_ROOT/campaign-phase"
cycle_once 0
assert_trace 'protected-prepare-work-review=0' 'review:same-protected-review-job=0' 'protected-gate-released=1' 'executor=1'
cmp -s "$STATE_ROOT/released-retry" "$STATE_ROOT/original-retry"
printf 'PASS crash after finish resumes exact gate release without another review\n'

fresh_case unrelated_after_approval
cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/archived-retry"
printf 'continued\n' > "$STATE_ROOT/review-phase"
printf 'active\n' > "$STATE_ROOT/campaign-phase"
printf '# another failure\n' >> "$STATE_ROOT/issue-retry"
cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/unrelated-retry"
cycle_once 65
assert_trace 'protected-gate-released=0' 'executor=0' 'review:same-protected-review-job=0'
cmp -s "$STATE_ROOT/issue-retry" "$STATE_ROOT/unrelated-retry"
printf 'PASS continued checkpoint cannot release a changed unrelated gate\n'

fresh_case ineligible
touch "$STATE_ROOT/not-eligible"
cycle_once 75
assert_trace 'review:same-protected-review-job=0' 'executor=0' 'protected-gate-released=0' 'existing-recovery=1'
cmp -s "$STATE_ROOT/issue-retry" "$STATE_ROOT/original-retry"
printf 'PASS ineligible handoff preserves the existing recovery boundary\n'

# The protected Python boundary derives this correction from the existing grant;
# the shell must consume that result without commissioning another review.
fresh_case active_offline_correction
cp "$STATE_ROOT/issue-retry" "$STATE_ROOT/archived-retry"
touch "$STATE_ROOT/active-offline-correction"
cycle_once 0
assert_trace 'protected-existing-grant-correction=1' 'protected-gate-released=1' \
  'protected-existing-grant-correction<protected-gate-released' 'protected-gate-released<executor' \
  'protected-prepare-work-review=0' 'review:same-protected-review-job=0' \
  'existing-recovery=0' 'begin=1' 'executor=1'
cmp -s "$STATE_ROOT/released-retry" "$STATE_ROOT/original-retry"
[[ ! -e $STATE_ROOT/issue-retry ]]
printf 'PASS existing target offline correction resumes normally without another review or recovery\n'
