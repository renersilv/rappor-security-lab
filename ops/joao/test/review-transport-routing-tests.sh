#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091,SC2034,SC2317
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
source "${JOAO_CAMPAIGN_SHELL_SOURCE:-$ROOT/campaign.sh}"
STATE_ROOT=$TMP
log() { :; }
record() { printf '%s\n' "$1" >> "$TMP/trace"; }
campaign_review_command() {
  case $1 in
    phase) printf 'review_pending\n' ;;
    transport-status) printf '%s\n' "$STATUS" ;;
    record-transport-exhaustion)
      record reconcile-consumed
      [[ $STATUS != invalid ]]
      : > "$TMP/recorded" ;;
    *) return 98 ;;
  esac
}
run_campaign_review() { record review-dispatch; return 70; }
recover_campaign_failure() {
  [[ -f $TMP/recorded ]]
  record recover
  [[ ! -e $TMP/terminal ]] || return 0
  : > "$TMP/terminal"
  record one-diagnosis
}
: > "$TMP/trace"
STATUS=exhausted
for _ in 1 2 3; do
  actual=0
  campaign_work_review_dispatch /synthetic/worktree || actual=$?
  [[ $actual == 75 ]]
done
[[ $(grep -c '^recover$' "$TMP/trace" || :) == 3 ]]
[[ $(grep -c '^one-diagnosis$' "$TMP/trace" || :) == 1 ]]
printf 'PASS exhausted review reaches recovery and terminal recovery does not restart diagnosis\n'
for STATUS in pending hard_limit verdict_pending not_pending; do
  : > "$TMP/trace"
  actual=0
  campaign_work_review_dispatch /synthetic/worktree || actual=$?
  [[ $actual == 75 ]]
  [[ $(grep -c '^recover$' "$TMP/trace" || :) == 0 ]]
done
printf 'PASS unconsumed review, hard work limit and verdict do not trigger generic recovery\n'
