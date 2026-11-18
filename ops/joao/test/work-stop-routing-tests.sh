#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034,SC2329
set -euo pipefail
ROOT=${JOAO_TEST_SOURCE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export JOAO_SOURCE_ONLY=1 JOAO_STATE_ROOT="$TEST_ROOT/state"
mkdir -p "$JOAO_STATE_ROOT"
source "$ROOT/ops/joao/run.sh"
log() { :; }
STOP=offline_preparation_exhausted
campaign_review_flush_notice() { :; }
campaign_review_command() {
  case $1 in
    phase) printf 'stalled\n' ;;
    resume-correction|prepare-work-review) printf 'not_eligible\n' ;;
    work-stop|record-work-stop) printf '%s\n' "$STOP" ;;
    *) return 65 ;;
  esac
}
for iteration in 1 2 3; do
  status=0
  campaign_work_review_dispatch "$TEST_ROOT" || status=$?
  if [[ $status != 75 ]]; then
    printf 'FAIL exhausted preparation fell through to operational recovery: exit %s\n' "$status" >&2
    exit 1
  fi
done
printf 'PASS exhausted preparation stops before operational recovery on repeated activations\n'
STOP=none
status=0
campaign_work_review_dispatch "$TEST_ROOT" || status=$?
[[ $status == 0 ]]
printf 'PASS unrelated operational recovery remains available\n'

# A newly rejected review must not create the first operational retry either.
STOP=offline_preparation_exhausted
campaign_enabled() { return 0; }
candidate_repair_dispatch() { return 0; }
execute_campaign_item() { return 70; }
record_issue_failure() { printf 'forbidden-retry\n' >> "$TEST_ROOT/mutations"; }
clear_issue_retry() { printf 'forbidden-clear\n' >> "$TEST_ROOT/mutations"; }
status=0
execute_staged_item 19 "$TEST_ROOT" joao/batch-20261118T000000Z-19-19 || status=$?
[[ $status == 0 && ! -e $TEST_ROOT/mutations ]]
printf 'PASS fresh exhausted rejection neither inflates nor clears operational retry state\n'
