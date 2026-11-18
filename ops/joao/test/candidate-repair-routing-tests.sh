#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034,SC2329
set -euo pipefail
ROOT=${JOAO_TEST_SOURCE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)}
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export JOAO_SOURCE_ONLY=1 JOAO_STATE_ROOT="$TEST_ROOT/state"
mkdir -p "$JOAO_STATE_ROOT"
source "$ROOT/ops/joao/run.sh"
campaign_enabled() { return 0; }
candidate_repair_dispatch() { printf 'repair\n' >> "$TEST_ROOT/events"; return 75; }
execute_campaign_item() { printf 'executor\n' >> "$TEST_ROOT/events"; return 70; }
campaign_review_command() { if [[ $1 == pending-completed-review ]]; then printf 'no\n'; else printf 'campaign_70_fixture'; fi; }
record_issue_failure() { printf 'transport-failure\n' >> "$TEST_ROOT/events"; }
clear_issue_retry() { printf 'clear-retry\n' >> "$TEST_ROOT/events"; }
recover_campaign_failure() { printf 'wrong-recovery\n' >> "$TEST_ROOT/events"; }
: > "$TEST_ROOT/events"
for iteration in 1 2 3; do
  status=0
  execute_staged_item 19 "$TEST_ROOT" joao/batch-20261115T000000Z-19-19 || status=$?
  if [[ $status != 0 ]]; then
    printf 'FAIL expected handled offline repair, got exit %s and events: %s\n' "$status" "$(cat "$TEST_ROOT/events")" >&2
    exit 1
  fi
done
[[ $(cat "$TEST_ROOT/events") == $'repair\nrepair\nrepair' ]]
printf 'PASS rejected review dispatches repair without executor, retry inflation or gate deletion\n'
: > "$TEST_ROOT/events"
status=0
check_issue_retry_gate 19 joao/batch-20261115T000000Z-19-19 || status=$?
[[ $status == 75 && $(cat "$TEST_ROOT/events") == repair ]]
printf 'PASS repair is reached before the old operational retry gate\n'

# An unrelated transport failure still uses its existing bounded retry path.
: > "$TEST_ROOT/events"
candidate_repair_dispatch() { return 0; }
status=0
execute_staged_item 19 "$TEST_ROOT" joao/batch-20261115T000000Z-19-19 || status=$?
[[ $status == 70 && $(cat "$TEST_ROOT/events") == $'executor\ntransport-failure' ]]
printf 'PASS genuine transport failures preserve the original recovery boundary\n'
