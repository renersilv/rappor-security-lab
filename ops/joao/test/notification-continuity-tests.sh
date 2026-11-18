#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034,SC2329
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
STATE_ROOT=$TEST_ROOT MODEL=synthetic REASONING_EFFORT=test REPOSITORY_PATH=$TEST_ROOT
# shellcheck source=ops/joao/recovery.sh
source "$SCRIPT_DIR/recovery.sh"
queue_comment() { printf 'send\n' >> "$TEST_ROOT/events"; if [[ -f $TEST_ROOT/outage ]]; then return 75; fi; }
log() { :; }
python3() {
 case $2 in
  notice) printf 'Synthetic notification.\n' ;;
  supervise) printf 'supervise\n' >> "$TEST_ROOT/events"; printf yes > "$TEST_ROOT/pending" ;;
  phase) printf 'failed\n' ;;
  notice-pending) cat "$TEST_ROOT/pending" ;;
  notice-done) if [[ -f $TEST_ROOT/persist-failure ]]; then return 65; fi; printf no > "$TEST_ROOT/pending"; printf 'ack\n' >> "$TEST_ROOT/events" ;;
  *) return 99 ;;
 esac
}
touch "$TEST_ROOT/outage"
printf yes > "$TEST_ROOT/pending"
recover_campaign_failure
[[ $(cat "$TEST_ROOT/pending") == yes ]]
[[ $(grep -c '^supervise$' "$TEST_ROOT/events") == 1 ]]
if grep -q '^ack$' "$TEST_ROOT/events"; then exit 1; fi
recovery_flush_notice
[[ $(cat "$TEST_ROOT/pending") == yes ]]
rm "$TEST_ROOT/outage"
recovery_flush_notice
[[ $(cat "$TEST_ROOT/pending") == no ]]
[[ $(grep -c '^ack$' "$TEST_ROOT/events") == 1 ]]
recovery_flush_notice
[[ $(grep -c '^ack$' "$TEST_ROOT/events") == 1 ]]
printf 'PASS notification outage preserves pending state and does not gate recovery\n'

printf yes > "$TEST_ROOT/pending"
touch "$TEST_ROOT/persist-failure"
result=0
recovery_flush_notice || result=$?
[[ $result == 65 ]]
[[ $(cat "$TEST_ROOT/pending") == yes ]]
printf 'PASS notification acknowledgment persistence failure remains fatal\n'
