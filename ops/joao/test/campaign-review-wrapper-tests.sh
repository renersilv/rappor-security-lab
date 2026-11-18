#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091,SC2030,SC2031,SC2034,SC2329
# Exercise the real campaign shell dispatcher with offline boundary doubles.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export TEST_ROOT
export CODEX_BIN="$TEST_ROOT/codex" TIMEOUT_BIN="$TEST_ROOT/timeout"
MODEL=test-model REASONING_EFFORT=test REPOSITORY_SLUG=example/laboratory

queue_comment() {
  local pending
  python3 -c 'import json,sys; from pathlib import Path; Path(sys.argv[1]).write_text(json.dumps({"body":sys.argv[2]}))' "$STATE_ROOT/last-notice.json" "$3"
  pending=$(cat "$STATE_ROOT/notice")
  record "notice:$pending"
  if [[ -f $STATE_ROOT/fail-notice-always ]]; then return 75; fi
  if [[ $pending == continued && -f $STATE_ROOT/fail-notice-once ]]; then
    rm "$STATE_ROOT/fail-notice-once"
    return 75
  fi
}
set_item_phase() {
  printf '%s\n' "$2" > "$STATE_ROOT/operational"
  record "label:$2"
}

cat > "$CODEX_BIN" <<'PY'
#!/usr/bin/env python3
import os
from pathlib import Path
import sys
root = Path(os.environ['STATE_ROOT'])
sys.stdin.read()
with (root / 'trace').open('a') as out:
    out.write('review-model\n')
counter = root / 'model-count'
number = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(number))
if (root / 'repair-on-model').exists():
    (root / 'invalid-response').unlink(missing_ok=True)
print('{"type":"diagnostic","attempt":' + str(number) + '}')
print('private-review-error-' + str(number), file=sys.stderr)
if (root / 'model-timeout').exists():
    sys.exit(124)
PY

cat > "$TIMEOUT_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 && $1 != "$CODEX_BIN" ]]; do shift; done
[[ $# -gt 0 ]]
exec "$@"
SH
chmod 700 "$CODEX_BIN" "$TIMEOUT_BIN"

source "${JOAO_CAMPAIGN_SHELL_SOURCE:-$SCRIPT_DIR/campaign.sh}"

record() { printf '%s\n' "$1" >> "$STATE_ROOT/trace"; }
state_file() { printf '%s/%s\n' "$STATE_ROOT" "$1"; }
log() { :; }
issue_operational_state() { cat "$STATE_ROOT/operational"; }
run_codex() { record executor; }
publication_ready() { [[ ! -f $STATE_ROOT/publication-changed ]]; }

campaign_command() {
  case $1 in
    phase) cat "$STATE_ROOT/phase" ;;
    begin) record begin ;;
    finish) record executor-finish; cat "$STATE_ROOT/phase" ;;
    *) printf 'Unexpected campaign command: %s\n' "$1" >&2; return 98 ;;
  esac
}

campaign_review_command() {
  case $1 in
    settlement-mode|web-zip-mode|work-stop) printf 'none\n' ;;
    web-zip-reconcile) : ;;
    pending-completed-review) printf 'yes\n' ;;
    transport-status) printf '%s\n' "${REVIEW_TRANSPORT_STATUS:-pending}" ;;
    work-review-limit)
      if [[ -f $STATE_ROOT/work-rereview ]]; then printf '3\n'; else printf 'none\n'; fi ;;
    resume-correction|prepare-work-review) printf 'not_eligible\n' ;;
    owner-claim-pending)
      if [[ -f $STATE_ROOT/unreviewed-owner ]]; then printf yes; else printf no; fi ;;
    validate-response)
      if [[ -f $STATE_ROOT/invalid-response ]]; then printf 'regenerate\n'; else printf 'valid\n'; fi ;;
    reconcile)
      record reconcile
      if [[ -f $STATE_ROOT/transition-intent ]]; then
        cp "$STATE_ROOT/transition-intent" "$STATE_ROOT/notice"
        cp "$STATE_ROOT/transition-intent" "$STATE_ROOT/review-phase"
        rm "$STATE_ROOT/transition-intent"
      fi ;;
    notice) cat "$STATE_ROOT/notice" ;;
    notice-body) printf '**Preciso de você:** @owner, conclua o login no cliente do laboratório.\n' ;;
    notice-done) record notice-done; printf 'none\n' > "$STATE_ROOT/notice" ;;
    phase) cat "$STATE_ROOT/review-phase" ;;
    prepare)
      record prepare
      mkdir -p "$STATE_ROOT/job"
      printf 'Offline review prompt.\n' > "$STATE_ROOT/job/prompt.md"
      printf 'reviewing\n' > "$STATE_ROOT/notice"
      printf '%s/job\n' "$STATE_ROOT" ;;
    finish)
      record review-finish
      if [[ -f $STATE_ROOT/require-owner ]]; then
        printf 'owner_required\n' > "$STATE_ROOT/phase"
        printf 'owner_required\n' > "$STATE_ROOT/notice"
      else
        printf 'active\n' > "$STATE_ROOT/phase"
        printf 'continued\n' > "$STATE_ROOT/notice"
      fi
      cp "$STATE_ROOT/notice" "$STATE_ROOT/review-phase"
      cat "$STATE_ROOT/notice" ;;
    *) printf 'Unexpected review command: %s\n' "$1" >&2; return 98 ;;
  esac
}

fresh_case() {
  STATE_ROOT="$TEST_ROOT/$1"
  export STATE_ROOT
  mkdir -p "$STATE_ROOT/worktree"
  : > "$STATE_ROOT/trace"
  printf 'review_pending\n' > "$STATE_ROOT/phase"
  printf 'not_started\n' > "$STATE_ROOT/review-phase"
  printf 'none\n' > "$STATE_ROOT/notice"
  printf 'doing\n' > "$STATE_ROOT/operational"
}

dispatch() {
  local actual=0
  execute_campaign_item 19 "$STATE_ROOT/worktree" test-branch || actual=$?
  [[ $actual == "$1" ]] || {
    printf 'Expected dispatch exit %s, got %s (%s)\n' "$1" "$actual" "$STATE_ROOT" >&2
    cat "$STATE_ROOT/trace" >&2
    return 1
  }
}

assert_trace() {
  python3 - "$STATE_ROOT/trace" "$@" <<'PY'
from pathlib import Path
import sys
events = Path(sys.argv[1]).read_text().splitlines()
for expression in sys.argv[2:]:
    if '=' in expression:
        event, count = expression.rsplit('=', 1)
        assert events.count(event) == int(count), (expression, events)
    else:
        before, after = expression.split('<', 1)
        assert events.index(before) < events.index(after), (expression, events)
PY
}

fresh_case success
dispatch 0
assert_trace 'review-model=1' 'executor=1' 'review-finish<notice:continued' 'notice:continued<executor'
printf 'PASS review_pending review precedes executor\n'

fresh_case notification_retry
touch "$STATE_ROOT/fail-notice-once"
dispatch 0
assert_trace 'review-model=1' 'executor=1'
[[ $(cat "$STATE_ROOT/notice") == continued ]]
dispatch 0
assert_trace 'review-model=1' 'review-finish=1' 'notice:continued=2' 'executor=2'
[[ $(cat "$STATE_ROOT/notice") == none ]]
printf 'PASS failed notice stays pending while authorized work continues\n'

fresh_case notification_outage_owner
touch "$STATE_ROOT/fail-notice-always" "$STATE_ROOT/require-owner"
dispatch 0
assert_trace 'review-model=1' 'executor=0' 'label:blocked=0'
[[ $(cat "$STATE_ROOT/notice") == owner_required ]]
rm "$STATE_ROOT/fail-notice-always"
dispatch 0
assert_trace 'review-model=1' 'executor=0' 'notice:owner_required=2'
[[ $(cat "$STATE_ROOT/notice") == none ]]
printf 'PASS owner gate applies even when its notice cannot be delivered\n'

fresh_case committed_crash
printf 'active\n' > "$STATE_ROOT/phase"
printf 'continued\n' > "$STATE_ROOT/transition-intent"
dispatch 0
assert_trace 'review-model=0' 'review-finish=0' 'notice:continued<executor' 'executor=1'
printf 'PASS committed transition reconciled before executor\n'

fresh_case assisted_operator_checkpoint
printf 'active\n' > "$STATE_ROOT/phase"
printf 'operator_reviewed\n' > "$STATE_ROOT/transition-intent"
dispatch 0
assert_trace 'review-model=0' 'review-finish=0' 'notice:operator_reviewed<executor' 'executor=1'
dispatch 0
assert_trace 'review-model=0' 'notice:operator_reviewed=1' 'executor=2'
printf 'PASS assisted checkpoint dispatches and retains its acknowledged marker\n'

fresh_case owner_action
touch "$STATE_ROOT/require-owner"
dispatch 0
assert_trace 'review-model=1' 'executor=0' 'notice:owner_required=1' 'label:blocked=1'
[[ $(cat "$STATE_ROOT/operational") == blocked ]]
dispatch 0
assert_trace 'review-model=1' 'executor=0' 'notice:owner_required=1'
printf 'PASS owner action notified and blocked without executor\n'

fresh_case review_timeout
touch "$STATE_ROOT/model-timeout"
dispatch 70
assert_trace 'review-model=1' 'executor=0' 'review-finish=0'
python3 - "$STATE_ROOT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in (root / 'job').rglob('*') if p.is_file() and
         (p.suffix == '.jsonl' or p.name.endswith('.log'))}
assert len(files) >= 2, 'Missing failed model stdout/stderr evidence'
(root / 'first-failure-hashes.json').write_text(json.dumps(files))
PY
dispatch 70
assert_trace 'review-model=2' 'executor=0' 'review-finish=0'
python3 - "$STATE_ROOT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
present = {hashlib.sha256(p.read_bytes()).hexdigest()
           for p in (root / 'job').rglob('*') if p.is_file()}
for name, expected in json.loads((root / 'first-failure-hashes.json').read_text()).items():
    assert expected in present, 'Lost prior failed attempt: ' + name
assert not (root / 'job/model-completed').exists()
assert (root / 'phase').read_text().strip() == 'review_pending'
PY
printf 'PASS review timeout returns 70 and preserves both failed attempts\n'

fresh_case cached_invalid_response
mkdir -p "$STATE_ROOT/job"
printf 'Original invalid review must survive.\n' > "$STATE_ROOT/job/events.jsonl"
printf 'completed\n' > "$STATE_ROOT/job/model-completed"
touch "$STATE_ROOT/invalid-response" "$STATE_ROOT/repair-on-model"
dispatch 0
assert_trace 'review-model=1' 'review-finish=1' 'executor=1'
[[ $(cat "$STATE_ROOT/job/model-attempts") == 2 ]]
python3 - "$STATE_ROOT/job" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
assert any(p.read_text() == 'Original invalid review must survive.\n' for p in root.glob('rejected-*/events.jsonl'))
assert len(list(root.glob('request-*.md.sha256'))) == 1
PY
printf 'PASS invalid cached response is preserved and regenerated before continuation\n'

fresh_case bounded_invalid_responses
touch "$STATE_ROOT/invalid-response"
dispatch 70
dispatch 70
dispatch 70
dispatch 70
assert_trace 'review-model=3' 'review-finish=0' 'executor=0'
[[ ! -e $STATE_ROOT/job/model-completed ]]
[[ $(cat "$STATE_ROOT/job/model-attempts") == 3 ]]
printf 'PASS invalid responses cannot consume more than three transports per job\n'

# A historical continued campaign cannot bypass the reconciled evidence stop.
fresh_case exhausted-active
printf 'active\n' > "$STATE_ROOT/phase"
printf 'stalled\n' > "$STATE_ROOT/review-phase"
dispatch 70
if grep -Eq '^(begin|executor|prepare|review-finish)$' "$STATE_ROOT/trace"; then
  printf 'Unexpected execution after the exhausted boundary\n' >&2
  exit 1
fi
printf 'PASS exhausted active campaign does not launch executor or review\n'


fresh_case unreviewed_owner_claim
printf 'owner_required\n' > "$STATE_ROOT/phase"
printf 'continued\n' > "$STATE_ROOT/review-phase"
touch "$STATE_ROOT/unreviewed-owner"
dispatch 0
assert_trace 'review-model=1' 'executor=1' 'review-finish<executor'
printf 'PASS unreviewed owner claim receives independent review before continuation\n'

(
  fresh_case premature_azure_block
  printf 'active\n' > "$STATE_ROOT/phase"
  printf 'continued\n' > "$STATE_ROOT/review-phase"
  run_codex() {
    record executor
    printf 'review_pending\n' > "$STATE_ROOT/phase"
    printf 'blocked\n' > "$STATE_ROOT/operational"
  }
  dispatch 0
  assert_trace 'review-model=1' 'executor=1'
  [[ $(cat "$STATE_ROOT/operational") == blocked ]]
  dispatch 0
  assert_trace 'review-model=1' 'executor=1'
  printf 'PASS premature block cannot skip review or be silently cleared\n'
)

# Exercise the actual review loop with a protected-command double for the wider
# recovery allowance. A work handoff cannot inherit that unrelated allowance.
# SCRIPT_DIR changes intentionally stay inside each isolated subshell fixture.
for recovery_limit in 6 9; do
  (
    fresh_case "work_budget_${recovery_limit}"
    original_script_dir=$SCRIPT_DIR
    SCRIPT_DIR="$STATE_ROOT/review-support"
    mkdir -p "$SCRIPT_DIR" "$STATE_ROOT/job"
    cp "$original_script_dir/CAMPAIGN_REVIEW_PROMPT.md" "$SCRIPT_DIR/"
    printf 'print("Synthetic objective status.")\n' > "$SCRIPT_DIR/objectives.py"
    printf 'import sys\nassert sys.argv[1] == "review-limit"\nprint(%s)\n' "$recovery_limit" > "$SCRIPT_DIR/recovery.py"
    touch "$STATE_ROOT/work-rereview" "$STATE_ROOT/model-timeout"
    printf '2\n' > "$STATE_ROOT/job/model-attempts"
    result=0
    run_campaign_review "$STATE_ROOT/worktree" || result=$?
    [[ $result == 70 ]]
    assert_trace 'review-model=1' 'review-finish=0' 'executor=0'
    [[ $(cat "$STATE_ROOT/job/model-attempts") == 3 ]]
    # Reload the real dispatcher as a service restart would; persisted use wins.
    review_command_double=$(declare -f campaign_review_command)
    source "${JOAO_CAMPAIGN_SHELL_SOURCE:-$original_script_dir/campaign.sh}"
    eval "$review_command_double"
    result=0
    run_campaign_review "$STATE_ROOT/worktree" || result=$?
    [[ $result == 70 ]]
    assert_trace 'review-model=1' 'review-finish=0' 'executor=0'
    [[ $(cat "$STATE_ROOT/job/model-attempts") == 3 ]]
    printf 'PASS work review inherits two attempts and stops at three despite recovery limit %s across restart\n' "$recovery_limit"
  )
  (
    fresh_case "work_budget_exhausted_${recovery_limit}"
    original_script_dir=$SCRIPT_DIR
    SCRIPT_DIR="$STATE_ROOT/review-support"
    mkdir -p "$SCRIPT_DIR" "$STATE_ROOT/job"
    cp "$original_script_dir/CAMPAIGN_REVIEW_PROMPT.md" "$SCRIPT_DIR/"
    printf 'print("Synthetic objective status.")\n' > "$SCRIPT_DIR/objectives.py"
    printf 'import sys\nassert sys.argv[1] == "review-limit"\nprint(%s)\n' "$recovery_limit" > "$SCRIPT_DIR/recovery.py"
    touch "$STATE_ROOT/work-rereview" "$STATE_ROOT/model-timeout"
    printf '3\n' > "$STATE_ROOT/job/model-attempts"
    result=0
    run_campaign_review "$STATE_ROOT/worktree" || result=$?
    [[ $result == 70 ]]
    assert_trace 'review-model=0' 'review-finish=0' 'executor=0'
    [[ $(cat "$STATE_ROOT/job/model-attempts") == 3 ]]
    printf 'PASS exhausted work review cannot inherit recovery limit %s\n' "$recovery_limit"
  )
done

fresh_case publication_changed_after_review
touch "$STATE_ROOT/publication-changed"
dispatch 0
assert_trace 'review-model=1' 'executor=0'
printf 'PASS publication is revalidated after review before execution\n'

# The completed-evidence lane must expose exhaustion while preserving the real
# model-attempts guard across notice retries and a service-source reload.
(
  fresh_case completed_review_exhaustion_notice
  original_script_dir=$SCRIPT_DIR
  SCRIPT_DIR="$STATE_ROOT/review-support"
  mkdir -p "$SCRIPT_DIR" "$STATE_ROOT/job"
  cp "$original_script_dir/CAMPAIGN_REVIEW_PROMPT.md" "$SCRIPT_DIR/"
  printf 'print("Synthetic objective status.")\n' > "$SCRIPT_DIR/objectives.py"
  printf 'import sys\nassert sys.argv[1] == "review-limit"\nprint(3)\n' > "$SCRIPT_DIR/recovery.py"
  touch "$STATE_ROOT/model-timeout"
  printf '2\n' > "$STATE_ROOT/job/model-attempts"
  printf 'preserved old executor gate\n' > "$STATE_ROOT/issue-retry"
  REVIEW_TRANSPORT_STATUS=exhausted NOTICE_RESULT=75
  queue_comment() {
    if [[ $2 == '<!-- joao-campaign-review-transport:19 -->' ]]; then
      record cap-notice
      printf '%s\n' "$3" > "$STATE_ROOT/cap-notice-body"
      (( NOTICE_RESULT == 0 )) || return "$NOTICE_RESULT"
      # The production Azure adapter upserts by the stable marker; model one row.
      printf '%s\n' "$3" > "$STATE_ROOT/published-cap-notice"
      return 0
    fi
    record ordinary-notice
  }
  result=0
  campaign_pending_review_dispatch "$STATE_ROOT/worktree" || result=$?
  [[ $result == 75 && $(cat "$STATE_ROOT/job/model-attempts") == 3 ]]
  assert_trace 'review-model=1' 'cap-notice=1' 'review-finish=0' 'executor=0'
  [[ ! -f $STATE_ROOT/published-cap-notice ]]
  review_command_double=$(declare -f campaign_review_command)
  source "${JOAO_CAMPAIGN_SHELL_SOURCE:-$original_script_dir/campaign.sh}"
  eval "$review_command_double"
  NOTICE_RESULT=0
  for iteration in 1 2; do
    result=0
    campaign_pending_review_dispatch "$STATE_ROOT/worktree" || result=$?
    [[ $result == 75 ]]
  done
  assert_trace 'review-model=1' 'cap-notice=3' 'review-finish=0' 'executor=0'
  cmp -s "$STATE_ROOT/published-cap-notice" "$STATE_ROOT/cap-notice-body"
  grep -q 'esgotou as tentativas de transporte autorizadas' "$STATE_ROOT/published-cap-notice"
  grep -q 'execução permanece suspensa' "$STATE_ROOT/published-cap-notice"
  if grep -q -E 'retoma|cinco minutos|Preciso de você' "$STATE_ROOT/published-cap-notice"; then exit 1; fi
  NOTICE_RESULT=65
  result=0
  campaign_pending_review_dispatch "$STATE_ROOT/worktree" || result=$?
  [[ $result == 65 ]]
  assert_trace 'review-model=1' 'cap-notice=4'
  [[ $(cat "$STATE_ROOT/job/model-attempts") == 3 && $(cat "$STATE_ROOT/issue-retry") == 'preserved old executor gate' ]]
  REVIEW_TRANSPORT_STATUS=hard_limit NOTICE_RESULT=0
  result=0
  campaign_pending_review_dispatch "$STATE_ROOT/worktree" || result=$?
  [[ $result == 75 ]]
  assert_trace 'review-model=1' 'cap-notice=5'
  printf 'PASS exhausted review notice retries delivery without another model or quota reset; fatal persistence errors propagate\n'
)
