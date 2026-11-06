#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091,SC2034,SC2329
# Exercise the real campaign shell dispatcher with offline boundary doubles.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export TEST_ROOT
export GH_BIN="$TEST_ROOT/gh" CODEX_BIN="$TEST_ROOT/codex" TIMEOUT_BIN="$TEST_ROOT/timeout"
MODEL=test-model REASONING_EFFORT=test REPOSITORY_SLUG=example/laboratory

cat > "$GH_BIN" <<'PY'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ['STATE_ROOT'])
args = sys.argv[1:]
def event(value):
    with (root / 'trace').open('a') as out:
        out.write(value + '\n')
if args[:2] == ['issue', 'edit']:
    label = args[args.index('--add-label') + 1]
    (root / 'operational').write_text(label)
    event('label:' + label)
elif args[:1] == ['api'] and '--method' not in args:
    print('123')
elif args[:1] == ['api'] and '--input' in args:
    payload = json.loads(Path(args[args.index('--input') + 1]).read_text())
    (root / 'last-notice.json').write_text(json.dumps(payload))
    pending = (root / 'notice').read_text().strip()
    event('notice:' + pending)
    if pending == 'continued' and (root / 'fail-notice-once').exists():
        (root / 'fail-notice-once').unlink()
        sys.exit(23)
else:
    event('unexpected-github-command')
    sys.exit(98)
PY

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
chmod 700 "$GH_BIN" "$CODEX_BIN" "$TIMEOUT_BIN"

source "$SCRIPT_DIR/campaign.sh"

record() { printf '%s\n' "$1" >> "$STATE_ROOT/trace"; }
state_file() { printf '%s/%s\n' "$STATE_ROOT" "$1"; }
log() { :; }
issue_operational_state() { cat "$STATE_ROOT/operational"; }
run_codex() { record executor; }

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
dispatch 23
assert_trace 'review-model=1' 'executor=0'
[[ $(cat "$STATE_ROOT/phase") == active ]]
dispatch 0
assert_trace 'review-model=1' 'review-finish=1' 'notice:continued=2' 'executor=1'
python3 - "$STATE_ROOT/trace" <<'PY'
from pathlib import Path
import sys
events = Path(sys.argv[1]).read_text().splitlines()
assert max(i for i, v in enumerate(events) if v == 'notice:continued') < events.index('executor')
PY
printf 'PASS failed committed notice recovered before executor without another model\n'

fresh_case committed_crash
printf 'active\n' > "$STATE_ROOT/phase"
printf 'continued\n' > "$STATE_ROOT/transition-intent"
dispatch 0
assert_trace 'review-model=0' 'review-finish=0' 'notice:continued<executor' 'executor=1'
printf 'PASS committed transition reconciled before executor\n'

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
! grep -Eq '^(begin|executor|prepare|review-finish)$' "$STATE_ROOT/trace"
printf 'PASS exhausted active campaign does not launch executor or review\n'
