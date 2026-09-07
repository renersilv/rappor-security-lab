#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034,SC2329
set -euo pipefail

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(CDPATH='' cd -- "$TEST_DIR/../../.." && pwd)
RUNNER="$ROOT/ops/joao/run.sh"
CONTROL="$ROOT/ops/joao/control.sh"

assert_equal() {
  local expected=$1 actual=$2 message=$3
  if [[ $expected != "$actual" ]]; then
    printf 'not ok - %s (expected %s, got %s)\n' "$message" "$expected" "$actual" >&2
    return 1
  fi
}

new_sandbox() {
  TEST_SANDBOX=$(mktemp -d)
  export JOAO_STATE_ROOT="$TEST_SANDBOX/state"
  export JOAO_REPOSITORY_PATH="$TEST_SANDBOX/repository"
  export JOAO_BATCH_STAMP=20260907T000000Z
  export JOAO_SOURCE_ONLY=1
  mkdir -p "$JOAO_STATE_ROOT" "$JOAO_REPOSITORY_PATH"
  source "$RUNNER"
  chmod 700 "$JOAO_STATE_ROOT"
}

remove_sandbox() {
  [[ -z ${TEST_SANDBOX:-} ]] || rm -rf -- "$TEST_SANDBOX"
}

test_fixed_batch_and_delivery() (
  trap remove_sandbox EXIT
  new_sandbox
  CURRENT_DOING=
  DELIVERED=
  PROCESSED=
  TODO_LIST=$'2\n3'

  list_open_with_label() {
    if [[ $1 == doing ]]; then
      [[ -z $CURRENT_DOING ]] || printf '%s\n' "$CURRENT_DOING"
    else
      printf '%s\n' "$TODO_LIST"
    fi
  }
  issue_is_eligible() { return 0; }
  mock_git() {
    if [[ $* == *"rev-parse origin/main"* || $* == *"rev-parse HEAD"* ]]; then
      printf '%040d\n' 0
    elif [[ $* == *"worktree add"* ]]; then
      mkdir -p "$(read_state worktree)"
    fi
  }
  mock_gh() {
    local issue=$3
    CURRENT_DOING=$issue
  }
  GIT_BIN=mock_git
  GH_BIN=mock_gh
  capture_batch
  assert_equal $'2\n3' "$(cat "$(state_file batch)")" "capture stores the initial ordered batch"

  TODO_LIST=$'2\n3\n8'
  issue_has_label() {
    local issue=$1 label=$2
    [[ $label == to-do ]] && return 0
    [[ $label == validating && " $DELIVERED " == *" $issue "* ]]
  }
  run_codex() {
    PROCESSED+=" $1"
    DELIVERED+=" $1"
    CURRENT_DOING=
  }
  verify_delivery() { return 0; }
  execute_issues
  assert_equal " 2 3" "$PROCESSED" "new Issue is excluded from the fixed batch"
  assert_equal integration "$(read_state phase)" "delivery advances to integration"
  assert_equal 3 "$(read_state next)" "delivery advances the cursor"
)

test_owner_or_explicit_approval() (
  trap remove_sandbox EXIT
  new_sandbox
  eligibility_gh() {
    if [[ $1 == issue ]]; then
      [[ $3 == 2 ]] && printf 'renersilv\n' || printf 'contributor\n'
    elif [[ $2 == *"/issues/7/comments" ]]; then
      printf 'true\n'
    else
      printf 'false\n'
    fi
  }
  GH_BIN=eligibility_gh
  issue_is_eligible 2
  issue_is_eligible 7
  if issue_is_eligible 8; then
    printf 'not ok - unapproved external Issue was eligible\n' >&2
    return 1
  fi
)

prepare_resumable_issue() {
  local issue=$1 branch worktree
  branch="joao/batch-20260907T000000Z-$issue-$issue"
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  printf '%s\n' "$issue" > "$(state_file batch)"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state base_sha 0000000000000000000000000000000000000000
  write_state issue_base_sha 0000000000000000000000000000000000000000
  write_state next 1
  write_state phase issues
  mkdir -p "$worktree"
}

test_session_resume() (
  trap remove_sandbox EXIT
  new_sandbox
  prepare_resumable_issue 5
  write_state current_issue 5
  write_state session 11111111-1111-1111-1111-111111111111
  list_open_with_label() { [[ $1 != doing ]] || printf '5\n'; }
  issue_has_label() { [[ $2 == validating ]]; }
  verify_delivery() { return 0; }
  run_codex() {
    assert_equal 11111111-1111-1111-1111-111111111111 "$(read_state session)" "saved session is resumed"
  }
  execute_issues
  [[ ! -e $(state_file session) ]]
  assert_equal integration "$(read_state phase)" "resumed delivery completes"
)

test_doing_uniqueness() (
  trap remove_sandbox EXIT
  new_sandbox
  prepare_resumable_issue 6
  list_open_with_label() { [[ $1 != doing ]] || printf '6\n9\n'; }
  set +e
  execute_issues >/dev/null 2>&1
  result=$?
  set -e
  [[ $result -ne 0 ]]
  [[ -f $(state_file suspended) ]]
  assert_equal 1 "$(read_state next)" "uniqueness failure preserves cursor"
)

test_timeout_preserves_resume() (
  trap remove_sandbox EXIT
  new_sandbox
  prepare_resumable_issue 6
  list_open_with_label() { [[ $1 != doing ]] || printf '6\n'; }
  run_codex() { return 124; }
  set +e
  execute_issues >/dev/null 2>&1
  result=$?
  set -e
  assert_equal 124 "$result" "timeout is propagated"
  assert_equal 6 "$(read_state current_issue)" "timeout preserves current Issue"
  assert_equal 1 "$(read_state next)" "timeout preserves cursor"
  [[ ! -e $(state_file suspended) ]]
)

test_codex_session_and_parameters() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-7-7
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  mkdir -p "$worktree"
  : > "$TEST_SANDBOX/codex.log"
  : > "$TEST_SANDBOX/timeout.log"
  mock_timeout() {
    printf '%s\n' "$1 $2 $3" >> "$TEST_SANDBOX/timeout.log"
    shift 3
    "$@"
  }
  mock_codex() {
    printf '%s\n' "$*" >> "$TEST_SANDBOX/codex.log"
    cat >/dev/null
    printf '{"type":"thread.started","thread_id":"11111111-1111-1111-1111-111111111111"}\n'
  }
  TIMEOUT_BIN=mock_timeout
  CODEX_BIN=mock_codex
  run_codex 7 "$worktree" "$branch"
  assert_equal 11111111-1111-1111-1111-111111111111 "$(read_state session)" "new execution saves its session"
  run_codex 7 "$worktree" "$branch"
  [[ $(cat "$TEST_SANDBOX/codex.log") == *"exec -C $worktree -m gpt-5.6-sol"* ]]
  [[ $(cat "$TEST_SANDBOX/codex.log") == *'model_reasoning_effort="xhigh"'* ]]
  [[ $(cat "$TEST_SANDBOX/codex.log") == *"exec resume -m gpt-5.6-sol"* ]]
  assert_equal $'--signal=TERM --kill-after=30s 3h\n--signal=TERM --kill-after=30s 3h' \
    "$(cat "$TEST_SANDBOX/timeout.log")" "timeout is applied per new and resumed execution"
)

test_wrapper_integration_and_final_states() (
  trap remove_sandbox EXIT
  new_sandbox
  printf '2\n3\n' > "$(state_file batch)"
  branch=joao/batch-20260907T000000Z-2-3
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state base_sha 0000000000000000000000000000000000000000
  write_state next 3
  write_state phase integration
  mkdir -p "$worktree"
  : > "$TEST_SANDBOX/git.log"
  : > "$TEST_SANDBOX/done.log"
  preflight() { return 0; }
  mock_git() {
    printf '%s\n' "$*" >> "$TEST_SANDBOX/git.log"
    return 0
  }
  mock_npm() { return 0; }
  mock_gh() {
    if [[ $* == *"--add-label done"* ]]; then
      printf '%s\n' "$3" >> "$TEST_SANDBOX/done.log"
    fi
  }
  issue_has_label() { return 1; }
  GIT_BIN=mock_git
  NPM_BIN=mock_npm
  GH_BIN=mock_gh
  integrate_batch
  assert_equal $'2\n3' "$(cat "$TEST_SANDBOX/done.log")" "wrapper finalizes delivered Issues"
  [[ $(cat "$TEST_SANDBOX/git.log") == *"push origin main"* ]]
  [[ ! -e $(state_file batch) ]]
)

test_control_status_and_resume() (
  trap remove_sandbox EXIT
  new_sandbox
  printf '4\n5\n' > "$(state_file batch)"
  write_state branch joao/batch-20260907T000000Z-4-5
  write_state phase issues
  write_state current_issue 4
  write_state session private-session-identifier
  write_state suspended true
  mock_systemctl="$TEST_SANDBOX/systemctl"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" > "%s/systemctl.log"\n' "$TEST_SANDBOX" > "$mock_systemctl"
  chmod +x "$mock_systemctl"
  status_output=$(JOAO_STATE_ROOT="$JOAO_STATE_ROOT" "$CONTROL" status)
  [[ $status_output == *"session_saved=yes"* ]]
  [[ $status_output != *"private-session-identifier"* ]]
  JOAO_STATE_ROOT="$JOAO_STATE_ROOT" JOAO_SYSTEMCTL_BIN="$mock_systemctl" "$CONTROL" resume >/dev/null
  [[ -f $(state_file batch) ]]
  [[ ! -e $(state_file suspended) ]]
  assert_equal "--user start joao.service" "$(cat "$TEST_SANDBOX/systemctl.log")" "resume starts the service"
)

test_fixed_batch_and_delivery
test_owner_or_explicit_approval
test_session_resume
test_doing_uniqueness
test_timeout_preserves_resume
test_codex_session_and_parameters
test_wrapper_integration_and_final_states
test_control_status_and_resume
printf 'ok - joao runner scenarios\n'
