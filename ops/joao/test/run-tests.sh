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
  PROCESSED=
  TODO_LIST=$'2\n3'
  declare -A OPS=([2]=to-do [3]=to-do [8]=to-do)
  : > "$TEST_SANDBOX/git.log"

  list_open_with_label() {
    if [[ $1 == doing ]]; then
      [[ -z $CURRENT_DOING ]] || printf '%s\n' "$CURRENT_DOING"
    else
      printf '%s\n' "$TODO_LIST"
    fi
  }
  issue_is_eligible() { return 0; }
  validate_worktree() { return 0; }
  mock_git() {
    printf '%s\n' "$*" >> "$TEST_SANDBOX/git.log"
    if [[ $* == *"rev-parse origin/main"* || $* == *"rev-parse HEAD"* ]]; then
      printf '%040d\n' 0
    elif [[ $* == *"show-ref --verify"* ]]; then
      return 1
    elif [[ $* == *"worktree add"* ]]; then
      [[ -f $(state_file batch) ]]
      assert_equal setup "$(read_state phase)" "batch is published only after setup state"
      mkdir -p "$(read_state worktree)"
    fi
  }
  mock_gh() {
    local issue=$3
    OPS[$issue]=doing
    CURRENT_DOING=$issue
  }
  GIT_BIN=mock_git
  GH_BIN=mock_gh
  capture_batch
  assert_equal $'2\n3' "$(cat "$(state_file batch)")" "capture stores the initial ordered batch"
  [[ $(cat "$TEST_SANDBOX/git.log") == *"worktree add -b joao/batch-20260907T000000Z-2-3"*"0000000000000000000000000000000000000000"* ]]

  TODO_LIST=$'2\n3\n8'
  issue_operational_state() { printf '%s' "${OPS[$1]}"; }
  run_codex() {
    PROCESSED+=" $1"
    OPS[$1]=validating
    CURRENT_DOING=
  }
  verify_delivery() { return 0; }
  execute_issues
  assert_equal " 2 3" "$PROCESSED" "new Issue is excluded from the fixed batch"
  assert_equal integration "$(read_state phase)" "delivery advances to integration"
  assert_equal 3 "$(read_state next)" "delivery advances the cursor"
  assert_equal $'2\n3' "$(cat "$(state_file delivered)")" "delivery list is private and exact"
)

test_owner_or_explicit_approval() (
  trap remove_sandbox EXIT
  new_sandbox
  issue_operational_state() { printf 'to-do'; }
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
  write_state current_issue "$issue"
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
  OP_STATE=doing
  list_open_with_label() { [[ $1 != doing || $OP_STATE != doing ]] || printf '5\n'; }
  issue_operational_state() { printf '%s' "$OP_STATE"; }
  verify_delivery() { return 0; }
  run_codex() {
    assert_equal 11111111-1111-1111-1111-111111111111 "$(read_state session)" "saved session is resumed"
    OP_STATE=validating
  }
  execute_issues
  [[ ! -e $(state_file session) ]]
  assert_equal integration "$(read_state phase)" "resumed delivery completes"
)

test_doing_uniqueness() (
  trap remove_sandbox EXIT
  new_sandbox
  prepare_resumable_issue 6
  issue_operational_state() { printf 'doing'; }
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
  issue_operational_state() { printf 'doing'; }
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

test_reboot_recovers_surviving_jsonl() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-7-7
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  mkdir -p "$worktree"
  printf '{"type":"thread.started","thread_id":"22222222-2222-2222-2222-222222222222"}\n' > \
    "$(state_file codex-events.jsonl)"
  mock_timeout() { shift 3; "$@"; }
  mock_codex() {
    printf '%s\n' "$*" > "$TEST_SANDBOX/recovered.log"
    cat >/dev/null
  }
  TIMEOUT_BIN=mock_timeout
  CODEX_BIN=mock_codex
  run_codex 7 "$worktree" "$branch"
  [[ $(cat "$TEST_SANDBOX/recovered.log") == *"exec resume -m gpt-5.6-sol"* ]]
  [[ $(cat "$TEST_SANDBOX/recovered.log") == *"22222222-2222-2222-2222-222222222222"* ]]
)

test_timeout_preserves_jsonl_and_session() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-7-7
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  mkdir -p "$worktree"
  mock_timeout() {
    shift 3
    "$@"
    return 124
  }
  mock_codex() {
    cat >/dev/null
    printf '{"type":"thread.started","thread_id":"33333333-3333-3333-3333-333333333333"}\n'
  }
  TIMEOUT_BIN=mock_timeout
  CODEX_BIN=mock_codex
  set +e
  run_codex 7 "$worktree" "$branch" >/dev/null
  result=$?
  set -e
  assert_equal 124 "$result" "Codex timeout is preserved"
  assert_equal 33333333-3333-3333-3333-333333333333 "$(read_state session)" "timeout saves session"
  [[ -s $(state_file codex-events.jsonl) ]]
)

test_validating_crash_recovery_skips_codex() (
  trap remove_sandbox EXIT
  new_sandbox
  prepare_resumable_issue 9
  : > "$(state_file delivered)"
  : > "$(state_file not_delivered)"
  issue_operational_state() { printf 'validating'; }
  list_open_with_label() { return 0; }
  verify_delivery() { return 0; }
  run_codex() {
    printf 'not ok - validating recovery reexecuted Codex\n' >&2
    return 1
  }
  execute_issues
  assert_equal 9 "$(cat "$(state_file delivered)")" "validating crash recovery records delivery"
  assert_equal integration "$(read_state phase)" "validating crash recovery advances"
)

test_issue_boundary_recovery_is_idempotent() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-10-11
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  printf '10\n11\n' > "$(state_file batch)"
  printf '10\n' > "$(state_file delivered)"
  : > "$(state_file not_delivered)"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state base_sha 0000000000000000000000000000000000000000
  write_state next 2
  write_state phase issues
  write_state current_issue 10
  write_state issue_base_sha 1111111111111111111111111111111111111111
  write_state session 11111111-1111-1111-1111-111111111111
  mkdir -p "$worktree"
  OP_STATE=validating
  VERIFY_COUNT=0
  CODEX_COUNT=0
  issue_operational_state() { printf '%s' "$OP_STATE"; }
  list_open_with_label() { return 0; }
  verify_delivery() { VERIFY_COUNT=$((VERIFY_COUNT + 1)); }
  run_codex() { CODEX_COUNT=$((CODEX_COUNT + 1)); }
  boundary_git() {
    [[ $* != *"rev-parse HEAD"* ]] || printf '2222222222222222222222222222222222222222\n'
  }
  GIT_BIN=boundary_git
  execute_issues
  assert_equal 1 "$VERIFY_COUNT" "only the unrecorded cursor Issue is verified"
  assert_equal 0 "$CODEX_COUNT" "recorded and validating Issues do not rerun Codex"
  assert_equal $'10\n11' "$(cat "$(state_file delivered)")" "boundary recovery appends once"
  [[ ! -e $(state_file current_issue) ]]
  [[ ! -e $(state_file issue_base_sha) ]]
  assert_equal 3 "$(read_state next)" "boundary recovery advances the cursor once"
)

test_recorded_cursor_after_cleanup_skips_validation() (
  trap remove_sandbox EXIT
  new_sandbox
  prepare_resumable_issue 12
  printf '12\n' > "$(state_file delivered)"
  : > "$(state_file not_delivered)"
  clear_item_state
  write_state issue_base_sha 1111111111111111111111111111111111111111
  write_state session 11111111-1111-1111-1111-111111111111
  issue_operational_state() { printf 'not ok - recorded cursor was revalidated\n' >&2; return 1; }
  list_open_with_label() { return 0; }
  run_codex() { printf 'not ok - recorded cursor reran Codex\n' >&2; return 1; }
  execute_issues
  [[ ! -e $(state_file issue_base_sha) ]]
  [[ ! -e $(state_file session) ]]
  assert_equal 2 "$(read_state next)" "post-cleanup crash advances the cursor once"
  assert_equal integration "$(read_state phase)" "post-cleanup crash completes issue phase"
)

test_blocked_issue_does_not_stop_independent_delivery() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-4-5
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  printf '4\n5\n' > "$(state_file batch)"
  : > "$(state_file delivered)"
  : > "$(state_file not_delivered)"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state base_sha 0000000000000000000000000000000000000000
  write_state issue_base_sha 0000000000000000000000000000000000000000
  write_state current_issue 4
  write_state next 1
  write_state phase issues
  mkdir -p "$worktree"
  declare -A OPS=([4]=blocked [5]=to-do)
  CURRENT_DOING=
  PROCESSED=
  issue_operational_state() { printf '%s' "${OPS[$1]}"; }
  list_open_with_label() { [[ $1 != doing || -z $CURRENT_DOING ]] || printf '%s\n' "$CURRENT_DOING"; }
  validate_worktree() { return 0; }
  mock_git() {
    case "$*" in
      *"status --porcelain"*) ;;
      *"rev-parse HEAD"*) printf '%040d\n' 0 ;;
    esac
  }
  mock_gh() {
    OPS[$3]=doing
    CURRENT_DOING=$3
  }
  run_codex() {
    PROCESSED+=" $1"
    OPS[$1]=validating
    CURRENT_DOING=
  }
  verify_delivery() { return 0; }
  GIT_BIN=mock_git
  GH_BIN=mock_gh
  execute_issues
  assert_equal 4 "$(cat "$(state_file not_delivered)")" "blocked Issue is recorded as not delivered"
  assert_equal 5 "$(cat "$(state_file delivered)")" "independent Issue is delivered"
  assert_equal " 5" "$PROCESSED" "Codex skips blocked Issue"
)

test_conflicting_labels_and_closed_issue_are_rejected() (
  trap remove_sandbox EXIT
  new_sandbox
  state_gh() { printf '%s\n' "$SNAPSHOT"; }
  GH_BIN=state_gh
  SNAPSHOT=$'OPEN\t2\tdoing'
  if issue_operational_state 7 >/dev/null 2>&1; then
    printf 'not ok - conflicting operational labels were accepted\n' >&2
    return 1
  fi
  SNAPSHOT=$'CLOSED\t1\tvalidating'
  if issue_operational_state 7 >/dev/null 2>&1; then
    printf 'not ok - closed Issue was accepted\n' >&2
    return 1
  fi
)

test_unexpected_push_url_is_rejected() (
  trap remove_sandbox EXIT
  new_sandbox
  remote_git() {
    if [[ $* == *"--push --all"* ]]; then
      printf 'https://github.com/renersilv/rappor-security.git\n'
    else
      printf 'https://github.com/renersilv/rappor-security-lab.git\n'
    fi
  }
  GIT_BIN=remote_git
  if validate_origin_urls >/dev/null 2>&1; then
    printf 'not ok - unexpected push URL was accepted\n' >&2
    return 1
  fi
)

test_stale_worktree_is_rejected() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-7-7
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  mkdir -p "$worktree"
  stale_git() {
    if [[ $* == *"rev-parse --show-toplevel"* ]]; then
      printf '%s\n' "$TEST_SANDBOX/other"
    fi
  }
  GIT_BIN=stale_git
  if validate_worktree "$branch" "$worktree" 0000000000000000000000000000000000000000 >/dev/null 2>&1; then
    printf 'not ok - stale worktree was accepted\n' >&2
    return 1
  fi
)

test_wrapper_integration_and_final_states() (
  trap remove_sandbox EXIT
  new_sandbox
  printf '2\n3\n4\n' > "$(state_file batch)"
  branch=joao/batch-20260907T000000Z-2-4
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state base_sha 0000000000000000000000000000000000000000
  write_state next 3
  write_state phase integration
  printf '2\n3\n' > "$(state_file delivered)"
  printf '4\n' > "$(state_file not_delivered)"
  mkdir -p "$worktree"
  : > "$TEST_SANDBOX/git.log"
  : > "$TEST_SANDBOX/done.log"
  delivered_sha=1111111111111111111111111111111111111111
  integrated_sha=2222222222222222222222222222222222222222
  HEAD_SHA=$delivered_sha
  REMOTE_SHA=$delivered_sha
  MERGE_ACTIVE=1
  declare -A OPS=([2]=validating [3]=validating [4]=blocked)
  preflight() { return 0; }
  validate_worktree() { return 0; }
  mock_git() {
    printf '%s\n' "$*" >> "$TEST_SANDBOX/git.log"
    case "$*" in
      *"symbolic-ref --short HEAD"*) printf '%s\n' "$branch" ;;
      *"status --porcelain"*|*"diff --name-only --diff-filter=U"*) ;;
      *"rev-parse HEAD"*) printf '%s\n' "$HEAD_SHA" ;;
      *"rev-parse origin/$branch"*) printf '%s\n' "$REMOTE_SHA" ;;
      *"rev-parse origin/main"*) printf '%s\n' "$integrated_sha" ;;
      *"rev-parse -q --verify MERGE_HEAD"*)
        (( MERGE_ACTIVE == 1 )) && return 0
        return 1
        ;;
      *"ls-remote --exit-code --heads origin refs/heads/$branch"*) printf '%s\trefs/heads/%s\n' "$integrated_sha" "$branch" ;;
      *"merge --no-edit origin/main"*) printf 'not ok - active staged merge was restarted\n' >&2; return 1 ;;
      *"push origin $branch"*) REMOTE_SHA=$integrated_sha ;;
    esac
    return 0
  }
  mock_npm() { return 0; }
  resolve_conflict() {
    assert_equal "$delivered_sha" "$(read_state delivered_head)" "delivered head survives conflict recovery"
    assert_equal "$delivered_sha" "$(read_state resolver_remote_head)" "resolver pins the remote batch head"
    HEAD_SHA=$integrated_sha
    MERGE_ACTIVE=0
  }
  mock_gh() {
    if [[ $* == *"--add-label done"* ]]; then
      printf '%s\n' "$3" >> "$TEST_SANDBOX/done.log"
      OPS[$3]="done"
    fi
  }
  issue_operational_state() { printf '%s' "${OPS[$1]}"; }
  GIT_BIN=mock_git
  NPM_BIN=mock_npm
  GH_BIN=mock_gh
  integrate_batch
  assert_equal $'2\n3' "$(cat "$TEST_SANDBOX/done.log")" "wrapper finalizes delivered Issues"
  [[ $(cat "$TEST_SANDBOX/git.log") == *"push origin main"* ]]
  [[ $(cat "$TEST_SANDBOX/git.log") == *"merge-base --is-ancestor $delivered_sha HEAD"* ]]
  [[ $(cat "$TEST_SANDBOX/git.log") == *"--force-with-lease=refs/heads/$branch:$integrated_sha origin --delete $branch"* ]]
  [[ ! -e $(state_file batch) ]]
)

test_capture_crash_is_recovered_before_recapture() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-2-3
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  printf '2\n3\n' > "$(state_file batch.pending)"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state base_sha 0000000000000000000000000000000000000000
  write_state next 1
  write_state phase setup
  : > "$(state_file delivered)"
  : > "$(state_file not_delivered)"
  capture_git() {
    [[ $* != *"worktree list --porcelain"* ]] || return 0
  }
  GIT_BIN=capture_git
  preflight() { return 0; }
  capture_batch() {
    for name in batch.pending branch worktree base_sha next phase delivered not_delivered; do
      [[ ! -e $(state_file "$name") ]]
    done
    printf '7\n' > "$(state_file batch)"
    write_state phase finalization
  }
  finalize_batch() { write_state recaptured true; }
  run_cycle
  assert_equal true "$(read_state recaptured)" "batch-less capture state is cleared before recapture"
)

test_invalid_phase_with_published_batch_suspends() (
  trap remove_sandbox EXIT
  new_sandbox
  printf '7\n' > "$(state_file batch)"
  write_state phase corrupt
  preflight() { return 0; }
  set +e
  run_cycle >/dev/null 2>&1
  result=$?
  set -e
  [[ $result -ne 0 ]]
  [[ -f $(state_file suspended) ]]
)

test_returned_delivery_is_not_finalized() (
  trap remove_sandbox EXIT
  new_sandbox
  branch=joao/batch-20260907T000000Z-7-7
  worktree="$JOAO_STATE_ROOT/worktrees/${branch//\//-}"
  printf '7\n' > "$(state_file delivered)"
  write_state branch "$branch"
  write_state worktree "$worktree"
  write_state integrated_head 4444444444444444444444444444444444444444
  issue_operational_state() { printf 'to-do'; }
  mock_gh() { printf 'edited\n' > "$TEST_SANDBOX/edited"; }
  GH_BIN=mock_gh
  set +e
  finalize_batch >/dev/null 2>&1
  result=$?
  set -e
  [[ $result -ne 0 ]]
  [[ ! -e $TEST_SANDBOX/edited ]]
)

test_service_uses_closed_path_and_preflight() (
  service_file="$ROOT/ops/joao/systemd/joao.service"
  grep -Fxq 'Environment=PATH=%h/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin' "$service_file"
  grep -Fxq 'ExecStartPre=%h/rappor-security-lab/ops/joao/run.sh preflight' "$service_file"
  grep -Fxq 'NoNewPrivileges=true' "$service_file"
  grep -Fxq 'ProtectSystem=full' "$service_file"
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
  printf '#!/usr/bin/env bash\nexec 8> "%s/state/run.lock"\nflock -n 8 || exit 91\nprintf "%%s\\n" "$*" > "%s/systemctl.log"\n' \
    "$TEST_SANDBOX" "$TEST_SANDBOX" > "$mock_systemctl"
  chmod +x "$mock_systemctl"
  status_output=$(JOAO_STATE_ROOT="$JOAO_STATE_ROOT" "$CONTROL" status)
  [[ $status_output == *"session_saved=yes"* ]]
  [[ $status_output != *"private-session-identifier"* ]]
  exec 7> "$JOAO_STATE_ROOT/run.lock"
  flock -n 7
  set +e
  JOAO_STATE_ROOT="$JOAO_STATE_ROOT" JOAO_SYSTEMCTL_BIN="$mock_systemctl" "$CONTROL" resume >/dev/null 2>&1
  locked_result=$?
  set -e
  [[ $locked_result -ne 0 ]]
  [[ -f $(state_file suspended) ]]
  flock -u 7
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
test_reboot_recovers_surviving_jsonl
test_timeout_preserves_jsonl_and_session
test_validating_crash_recovery_skips_codex
test_issue_boundary_recovery_is_idempotent
test_recorded_cursor_after_cleanup_skips_validation
test_blocked_issue_does_not_stop_independent_delivery
test_conflicting_labels_and_closed_issue_are_rejected
test_unexpected_push_url_is_rejected
test_stale_worktree_is_rejected
test_wrapper_integration_and_final_states
test_capture_crash_is_recovered_before_recapture
test_invalid_phase_with_published_batch_suspends
test_returned_delivery_is_not_finalized
test_service_uses_closed_path_and_preflight
test_control_status_and_resume
printf 'ok - joao runner scenarios\n'
