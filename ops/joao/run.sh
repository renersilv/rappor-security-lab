#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_PATH=${JOAO_REPOSITORY_PATH:-$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)}
REPOSITORY_SLUG=renersilv/rappor-security-lab
MAIN_BRANCH=${JOAO_MAIN_BRANCH:-main}
OWNER_LOGIN=renersilv
MODEL=gpt-5.6-sol
REASONING_EFFORT=xhigh
ISSUE_TIMEOUT=${JOAO_ISSUE_TIMEOUT:-3h}
STATE_ROOT=${JOAO_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security-lab/joao}
GH_BIN=${JOAO_GH_BIN:-gh}
GIT_BIN=${JOAO_GIT_BIN:-git}
CODEX_BIN=${JOAO_CODEX_BIN:-codex}
TIMEOUT_BIN=${JOAO_TIMEOUT_BIN:-timeout}
NODE_BIN=${JOAO_NODE_BIN:-node}
NPM_BIN=${JOAO_NPM_BIN:-npm}
PROMPT_FILE="$SCRIPT_DIR/PROMPT.md"
RUN_LOCK="$STATE_ROOT/run.lock"
MAIN_LOCK="$STATE_ROOT/main-integration.lock"

log() {
  printf 'joao: %s\n' "$*"
}

fail() {
  log "$*" >&2
  return 1
}

state_file() {
  printf '%s/%s' "$STATE_ROOT" "$1"
}

read_state() {
  local name=$1
  if [[ -f $(state_file "$name") ]]; then
    IFS= read -r REPLY < "$(state_file "$name")" || true
    printf '%s' "$REPLY"
  fi
}

write_state() {
  local name=$1 value=$2 temporary
  temporary=$(state_file ".$name.tmp")
  printf '%s\n' "$value" > "$temporary"
  chmod 600 "$temporary"
  mv -f -- "$temporary" "$(state_file "$name")"
}

clear_state_file() {
  local path
  path=$(state_file "$1")
  [[ ! -e $path ]] || rm -f -- "$path"
}

safe_branch() {
  [[ $1 =~ ^joao/batch-[0-9TZ-]+-[0-9]+-[0-9]+$ ]]
}

safe_issue() {
  [[ $1 =~ ^[1-9][0-9]*$ ]]
}

safe_session() {
  [[ $1 =~ ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ ]]
}

safe_worktree() {
  local branch=$1 worktree=$2
  [[ $worktree == "$STATE_ROOT/worktrees/${branch//\//-}" ]]
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

remote_is_expected() {
  local remote=$1
  [[ $remote == "https://github.com/$REPOSITORY_SLUG" ]] ||
    [[ $remote == "https://github.com/$REPOSITORY_SLUG.git" ]] ||
    [[ $remote == "git@github.com:$REPOSITORY_SLUG.git" ]] ||
    [[ $remote == "ssh://git@github.com/$REPOSITORY_SLUG.git" ]]
}

preflight() {
  local root remote branch
  for command_name in "$GH_BIN" "$GIT_BIN" "$CODEX_BIN" "$TIMEOUT_BIN" "$NODE_BIN" "$NPM_BIN" flock; do
    require_command "$command_name"
  done
  root=$($GIT_BIN -C "$REPOSITORY_PATH" rev-parse --show-toplevel)
  [[ $root == "$REPOSITORY_PATH" ]] || fail "repository path does not match its Git root"
  remote=$($GIT_BIN -C "$REPOSITORY_PATH" remote get-url origin)
  remote_is_expected "$remote" || fail "origin does not match the laboratory repository"
  branch=$($GIT_BIN -C "$REPOSITORY_PATH" symbolic-ref --short HEAD)
  [[ $branch == "$MAIN_BRANCH" ]] || fail "repository worktree must remain on main"
  [[ -z $($GIT_BIN -C "$REPOSITORY_PATH" status --porcelain) ]] || fail "main worktree is not clean"
  $GIT_BIN -C "$REPOSITORY_PATH" fetch --quiet origin "$MAIN_BRANCH"
  $GIT_BIN -C "$REPOSITORY_PATH" rev-parse --verify "origin/$MAIN_BRANCH" >/dev/null
  local repository_name
  repository_name=$($GH_BIN api "repos/$REPOSITORY_SLUG" --jq .full_name)
  [[ $repository_name == "$REPOSITORY_SLUG" ]] || fail "GitHub repository identity mismatch"
}

list_open_with_label() {
  local label=$1
  $GH_BIN issue list --repo "$REPOSITORY_SLUG" --state open --label "$label" --limit 100 \
    --json number --jq '.[].number'
}

issue_has_label() {
  local issue=$1 label=$2
  [[ $($GH_BIN issue view "$issue" --repo "$REPOSITORY_SLUG" --json labels \
    --jq ".labels | any(.name == \"$label\")") == true ]]
}

issue_is_eligible() {
  local issue=$1 author approved
  author=$($GH_BIN issue view "$issue" --repo "$REPOSITORY_SLUG" --json author --jq .author.login)
  [[ $author == "$OWNER_LOGIN" ]] && return 0
  approved=$($GH_BIN api "repos/$REPOSITORY_SLUG/issues/$issue/comments" \
    --jq "any(.[]; .user.login == \"$OWNER_LOGIN\" and (.body | contains(\"/joao approve\")))")
  [[ $approved == true ]]
}

suspend() {
  write_state suspended true
  fail "$1"
}

capture_batch() {
  local doing_count issue first last stamp branch worktree base_sha
  mapfile -t doing_issues < <(list_open_with_label doing)
  doing_count=${#doing_issues[@]}
  if (( doing_count > 1 )); then
    suspend "more than one Issue is in doing"
    return 1
  fi
  if (( doing_count == 1 )); then
    suspend "a doing Issue exists without resumable private state"
    return 1
  fi

  : > "$(state_file batch)"
  chmod 600 "$(state_file batch)"
  while IFS= read -r issue; do
    safe_issue "$issue" || continue
    if issue_is_eligible "$issue"; then
      printf '%s\n' "$issue" >> "$(state_file batch)"
    fi
  done < <(list_open_with_label to-do | sort -n)

  if [[ ! -s $(state_file batch) ]]; then
    clear_state_file batch
    log "no eligible work"
    return 2
  fi

  first=$(head -n 1 "$(state_file batch)")
  last=$(tail -n 1 "$(state_file batch)")
  stamp=${JOAO_BATCH_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
  branch="joao/batch-$stamp-$first-$last"
  safe_branch "$branch" || suspend "generated branch name is invalid"
  worktree="$STATE_ROOT/worktrees/${branch//\//-}"
  write_state branch "$branch"
  write_state worktree "$worktree"
  base_sha=$($GIT_BIN -C "$REPOSITORY_PATH" rev-parse "origin/$MAIN_BRANCH")
  write_state base_sha "$base_sha"
  write_state next 1
  write_state phase setup
  mkdir -p -- "$(dirname -- "$worktree")"
  ensure_worktree
}

ensure_worktree() {
  local branch worktree
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  safe_branch "$branch" || suspend "saved branch is invalid"
  safe_worktree "$branch" "$worktree" || suspend "saved worktree path is invalid"
  if [[ ! -d $worktree ]]; then
    mkdir -p -- "$(dirname -- "$worktree")"
    if $GIT_BIN -C "$REPOSITORY_PATH" show-ref --verify --quiet "refs/heads/$branch"; then
      $GIT_BIN -C "$REPOSITORY_PATH" worktree add "$worktree" "$branch"
    else
      $GIT_BIN -C "$REPOSITORY_PATH" worktree add -b "$branch" "$worktree" "origin/$MAIN_BRANCH"
    fi
  fi
  write_state phase issues
}

extract_session() {
  local events=$1
  $NODE_BIN -e '
    const fs = require("node:fs");
    const path = process.argv[1];
    if (!fs.existsSync(path)) process.exit(0);
    for (const line of fs.readFileSync(path, "utf8").split("\n")) {
      try {
        const event = JSON.parse(line);
        if (event.type === "thread.started" && event.thread_id) {
          process.stdout.write(event.thread_id);
          break;
        }
      } catch {}
    }
  ' "$events"
}

run_codex() {
  local issue=$1 worktree=$2 branch=$3 session events errors prompt exit_code=0 extracted
  session=$(read_state session)
  [[ -z $session ]] || safe_session "$session" || suspend "saved Codex session is invalid"
  events=$(state_file codex-events.jsonl)
  errors=$(state_file codex-errors.log)
  prompt=$(state_file issue-prompt.md)
  {
    sed -n '1,$p' "$PROMPT_FILE"
    printf '\nCurrent Issue: #%s\nBatch branch: %s\n' "$issue" "$branch"
  } > "$prompt"
  chmod 600 "$prompt"
  : > "$events"
  : > "$errors"
  chmod 600 "$events" "$errors"

  if [[ -n $session ]]; then
    (
      cd -- "$worktree"
      JOAO_ISSUE_NUMBER=$issue JOAO_BATCH_BRANCH=$branch \
        "$TIMEOUT_BIN" --signal=TERM --kill-after=30s "$ISSUE_TIMEOUT" \
        "$CODEX_BIN" exec resume -m "$MODEL" -c "model_reasoning_effort=\"$REASONING_EFFORT\"" \
        --json "$session" - < "$prompt" > "$events" 2> "$errors"
    ) || exit_code=$?
  else
    JOAO_ISSUE_NUMBER=$issue JOAO_BATCH_BRANCH=$branch \
      "$TIMEOUT_BIN" --signal=TERM --kill-after=30s "$ISSUE_TIMEOUT" \
      "$CODEX_BIN" exec -C "$worktree" -m "$MODEL" -c "model_reasoning_effort=\"$REASONING_EFFORT\"" \
      --sandbox workspace-write --approve-for-me --json - < "$prompt" > "$events" 2> "$errors" || exit_code=$?
    extracted=$(extract_session "$events")
    [[ -z $extracted ]] || write_state session "$extracted"
  fi

  clear_state_file issue-prompt.md
  clear_state_file codex-events.jsonl
  clear_state_file codex-errors.log
  if (( exit_code == 124 )); then
    log "Issue #$issue reached its three-hour limit; preserving doing state"
    return 124
  fi
  (( exit_code == 0 )) || return "$exit_code"
}

verify_delivery() {
  local issue=$1 worktree=$2 branch=$3 local_head remote_head base_sha issue_base_sha commit_count
  issue_has_label "$issue" validating || fail "Issue #$issue was not delivered as validating"
  local_head=$($GIT_BIN -C "$worktree" rev-parse HEAD)
  $GIT_BIN -C "$worktree" fetch --quiet origin "$branch"
  remote_head=$($GIT_BIN -C "$worktree" rev-parse "origin/$branch")
  [[ $local_head == "$remote_head" ]] || fail "batch branch was not pushed"
  base_sha=$(read_state base_sha)
  [[ $base_sha =~ ^[a-f0-9]{40}$ ]] || suspend "saved base revision is invalid"
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "$base_sha" HEAD ||
    fail "delivery does not descend from captured main"
  issue_base_sha=$(read_state issue_base_sha)
  [[ $issue_base_sha =~ ^[a-f0-9]{40}$ ]] || suspend "saved Issue base revision is invalid"
  commit_count=$($GIT_BIN -C "$worktree" rev-list --count "$issue_base_sha..HEAD")
  [[ $commit_count == 1 ]] || fail "Issue #$issue must contain exactly one commit"
}

execute_issues() {
  local branch worktree next total issue doing_count
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  safe_branch "$branch" || suspend "saved branch is invalid"
  safe_worktree "$branch" "$worktree" || suspend "saved worktree path is invalid"
  [[ -d $worktree ]] || suspend "saved worktree is unavailable"
  next=$(read_state next)
  [[ $next =~ ^[1-9][0-9]*$ ]] || suspend "saved batch cursor is invalid"
  total=$(wc -l < "$(state_file batch)")

  while (( next <= total )); do
    issue=$(sed -n "${next}p" "$(state_file batch)")
    safe_issue "$issue" || suspend "saved Issue is invalid"
    write_state current_issue "$issue"
    mapfile -t doing_issues < <(list_open_with_label doing)
    doing_count=${#doing_issues[@]}
    if (( doing_count == 0 )); then
      issue_has_label "$issue" to-do || suspend "Issue #$issue is no longer eligible"
      $GH_BIN issue edit "$issue" --repo "$REPOSITORY_SLUG" --remove-label to-do --add-label doing >/dev/null
      mapfile -t doing_issues < <(list_open_with_label doing)
      if (( ${#doing_issues[@]} != 1 )) || [[ ${doing_issues[0]} != "$issue" ]]; then
        suspend "doing uniqueness changed while starting Issue #$issue"
      fi
    elif (( doing_count != 1 )) || [[ ${doing_issues[0]} != "$issue" ]]; then
      suspend "doing uniqueness does not match the saved Issue"
    fi

    if [[ ! -f $(state_file issue_base_sha) ]]; then
      write_state issue_base_sha "$($GIT_BIN -C "$worktree" rev-parse HEAD)"
    fi
    run_codex "$issue" "$worktree" "$branch" || return $?
    verify_delivery "$issue" "$worktree" "$branch" || return $?
    clear_state_file session
    clear_state_file current_issue
    clear_state_file issue_base_sha
    next=$((next + 1))
    write_state next "$next"
  done
  write_state phase integration
}

resolve_conflict() {
  local worktree=$1 branch=$2 prompt events errors exit_code=0
  prompt=$(state_file integration-prompt.md)
  events=$(state_file integration-events.jsonl)
  errors=$(state_file integration-errors.log)
  {
    sed -n '1,$p' "$PROMPT_FILE"
    printf '\nResolve only the current merge conflicts in branch %s. Preserve both histories, run tests, and commit the merge. Do not access Issues or main.\n' "$branch"
  } > "$prompt"
  chmod 600 "$prompt"
  "$TIMEOUT_BIN" --signal=TERM --kill-after=30s "$ISSUE_TIMEOUT" \
    "$CODEX_BIN" exec -C "$worktree" -m "$MODEL" -c "model_reasoning_effort=\"$REASONING_EFFORT\"" \
    --sandbox workspace-write --approve-for-me --json - < "$prompt" > "$events" 2> "$errors" || exit_code=$?
  clear_state_file integration-prompt.md
  clear_state_file integration-events.jsonl
  clear_state_file integration-errors.log
  (( exit_code == 0 )) || return "$exit_code"
  [[ -z $($GIT_BIN -C "$worktree" diff --name-only --diff-filter=U) ]] || return 1
}

integrate_batch() {
  local branch worktree issue
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  safe_branch "$branch" || suspend "saved branch is invalid"
  safe_worktree "$branch" "$worktree" || suspend "saved worktree path is invalid"
  [[ -d $worktree ]] || suspend "saved worktree is unavailable"

  exec 8> "$MAIN_LOCK"
  flock -n 8 || fail "main integration lock is busy"
  preflight
  if ! $GIT_BIN -C "$worktree" merge --no-edit "origin/$MAIN_BRANCH"; then
    resolve_conflict "$worktree" "$branch" || return $?
  fi
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "origin/$MAIN_BRANCH" HEAD ||
    fail "batch does not contain current main"
  $NPM_BIN --prefix "$worktree" test
  $NPM_BIN --prefix "$worktree" run check
  $GIT_BIN -C "$worktree" push origin "$branch"

  $GIT_BIN -C "$REPOSITORY_PATH" merge --ff-only "$branch"
  $NPM_BIN --prefix "$REPOSITORY_PATH" test
  $NPM_BIN --prefix "$REPOSITORY_PATH" run check
  $GIT_BIN -C "$REPOSITORY_PATH" push origin "$MAIN_BRANCH"

  while IFS= read -r issue; do
    issue_has_label "$issue" "done" ||
      $GH_BIN issue edit "$issue" --repo "$REPOSITORY_SLUG" --remove-label validating --add-label "done" >/dev/null
  done < "$(state_file batch)"

  $GIT_BIN -C "$REPOSITORY_PATH" worktree remove "$worktree"
  $GIT_BIN -C "$REPOSITORY_PATH" branch -d "$branch"
  for name in batch branch worktree base_sha next phase current_issue issue_base_sha session suspended; do
    clear_state_file "$name"
  done
  log "batch integrated"
}

run_cycle() {
  mkdir -p -- "$STATE_ROOT"
  chmod 700 "$STATE_ROOT"
  exec 9> "$RUN_LOCK"
  flock -n 9 || {
    log "another run is active"
    return 0
  }
  [[ ! -f $(state_file suspended) ]] || fail "execution is suspended; use control.sh resume"
  preflight
  if [[ ! -f $(state_file batch) ]]; then
    capture_batch || {
      local capture_exit=$?
      (( capture_exit == 2 )) && return 0
      return "$capture_exit"
    }
  fi
  if [[ $(read_state phase) == setup ]]; then
    ensure_worktree || return $?
  fi
  if [[ $(read_state phase) == issues ]]; then
    execute_issues || return $?
  fi
  [[ $(read_state phase) == integration ]] && integrate_batch
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  case ${1:-cycle} in
    cycle)
      run_cycle
      ;;
    preflight)
      mkdir -p -- "$STATE_ROOT"
      chmod 700 "$STATE_ROOT"
      preflight
      log "preflight passed"
      ;;
    *)
      fail "usage: run.sh [cycle|preflight]"
      exit 2
      ;;
  esac
fi
