#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_PATH=${JOAO_REPOSITORY_PATH:-$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)}
REPOSITORY_SLUG=renersilv/rappor-security-lab
MAIN_BRANCH=main
OWNER_LOGIN=renersilv
GIT_IDENTITY_NAME=Joao
GIT_IDENTITY_EMAIL=codex@openai.com
MODEL=gpt-5.6-sol
REASONING_EFFORT=xhigh
ISSUE_TIMEOUT=3h
ISSUE_RETRY_MAX_ATTEMPTS=3
STATE_SETTLE_ATTEMPTS=${JOAO_STATE_SETTLE_ATTEMPTS:-6}
STATE_SETTLE_DELAY_SECONDS=${JOAO_STATE_SETTLE_DELAY_SECONDS:-2}
STATE_ROOT=${JOAO_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security-lab/joao}
RUNTIME_TMP="$STATE_ROOT/tmp"
export TMPDIR="$RUNTIME_TMP"
GH_BIN=gh
GIT_BIN=git
CODEX_BIN=codex
TIMEOUT_BIN=timeout
NODE_BIN=node
NPM_BIN=npm
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

prepare_private_directories() {
  mkdir -p -- "$STATE_ROOT" "$RUNTIME_TMP"
  chmod 700 "$STATE_ROOT" "$RUNTIME_TMP"
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

validate_issue_retry_error_class() {
  [[ $1 =~ ^(codex_exit|delivery_invalid)$ ]]
}

read_issue_retry() {
  local path key value
  local version_count=0 issue_count=0 branch_count=0 class_count=0
  local fingerprint_count=0 attempts_count=0 suspended_count=0
  path=$(state_file issue-retry)
  [[ -f $path && ! -L $path && -O $path && $(stat -c '%a' "$path") == 600 ]] || {
    fail "Issue retry marker is not a regular private file"
    return 1
  }
  ISSUE_RETRY_VERSION=
  ISSUE_RETRY_ISSUE=
  ISSUE_RETRY_BRANCH=
  ISSUE_RETRY_ERROR_CLASS=
  ISSUE_RETRY_FINGERPRINT=
  ISSUE_RETRY_ATTEMPTS=
  ISSUE_RETRY_SUSPENDED=
  while IFS='=' read -r key value || [[ -n ${key}${value} ]]; do
    case $key in
      version) ISSUE_RETRY_VERSION=$value; version_count=$((version_count + 1)) ;;
      issue) ISSUE_RETRY_ISSUE=$value; issue_count=$((issue_count + 1)) ;;
      branch) ISSUE_RETRY_BRANCH=$value; branch_count=$((branch_count + 1)) ;;
      error_class) ISSUE_RETRY_ERROR_CLASS=$value; class_count=$((class_count + 1)) ;;
      fingerprint) ISSUE_RETRY_FINGERPRINT=$value; fingerprint_count=$((fingerprint_count + 1)) ;;
      attempts) ISSUE_RETRY_ATTEMPTS=$value; attempts_count=$((attempts_count + 1)) ;;
      suspended) ISSUE_RETRY_SUSPENDED=$value; suspended_count=$((suspended_count + 1)) ;;
      *) fail "Issue retry marker has an unexpected field"; return 1 ;;
    esac
  done < "$path"
  [[ $version_count == 1 && $issue_count == 1 && $branch_count == 1 && $class_count == 1 &&
    $fingerprint_count == 1 && $attempts_count == 1 && $suspended_count == 1 &&
    $ISSUE_RETRY_VERSION == 1 ]] || { fail "Issue retry marker is invalid"; return 1; }
  safe_issue "$ISSUE_RETRY_ISSUE" || { fail "Issue retry marker has an invalid Issue"; return 1; }
  safe_branch "$ISSUE_RETRY_BRANCH" || { fail "Issue retry marker has an invalid branch"; return 1; }
  validate_issue_retry_error_class "$ISSUE_RETRY_ERROR_CLASS" || {
    fail "Issue retry marker has an invalid error class"
    return 1
  }
  [[ $ISSUE_RETRY_FINGERPRINT =~ ^[a-f0-9]{64}$ &&
    $ISSUE_RETRY_ATTEMPTS =~ ^[1-3]$ &&
    $ISSUE_RETRY_SUSPENDED =~ ^(true|false)$ ]] || {
    fail "Issue retry marker values are invalid"
    return 1
  }
  if [[ $ISSUE_RETRY_SUSPENDED == true ]]; then
    [[ $ISSUE_RETRY_ATTEMPTS == "$ISSUE_RETRY_MAX_ATTEMPTS" ]] || {
      fail "Suspended Issue retry marker has an invalid attempt count"
      return 1
    }
  else
    (( ISSUE_RETRY_ATTEMPTS < ISSUE_RETRY_MAX_ATTEMPTS )) || {
      fail "Scheduled Issue retry marker has an invalid attempt count"
      return 1
    }
  fi
}

write_issue_retry() {
  local temporary
  temporary=$(state_file .issue-retry.tmp)
  {
    printf 'version=1\n'
    printf 'issue=%s\n' "$ISSUE_RETRY_ISSUE"
    printf 'branch=%s\n' "$ISSUE_RETRY_BRANCH"
    printf 'error_class=%s\n' "$ISSUE_RETRY_ERROR_CLASS"
    printf 'fingerprint=%s\n' "$ISSUE_RETRY_FINGERPRINT"
    printf 'attempts=%s\n' "$ISSUE_RETRY_ATTEMPTS"
    printf 'suspended=%s\n' "$ISSUE_RETRY_SUSPENDED"
  } > "$temporary"
  chmod 600 "$temporary"
  mv -f -- "$temporary" "$(state_file issue-retry)"
}

notify_issue_retry_attention() {
  local attention_hash attention_id marker body existing
  attention_hash=$(printf 'v1:joao-issue-attention:%s' "$ISSUE_RETRY_FINGERPRINT" | sha256sum)
  attention_id=${attention_hash%% *}
  marker="<!-- joao-issue-attention:${attention_id} -->"
  existing=$($GH_BIN api --paginate \
    "repos/$REPOSITORY_SLUG/issues/$ISSUE_RETRY_ISSUE/comments" \
    --jq ".[] | select(.body | contains(\"$marker\")) | .id") || return 1
  [[ -z $existing ]] || return 0
  body=$(printf '%s\n\n%s\n\n%s\n\n%s\n' \
    '**Atenção: o João interrompeu novas tentativas automáticas.**' \
    "A Issue #$ISSUE_RETRY_ISSUE permaneceu em andamento após três falhas operacionais equivalentes. A branch, o worktree, a sessão e os diagnósticos privados foram preservados; nenhum item novo da fila foi iniciado." \
    '**Preciso de você:** @renersilv, solicite uma revisão assistida do executor e use ops/joao/control.sh status. Depois da correção, ops/joao/control.sh resume libera somente esta retomada.' \
    "$marker")
  $GH_BIN issue comment "$ISSUE_RETRY_ISSUE" --repo "$REPOSITORY_SLUG" --body "$body" >/dev/null
}

record_issue_failure() {
  local issue=$1 branch=$2 error_class=$3 fingerprint_detail=$4 base_sha fingerprint_input calculated
  local previous_attempts=0
  safe_issue "$issue" || return 1
  safe_branch "$branch" || return 1
  validate_issue_retry_error_class "$error_class" || return 1
  [[ $fingerprint_detail =~ ^[a-z0-9_-]+$ ]] || return 1
  base_sha=$(read_state base_sha)
  [[ $base_sha =~ ^[a-f0-9]{40}$ ]] || return 1
  fingerprint_input=$(printf 'v1:%s:%s:%s:%s:%s' \
    "$base_sha" "$branch" "$issue" "$error_class" "$fingerprint_detail")
  calculated=$(printf '%s' "$fingerprint_input" | sha256sum)
  calculated=${calculated%% *}
  if [[ -e $(state_file issue-retry) ]]; then
    read_issue_retry || return 1
    [[ $ISSUE_RETRY_ISSUE == "$issue" && $ISSUE_RETRY_BRANCH == "$branch" ]] || {
      fail "Issue retry marker belongs to another recoverable item"
      return 1
    }
    if [[ $ISSUE_RETRY_FINGERPRINT == "$calculated" ]]; then
      previous_attempts=$ISSUE_RETRY_ATTEMPTS
    fi
  fi
  ISSUE_RETRY_VERSION=1
  ISSUE_RETRY_ISSUE=$issue
  ISSUE_RETRY_BRANCH=$branch
  ISSUE_RETRY_ERROR_CLASS=$error_class
  ISSUE_RETRY_FINGERPRINT=$calculated
  ISSUE_RETRY_ATTEMPTS=$((previous_attempts + 1))
  if (( ISSUE_RETRY_ATTEMPTS >= ISSUE_RETRY_MAX_ATTEMPTS )); then
    ISSUE_RETRY_ATTEMPTS=$ISSUE_RETRY_MAX_ATTEMPTS
    ISSUE_RETRY_SUSPENDED=true
  else
    ISSUE_RETRY_SUSPENDED=false
  fi
  write_issue_retry
  if [[ $ISSUE_RETRY_SUSPENDED == true ]]; then
    notify_issue_retry_attention || log "owner attention could not be published; the next activation will retry it"
    log "Issue #$issue automatic execution suspended after equivalent failures"
  else
    log "Issue #$issue retry $ISSUE_RETRY_ATTEMPTS/$ISSUE_RETRY_MAX_ATTEMPTS scheduled"
  fi
}

check_issue_retry_gate() {
  local issue=$1 branch=$2
  [[ -e $(state_file issue-retry) ]] || return 0
  read_issue_retry || return 1
  [[ $ISSUE_RETRY_ISSUE == "$issue" && $ISSUE_RETRY_BRANCH == "$branch" ]] || {
    fail "Issue retry marker does not match the recoverable item"
    return 1
  }
  if [[ $ISSUE_RETRY_SUSPENDED == true ]]; then
    notify_issue_retry_attention || log "owner attention could not be published; a later activation will retry it"
    log "Issue #$issue retry is suspended; use ops/joao/control.sh status or resume"
    return 75
  fi
}

clear_issue_retry() {
  clear_state_file issue-retry
}

archive_current_diagnostics() {
  local issue=$1 directory attempt=1 name source target
  safe_issue "$issue" || return 1
  directory="$STATE_ROOT/diagnostics/issue-$issue"
  if [[ ! -e $(state_file codex-events.jsonl) && ! -e $(state_file codex-errors.log) &&
    ! -e $(state_file issue-prompt.md) ]]; then
    return 0
  fi
  mkdir -p -- "$directory"
  chmod 700 "$STATE_ROOT/diagnostics" "$directory"
  while [[ -e $directory/attempt-$attempt.events.jsonl ||
    -e $directory/attempt-$attempt.errors.log || -e $directory/attempt-$attempt.prompt.md ]]; do
    attempt=$((attempt + 1))
  done
  for name in codex-events.jsonl codex-errors.log issue-prompt.md; do
    source=$(state_file "$name")
    [[ -e $source ]] || continue
    case $name in
      codex-events.jsonl) target="$directory/attempt-$attempt.events.jsonl" ;;
      codex-errors.log) target="$directory/attempt-$attempt.errors.log" ;;
      issue-prompt.md) target="$directory/attempt-$attempt.prompt.md" ;;
    esac
    mv -- "$source" "$target"
    chmod 600 "$target"
  done
}

clear_issue_diagnostics() {
  local issue=$1 directory
  safe_issue "$issue" || return 1
  directory="$STATE_ROOT/diagnostics/issue-$issue"
  [[ ! -e $directory ]] || rm -rf -- "$directory"
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

validate_origin_urls() {
  local urls url
  urls=$($GIT_BIN -C "$REPOSITORY_PATH" remote get-url --all origin)
  [[ -n $urls ]] || { fail "origin has no fetch URL"; return 1; }
  while IFS= read -r url; do
    remote_is_expected "$url" || { fail "origin contains an unexpected fetch URL"; return 1; }
  done <<< "$urls"
  urls=$($GIT_BIN -C "$REPOSITORY_PATH" remote get-url --push --all origin)
  [[ -n $urls ]] || { fail "origin has no push URL"; return 1; }
  while IFS= read -r url; do
    remote_is_expected "$url" || { fail "origin contains an unexpected push URL"; return 1; }
  done <<< "$urls"
}

configure_git_identity() {
  local configured_name configured_email
  $GIT_BIN -C "$REPOSITORY_PATH" config --local user.name "$GIT_IDENTITY_NAME"
  $GIT_BIN -C "$REPOSITORY_PATH" config --local user.email "$GIT_IDENTITY_EMAIL"
  configured_name=$($GIT_BIN -C "$REPOSITORY_PATH" config --local --get user.name)
  configured_email=$($GIT_BIN -C "$REPOSITORY_PATH" config --local --get user.email)
  [[ $configured_name == "$GIT_IDENTITY_NAME" ]] || fail "Git commit identity name is invalid"
  [[ $configured_email == "$GIT_IDENTITY_EMAIL" ]] || fail "Git commit identity email is invalid"
}

fetch_batch_branch() {
  local repository=$1 branch=$2 remote_ref
  safe_branch "$branch" || { fail "batch branch is invalid"; return 1; }
  remote_ref="refs/remotes/origin/$branch"
  if ! $GIT_BIN -C "$repository" fetch --quiet --no-tags origin \
    "refs/heads/$branch:$remote_ref"; then
    fail "remote batch branch could not be fetched"
    return 1
  fi
  $GIT_BIN -C "$repository" show-ref --verify --quiet "$remote_ref" || {
    fail "remote batch branch was not recorded locally"
    return 1
  }
}

preflight() {
  local root branch
  for command_name in "$GH_BIN" "$GIT_BIN" "$CODEX_BIN" "$TIMEOUT_BIN" "$NODE_BIN" "$NPM_BIN" flock sha256sum; do
    require_command "$command_name"
  done
  [[ $STATE_SETTLE_ATTEMPTS =~ ^[1-9][0-9]*$ ]] || fail "state settle attempts must be a positive integer"
  [[ $STATE_SETTLE_DELAY_SECONDS =~ ^[0-9]+$ ]] || fail "state settle delay must be a non-negative integer"
  root=$($GIT_BIN -C "$REPOSITORY_PATH" rev-parse --show-toplevel)
  [[ $root == "$REPOSITORY_PATH" ]] || fail "repository path does not match its Git root"
  configure_git_identity
  validate_origin_urls
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
  $GH_BIN api --method GET --paginate "repos/$REPOSITORY_SLUG/issues" \
    -f state=open -f labels="$label" -f per_page=100 \
    --jq '.[] | select(.pull_request == null) | .number'
}

wait_for_doing_state() {
  local expected=${1:-} attempt
  for ((attempt = 1; attempt <= STATE_SETTLE_ATTEMPTS; attempt++)); do
    mapfile -t doing_issues < <(list_open_with_label doing)
    if [[ -z $expected && ${#doing_issues[@]} == 0 ]]; then
      return 0
    fi
    if [[ -n $expected && ${#doing_issues[@]} == 1 && ${doing_issues[0]} == "$expected" ]]; then
      return 0
    fi
    (( attempt == STATE_SETTLE_ATTEMPTS )) || sleep "$STATE_SETTLE_DELAY_SECONDS"
  done
  return 1
}

issue_operational_state() {
  local issue=$1 snapshot github_state count operational
  snapshot=$($GH_BIN issue view "$issue" --repo "$REPOSITORY_SLUG" --json state,labels --jq \
    '[.state, ([.labels[].name | select(. == "to-do" or . == "doing" or . == "validating" or . == "done" or . == "blocked")] | length), ([.labels[].name | select(. == "to-do" or . == "doing" or . == "validating" or . == "done" or . == "blocked")][0] // "")] | @tsv')
  IFS=$'\t' read -r github_state count operational <<< "$snapshot"
  [[ $github_state == OPEN ]] || { fail "Issue #$issue is not open"; return 1; }
  [[ $count == 1 ]] || { fail "Issue #$issue must have exactly one operational state"; return 1; }
  case $operational in
    to-do|doing|validating|done|blocked) printf '%s' "$operational" ;;
    *) fail "Issue #$issue has an invalid operational state" ;;
  esac
}

issue_is_eligible() {
  local issue=$1 author approved operational
  operational=$(issue_operational_state "$issue") || return 1
  [[ $operational == to-do ]] || return 1
  author=$($GH_BIN issue view "$issue" --repo "$REPOSITORY_SLUG" --json author --jq .author.login)
  [[ $author == "$OWNER_LOGIN" ]] && return 0
  approved=$($GH_BIN api "repos/$REPOSITORY_SLUG/issues/$issue/comments" \
    --jq "any(.[]; .user.login == \"$OWNER_LOGIN\" and (.body | contains(\"/joao approve\")))")
  [[ $approved == true ]]
}

validate_worktree() {
  local branch=$1 worktree=$2 base_sha=$3 root repository_common worktree_common actual_branch
  safe_branch "$branch" || { fail "saved branch is invalid"; return 1; }
  safe_worktree "$branch" "$worktree" || { fail "saved worktree path is invalid"; return 1; }
  [[ $base_sha =~ ^[a-f0-9]{40}$ ]] || { fail "saved base revision is invalid"; return 1; }
  [[ -d $worktree ]] || { fail "saved worktree is unavailable"; return 1; }
  root=$($GIT_BIN -C "$worktree" rev-parse --show-toplevel)
  [[ $root == "$worktree" ]] || { fail "worktree root is not exact"; return 1; }
  repository_common=$($GIT_BIN -C "$REPOSITORY_PATH" rev-parse --path-format=absolute --git-common-dir)
  worktree_common=$($GIT_BIN -C "$worktree" rev-parse --path-format=absolute --git-common-dir)
  [[ $worktree_common == "$repository_common" ]] || { fail "worktree belongs to another repository"; return 1; }
  actual_branch=$($GIT_BIN -C "$worktree" symbolic-ref --short HEAD)
  [[ $actual_branch == "$branch" ]] || { fail "worktree branch mismatch"; return 1; }
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "$base_sha" HEAD || {
    fail "worktree HEAD does not descend from the saved base"
    return 1
  }
}

suspend() {
  write_state suspended true
  fail "$1"
}

capture_batch() {
  local doing_count issue first last stamp branch worktree base_sha pending
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

  pending=$(state_file batch.pending)
  : > "$pending"
  chmod 600 "$pending"
  while IFS= read -r issue; do
    safe_issue "$issue" || continue
    if issue_is_eligible "$issue"; then
      printf '%s\n' "$issue" >> "$pending"
    fi
  done < <(list_open_with_label to-do | sort -n)

  if [[ ! -s $pending ]]; then
    clear_state_file batch.pending
    log "no eligible work"
    return 2
  fi

  first=$(head -n 1 "$pending")
  last=$(tail -n 1 "$pending")
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
  : > "$(state_file delivered)"
  : > "$(state_file not_delivered)"
  chmod 600 "$(state_file delivered)" "$(state_file not_delivered)"
  mv -f -- "$pending" "$(state_file batch)"
  mkdir -p -- "$(dirname -- "$worktree")"
  ensure_worktree
}

recover_incomplete_capture() {
  local branch worktree base_sha next phase name worktree_list
  [[ ! -e $(state_file batch) ]] || { suspend "cannot recover capture while a batch exists"; return 1; }
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  base_sha=$(read_state base_sha)
  next=$(read_state next)
  phase=$(read_state phase)

  [[ -z $branch ]] || safe_branch "$branch" || { suspend "incomplete capture has an invalid branch"; return 1; }
  if [[ -n $worktree ]]; then
    if [[ -z $branch ]] || ! safe_worktree "$branch" "$worktree"; then
      suspend "incomplete capture has an invalid worktree path"
      return 1
    fi
    worktree_list=$($GIT_BIN -C "$REPOSITORY_PATH" worktree list --porcelain) || {
      suspend "could not validate incomplete capture worktrees"
      return 1
    }
    if [[ -e $worktree ]] || grep -Fxq "worktree $worktree" <<< "$worktree_list"; then
      suspend "incomplete capture unexpectedly has a worktree"
      return 1
    fi
  fi
  [[ -z $base_sha || $base_sha =~ ^[a-f0-9]{40}$ ]] || {
    suspend "incomplete capture has an invalid base revision"
    return 1
  }
  [[ -z $next || $next == 1 ]] || { suspend "incomplete capture has an invalid cursor"; return 1; }
  [[ -z $phase || $phase == setup ]] || { suspend "batch-less state has an invalid phase"; return 1; }
  for name in delivered not_delivered; do
    [[ ! -s $(state_file "$name") ]] || { suspend "incomplete capture contains outcomes"; return 1; }
  done
  for name in current_issue issue_base_sha session delivered_head integrated_head resolver_remote_head; do
    [[ ! -e $(state_file "$name") ]] || { suspend "incomplete capture contains item or integration state"; return 1; }
  done
  for name in batch.pending delivered not_delivered branch worktree base_sha next phase; do
    clear_state_file "$name"
  done
}

ensure_worktree() {
  local branch worktree base_sha
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  base_sha=$(read_state base_sha)
  safe_branch "$branch" || suspend "saved branch is invalid"
  safe_worktree "$branch" "$worktree" || suspend "saved worktree path is invalid"
  [[ $base_sha =~ ^[a-f0-9]{40}$ ]] || suspend "saved base revision is invalid"
  if [[ ! -d $worktree ]]; then
    mkdir -p -- "$(dirname -- "$worktree")"
    if $GIT_BIN -C "$REPOSITORY_PATH" show-ref --verify --quiet "refs/heads/$branch"; then
      $GIT_BIN -C "$REPOSITORY_PATH" worktree add "$worktree" "$branch"
    else
      $GIT_BIN -C "$REPOSITORY_PATH" worktree add -b "$branch" "$worktree" "$base_sha"
    fi
  fi
  validate_worktree "$branch" "$worktree" "$base_sha" || suspend "saved worktree validation failed"
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

recover_session() {
  local events session
  events=$(state_file codex-events.jsonl)
  session=$(read_state session)
  if [[ -z $session && -s $events ]]; then
    session=$(extract_session "$events")
    if [[ -n $session ]]; then
      safe_session "$session" || suspend "recovered Codex session is invalid"
      write_state session "$session"
    fi
  fi
}

run_codex() {
  local issue=$1 worktree=$2 branch=$3 session events errors prompt exit_code=0 extracted
  recover_session
  session=$(read_state session)
  [[ -z $session ]] || safe_session "$session" || suspend "saved Codex session is invalid"
  events=$(state_file codex-events.jsonl)
  errors=$(state_file codex-errors.log)
  prompt=$(state_file issue-prompt.md)
  archive_current_diagnostics "$issue"
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
      --approve-for-me --json - < "$prompt" > "$events" 2> "$errors" || exit_code=$?
    extracted=$(extract_session "$events")
    if [[ -n $extracted ]]; then
      safe_session "$extracted" || suspend "new Codex session is invalid"
      write_state session "$extracted"
    fi
  fi

  if (( exit_code == 124 )); then
    log "Issue #$issue reached its three-hour limit; preserving doing state"
    return 124
  fi
  (( exit_code == 0 )) || return "$exit_code"
}

verify_delivery() {
  local issue=$1 worktree=$2 branch=$3 local_head remote_head base_sha issue_base_sha commit_count
  [[ $(issue_operational_state "$issue") == validating ]] || { fail "Issue #$issue was not delivered as validating"; return 1; }
  validate_worktree "$branch" "$worktree" "$(read_state base_sha)" || return 1
  [[ -z $($GIT_BIN -C "$worktree" status --porcelain) ]] || { fail "delivered worktree is not clean"; return 1; }
  local_head=$($GIT_BIN -C "$worktree" rev-parse HEAD)
  fetch_batch_branch "$worktree" "$branch" || return 1
  remote_head=$($GIT_BIN -C "$worktree" rev-parse --verify "refs/remotes/origin/$branch")
  [[ $local_head == "$remote_head" ]] || { fail "batch branch was not pushed"; return 1; }
  base_sha=$(read_state base_sha)
  [[ $base_sha =~ ^[a-f0-9]{40}$ ]] || suspend "saved base revision is invalid"
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "$base_sha" HEAD || {
    fail "delivery does not descend from captured main"
    return 1
  }
  issue_base_sha=$(read_state issue_base_sha)
  [[ $issue_base_sha =~ ^[a-f0-9]{40}$ ]] || suspend "saved Issue base revision is invalid"
  commit_count=$($GIT_BIN -C "$worktree" rev-list --count "$issue_base_sha..HEAD")
  [[ $commit_count == 1 ]] || { fail "Issue #$issue must contain exactly one commit"; return 1; }
}

append_unique_state() {
  local name=$1 issue=$2 path
  path=$(state_file "$name")
  touch "$path"
  chmod 600 "$path"
  grep -Fxq "$issue" "$path" || printf '%s\n' "$issue" >> "$path"
}

recorded_outcome() {
  local issue=$1 delivered_match=0 not_delivered_match=0
  if [[ -f $(state_file delivered) ]] && grep -Fxq "$issue" "$(state_file delivered)"; then
    delivered_match=1
  fi
  if [[ -f $(state_file not_delivered) ]] && grep -Fxq "$issue" "$(state_file not_delivered)"; then
    not_delivered_match=1
  fi
  if (( delivered_match + not_delivered_match > 1 )); then
    suspend "Issue #$issue appears in conflicting private outcome lists"
    return 1
  fi
  (( delivered_match == 0 )) || { printf 'delivered'; return 0; }
  (( not_delivered_match == 0 )) || { printf 'not_delivered'; return 0; }
}

clear_item_state() {
  local issue=${1:-} name
  for name in session current_issue issue_base_sha issue-prompt.md codex-events.jsonl codex-errors.log; do
    clear_state_file "$name"
  done
  clear_issue_retry
  if [[ -n $issue ]]; then
    clear_issue_diagnostics "$issue"
  fi
}

reconcile_stale_item() {
  local cursor_issue=$1 next=$2 saved_issue saved_line outcome name
  saved_issue=$(read_state current_issue)
  if [[ -z $saved_issue ]]; then
    for name in session issue_base_sha issue-retry issue-prompt.md codex-events.jsonl codex-errors.log; do
      if [[ -e $(state_file "$name") ]]; then
        suspend "orphaned item state has no owning Issue"
        return 1
      fi
    done
    return 0
  fi
  safe_issue "$saved_issue" || { suspend "saved stale Issue is invalid"; return 1; }
  saved_line=$(grep -n -m 1 -Fx "$saved_issue" "$(state_file batch)" | cut -d: -f1 || true)
  [[ $saved_line =~ ^[1-9][0-9]*$ && $saved_line -le $next ]] || {
    suspend "stale item state does not belong to the completed cursor"
    return 1
  }
  outcome=$(recorded_outcome "$saved_issue") || return 1
  [[ -n $outcome ]] || {
    [[ $saved_issue == "$cursor_issue" ]] && return 0
    suspend "stale previous Issue has no recorded outcome"
    return 1
  }
  clear_item_state "$saved_issue"
}

advance_issue() {
  local issue=$1 outcome=$2 next=$3
  append_unique_state "$outcome" "$issue"
  clear_item_state "$issue"
  write_state next "$((next + 1))"
}

accept_blocked() {
  local issue=$1 worktree=$2 branch=$3 next=$4 issue_base_sha head
  [[ $(issue_operational_state "$issue") == blocked ]] || return 1
  validate_worktree "$branch" "$worktree" "$(read_state base_sha)" || return 1
  [[ -z $($GIT_BIN -C "$worktree" status --porcelain) ]] || {
    suspend "blocked Issue #$issue changed the worktree; work was preserved and requires owner replanning"
    return 1
  }
  issue_base_sha=$(read_state issue_base_sha)
  [[ $issue_base_sha =~ ^[a-f0-9]{40}$ ]] || suspend "saved Issue base revision is invalid"
  head=$($GIT_BIN -C "$worktree" rev-parse HEAD)
  [[ $head == "$issue_base_sha" ]] || {
    suspend "blocked Issue #$issue created a commit; work was preserved and requires owner replanning"
    return 1
  }
  advance_issue "$issue" not_delivered "$next"
}

execute_issues() {
  local branch worktree next total issue doing_count operational outcome retry_status run_status
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
    outcome=$(recorded_outcome "$issue") || return 1
    if [[ -n $outcome ]]; then
      if [[ -n $(read_state current_issue) ]]; then
        reconcile_stale_item "$issue" "$next" || return 1
      else
        clear_item_state "$issue"
      fi
      next=$((next + 1))
      write_state next "$next"
      continue
    fi
    reconcile_stale_item "$issue" "$next" || return 1
    write_state current_issue "$issue"
    if [[ ! -f $(state_file issue_base_sha) ]]; then
      write_state issue_base_sha "$($GIT_BIN -C "$worktree" rev-parse HEAD)"
    fi
    operational=$(issue_operational_state "$issue") || suspend "Issue #$issue state is invalid"
    retry_status=0
    check_issue_retry_gate "$issue" "$branch" || retry_status=$?
    if (( retry_status == 75 )); then
      return 0
    elif (( retry_status != 0 )); then
      return "$retry_status"
    fi
    mapfile -t doing_issues < <(list_open_with_label doing)
    doing_count=${#doing_issues[@]}

    if [[ $operational == validating ]]; then
      (( doing_count == 0 )) || suspend "another Issue is in doing during delivery recovery"
      if ! verify_delivery "$issue" "$worktree" "$branch"; then
        record_issue_failure "$issue" "$branch" delivery_invalid validating
        return 70
      fi
      advance_issue "$issue" delivered "$next"
      next=$((next + 1))
      continue
    fi
    if [[ $operational == blocked ]]; then
      (( doing_count == 0 )) || suspend "another Issue is in doing during blocked recovery"
      accept_blocked "$issue" "$worktree" "$branch" "$next"
      next=$((next + 1))
      continue
    fi
    if [[ $operational == to-do ]]; then
      (( doing_count == 0 )) || suspend "another Issue is already in doing"
      $GH_BIN issue edit "$issue" --repo "$REPOSITORY_SLUG" --remove-label to-do --add-label doing >/dev/null
      [[ $(issue_operational_state "$issue") == doing ]] || suspend "Issue #$issue did not enter doing exclusively"
      if ! wait_for_doing_state "$issue"; then
        suspend "doing uniqueness changed while starting Issue #$issue"
      fi
    elif [[ $operational == doing ]]; then
      if (( doing_count != 1 )) || [[ ${doing_issues[0]} != "$issue" ]]; then
        suspend "doing uniqueness does not match the saved Issue"
      fi
    else
      suspend "Issue #$issue cannot be executed from state $operational"
    fi

    run_status=0
    run_codex "$issue" "$worktree" "$branch" || run_status=$?
    if (( run_status == 124 )); then
      return 124
    elif (( run_status != 0 )); then
      record_issue_failure "$issue" "$branch" codex_exit "exit_$run_status"
      return 70
    fi
    operational=$(issue_operational_state "$issue") || suspend "Issue #$issue delivery state is invalid"
    if [[ $operational == validating ]]; then
      wait_for_doing_state || suspend "doing remained after Issue #$issue delivery"
      if ! verify_delivery "$issue" "$worktree" "$branch"; then
        record_issue_failure "$issue" "$branch" delivery_invalid validating
        return 70
      fi
      advance_issue "$issue" delivered "$next"
    elif [[ $operational == blocked ]]; then
      wait_for_doing_state || suspend "doing remained after Issue #$issue blocking"
      accept_blocked "$issue" "$worktree" "$branch" "$next"
    elif [[ $operational == doing ]]; then
      log "Issue #$issue returned without delivery and remains doing" >&2
      record_issue_failure "$issue" "$branch" delivery_invalid doing
      return 70
    else
      suspend "Issue #$issue ended in unexpected state $operational"
    fi
    next=$((next + 1))
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
    --approve-for-me --json - < "$prompt" > "$events" 2> "$errors" || exit_code=$?
  clear_state_file integration-prompt.md
  clear_state_file integration-events.jsonl
  clear_state_file integration-errors.log
  (( exit_code == 0 )) || return "$exit_code"
  [[ -z $($GIT_BIN -C "$worktree" diff --name-only --diff-filter=U) ]] || return 1
}

require_delivered_states() {
  local issue operational
  while IFS= read -r issue; do
    [[ -z $issue ]] && continue
    operational=$(issue_operational_state "$issue") || return 1
    [[ $operational == validating ]] || fail "delivered Issue #$issue is no longer validating"
  done < "$(state_file delivered)"
}

clear_batch_state() {
  local name
  for name in batch batch.pending delivered not_delivered branch worktree base_sha next phase current_issue \
    issue_base_sha session suspended issue-retry delivered_head integrated_head resolver_remote_head \
    issue-prompt.md codex-events.jsonl codex-errors.log integration-prompt.md \
    integration-events.jsonl integration-errors.log; do
    clear_state_file "$name"
  done
  [[ ! -e $STATE_ROOT/diagnostics ]] || rm -rf -- "$STATE_ROOT/diagnostics"
}

remove_batch_branch() {
  local branch=$1 worktree=$2 expected_remote=${3:-} remote_line remote_head main_head remote_status
  $GIT_BIN -C "$REPOSITORY_PATH" fetch --quiet origin "$MAIN_BRANCH"
  if remote_line=$($GIT_BIN -C "$REPOSITORY_PATH" ls-remote --exit-code --heads origin "refs/heads/$branch"); then
    remote_head=${remote_line%%[[:space:]]*}
    [[ $remote_head =~ ^[a-f0-9]{40}$ ]] || { fail "remote batch revision is invalid"; return 1; }
    [[ -z $expected_remote || $remote_head == "$expected_remote" ]] || {
      fail "remote batch branch changed before deletion"
      return 1
    }
    main_head=$($GIT_BIN -C "$REPOSITORY_PATH" rev-parse "origin/$MAIN_BRANCH")
    $GIT_BIN -C "$REPOSITORY_PATH" merge-base --is-ancestor "$remote_head" "$main_head" || {
      fail "remote batch branch is not integrated"
      return 1
    }
    $GIT_BIN -C "$REPOSITORY_PATH" push \
      "--force-with-lease=refs/heads/$branch:$remote_head" origin --delete "$branch"
  else
    remote_status=$?
    [[ $remote_status == 2 ]] || { fail "could not verify remote batch branch"; return 1; }
  fi
  if ! $GIT_BIN -C "$REPOSITORY_PATH" worktree remove "$worktree"; then
    if $GIT_BIN -C "$REPOSITORY_PATH" worktree list --porcelain | grep -Fxq "worktree $worktree"; then
      fail "could not remove registered batch worktree"
      return 1
    fi
  fi
  if $GIT_BIN -C "$REPOSITORY_PATH" show-ref --verify --quiet "refs/heads/$branch"; then
    $GIT_BIN -C "$REPOSITORY_PATH" branch -d "$branch"
  fi
  clear_batch_state
}

finalize_batch() {
  local branch worktree integrated_head issue operational
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  integrated_head=$(read_state integrated_head)
  [[ $integrated_head =~ ^[a-f0-9]{40}$ ]] || { suspend "saved integrated revision is invalid"; return 1; }
  while IFS= read -r issue; do
    [[ -z $issue ]] && continue
    operational=$(issue_operational_state "$issue") || return 1
    if [[ $operational == validating ]]; then
      $GH_BIN issue edit "$issue" --repo "$REPOSITORY_SLUG" --remove-label validating --add-label "done" >/dev/null
      [[ $(issue_operational_state "$issue") == "done" ]] || {
        fail "Issue #$issue did not enter done exclusively"
        return 1
      }
    elif [[ $operational != "done" ]]; then
      fail "delivered Issue #$issue changed state before finalization"
      return 1
    fi
  done < "$(state_file delivered)"
  remove_batch_branch "$branch" "$worktree" "$integrated_head"
  log "batch integrated"
}

integrate_batch() {
  local branch worktree base_sha issue delivered_head remote_before remote_after integrated_head actual_branch
  branch=$(read_state branch)
  worktree=$(read_state worktree)
  base_sha=$(read_state base_sha)
  validate_worktree "$branch" "$worktree" "$base_sha" || { suspend "saved worktree validation failed"; return 1; }

  exec 8> "$MAIN_LOCK"
  flock -n 8 || { fail "main integration lock is busy"; return 1; }
  preflight
  if [[ ! -s $(state_file delivered) ]]; then
    [[ -z $($GIT_BIN -C "$worktree" status --porcelain) ]] || { fail "non-delivered batch worktree is not clean"; return 1; }
    [[ $($GIT_BIN -C "$worktree" rev-parse HEAD) == "$base_sha" ]] || {
      fail "non-delivered batch changed HEAD"
      return 1
    }
    remove_batch_branch "$branch" "$worktree" "$base_sha"
    log "batch completed without delivered Issues"
    return 0
  fi

  require_delivered_states
  delivered_head=$(read_state delivered_head)
  if [[ -z $delivered_head ]]; then
    delivered_head=$($GIT_BIN -C "$worktree" rev-parse HEAD)
    write_state delivered_head "$delivered_head"
  fi
  [[ $delivered_head =~ ^[a-f0-9]{40}$ ]] || { suspend "saved delivered revision is invalid"; return 1; }
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "$delivered_head" HEAD || {
    fail "worktree lost the delivered revision"
    return 1
  }
  actual_branch=$($GIT_BIN -C "$worktree" symbolic-ref --short HEAD)
  [[ $actual_branch == "$branch" ]] || { fail "integration worktree branch mismatch"; return 1; }

  fetch_batch_branch "$worktree" "$branch" || return 1
  remote_before=$($GIT_BIN -C "$worktree" rev-parse --verify "refs/remotes/origin/$branch")
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "$delivered_head" "$remote_before" || {
    fail "remote batch branch lost the delivered revision"
    return 1
  }

  if $GIT_BIN -C "$worktree" rev-parse -q --verify MERGE_HEAD >/dev/null 2>&1 ||
    [[ -n $($GIT_BIN -C "$worktree" diff --name-only --diff-filter=U) ]]; then
    if [[ -n $(read_state resolver_remote_head) ]]; then
      [[ $(read_state resolver_remote_head) == "$remote_before" ]] || {
        fail "remote batch head changed during interrupted conflict recovery"
        return 1
      }
    else
      write_state resolver_remote_head "$remote_before"
    fi
    resolve_conflict "$worktree" "$branch" || return $?
  else
    [[ -z $($GIT_BIN -C "$worktree" status --porcelain) ]] || { fail "integration worktree is not clean"; return 1; }
    write_state resolver_remote_head "$remote_before"
    if ! $GIT_BIN -C "$worktree" merge --no-edit "origin/$MAIN_BRANCH"; then
      resolve_conflict "$worktree" "$branch" || return $?
    fi
  fi

  if $GIT_BIN -C "$worktree" rev-parse -q --verify MERGE_HEAD >/dev/null 2>&1; then
    fail "conflict resolver left the merge unfinished"
    return 1
  fi
  fetch_batch_branch "$worktree" "$branch" || return 1
  remote_after=$($GIT_BIN -C "$worktree" rev-parse --verify "refs/remotes/origin/$branch")
  [[ $remote_after == "$remote_before" ]] || { fail "remote batch head changed during conflict recovery"; return 1; }
  clear_state_file resolver_remote_head
  actual_branch=$($GIT_BIN -C "$worktree" symbolic-ref --short HEAD)
  [[ $actual_branch == "$branch" ]] || { fail "resolved worktree branch mismatch"; return 1; }
  [[ -z $($GIT_BIN -C "$worktree" status --porcelain) ]] || { fail "resolved worktree is not clean"; return 1; }
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "origin/$MAIN_BRANCH" HEAD || {
    fail "batch does not contain current main"
    return 1
  }
  $GIT_BIN -C "$worktree" merge-base --is-ancestor "$delivered_head" HEAD || {
    fail "resolved batch does not contain delivered work"
    return 1
  }
  $NPM_BIN --prefix "$worktree" test
  $NPM_BIN --prefix "$worktree" run check
  $GIT_BIN -C "$worktree" push origin "$branch"
  integrated_head=$($GIT_BIN -C "$worktree" rev-parse HEAD)
  write_state integrated_head "$integrated_head"

  require_delivered_states
  $GIT_BIN -C "$REPOSITORY_PATH" merge --ff-only "$branch"
  $NPM_BIN --prefix "$REPOSITORY_PATH" test
  $NPM_BIN --prefix "$REPOSITORY_PATH" run check
  $GIT_BIN -C "$REPOSITORY_PATH" push origin "$MAIN_BRANCH"
  write_state phase finalization
  finalize_batch
}

run_cycle() {
  prepare_private_directories
  exec 9> "$RUN_LOCK"
  flock -n 9 || {
    log "another run is active"
    return 0
  }
  [[ ! -f $(state_file suspended) ]] || fail "execution is suspended; use control.sh resume"
  preflight
  if [[ ! -f $(state_file batch) ]]; then
    recover_incomplete_capture || return $?
    capture_batch || {
      local capture_exit=$?
      (( capture_exit == 2 )) && return 0
      return "$capture_exit"
    }
  fi
  case $(read_state phase) in
    setup|issues|integration|finalization) ;;
    *) suspend "saved batch has an invalid phase"; return 1 ;;
  esac
  if [[ $(read_state phase) == setup ]]; then
    ensure_worktree
  fi
  if [[ $(read_state phase) == issues ]]; then
    execute_issues
  fi
  if [[ $(read_state phase) == integration ]]; then
    integrate_batch
  fi
  if [[ $(read_state phase) == finalization ]]; then
    finalize_batch
  fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  case ${1:-cycle} in
    cycle)
      run_cycle
      ;;
    preflight)
      prepare_private_directories
      preflight
      log "preflight passed"
      ;;
    *)
      fail "usage: run.sh [cycle|preflight]"
      exit 2
      ;;
  esac
fi
