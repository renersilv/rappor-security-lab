#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT=${JOAO_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security-lab/joao}
SYSTEMCTL_BIN=${JOAO_SYSTEMCTL_BIN:-systemctl}

read_value() {
  local name=$1 value=
  if [[ -f $STATE_ROOT/$name ]]; then
    IFS= read -r value < "$STATE_ROOT/$name" || true
  fi
  printf '%s' "$value"
}

status() {
  local phase branch issue batch_count session_state suspended_state retry_state retry_attempts retry_error_class
  phase=$(read_value phase)
  branch=$(read_value branch)
  issue=$(read_value current_issue)
  batch_count=0
  [[ ! -f $STATE_ROOT/batch ]] || batch_count=$(wc -l < "$STATE_ROOT/batch")
  session_state=no
  [[ ! -s $STATE_ROOT/session ]] || session_state=yes
  suspended_state=no
  [[ ! -f $STATE_ROOT/suspended ]] || suspended_state=yes
  retry_state=none
  retry_attempts=none
  retry_error_class=none
  if [[ -e $STATE_ROOT/issue-retry ]]; then
    if [[ -f $STATE_ROOT/issue-retry && ! -L $STATE_ROOT/issue-retry &&
      -O $STATE_ROOT/issue-retry && $(stat -c '%a' "$STATE_ROOT/issue-retry") == 600 ]]; then
      retry_attempts=$(sed -n 's/^attempts=//p' "$STATE_ROOT/issue-retry")
      retry_error_class=$(sed -n 's/^error_class=//p' "$STATE_ROOT/issue-retry")
      retry_state=scheduled
      grep -Fxq 'suspended=true' "$STATE_ROOT/issue-retry" && retry_state=suspended
      [[ $retry_attempts =~ ^[1-3]$ ]] || retry_attempts=invalid
      [[ $retry_error_class =~ ^(codex_exit|delivery_invalid)$ ]] || retry_error_class=invalid
    else
      retry_state=invalid
      retry_attempts=invalid
      retry_error_class=invalid
    fi
  fi
  [[ $branch =~ ^joao/batch-[0-9TZ-]+-[0-9]+-[0-9]+$ ]] || branch=none
  [[ $issue =~ ^[1-9][0-9]*$ ]] || issue=none
  [[ $phase == setup || $phase == issues || $phase == integration || $phase == finalization ]] || phase=idle
  printf 'phase=%s\nbatch_size=%s\nbranch=%s\ncurrent_issue=%s\nsession_saved=%s\nsuspended=%s\nissue_retry=%s\nretry_attempts=%s\nretry_error_class=%s\n' \
    "$phase" "$batch_count" "$branch" "$issue" "$session_state" "$suspended_state" \
    "$retry_state" "$retry_attempts" "$retry_error_class"
}

resume() {
  mkdir -p -- "$STATE_ROOT"
  chmod 700 "$STATE_ROOT"
  {
    flock -n 9 || {
      printf 'resume_failed=runner_active\n' >&2
      return 1
    }
    rm -f -- "$STATE_ROOT/suspended"
    if [[ -f $STATE_ROOT/issue-retry && ! -L $STATE_ROOT/issue-retry &&
      -O $STATE_ROOT/issue-retry && $(stat -c '%a' "$STATE_ROOT/issue-retry") == 600 ]] &&
      grep -Fxq 'suspended=true' "$STATE_ROOT/issue-retry"; then
      rm -f -- "$STATE_ROOT/issue-retry"
    fi
  } 9> "$STATE_ROOT/run.lock"
  "$SYSTEMCTL_BIN" --user start --no-block joao.service
  printf 'resume_requested=yes\n'
}

case ${1:-status} in
  status) status ;;
  resume) resume ;;
  *)
    printf 'usage: control.sh status|resume\n' >&2
    exit 2
    ;;
esac
