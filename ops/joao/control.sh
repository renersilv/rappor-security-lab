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
  local phase branch issue batch_count session_state suspended_state
  phase=$(read_value phase)
  branch=$(read_value branch)
  issue=$(read_value current_issue)
  batch_count=0
  [[ ! -f $STATE_ROOT/batch ]] || batch_count=$(wc -l < "$STATE_ROOT/batch")
  session_state=no
  [[ ! -s $STATE_ROOT/session ]] || session_state=yes
  suspended_state=no
  [[ ! -f $STATE_ROOT/suspended ]] || suspended_state=yes
  [[ $branch =~ ^joao/batch-[0-9TZ-]+-[0-9]+-[0-9]+$ ]] || branch=none
  [[ $issue =~ ^[1-9][0-9]*$ ]] || issue=none
  [[ $phase == setup || $phase == issues || $phase == integration ]] || phase=idle
  printf 'phase=%s\nbatch_size=%s\nbranch=%s\ncurrent_issue=%s\nsession_saved=%s\nsuspended=%s\n' \
    "$phase" "$batch_count" "$branch" "$issue" "$session_state" "$suspended_state"
}

resume() {
  mkdir -p -- "$STATE_ROOT"
  chmod 700 "$STATE_ROOT"
  exec 9> "$STATE_ROOT/run.lock"
  flock -n 9 || {
    printf 'resume_failed=runner_active\n' >&2
    return 1
  }
  rm -f -- "$STATE_ROOT/suspended"
  "$SYSTEMCTL_BIN" --user start joao.service
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
