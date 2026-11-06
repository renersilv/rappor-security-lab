#!/usr/bin/env bash
# Sourced by the installed wrapper, never by the task implementation model.

recovery_notice() {
  local marker='<!-- joao-recovery:19 -->' message
  message=$(python3 "$SCRIPT_DIR/recovery.py" notice "$STATE_ROOT") || return $?
  queue_comment 19 "$marker" "$message"
}

recover_campaign_failure() {
  local result=0 phase
  recovery_notice || return $?
  python3 "$SCRIPT_DIR/recovery.py" supervise "$STATE_ROOT" --repository "$REPOSITORY_PATH" \
    --model "$MODEL" --effort "$REASONING_EFFORT" || result=$?
  recovery_flush_notice || return $?
  phase=$(python3 "$SCRIPT_DIR/recovery.py" phase "$STATE_ROOT") || return $?
  case $phase in
    recovered) log "Reviewed repair installed; preserved task resumes on the next timer activation" ;;
    unrepairable|external_action) log "Campaign recovery stopped with phase $phase; preserved task is not resuming" ;;
    *) log "Campaign recovery turn ended with phase $phase and status $result; original task remains gated" ;;
  esac
  return "$result"
}

recovery_flush_notice() {
  local pending
  pending=$(python3 "$SCRIPT_DIR/recovery.py" notice-pending "$STATE_ROOT") || return $?
  [[ $pending == yes ]] || return 0
  recovery_notice || return $?
  python3 "$SCRIPT_DIR/recovery.py" notice-done "$STATE_ROOT"
}
