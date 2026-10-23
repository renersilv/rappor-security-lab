#!/usr/bin/env bash
# Sourced by stages.sh; no experiment or final delivery is started by this adapter.

campaign_enabled() {
  [[ $1 == 19 && -e $STATE_ROOT/campaign.json ]]
}

campaign_command() {
  python3 "$SCRIPT_DIR/campaign-control.py" "$1" "$STATE_ROOT"
}

execute_campaign_item() {
  local issue=$1 worktree=$2 branch=$3 phase operational result=0
  phase=$(campaign_command phase) || return $?
  if [[ $phase != active ]]; then
    log "Issue #$issue campaign is $phase; preserving evidence without another model"
    return 0
  fi
  operational=$(issue_operational_state "$issue") || return $?
  if [[ $operational == blocked ]]; then
    $GH_BIN issue edit "$issue" --repo "$REPOSITORY_SLUG" --remove-label blocked --add-label doing >/dev/null || return $?
  elif [[ $operational != doing ]]; then
    return 65
  fi
  campaign_command begin || return $?
  run_codex "$issue" "$worktree" "$branch" || result=$?
  if (( result == 124 )); then
    return 124
  elif (( result != 0 )); then
    return "$result"
  fi
  phase=$(campaign_command finish) || return $?
  operational=$(issue_operational_state "$issue") || return $?
  if [[ $phase == owner_required ]]; then
    [[ $operational == blocked ]] || return 65
  else
    [[ $operational == doing ]] || return 65
  fi
  log "Issue #$issue campaign progressed to $phase; final acceptance remains pending"
}
