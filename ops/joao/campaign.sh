#!/usr/bin/env bash
# Sourced by stages.sh; no experiment or final delivery is started by this adapter.

campaign_enabled() {
  [[ $1 == 19 && -e $STATE_ROOT/campaign.json && $(azure_queue campaign --item "$1") == 19 ]]
}

campaign_command() {
  python3 "$SCRIPT_DIR/campaign-control.py" "$1" "$STATE_ROOT"
}

campaign_review_command() {
  python3 "$SCRIPT_DIR/campaign-review.py" "$1" "$STATE_ROOT"
}

campaign_review_notice() {
  local phase=$1 marker='<!-- joao-campaign-review:19 -->' message
  case $phase in
    reviewing) message='A revisão independente automática está em execução, limitada a 20 minutos. O próprio serviço entregará o diagnóstico ao João. Nenhuma ação sua é necessária nesta etapa.' ;;
    continued) message='A revisão independente entregou o próximo passo ao João. O serviço retoma a mesma tarefa automaticamente, nesta ativação ou no próximo ciclo de até cinco minutos. Esta revisão não conclui os testes da plataforma.' ;;
    stalled) message='A continuação automática esgotou as revisões sem progresso relevante confirmado, incluindo o replanejamento quando aplicável. A issue permanece em andamento: é uma falha técnica, não falta de autorização. O diagnóstico foi preservado; a recuperação não pode declarar uma retomada enquanto essa condição persistir.' ;;
    owner_required) message=$(campaign_review_command notice-body) || return $? ;;
    *) return 65 ;;
  esac
  message+=$'\n\n'$(python3 "$SCRIPT_DIR/objectives.py" public "$STATE_ROOT") || return $?
  queue_comment 19 "$marker" "$message"
}

campaign_review_flush_notice() {
  local phase operational
  campaign_review_command reconcile || return $?
  phase=$(campaign_review_command notice) || return $?
  [[ $phase != none ]] || return 0
  campaign_review_notice "$phase" || return $?
  if [[ $phase == owner_required ]]; then
    operational=$(issue_operational_state 19) || return $?
    if [[ $operational == doing ]]; then
      set_item_phase 19 blocked || return $?
    else
      [[ $operational == blocked ]] || return 65
    fi
  fi
  campaign_review_command notice-done
}

run_campaign_review() {
  local worktree=$1 directory phase archive validation attempts limit request result=0
  phase=$(campaign_review_command phase) || return $?
  if [[ $phase == stalled ]]; then
    campaign_review_notice stalled || return $?
    return 70
  fi
  directory=$(campaign_review_command prepare) || return $?
  campaign_review_notice reviewing || return $?
  # The saved executor session never reviews or writes its own checkpoint.
  # Cache only a valid response. A malformed verdict is never an approval.
  if [[ -f $directory/model-completed ]]; then
    validation=$(campaign_review_command validate-response) || return $?
    if [[ $validation == regenerate ]]; then
      archive=$(mktemp -d "$directory/rejected-XXXXXX") || return $?
      cp "$directory/events.jsonl" "$archive/events.jsonl" || return $?
      mv "$directory/model-completed" "$archive/model-completed" || return $?
    elif [[ $validation != valid ]]; then
      return 65
    fi
  fi
  if [[ ! -f $directory/model-completed ]]; then
    limit=$(python3 "$SCRIPT_DIR/recovery.py" review-limit "$STATE_ROOT") || return $?
    [[ $limit =~ ^(3|6|9)$ ]] || return 65
    if [[ -f $directory/model-attempts ]]; then
      attempts=$(cat "$directory/model-attempts") || return $?
      [[ $attempts =~ ^[0-9]$ ]] || return 65
    elif [[ -f $directory/events.jsonl ]]; then
      # Preserve already consumed transports when upgrading an existing job.
      attempts=1
      for archive in "$directory"/retry-*; do
        [[ ! -d $archive ]] || attempts=$((attempts + 1))
      done
    else
      attempts=0
    fi
    (( attempts < limit )) || return 70
    if [[ -f $directory/events.jsonl || -f $directory/errors.log ]]; then
      archive=$(mktemp -d "$directory/retry-XXXXXX") || return $?
      if [[ -f $directory/events.jsonl ]]; then
        mv "$directory/events.jsonl" "$archive/" || return $?
      fi
      if [[ -f $directory/errors.log ]]; then
        mv "$directory/errors.log" "$archive/" || return $?
      fi
    fi
    request=$(mktemp "$directory/request-XXXXXX.md") || return $?
    # Keep the original snapshot immutable; bind the actual updated instructions too.
    cat "$SCRIPT_DIR/CAMPAIGN_REVIEW_PROMPT.md" "$directory/prompt.md" > "$request" || return $?
    sha256sum "$request" > "$request.sha256" || return $?
    chmod 600 "$request" "$request.sha256"
    printf '%s\n' "$((attempts + 1))" > "$directory/model-attempts" || return $?
    chmod 600 "$directory/model-attempts"
    env -u OPENAI_API_KEY -u CODEX_API_KEY \
      "$TIMEOUT_BIN" --signal=TERM --kill-after=15s 20m \
      "$CODEX_BIN" exec --ignore-user-config -C "$worktree" -m "$MODEL" -s read-only \
      -c 'approval_policy="never"' -c "model_reasoning_effort=\"$REASONING_EFFORT\"" \
      --disable shell_tool --disable apps --disable plugins --disable remote_plugin --disable multi_agent \
      -c 'web_search="disabled"' --output-schema "$SCRIPT_DIR/campaign-review-result.schema.json" \
      --json - < "$request" > "$directory/events.jsonl" 2> "$directory/errors.log" || result=$?
    chmod 600 "$directory/events.jsonl" "$directory/errors.log"
    # Review timeout is an operational failure, not an executor time slice.
    (( result == 0 )) || return 70
    validation=$(campaign_review_command validate-response) || return $?
    [[ $validation == valid ]] || return 70
    printf 'completed\n' > "$directory/model-completed"
    chmod 600 "$directory/model-completed"
  fi
  phase=$(campaign_review_command finish) || return $?
  campaign_review_flush_notice || return $?
  [[ $phase != stalled ]] || return 70
}

execute_campaign_item() {
  local issue=$1 worktree=$2 branch=$3 phase operational result=0
  campaign_review_flush_notice || return $?
  phase=$(campaign_review_command phase) || return $?
  [[ $phase != stalled ]] || return 70
  phase=$(campaign_command phase) || return $?
  if [[ $phase == review_pending ]]; then
    run_campaign_review "$worktree" || return $?
    phase=$(campaign_command phase) || return $?
  fi
  if [[ $phase != active ]]; then
    log "Issue #$issue campaign is $phase; preserving evidence without another model"
    return 0
  fi
  operational=$(issue_operational_state "$issue") || return $?
  if [[ $operational == blocked ]]; then
    log "Owner-blocked campaign awaits an authorized Azure To Do transition"
    return 0
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
  if [[ $phase == review_pending ]]; then
    run_campaign_review "$worktree" || return $?
  fi
}
