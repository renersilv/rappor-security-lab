#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { printf 'usage: activate-campaign.sh authorization attempts-root candidate\n' >&2; exit 2; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
state_root=${JOAO_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security-lab/joao}
shared_lock=${JOAO_SHARED_LOCK:-${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security/sequential-agents.lock}
{
  flock -n 8 || { printf 'campaign_wait=shared_worker_active\n' >&2; exit 75; }
  {
    flock -n 9 || { printf 'campaign_wait=joao_active\n' >&2; exit 75; }
    python3 "$script_dir/campaign-control.py" activate "$state_root" "$1" "$2" "$3"
  } 9> "$state_root/run.lock"
} 8> "$shared_lock"
