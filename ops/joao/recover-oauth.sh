#!/usr/bin/env bash
set -euo pipefail
# Run inside the existing serialized worker, before an implementation call. No new test model.
[[ ${1:-} == 19 && ${2:-} == --worker-lock-held ]] || exit 64
[[ ${INVOCATION_ID:-} =~ ^[a-f0-9]{32}$ ]] || exit 65
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
STATE_ROOT=${JOAO_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security-lab/joao}
IFS= read -r worktree < "$STATE_ROOT/worktree"
[[ $worktree == "$STATE_ROOT"/worktrees/joao-batch-* && -d $worktree ]] || exit 65
[[ -f $worktree/src/run-current-workspace-ai-client.mjs ]] || exit 65
log=$(mktemp "$STATE_ROOT/tmp/oauth-preflight-XXXXXX.log")
chmod 600 "$log"
trap 'rm -f -- "$log"' EXIT
preflight() {
  env -u OPENAI_API_KEY -u CODEX_API_KEY \
    RAPPOR_CURRENT_WORKSPACE="$STATE_ROOT/tmp/issue-19-current-workspace" \
    RAPPOR_ISSUE19_MCP_OVERRIDE='mcp_servers.rapporLabIssue19.url="https://linux-ai2.taile60a95.ts.net:8443/mcp"' \
    timeout --signal=TERM --kill-after=5s 45s node "$worktree/src/run-current-workspace-ai-client.mjs" --preflight > "$log" 2>&1
}
if preflight; then
  printf 'oauth_preflight=ready\n'
  exit 0
fi
# Network, scope, unavailable runtime or an unclassified failure never triggers login.
if ! grep -Fq '"failureClass":"oauth-refresh-failed"' "$log"; then
  printf 'oauth_preflight=unavailable_offline_work_allowed\n'
  exit 0
fi
# One recovery attempt per failed credential generation. Failure is not retried on every timer.
marker="$STATE_ROOT/oauth-recovery-generation"
fingerprint=$(sha256sum /home/linux/.config/rappor-security-lab/issue19-preparation.json)
fingerprint=${fingerprint%% *}
if [[ -f $marker ]] && grep -Fxq "$fingerprint" "$marker"; then
  printf 'oauth_preflight=recovery_already_attempted\n'
  exit 0
fi
printf '%s\n' "$fingerprint" > "$marker"
chmod 600 "$marker"
if timeout --signal=TERM --kill-after=5s 110s node "$SCRIPT_DIR/recover-oauth.mjs"; then
  if preflight; then
    printf 'oauth_preflight=recovered\n'
  else
    # Bind the failure to the new generation too; avoid creating fresh authorizations in a loop.
    sha256sum /home/linux/.config/rappor-security-lab/issue19-preparation.json | cut -d' ' -f1 > "$marker"
    printf 'oauth_preflight=post_recovery_failed\n'
  fi
else
  printf 'oauth_preflight=recovery_failed_offline_work_allowed\n'
fi
