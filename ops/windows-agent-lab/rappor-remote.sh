#!/usr/bin/env bash
set -euo pipefail

readonly SSH_HOST="127.0.0.1"
readonly SSH_PORT="2222"
readonly SSH_USER="joao"
readonly WORKSPACE='C:\RapporLab\corpus'

fail() {
  printf 'Restricted Windows client failed: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 10 ]] || fail "expected the public workspace continue invocation"
[[ $1 == workspace && $2 == continue && $3 == --operation && $5 == --control-plane && $7 == --protocol ]] ||
  fail "only workspace continue is allowed"
[[ $4 =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] ||
  fail "the operation identifier is invalid"
[[ $6 =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] || fail "the control-plane origin is invalid"
[[ $8 == 1 ]] || fail "the public local-client protocol is invalid"
[[ $9 == --workspace && ${10} == "$WORKSPACE" ]] || fail "the exact synthetic workspace is required"
[[ ${RAPPOR_WINDOWS_SSH_KEY:-} ]] || fail "the protected SSH key path is unavailable"
[[ -f $RAPPOR_WINDOWS_SSH_KEY ]] || fail "the protected SSH key is unavailable"
[[ $(stat -c '%a' "$RAPPOR_WINDOWS_SSH_KEY") == 600 ]] || fail "the protected SSH key must have mode 0600"

control_plane="${6%/}"
[[ $control_plane == "${RAPPOR_WINDOWS_HML_BASE_URL%/}" ]] || fail "the exact authorized control plane is required"
[[ ${RAPPOR_LAB_ATTEMPT_DEADLINE:-} =~ ^[0-9]{10}$ ]] || fail "the one-shot deadline is required"
readonly remote_command="powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:/RapporLab/runtime/workspace-interactive.ps1 -Action Continue -Operation $4 -Origin $control_plane/ -DeadlineUnix $RAPPOR_LAB_ATTEMPT_DEADLINE"

exec ssh \
  -F /dev/null \
  -p "$SSH_PORT" \
  -i "$RAPPOR_WINDOWS_SSH_KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=15 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "$SSH_USER@$SSH_HOST" \
  "$remote_command"
