#!/usr/bin/env bash
set -euo pipefail

readonly VM_NAME="joao-windows-x64"
readonly LIBVIRT_URI="qemu:///session"
readonly VM_SERVICE="rappor-windows-lab.service"
readonly DISK_DIRECTORY="/home/linux/.local/share/rappor-windows-lab/vms"
readonly OVERLAY="$DISK_DIRECTORY/joao-windows-x64.qcow2"
readonly BASE="$DISK_DIRECTORY/joao-windows-x64-base.qcow2"
readonly PREVIOUS="$DISK_DIRECTORY/joao-windows-x64.qcow2.pre-restore"
readonly VIRTUAL_SIZE="72G"

fail() {
  printf 'Windows VM control failed: %s\n' "$1" >&2
  exit 1
}

libvirt_service_ready() {
  systemctl --user is-active --quiet "$VM_SERVICE" || return 1
  local daemon pid
  for daemon in libvirtd virtqemud; do
    while IFS= read -r pid; do
      [[ -n "$pid" ]] || continue
      if grep -Fq "/$VM_SERVICE" "/proc/$pid/cgroup"; then
        return 0
      fi
    done < <(pgrep -u "$(id -u)" -x "$daemon" || true)
  done
  return 1
}

libvirt_daemon_running() {
  pgrep -u "$(id -u)" -x libvirtd >/dev/null || pgrep -u "$(id -u)" -x virtqemud >/dev/null
}

ensure_vm_service() {
  if libvirt_service_ready; then
    return
  fi
  systemctl --user stop "$VM_SERVICE" >/dev/null 2>&1 || true
  local attempt
  for ((attempt = 0; attempt < 75; attempt++)); do
    if ! libvirt_daemon_running; then
      break
    fi
    sleep 2
  done
  if libvirt_daemon_running; then
    fail "a libvirt daemon outside the dedicated VM service did not expire"
  fi
  systemctl --user reset-failed "$VM_SERVICE" >/dev/null 2>&1 || true
  systemctl --user start "$VM_SERVICE"
  libvirt_service_ready || fail "the dedicated VM service did not retain the libvirt daemon"
}

state() {
  ensure_vm_service
  virsh --connect "$LIBVIRT_URI" domstate "$VM_NAME" | tr -d '\r'
}

wait_for_state() {
  local expected="$1"
  local attempts="${2:-90}"
  local current
  for ((index = 0; index < attempts; index++)); do
    current="$(state)"
    if [[ "$current" == "$expected" ]]; then
      return 0
    fi
    sleep 2
  done
  fail "the VM did not reach state '$expected'"
}

require_exact_files() {
  [[ -f "$OVERLAY" ]] || fail "the exact writable overlay is absent"
  [[ -f "$BASE" ]] || fail "the exact immutable base is absent"
  local backing
  backing="$(qemu-img info --force-share --output=json "$OVERLAY" | jq -r '.["backing-filename"] // ""')"
  [[ "$backing" == "$BASE" ]] || fail "the writable overlay has an unexpected backing file"
}

case "${1:-}" in
  preflight)
    ensure_vm_service
    require_exact_files
    printf 'state=%s\n' "$(state)"
    virsh --connect "$LIBVIRT_URI" dominfo "$VM_NAME" | awk -F: '/^Autostart:/{gsub(/^[ \t]+/, "", $2); print "autostart=" $2}'
    qemu-img info --force-share --output=json "$OVERLAY" | jq -r '"overlay_bytes=" + (.["actual-size"] | tostring)'
    ;;
  start)
    ensure_vm_service
    if [[ "$(state)" != "running" ]]; then
      virsh --connect "$LIBVIRT_URI" start "$VM_NAME" >/dev/null
    fi
    wait_for_state running
    ;;
  wake-display)
    [[ "$(state)" == "running" ]] || fail "the VM must be running before waking its display"
    virsh --connect "$LIBVIRT_URI" send-key "$VM_NAME" KEY_LEFTSHIFT >/dev/null
    ;;
  shutdown)
    if [[ "$(state)" == "running" ]]; then
      virsh --connect "$LIBVIRT_URI" shutdown "$VM_NAME" >/dev/null
    fi
    wait_for_state "shut off"
    ;;
  suspend)
    [[ "$(state)" == "running" ]] || fail "the VM must be running before suspend"
    virsh --connect "$LIBVIRT_URI" suspend "$VM_NAME" >/dev/null
    wait_for_state paused 15
    ;;
  resume)
    [[ "$(state)" == "paused" ]] || fail "the VM must be paused before resume"
    virsh --connect "$LIBVIRT_URI" resume "$VM_NAME" >/dev/null
    wait_for_state running 15
    ;;
  restore-begin)
    require_exact_files
    [[ "$(state)" == "shut off" ]] || fail "the VM must be shut off before restore"
    [[ ! -e "$PREVIOUS" ]] || fail "a previous overlay is already retained"
    mv -- "$OVERLAY" "$PREVIOUS"
    if ! qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" "$VIRTUAL_SIZE"; then
      mv -- "$PREVIOUS" "$OVERLAY"
      fail "the fresh writable overlay could not be created"
    fi
    ;;
  restore-commit)
    [[ -f "$PREVIOUS" ]] || fail "no retained overlay is available to commit"
    [[ -f "$OVERLAY" ]] || fail "the restored overlay is absent"
    [[ "$(state)" == "running" ]] || fail "the restored VM must be verified while running"
    rm -- "$PREVIOUS"
    ;;
  restore-rollback)
    [[ "$(state)" == "shut off" ]] || fail "the VM must be shut off before rollback"
    [[ -f "$PREVIOUS" ]] || fail "no retained overlay is available to roll back"
    [[ -f "$OVERLAY" ]] || fail "the failed restored overlay is absent"
    rm -- "$OVERLAY"
    mv -- "$PREVIOUS" "$OVERLAY"
    ;;
  *)
    fail "expected preflight, start, wake-display, shutdown, suspend, resume, restore-begin, restore-commit or restore-rollback"
    ;;
esac
