#!/usr/bin/env bash
#
# capture-on-mac.sh — capture a real cloud-hypervisor arm64 KVM snapshot
# entirely on an Apple Silicon Mac, using Lima nested virtualization.
#
# What it does:
#   1. Verifies this is an M3+ Mac on macOS 15+ (nested-virt prerequisites).
#   2. Installs Lima (via Homebrew) if it is missing.
#   3. Starts the `lima-arm-kvm.yaml` guest, which exposes /dev/kvm nested.
#   4. Runs capture-arm-snapshot.sh INSIDE that guest, where cloud-hypervisor
#      boots a throwaway Ubuntu VM and snapshots it.
#   5. Copies the resulting snapshot back to the Mac.
#
# Output lands in $OUT_DIR (default: ./ch-arm-snapshot on the Mac).
#
# Usage:
#   scripts/hvf/capture-on-mac.sh            # capture, leave the VM running
#   KEEP_VM=0 scripts/hvf/capture-on-mac.sh  # capture, then stop the Lima VM

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="${VM_NAME:-arm-kvm}"
TEMPLATE="$HERE/lima-arm-kvm.yaml"
OUT_DIR="${OUT_DIR:-$PWD/ch-arm-snapshot}"
KEEP_VM="${KEEP_VM:-1}"

log()  { printf '\033[1;35m[mac]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mac] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- prerequisites --------------------------------------------------------- #
[ "$(uname -s)" = "Darwin" ] || die "run this on macOS"
[ "$(uname -m)" = "arm64" ]  || die "run this on Apple Silicon"

CHIP="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
case "$CHIP" in
  *"M1"*|*"M2"*)
    die "$CHIP has NO nested virtualization. Nested /dev/kvm needs Apple M3 or \
later. Use the cloud fallback (an ARM *.metal instance) with capture-arm-snapshot.sh." ;;
  *) log "chip: $CHIP" ;;
esac

OS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
[ "$OS_MAJOR" -ge 15 ] || die "macOS 15 (Sequoia) or newer is required for nested \
virtualization; this is $(sw_vers -productVersion)."

# --- Lima ------------------------------------------------------------------ #
if ! command -v limactl >/dev/null 2>&1; then
  command -v brew >/dev/null 2>&1 || die "Homebrew not found; install Lima manually."
  log "installing Lima via Homebrew"
  brew install lima
fi
log "lima: $(limactl --version)"

mkdir -p /tmp/lima "$OUT_DIR"

# --- start the nested-KVM guest -------------------------------------------- #
if limactl list --quiet 2>/dev/null | grep -qx "$VM_NAME"; then
  log "Lima VM '$VM_NAME' already exists; ensuring it is started"
  limactl start "$VM_NAME"
else
  log "creating + starting Lima VM '$VM_NAME' (nested virtualization)"
  limactl start --name="$VM_NAME" --tty=false "$TEMPLATE"
fi

log "verifying nested /dev/kvm inside the guest"
if ! limactl shell "$VM_NAME" test -e /dev/kvm; then
  die "nested /dev/kvm did not appear inside the guest. See the probe hint above."
fi
log "nested /dev/kvm is present ✓ — this M3 really can host KVM."

# --- run the capture inside the guest -------------------------------------- #
GUEST_OUT="/tmp/lima/ch-arm-snapshot"
GUEST_WORK="/var/tmp/ch-arm-snapshot-work"
log "running capture-arm-snapshot.sh inside the guest (this downloads ~600MB \
and boots a real Ubuntu guest; expect several minutes)"
limactl shell "$VM_NAME" env OUT_DIR="$GUEST_OUT" WORK_DIR="$GUEST_WORK" \
  bash -s < "$HERE/capture-arm-snapshot.sh"

# --- collect the artifact -------------------------------------------------- #
# /tmp/lima is a writable shared mount, so the output is already on the Mac.
if [ -d "$GUEST_OUT" ]; then
  log "copying snapshot from the shared mount to $OUT_DIR"
  cp -R "$GUEST_OUT/." "$OUT_DIR/"
else
  die "expected output at $GUEST_OUT (shared mount) but it is missing."
fi

[ -s "$OUT_DIR/state.json" ] || die "no state.json in $OUT_DIR"
log "captured snapshot on the Mac:"
ls -lh "$OUT_DIR" | sed 's/^/    /'

if [ "$KEEP_VM" = "0" ]; then
  log "stopping Lima VM '$VM_NAME' (KEEP_VM=0)"
  limactl stop "$VM_NAME"
fi

log "DONE. Real arm64 KVM snapshot is at: $OUT_DIR"
log "  state.json (registers + GIC blob): $OUT_DIR/state.json"
log "  full snapshot + memory          : $OUT_DIR/snapshot/"
