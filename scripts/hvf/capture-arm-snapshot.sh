#!/usr/bin/env bash
#
# capture-arm-snapshot.sh — produce a REAL cloud-hypervisor arm64 KVM snapshot.
#
# Runs INSIDE any aarch64 Linux host that exposes /dev/kvm:
#   * a Lima nested-virtualization guest on an Apple M3+ Mac (see capture-on-mac.sh)
#   * an AWS Graviton *.metal instance, Oracle BM.Standard.A1, or any ARM bare metal
#
# It boots a throwaway Ubuntu guest under cloud-hypervisor, lets it reach
# userspace (so the GICv3 distributor/redistributors and vCPU registers hold
# real state), then `pause`s and `snapshot`s it. The snapshot directory
# contains `state.json` — which serializes every vCPU's `VcpuKvmState`
# (kvm_regs + the system-register kvm_one_reg list) AND the GIC
# `Gicv3ItsState { dist, rdist, icc, gicd_ctlr }` — exactly the input the
# macOS Hypervisor.framework port's KVM->HVF translator consumes.
#
# Output (under $OUT_DIR, default ./ch-arm-snapshot):
#   snapshot/                full cloud-hypervisor snapshot (state.json + memory)
#   state.json               copied out for convenience (the small fixture)
#   ch-arm-snapshot.tar.zst  the whole snapshot, compressed, ready to copy out
#
# Everything is overridable by environment variable; see the CONFIG block.

set -euo pipefail

# --------------------------------- CONFIG ---------------------------------- #
CH_VERSION="${CH_VERSION:-v52.0}"
CH_URL="${CH_URL:-https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static-aarch64}"
CHREMOTE_URL="${CHREMOTE_URL:-https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/ch-remote-static-aarch64}"
# AArch64 EDK2 UEFI firmware from cloud-hypervisor's edk2 fork (boots cloud images).
FW_URL="${FW_URL:-https://github.com/cloud-hypervisor/edk2/releases/latest/download/CLOUDHV_EFI.fd}"
# Ubuntu 24.04 (noble) arm64 cloud image — a real distro guest.
IMG_URL="${IMG_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img}"

GUEST_CPUS="${GUEST_CPUS:-1}"
GUEST_MEM_MB="${GUEST_MEM_MB:-1024}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"   # seconds to wait for the in-guest marker

WORK_DIR="${WORK_DIR:-$HOME/.cache/ch-arm-snapshot}"
OUT_DIR="${OUT_DIR:-$PWD/ch-arm-snapshot}"
# --------------------------------------------------------------------------- #

log()  { printf '\033[1;36m[capture]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[capture]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[capture] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -m)" = "aarch64" ] || die "must run on aarch64 (this is $(uname -m))"
[ -e /dev/kvm ] || die "/dev/kvm is missing — this host has no (nested) KVM. \
On an M3+ Mac use capture-on-mac.sh; in the cloud use an ARM *.metal instance."
[ -r /dev/kvm ] && [ -w /dev/kvm ] || \
  warn "/dev/kvm is not read/writable by $(id -un); will use sudo for the VM."

KVM_PREFIX=()
if ! { [ -r /dev/kvm ] && [ -w /dev/kvm ]; }; then KVM_PREFIX=(sudo); fi

# --- dependencies ---------------------------------------------------------- #
need_apt=()
command -v qemu-img    >/dev/null 2>&1 || need_apt+=(qemu-utils)
command -v cloud-localds >/dev/null 2>&1 || need_apt+=(cloud-image-utils)
command -v curl        >/dev/null 2>&1 || need_apt+=(curl)
command -v zstd        >/dev/null 2>&1 || need_apt+=(zstd)
if [ "${#need_apt[@]}" -gt 0 ]; then
  log "installing host deps: ${need_apt[*]}"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need_apt[@]}"
fi

mkdir -p "$WORK_DIR" "$OUT_DIR"
cd "$WORK_DIR"

fetch() { # url dest
  local url="$1" dest="$2"
  if [ -s "$dest" ]; then log "have $(basename "$dest") (cached)"; return; fi
  log "downloading $(basename "$dest")"
  curl --fail --location --progress-bar --output "$dest.part" "$url"
  mv "$dest.part" "$dest"
}

fetch "$CH_URL"      cloud-hypervisor
fetch "$CHREMOTE_URL" ch-remote
fetch "$FW_URL"      CLOUDHV_EFI.fd
fetch "$IMG_URL"     noble-arm64.img
chmod +x cloud-hypervisor ch-remote

# --- build the guest disk + a NoCloud seed (autologin, no network needed) --- #
if [ ! -s guest.raw ]; then
  log "converting cloud image to raw"
  qemu-img convert -O raw noble-arm64.img guest.raw
  qemu-img resize -f raw guest.raw 8G >/dev/null
fi

MARKER="CH_SNAPSHOT_READY_$$"
if [ ! -s seed.img ]; then
  log "building NoCloud seed (marker=$MARKER)"
  cat > user-data <<EOF
#cloud-config
password: ubuntu
chpasswd: { expire: false }
ssh_pwauth: true
# No datasource network wait; just announce readiness on the serial console so
# the host knows the guest fully booted and the GIC/vCPU state is "interesting".
runcmd:
  - [ sh, -c, "echo $MARKER > /dev/ttyAMA0" ]
EOF
  cat > meta-data <<EOF
instance-id: ch-snap-$$
local-hostname: ch-snap
EOF
  cloud-localds seed.img user-data meta-data
fi

# --- boot under cloud-hypervisor ------------------------------------------- #
API_SOCK="$WORK_DIR/ch.sock"
SERIAL_LOG="$WORK_DIR/serial.log"
rm -f "$API_SOCK" "$SERIAL_LOG"
: > "$SERIAL_LOG"

CH_PID=""
cleanup() {
  if [ -n "$CH_PID" ] && kill -0 "$CH_PID" 2>/dev/null; then
    log "shutting the guest down"
    "${KVM_PREFIX[@]}" ./ch-remote --api-socket "$API_SOCK" shutdown-vmm 2>/dev/null || true
    sleep 1
    kill "$CH_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log "booting guest (${GUEST_CPUS} vCPU, ${GUEST_MEM_MB} MiB) under cloud-hypervisor"
"${KVM_PREFIX[@]}" ./cloud-hypervisor \
  --api-socket "$API_SOCK" \
  --firmware ./CLOUDHV_EFI.fd \
  --disk path=guest.raw --disk path=seed.img,readonly=on \
  --cpus "boot=${GUEST_CPUS}" \
  --memory "size=${GUEST_MEM_MB}M" \
  --serial "file=$SERIAL_LOG" \
  --console off \
  >"$WORK_DIR/ch.stdout" 2>"$WORK_DIR/ch.stderr" &
CH_PID=$!

# --- wait for the guest to reach userspace --------------------------------- #
log "waiting up to ${BOOT_TIMEOUT}s for the guest to finish booting"
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
booted=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$CH_PID" 2>/dev/null; then
    warn "cloud-hypervisor exited early; stderr:"; cat "$WORK_DIR/ch.stderr" >&2
    die "guest VMM died before snapshot"
  fi
  if grep -q "$MARKER" "$SERIAL_LOG" 2>/dev/null; then booted=1; break; fi
  # Fallback signal: a late-boot systemd target also means the GIC is live.
  if grep -qiE "Reached target .*(Multi-User|Cloud-init|Login)" "$SERIAL_LOG" 2>/dev/null; then
    booted=1; break
  fi
  sleep 2
done
if [ "$booted" -eq 1 ]; then
  log "guest is up; letting it settle for 5s"
  sleep 5
else
  warn "boot marker not seen in ${BOOT_TIMEOUT}s — snapshotting anyway \
(kernel + GIC are almost certainly live). Check $SERIAL_LOG if restore misbehaves."
fi

# --- pause + snapshot ------------------------------------------------------ #
SNAP_DIR="$OUT_DIR/snapshot"
rm -rf "$SNAP_DIR"; mkdir -p "$SNAP_DIR"

log "pausing the guest"
"${KVM_PREFIX[@]}" ./ch-remote --api-socket "$API_SOCK" pause

log "taking the snapshot -> $SNAP_DIR"
"${KVM_PREFIX[@]}" ./ch-remote --api-socket "$API_SOCK" snapshot "file://$SNAP_DIR"

# cloud-hypervisor writes files owned by root when we used sudo; make them ours.
if [ "${#KVM_PREFIX[@]}" -gt 0 ]; then sudo chown -R "$(id -u):$(id -g)" "$SNAP_DIR"; fi

[ -s "$SNAP_DIR/state.json" ] || die "snapshot produced no state.json"
cp "$SNAP_DIR/state.json" "$OUT_DIR/state.json"

log "snapshot contents:"
ls -lh "$SNAP_DIR" | sed 's/^/    /'

# Quick sanity: confirm the artifact really carries KVM vCPU + GIC state.
if grep -q '"core_regs"' "$SNAP_DIR/state.json" 2>/dev/null; then
  log "state.json carries vCPU core_regs ✓"
fi
if grep -qiE '"(gicd_ctlr|rdist|dist)"' "$SNAP_DIR/state.json" 2>/dev/null; then
  log "state.json carries GIC distributor/redistributor state ✓"
fi

# --- package --------------------------------------------------------------- #
TARBALL="$OUT_DIR/ch-arm-snapshot.tar.zst"
log "packaging -> $TARBALL"
tar -C "$OUT_DIR" -c snapshot | zstd -q -19 -o "$TARBALL" -f

log "DONE."
log "  full snapshot dir : $SNAP_DIR"
log "  state.json        : $OUT_DIR/state.json  ($(wc -c < "$OUT_DIR/state.json") bytes)"
log "  tarball           : $TARBALL  ($(wc -c < "$TARBALL") bytes)"
log ""
log "Copy the tarball back to the Mac and point the HVF translator tests at it."
