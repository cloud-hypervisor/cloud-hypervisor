#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

process_common_args "$@"
# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ]; then
    test_features="--features mshv"
fi
WIN_IMAGE_FILE="/root/workloads/windows-server-2025-amd64-1.raw"

WORKLOADS_DIR="/root/workloads"
OVMF_FW="$WORKLOADS_DIR/CLOUDHV.fd"

if [ ! -f "$OVMF_FW" ]; then
    echo "Missing workload asset: $OVMF_FW"
    echo "Run: python3 scripts/fetch_workloads.py --test windows"
    exit 1
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

# Check if the images are present
if [[ ! -f ${WIN_IMAGE_FILE} || ! -f ${OVMF_FW} ]]; then
    echo "Windows image/firmware not present in the host"
    exit 1
fi

# Remove every device-mapper device this Windows test suite may have created
# (the base plus any per-test snapshot a crashed or timed-out test left
# behind). Snapshots reference the base as their origin and must be removed
# first, so retry a few times to tolerate ordering. Only 'windows-*' devices
# are touched, never any other device-mapper device on the host.
cleanup_windows_dm() {
    for _ in 1 2 3; do
        local devs
        devs=$(dmsetup ls 2>/dev/null | awk '{print $1}' | grep '^windows-' || true)
        [ -z "$devs" ] && break
        for dev in $devs; do
            dmsetup remove "$dev" 2>/dev/null || true
        done
    done
}

# Clear anything a previous crashed or killed run left behind so the dmsetup
# create below does not fail on a stale device, then detach any stale loop
# devices still backing the image.
cleanup_windows_dm
losetup -j ${WIN_IMAGE_FILE} | cut -d : -f 1 | while read -r stale; do
    losetup -d "$stale" 2>/dev/null || true
done

# Use device mapper to create a snapshot of the Windows image
img_blk_size=$(du -b -B 512 ${WIN_IMAGE_FILE} | awk '{print $1;}')
loop_device=$(losetup --find --show --read-only ${WIN_IMAGE_FILE})
dmsetup create windows-base --table "0 $img_blk_size linear $loop_device 0"
dmsetup mknodes

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# Common configuration for every test run
export RUST_BACKTRACE=1
export RUSTFLAGS="$RUSTFLAGS"

# Only run with 1 thread to avoid tests interfering with one another because
# Windows has a static IP configured
time cargo nextest run -p cloud-hypervisor --retries 3 --no-tests=pass $test_features "windows::$test_filter" --target "$BUILD_TARGET" -- ${test_binary_args[*]}
RES=$?

# Tear down the base and any per-test snapshot devices left over from a crash,
# then detach this run's loop device.
cleanup_windows_dm
losetup -d "$loop_device" 2>/dev/null || true

exit $RES
