#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ]; then
    test_features="--features mshv"
fi

NOBLE_OS_IMAGE_NAME="noble-server-cloudimg-amd64-custom-20260601-0.qcow2"
NOBLE_OS_IMAGE="$WORKLOADS_DIR/$NOBLE_OS_IMAGE_NAME"
if [ ! -f "$NOBLE_OS_IMAGE" ]; then
    echo "Missing: $NOBLE_OS_IMAGE — run: python3 scripts/fetch_workloads.py --test rate-limiter"
    exit 1
fi

NOBLE_OS_RAW_IMAGE_NAME="noble-server-cloudimg-amd64-custom-20260601-0.raw"
NOBLE_OS_RAW_IMAGE="$WORKLOADS_DIR/$NOBLE_OS_RAW_IMAGE_NAME"
if [ ! -f "$NOBLE_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $NOBLE_OS_IMAGE_NAME $NOBLE_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux-x86_64"
if [ ! -f "$VMLINUX_IMAGE" ]; then
    echo "Missing: $VMLINUX_IMAGE — run: python3 scripts/fetch_workloads.py --test rate-limiter"
    exit 1
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# Common configuration for every test run
export RUST_BACKTRACE=1
export RUSTFLAGS="$RUSTFLAGS"

time cargo nextest run -p cloud-hypervisor --no-tests=pass $test_features --test-threads=1 "rate_limiter::$test_filter" -- ${test_binary_args[*]}
RES=$?

exit $RES
