#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086,SC2154,SC1094
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "${BASH_SOURCE[0]}")/test-util.sh"

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"
mkdir -p "$WORKLOADS_DIR/junit"

process_common_args "$@"

test_features="--features mshv,igvm,sev_snp"
build_features="mshv,igvm,sev_snp"

JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.qcow2"
JAMMY_OS_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_IMAGE" ]; then
    echo "Missing: $JAMMY_OS_IMAGE — run: python3 scripts/fetch_workloads.py --test cvm"
    exit 1
fi

JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.raw"
JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $JAMMY_OS_IMAGE_NAME $JAMMY_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

cargo build --features $build_features --all --release --target "$BUILD_TARGET"

export RUST_BACKTRACE=1
time cargo nextest run -p cloud-hypervisor $test_features --profile common_cvm --no-tests=pass --test-threads=$(($(nproc) / 4)) "$test_filter" -- ${test_binary_args[*]}
RES=$?

exit $RES
