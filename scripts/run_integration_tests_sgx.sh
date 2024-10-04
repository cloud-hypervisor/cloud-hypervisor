#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

process_common_args "$@"

if [[ "$hypervisor" = "mshv" ]]; then
    echo "Unsupported SGX test for MSHV"
    exit 1
fi

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

download_hypervisor_fw

JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.qcow2"
JAMMY_OS_IMAGE_URL="https://ch-images.azureedge.net/$JAMMY_OS_IMAGE_NAME"
JAMMY_OS_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time wget --quiet $JAMMY_OS_IMAGE_URL || exit 1
    popd || exit
fi

JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.raw"
JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $JAMMY_OS_IMAGE_NAME $JAMMY_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target "$BUILD_TARGET"

export RUST_BACKTRACE=1

time cargo test "sgx::$test_filter" -- ${test_binary_args[*]}
RES=$?

exit $RES
