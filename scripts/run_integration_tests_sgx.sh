#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"

if [[ "$hypervisor" = "mshv" ]]; then
    echo "Unsupported SGX test for MSHV"
    exit 1
fi

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
FW="$WORKLOADS_DIR/hypervisor-fw"
pushd $WORKLOADS_DIR
rm -f $FW
time wget --quiet $FW_URL || exit 1
popd

JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20221118-1.qcow2"
JAMMY_OS_IMAGE_URL="https://cloud-hypervisor.azureedge.net/$JAMMY_OS_IMAGE_NAME"
JAMMY_OS_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $JAMMY_OS_IMAGE_URL || exit 1
    popd
fi

JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20221118-1.raw"
JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $JAMMY_OS_IMAGE_NAME $JAMMY_OS_RAW_IMAGE_NAME || exit 1
    popd
fi

# For now these values are default for kvm
features=""

BUILD_TARGET="$(uname -m)-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --all --release $features --target $BUILD_TARGET

export RUST_BACKTRACE=1

time cargo test $features "sgx::$test_filter" -- ${test_binary_args[*]}
RES=$?

exit $RES
