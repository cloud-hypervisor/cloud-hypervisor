#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"
# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ] ;  then
    test_features="--features mshv"
fi
WIN_IMAGE_FILE="/root/workloads/windows-server-2022-amd64-2.raw"

WORKLOADS_DIR="/root/workloads"
OVMF_FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/edk2/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
OVMF_FW="$WORKLOADS_DIR/CLOUDHV.fd"
if [ ! -f "$OVMF_FW" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $OVMF_FW_URL || exit 1
    popd
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

# Check if the images are present
if [[ ! -f ${WIN_IMAGE_FILE} || ! -f ${OVMF_FW} ]]; then
    echo "Windows image/firmware not present in the host"
    exit 1
fi

# Use device mapper to create a snapshot of the Windows image
img_blk_size=$(du -b -B 512 ${WIN_IMAGE_FILE} | awk '{print $1;}')
loop_device=$(losetup --find --show --read-only ${WIN_IMAGE_FILE})
dmsetup create windows-base --table "0 $img_blk_size linear $loop_device 0"
dmsetup mknodes
dmsetup create windows-snapshot-base --table "0 $img_blk_size snapshot-origin /dev/mapper/windows-base"
dmsetup mknodes

cargo build --features mshv --all --release --target $BUILD_TARGET

export RUST_BACKTRACE=1

# Only run with 1 thread to avoid tests interfering with one another because
# Windows has a static IP configured
time cargo test $test_features "windows::$test_filter" -- ${test_binary_args[*]}
RES=$?

dmsetup remove_all -f
losetup -D

exit $RES
