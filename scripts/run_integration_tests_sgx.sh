#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"
# For now these values are deafult for kvm
features_build=""
features_test="--features integration_tests"

BUILD_TARGET="$(uname -m)-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

# Use device mapper to create a snapshot of the Ubuntu Focal image
img_blk_size=$(du -b -B 512 /root/workloads/focal-server-cloudimg-amd64-sgx.raw | awk '{print $1;}')
loop_device=$(losetup --find --show --read-only /root/workloads/focal-server-cloudimg-amd64-sgx.raw)
dmsetup create focal-sgx-base --table "0 $img_blk_size linear $loop_device 0"
dmsetup mknodes
dmsetup create focal-sgx-snapshot-base --table "0 $img_blk_size snapshot-origin /dev/mapper/focal-sgx-base"
dmsetup mknodes

cargo build --all --release $features_build --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor

export RUST_BACKTRACE=1

time cargo test $features_test "tests::sgx::"
RES=$?

dmsetup remove -f focal-sgx-snapshot-base
dmsetup mknodes
dmsetup remove -f focal-sgx-base
losetup -d $loop_device

exit $RES
