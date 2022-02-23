#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"
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
strip target/$BUILD_TARGET/release/cloud-hypervisor

export RUST_BACKTRACE=1

time cargo test $features "vfio::$test_filter" -- --test-threads=1 ${test_binary_args[*]}
RES=$?

exit $RES
