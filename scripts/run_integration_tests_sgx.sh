#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"

if [[ "$hypervisor" = "mshv" ]]; then
    echo "Unsupported SGX test for MSHV"
    exit 1
fi

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

cargo build --all --release $features_build --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor

export RUST_BACKTRACE=1

time cargo test $features_test "tests::sgx::$test_filter"
RES=$?

exit $RES
