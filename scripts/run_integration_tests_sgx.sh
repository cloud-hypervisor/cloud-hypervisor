#!/bin/bash
set -x

source $HOME/.cargo/env

BUILD_TARGET="$(uname -m)-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --all --release --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor

export RUST_BACKTRACE=1

time cargo test --features "integration_tests" "tests::sgx::$@"
RES=$?

if [ $RES -eq 0 ]; then
    # virtio-mmio based testing
    cargo build --all --release --target $BUILD_TARGET --no-default-features --features "mmio,kvm"
    strip target/$BUILD_TARGET/release/cloud-hypervisor

    time cargo test --features "integration_tests,mmio" "tests::sgx::$@"
    RES=$?
fi

exit $RES
