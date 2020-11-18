#!/bin/bash

source $HOME/.cargo/env
source  $(dirname "$0")/test-util.sh

process_common_args "$@"

BUILD_TARGET=${BUILD_TARGET-x86_64-unknown-linux-gnu}
cargo_args=("")
[ $(uname -m) = "aarch64" ] && cargo_args+=("--no-default-features")
[ $(uname -m) = "aarch64" ] && cargo_args+=("--features kvm")

export RUST_BACKTRACE=1
cargo test --target $BUILD_TARGET --workspace ${cargo_args[@]} || exit 1;
