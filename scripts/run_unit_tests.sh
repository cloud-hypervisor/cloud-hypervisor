#!/bin/bash

source $HOME/.cargo/env
source  $(dirname "$0")/test-util.sh

process_common_args "$@"

BUILD_TARGET=${BUILD_TARGET-x86_64-unknown-linux-gnu}
cargo_args=("")

if [[ $(uname -m) = "aarch64" || $hypervisor = "mshv" ]]; then
    cargo_args+=("--no-default-features")
    cargo_args+=("--features $hypervisor")
fi
export RUST_BACKTRACE=1
cargo test --target $BUILD_TARGET --workspace ${cargo_args[@]} || exit 1;
