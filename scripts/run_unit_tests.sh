#!/bin/bash

source $HOME/.cargo/env

BUILD_TARGET=${BUILD_TARGET-x86_64-unknown-linux-gnu}
cargo_args=("$@")
[ $(uname -m) = "aarch64" ] && cargo_args+=("--no-default-features")
[ $(uname -m) = "aarch64" ] && cargo_args+=("--features mmio,kvm")

cargo test --target $BUILD_TARGET --workspace --no-run ${cargo_args[@]}
pushd target/$BUILD_TARGET/debug
ls  | grep net_util | grep -v "\.d" | xargs -n 1 sudo setcap cap_net_admin,cap_net_raw+ep
popd

sudo adduser $USER kvm
newgrp kvm << EOF || exit 1
  export RUST_BACKTRACE=1
  cargo test --target $BUILD_TARGET --workspace ${cargo_args[@]} || exit 1;
EOF
