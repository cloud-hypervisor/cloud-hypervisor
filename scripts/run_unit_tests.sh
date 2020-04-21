#!/bin/bash

source $HOME/.cargo/env

BUILD_TARGET=${BUILD_TARGET-x86_64-unknown-linux-gnu}

cargo test --target $BUILD_TARGET --workspace --no-run
pushd target/$BUILD_TARGET/debug
ls  | grep net_util | grep -v "\.d" | xargs -n 1 sudo setcap cap_net_admin,cap_net_raw+ep
popd

sudo adduser $USER kvm
newgrp kvm << EOF || exit 1
  export RUST_BACKTRACE=1
  cargo test --target $BUILD_TARGET --workspace "$@" || exit 1;
EOF
