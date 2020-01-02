#!/bin/bash

source $HOME/.cargo/env

cargo test --workspace --no-run
pushd target/debug
ls  | grep net_util | grep -v "\.d" | xargs -n 1 sudo setcap cap_net_admin,cap_net_raw+ep
popd

sudo adduser $USER kvm
newgrp kvm << EOF || exit 1
  export RUST_BACKTRACE=1
  cargo test --workspace || exit 1;
EOF
