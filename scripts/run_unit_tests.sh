#!/bin/bash

source $HOME/.cargo/env

BUILD_TARGET=${BUILD_TARGET-x86_64-unknown-linux-gnu}
cargo_args=("$@")
[ $(uname -m) = "aarch64" ] && cargo_args+=("--no-default-features")
[ $(uname -m) = "aarch64" ] && cargo_args+=("--features mmio,kvm")

if [ true = "$COVERAGE" ]; then
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
    export RUSTDOCFLAGS="-Cpanic=abort"
fi
cargo test --target $BUILD_TARGET --workspace --no-run ${cargo_args[@]}

pushd target/$BUILD_TARGET/debug
ls  | grep net_util | grep -v "\.d" | xargs -n 1 sudo setcap cap_net_admin,cap_net_raw+ep
popd

sudo adduser $USER kvm
newgrp kvm << EOF || exit 1
  export RUST_BACKTRACE=1
  cargo test --target $BUILD_TARGET --workspace ${cargo_args[@]} || exit 1;
EOF

if [ true = "$COVERAGE" ]; then
    BASE_DIR=./target/$BUILD_TARGET/debug
    LCOV_INFO=$BASE_DIR/$BUILD_TARGET.lcov.info
    OUT_DIR=$BASE_DIR/coverage

    grcov $BASE_DIR -s . -t lcov --branch --ignore-not-existing -o $LCOV_INFO \
	    --ignore '*registry/*' --ignore '*git/*' --ignore '*target/*'
    rm -rf $OUT_DIR
    genhtml -o $OUT_DIR --show-details --highlight --ignore-errors source --legend $LCOV_INFO --function-coverage --branch-coverage
fi

