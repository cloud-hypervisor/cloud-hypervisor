#!/bin/bash

source $HOME/.cargo/env

cargo test --all --no-run

pushd target/debug
ls  | grep net_util | grep -v "\.d" | xargs sudo setcap cap_net_admin,cap_net_raw+ep
popd

# More effective than just cargo test --all as it captures crates within crates
for f in $(find . -name Cargo.toml -printf '%h\n' | sort -u); do
  pushd $f > /dev/null;
  cargo test || exit 1;
  popd > /dev/null;
done
