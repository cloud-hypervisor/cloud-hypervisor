#!/bin/bash

source $HOME/.cargo/env

# More effective than just cargo test --all as it captures crates within crates
for f in $(find . -name Cargo.toml -printf '%h\n' | sort -u); do
  pushd $f > /dev/null;
  cargo test --no-run || exit 1;
  popd > /dev/null;
done

pushd target/debug
ls  | grep net_util | grep -v "\.d" | xargs -n 1 sudo setcap cap_net_admin,cap_net_raw+ep
popd

for f in $(find . -name Cargo.toml -printf '%h\n' | sort -u); do
  pushd $f > /dev/null;
  cargo test || exit 1;
  popd > /dev/null;
done
