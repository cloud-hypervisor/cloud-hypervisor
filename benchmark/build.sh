#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

cd "$REPO_ROOT"

if [[ -n ${CARGO_BIN:-} ]]; then
    cargo_bin=$CARGO_BIN
elif command -v cargo >/dev/null 2>&1; then
    cargo_bin=$(command -v cargo)
elif [[ -x ${HOME:-}/.cargo/bin/cargo ]]; then
    cargo_bin=$HOME/.cargo/bin/cargo
else
    echo "Cargo was not found. Run $BENCHMARK_DIR/setup.sh first." >&2
    exit 1
fi

if [[ ${WITH_QPL:-1} == 1 ]]; then
    export QPL_INCLUDE_DIR=${QPL_INCLUDE_DIR:-/usr/local/include}
    export QPL_LIB_DIR=${QPL_LIB_DIR:-/usr/local/lib64}
    "$cargo_bin" build --release \
        -p cloud-hypervisor --bins \
        -p offload_daemon \
        --features offload_daemon/qpl
else
    "$cargo_bin" build --release \
        -p cloud-hypervisor --bins \
        -p offload_daemon
fi

echo "Benchmark binaries built in $BIN_DIR"