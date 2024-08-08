#!/usr/bin/env bash
# shellcheck disable=SC2068

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

process_common_args "$@"

cargo_args=("")

# shellcheck disable=SC2154
if [[ $hypervisor = "mshv" ]]; then
    cargo_args+=("--features $hypervisor")
elif [[ $(uname -m) = "x86_64" ]]; then
    cargo_args+=("--features tdx")
fi

export RUST_BACKTRACE=1
cargo test --lib --bins --target "$BUILD_TARGET" --release --workspace ${cargo_args[@]} || exit 1
cargo test --doc --target "$BUILD_TARGET" --release --workspace ${cargo_args[@]} || exit 1
