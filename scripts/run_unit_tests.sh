#!/usr/bin/env bash
# shellcheck disable=SC2068

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

process_common_args "$@"

cargo_args=("")

# We test the superset of all unit tests in one go.
features="fw_cfg,ivshmem,pvmemcontrol"
if [[ $(uname -m) = "x86_64" ]]; then
    features+=",hypervisor/mshv_emulator,sev_snp"
fi
cargo_args+=("--features $features")

# shellcheck disable=SC2154
if [[ $hypervisor = "mshv" ]]; then
    cargo_args+=("--features $hypervisor")
fi

export RUST_BACKTRACE=1
cargo test --lib --bins --target "$BUILD_TARGET" --release --workspace ${cargo_args[@]} || exit 1
cargo test --doc --target "$BUILD_TARGET" --release --workspace ${cargo_args[@]} || exit 1
