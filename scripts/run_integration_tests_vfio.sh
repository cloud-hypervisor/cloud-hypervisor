#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# This set of vfio tests require to be ran on a specific machine with
# specific hardware (e.g. the "vfio" bare-metal worker equipped with a
# Nvidia Tesla T4 card). So the provisioning of the running machine is
# out of the scope of this script, including the custom guest image with
# Nvidia drivers installed, and properly configured Nvidia Tesla T4 card.

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

process_common_args "$@"

WORKLOADS_DIR="$HOME/workloads"

download_hypervisor_fw

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# Common configuration for every test run
export RUST_BACKTRACE=1
export RUSTFLAGS="$RUSTFLAGS"

time cargo nextest run --no-tests=pass --test-threads=1 "vfio::test_nvidia" -- ${test_binary_args[*]}
RES=$?

exit $RES
