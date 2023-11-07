#!/bin/bash
set -x

# This set of vfio tests require to be ran on a specific machine with
# specific hardware (e.g. the "vfio" bera-metal worker equipped with a
# Nvidia Tesla T4 card). So the provisioning of the running machine is
# out of the scope of this script, including the custom guest image with
# Nvidia drivers installed, and properly configured Nvidia Tesla T4 card.

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"

WORKLOADS_DIR="$HOME/workloads"

download_hypervisor_fw 

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target $BUILD_TARGET

export RUST_BACKTRACE=1
time cargo test "vfio::test_nvidia" -- --test-threads=1 ${test_binary_args[*]}
RES=$?

exit $RES
