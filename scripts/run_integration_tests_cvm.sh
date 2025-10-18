#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086,SC2154,SC1094
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "${BASH_SOURCE[0]}")/test-util.sh"

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

test_features="--features mshv,igvm,sev_snp"
build_features="mshv,igvm,sev_snp"

download_x86_guest_images
cp scripts/sha1sums-x86_64-common "$WORKLOADS_DIR"

pushd "$WORKLOADS_DIR" || exit
if ! sha1sum sha1sums-x86_64-common --check; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd || exit

cargo build --features $build_features --all --release --target "$BUILD_TARGET"

export RUST_BACKTRACE=1
cargo nextest run $test_features "common_cvm::$test_filter" -- ${test_binary_args[*]}
RES=$?

exit $RES
