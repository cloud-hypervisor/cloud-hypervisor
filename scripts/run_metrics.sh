#!/usr/bin/env bash
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

TEST_ARCH=$(uname -m)
export TEST_ARCH

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

build_features="mshv"
vm_type_arg=""
if [ "$VM_TYPE" = "confidential" ]; then
    build_features="mshv,igvm,sev_snp"
    vm_type_arg="--vm-type confidential"
fi

cp scripts/sha1sums-"${TEST_ARCH}"-common "$WORKLOADS_DIR"

if [ "${TEST_ARCH}" == "aarch64" ]; then
    JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-arm64-custom-20220329-0.qcow2"
else
    JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.qcow2"
fi

JAMMY_OS_IMAGE_URL="https://ch-images.azureedge.net/$JAMMY_OS_IMAGE_NAME"
JAMMY_OS_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time wget --quiet $JAMMY_OS_IMAGE_URL || exit 1
    popd || exit
fi

if [ "${TEST_ARCH}" == "aarch64" ]; then
    JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-arm64-custom-20220329-0.raw"
else
    JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.raw"
fi

JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $JAMMY_OS_IMAGE_NAME $JAMMY_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

pushd "$WORKLOADS_DIR" || exit
if ! grep jammy sha1sums-"${TEST_ARCH}"-common | sha1sum --check; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi

popd || exit

# Prepare linux image (build from source or download pre-built)
prepare_linux

CFLAGS=""
if [[ "${BUILD_TARGET}" == "${TEST_ARCH}-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/${TEST_ARCH}-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features "$build_features" --all --release --target "$BUILD_TARGET"

# setup hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((12288 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

if [ -n "$test_filter" ]; then
    test_binary_args+=("--test-filter $test_filter")
fi

if [ -n "$test_exclude" ]; then
    test_binary_args+=("--test-exclude $test_exclude")
fi

# Ensure that git commands can be run in this directory (for metrics report)
git config --global --add safe.directory "$PWD"

RUST_BACKTRACE_VALUE=$RUST_BACKTRACE
if [ -z "$RUST_BACKTRACE_VALUE" ]; then
    export RUST_BACKTRACE=1
else
    echo "RUST_BACKTRACE is set to: $RUST_BACKTRACE_VALUE"
fi
# shellcheck disable=SC2048,SC2086
time target/"$BUILD_TARGET"/release/performance-metrics $vm_type_arg ${test_binary_args[*]}
RES=$?

exit $RES
