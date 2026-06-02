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

if [ "${TEST_ARCH}" == "aarch64" ]; then
    GUEST_OS_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0.qcow2"
    GUEST_OS_RAW_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0.raw"
else
    GUEST_OS_IMAGE_NAME="debian-13-generic-amd64-custom-20260602-0.qcow2"
    GUEST_OS_RAW_IMAGE_NAME="debian-13-generic-amd64-custom-20260602-0.raw"
fi

GUEST_OS_IMAGE="$WORKLOADS_DIR/$GUEST_OS_IMAGE_NAME"
if [ ! -f "$GUEST_OS_IMAGE" ]; then
    echo "Missing: $GUEST_OS_IMAGE — run: python3 scripts/fetch_workloads.py --test metrics"
    exit 1
fi

GUEST_OS_RAW_IMAGE="$WORKLOADS_DIR/$GUEST_OS_RAW_IMAGE_NAME"
if [ ! -f "$GUEST_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $GUEST_OS_IMAGE_NAME $GUEST_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

if [ "${TEST_ARCH}" == "aarch64" ]; then
    KERNEL_IMAGE="$WORKLOADS_DIR/Image-arm64"
else
    KERNEL_IMAGE="$WORKLOADS_DIR/vmlinux-x86_64"
fi
if [ ! -f "$KERNEL_IMAGE" ]; then
    echo "Missing: $KERNEL_IMAGE — run: python3 scripts/fetch_workloads.py --test metrics"
    exit 1
fi

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
