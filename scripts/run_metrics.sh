#!/usr/bin/env bash
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

TEST_ARCH=$(uname -m)
export TEST_ARCH

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

build_fio() {
    FIO_DIR="$WORKLOADS_DIR/fio_build"
    FIO_REPO="https://github.com/axboe/fio.git"

    checkout_repo "$FIO_DIR" "$FIO_REPO" master "1953e1adb5a28ed21370e85991d7f5c3cdc699f3"
    if [ ! -f "$FIO_DIR/.built" ]; then
        pushd "$FIO_DIR" || exit
        ./configure
        make -j "$(nproc)"
        cp fio "$WORKLOADS_DIR/fio"
        touch .built
        popd || exit
    fi
}

process_common_args "$@"

cp scripts/sha1sums-"${TEST_ARCH}" "$WORKLOADS_DIR"

if [ "${TEST_ARCH}" == "aarch64" ]; then
    FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-arm64-custom-20210929-0.qcow2"
else
    FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.qcow2"
fi

FOCAL_OS_IMAGE_URL="https://ch-images.azureedge.net/$FOCAL_OS_IMAGE_NAME"
FOCAL_OS_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time wget --quiet $FOCAL_OS_IMAGE_URL || exit 1
    popd || exit
fi

if [ "${TEST_ARCH}" == "aarch64" ]; then
    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-arm64-custom-20210929-0.raw"
else
    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.raw"
fi

FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $FOCAL_OS_IMAGE_NAME $FOCAL_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

pushd "$WORKLOADS_DIR" || exit
if ! grep focal sha1sums-"${TEST_ARCH}" | sha1sum --check; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd || exit

if [ "${TEST_ARCH}" == "aarch64" ]; then
    build_fio

    # Update the fio in the cloud image to use io_uring on AArch64
    FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_NAME="focal-server-cloudimg-arm64-custom-20210929-0-update-tool.raw"
    cp "$FOCAL_OS_RAW_IMAGE" "$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_NAME"
    FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR="$WORKLOADS_DIR/focal-server-cloudimg-root"
    if [ ! -d "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR" ]; then
        mkdir -p "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"
    fi
    # Mount image partition
    IMG="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_NAME"
    # Get the sector size from the disk image
    SECTOR_SIZE=$(fdisk -l "$IMG" | awk '/Sector size/ {print $4; exit}')
    # Get the starting sector of the first partition (e.g., /dev/sda1 or $IMG'1)
    START_SECTOR=$(fdisk -l "$IMG" | awk '$1 == "'"$IMG"'1" {print $2; exit}')
    # Calculate the byte offset to the start of the partition
    OFFSET=$((START_SECTOR * SECTOR_SIZE))

    # Create a loop device that points to the partition using the calculated offset
    LOOP_DEV=$(sudo losetup -f --show -o "$OFFSET" "$IMG")

    # Mount the loop device (which represents the partition) to the temporary directory
    sudo mount "$LOOP_DEV" "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"
    # Replace the existing kernel image with the new compressed kernel file
    cp "$WORKLOADS_DIR"/Image-arm64.gz "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"/boot/vmlinuz
    # Unmount the image partition
    sudo umount "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"
    # Detach the loop device to free it up
    sudo losetup -d "$LOOP_DEV"
fi

# Prepare linux image (build from source or download pre-built)
prepare_linux

CFLAGS=""
if [[ "${BUILD_TARGET}" == "${TEST_ARCH}-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/${TEST_ARCH}-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# setup hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((12288 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

if [ -n "$test_filter" ]; then
    test_binary_args+=("--test-filter $test_filter")
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
time target/"$BUILD_TARGET"/release/performance-metrics ${test_binary_args[*]}
RES=$?

exit $RES
