#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

export TEST_ARCH=$(uname -m)

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

build_fio() {
    FIO_DIR="$WORKLOADS_DIR/fio_build"
    FIO_REPO="https://github.com/axboe/fio.git"

    checkout_repo "$FIO_DIR" "$FIO_REPO" master "1953e1adb5a28ed21370e85991d7f5c3cdc699f3"
    if [ ! -f "$FIO_DIR/.built" ]; then
        pushd $FIO_DIR
        ./configure
        make -j `nproc`
        cp fio "$WORKLOADS_DIR/fio"
        touch .built
        popd
    fi
}

process_common_args "$@"

cp scripts/sha1sums-${TEST_ARCH} $WORKLOADS_DIR

if [ ${TEST_ARCH} == "aarch64" ]; then
     FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-arm64-custom-20210929-0.qcow2"
else
     FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.qcow2"
fi

FOCAL_OS_IMAGE_URL="https://ch-images.azureedge.net/$FOCAL_OS_IMAGE_NAME"
FOCAL_OS_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FOCAL_OS_IMAGE_URL || exit 1
    popd
fi

if [ ${TEST_ARCH} == "aarch64" ]; then
    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-arm64-custom-20210929-0.raw"
else
    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.raw"
fi

FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $FOCAL_OS_IMAGE_NAME $FOCAL_OS_RAW_IMAGE_NAME || exit 1
    popd
fi

pushd $WORKLOADS_DIR
grep focal sha1sums-${TEST_ARCH} | sha1sum --check
if [ $? -ne 0 ]; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd

if [ ${TEST_ARCH} == "aarch64" ]; then
    build_fio

    # Update the fio in the cloud image to use io_uring on AArch64
    FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_NAME="focal-server-cloudimg-arm64-custom-20210929-0-update-tool.raw"
    cp "$FOCAL_OS_RAW_IMAGE" "$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_NAME"
    FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR="$WORKLOADS_DIR/focal-server-cloudimg-root"
    if [ ! -d "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR" ]; then
        mkdir -p "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"
    fi
    # Mount the 'raw' image, replace the fio and umount the working folder
    guestmount -a "$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_NAME" -m /dev/sda1 "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR" || exit 1
    cp "$WORKLOADS_DIR"/fio "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"/usr/bin/fio
    guestunmount "$FOCAL_OS_RAW_IMAGE_UPDATE_TOOL_ROOT_DIR"
fi

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
build_custom_linux

CFLAGS=""
if [[ "${BUILD_TARGET}" == "${TEST_ARCH}-unknown-linux-musl" ]]; then
    CFLAGS="-I /usr/include/${TEST_ARCH}-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target $BUILD_TARGET

# setup hugepages
HUGEPAGESIZE=`grep Hugepagesize /proc/meminfo | awk '{print $2}'`
PAGE_NUM=`echo $((12288 * 1024 / $HUGEPAGESIZE))`
echo $PAGE_NUM | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

if [ -n "$test_filter" ]; then
    test_binary_args+=("--test-filter $test_filter")
fi

# Ensure that git commands can be run in this directory (for metrics report)
git config --global --add safe.directory $PWD

RUST_BACKTRACE_VALUE=`echo $RUST_BACKTRACE`
if [ -z $RUST_BACKTRACE_VALUE ];then
	export RUST_BACKTRACE=1
else
	echo "RUST_BACKTRACE is set to: $RUST_BACKTRACE_VALUE"
fi
time target/$BUILD_TARGET/release/performance-metrics ${test_binary_args[*]}
RES=$?

exit $RES
