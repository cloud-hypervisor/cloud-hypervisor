#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

export TEST_ARCH=$(uname -m)
export BUILD_TARGET=${BUILD_TARGET-${TEST_ARCH}-unknown-linux-gnu}


WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

# For now these values are default for kvm
features=""

if [ "$hypervisor" = "mshv" ]; then
    features="--no-default-features --features mshv,common"
fi

cp scripts/sha1sums-${TEST_ARCH} $WORKLOADS_DIR

if [ ${TEST_ARCH} == "aarch64" ]; then
     FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-arm64-custom-20210929-0.qcow2"
else
     FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.qcow2"
fi

FOCAL_OS_IMAGE_URL="https://cloud-hypervisor.azureedge.net/$FOCAL_OS_IMAGE_NAME"
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

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
if [ ${TEST_ARCH} == "aarch64" ]; then
       VMLINUX_IMAGE="$WORKLOADS_DIR/Image"
else
       VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
fi

LINUX_CUSTOM_DIR="$WORKLOADS_DIR/linux-custom"

if [ ! -f "$VMLINUX_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    time git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b "ch-5.15.12" $LINUX_CUSTOM_DIR
    cp $SRCDIR/resources/linux-config-${TEST_ARCH} $LINUX_CUSTOM_DIR/.config
    popd
fi

if [ ! -f "$VMLINUX_IMAGE" ]; then
    pushd $LINUX_CUSTOM_DIR
    if [ ${TEST_ARCH} == "x86_64" ]; then
       make bzImage -j `nproc`
       cp vmlinux $VMLINUX_IMAGE || exit 1
    elif [ ${TEST_ARCH} == "aarch64" ]; then
       make Image -j `nproc`
       cp arch/arm64/boot/Image $VMLINUX_IMAGE || exit 1
    fi
    popd
fi

if [ -d "$LINUX_CUSTOM_DIR" ]; then
    rm -rf $LINUX_CUSTOM_DIR
fi

BUILD_TARGET="${TEST_ARCH}-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "${TEST_ARCH}-unknown-linux-musl" ]]; then
    TARGET_CC="musl-gcc"
    CFLAGS="-I /usr/include/${TEST_ARCH}-linux-musl/ -idirafter /usr/include/"
fi

cargo build --all --release $features --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor
strip target/$BUILD_TARGET/release/vhost_user_net
strip target/$BUILD_TARGET/release/ch-remote
strip target/$BUILD_TARGET/release/performance-metrics

# setup hugepages
echo 6144 | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

if [ -n "$test_filter" ]; then
    test_binary_args+=("--test-filter $test_filter")
fi

export RUST_BACKTRACE=1
time target/$BUILD_TARGET/release/performance-metrics ${test_binary_args[*]}
RES=$?

exit $RES
