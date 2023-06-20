#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

cp scripts/sha1sums-x86_64 $WORKLOADS_DIR

FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
FW="$WORKLOADS_DIR/hypervisor-fw"
if [ ! -f "$FW" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FW_URL || exit 1
    popd
fi

FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.qcow2"
FOCAL_OS_IMAGE_URL="https://cloud-hypervisor.azureedge.net/$FOCAL_OS_IMAGE_NAME"
FOCAL_OS_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FOCAL_OS_IMAGE_URL || exit 1
    popd
fi

FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.raw"
FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $FOCAL_OS_IMAGE_NAME $FOCAL_OS_RAW_IMAGE_NAME || exit 1
    popd
fi

pushd $WORKLOADS_DIR
sha1sum sha1sums-x86_64 --check --ignore-missing
if [ $? -ne 0 ]; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd

VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
build_custom_linux

BLK_IMAGE="$WORKLOADS_DIR/blk.img"
MNT_DIR="mount_image"
rm -rf $BLK_IMAGE
pushd $WORKLOADS_DIR
fallocate -l 16M $BLK_IMAGE
mkfs.ext4 -j $BLK_IMAGE
mkdir $MNT_DIR
sudo mount -t ext4 $BLK_IMAGE $MNT_DIR
sudo bash -c "echo bar > $MNT_DIR/foo" || exit 1
sudo umount $BLK_IMAGE
rm -r $MNT_DIR
popd

VFIO_DIR="$WORKLOADS_DIR/vfio"
VFIO_DISK_IMAGE="$WORKLOADS_DIR/vfio.img"
rm -rf $VFIO_DIR $VFIO_DISK_IMAGE
mkdir -p $VFIO_DIR
cp $FOCAL_OS_RAW_IMAGE $VFIO_DIR
cp $FW $VFIO_DIR
cp $VMLINUX_IMAGE $VFIO_DIR || exit 1

BUILD_TARGET="$(uname -m)-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --no-default-features --features "kvm,mshv" --all --release --target $BUILD_TARGET

# We always copy a fresh version of our binary for our L2 guest.
cp target/$BUILD_TARGET/release/cloud-hypervisor $VFIO_DIR
cp target/$BUILD_TARGET/release/ch-remote $VFIO_DIR

# test_vfio rely on hugepages
HUGEPAGESIZE=`grep Hugepagesize /proc/meminfo | awk '{print $2}'`
PAGE_NUM=`echo $((12288 * 1024 / $HUGEPAGESIZE))`
echo $PAGE_NUM | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

export RUST_BACKTRACE=1
time cargo test "vfio::test_vfio" -- ${test_binary_args[*]}
RES=$?

if [ $RES -eq 0 ]; then
	time cargo test "vfio::test_nvidia" -- --test-threads=1 ${test_binary_args[*]}
	RES=$?
fi

exit $RES
