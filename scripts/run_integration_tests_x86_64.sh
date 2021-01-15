#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

export BUILD_TARGET=${BUILD_TARGET-x86_64-unknown-linux-gnu}

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"


process_common_args "$@"

# For now these values are deafult for kvm
features_build=""
features_test="--features integration_tests"

cp scripts/sha1sums-x86_64 $WORKLOADS_DIR

FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
FW="$WORKLOADS_DIR/hypervisor-fw"
if [ ! -f "$FW" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FW_URL || exit 1
    popd
fi

BIONIC_OS_IMAGE_NAME="bionic-server-cloudimg-amd64.qcow2"
BIONIC_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$BIONIC_OS_IMAGE_NAME"
BIONIC_OS_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $BIONIC_OS_IMAGE_URL || exit 1
    popd
fi

BIONIC_OS_RAW_IMAGE_NAME="bionic-server-cloudimg-amd64.raw"
BIONIC_OS_RAW_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_RAW_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $BIONIC_OS_IMAGE_NAME $BIONIC_OS_RAW_IMAGE_NAME || exit 1
    popd
fi


FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210106-1.qcow2"
FOCAL_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$FOCAL_OS_IMAGE_NAME"
FOCAL_OS_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FOCAL_OS_IMAGE_URL || exit 1
    popd
fi

FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210106-1.raw"
FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $FOCAL_OS_IMAGE_NAME $FOCAL_OS_RAW_IMAGE_NAME || exit 1
    popd
fi

ALPINE_MINIROOTFS_URL="http://dl-cdn.alpinelinux.org/alpine/v3.11/releases/x86_64/alpine-minirootfs-3.11.3-x86_64.tar.gz"
ALPINE_MINIROOTFS_TARBALL="$WORKLOADS_DIR/alpine-minirootfs-x86_64.tar.gz"
if [ ! -f "$ALPINE_MINIROOTFS_TARBALL" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $ALPINE_MINIROOTFS_URL -O $ALPINE_MINIROOTFS_TARBALL || exit 1
    popd
fi

ALPINE_INITRAMFS_IMAGE="$WORKLOADS_DIR/alpine_initramfs.img"
if [ ! -f "$ALPINE_INITRAMFS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    mkdir alpine-minirootfs
    tar xf "$ALPINE_MINIROOTFS_TARBALL" -C alpine-minirootfs
    cat > alpine-minirootfs/init <<-EOF
		#! /bin/sh
		mount -t devtmpfs dev /dev
		echo \$TEST_STRING > /dev/console
		poweroff -f
	EOF
    chmod +x alpine-minirootfs/init
    cd alpine-minirootfs
    find . -print0 |
        cpio --null --create --verbose --owner root:root --format=newc > "$ALPINE_INITRAMFS_IMAGE"
    popd
fi

pushd $WORKLOADS_DIR
sha1sum sha1sums-x86_64 --check
if [ $? -ne 0 ]; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
VMLINUX_PVH_IMAGE="$WORKLOADS_DIR/vmlinux.pvh"
BZIMAGE_IMAGE="$WORKLOADS_DIR/bzImage"

LINUX_CUSTOM_DIR="$WORKLOADS_DIR/linux-custom"

if [ ! -f "$VMLINUX_IMAGE" ] || [ ! -f "$VMLINUX_PVH_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    time git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b "ch-5.10.6" $LINUX_CUSTOM_DIR
    cp $SRCDIR/resources/linux-config-x86_64 $LINUX_CUSTOM_DIR/.config
    popd
fi

if [ ! -f "$VMLINUX_IMAGE" ]; then
    pushd $LINUX_CUSTOM_DIR
    scripts/config --disable "CONFIG_PVH"
    time make bzImage -j `nproc`
    cp vmlinux $VMLINUX_IMAGE || exit 1
    cp arch/x86/boot/bzImage $BZIMAGE_IMAGE || exit 1
    popd
fi

if [ ! -f "$VMLINUX_PVH_IMAGE" ]; then
    pushd $LINUX_CUSTOM_DIR
    scripts/config --enable "CONFIG_PVH"
    time make bzImage -j `nproc`
    cp vmlinux $VMLINUX_PVH_IMAGE || exit 1
    popd
fi

if [ -d "$LINUX_CUSTOM_DIR" ]; then
    rm -rf $LINUX_CUSTOM_DIR
fi

VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
QEMU_DIR="qemu_build"
if [ ! -f "$VIRTIOFSD" ]; then
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://gitlab.com/virtio-fs/qemu.git" -b "qemu5.0-virtiofs-dax" $QEMU_DIR
    pushd $QEMU_DIR
    time ./configure --prefix=$PWD --target-list=x86_64-softmmu
    time make virtiofsd -j `nproc`
    cp virtiofsd $VIRTIOFSD || exit 1
    popd
    rm -rf $QEMU_DIR
    popd
fi

VIRTIOFSD_RS="$WORKLOADS_DIR/virtiofsd-rs"
VIRTIOFSD_RS_DIR="virtiofsd_rs_build"
if [ ! -f "$VIRTIOFSD_RS" ]; then
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://gitlab.com/virtio-fs/virtiofsd-rs.git" $VIRTIOFSD_RS_DIR
    pushd $VIRTIOFSD_RS_DIR
    time cargo build --release
    cp target/release/virtiofsd-rs $VIRTIOFSD_RS || exit 1
    popd
    rm -rf $VIRTIOFSD_RS_DIR
    popd
fi


BLK_IMAGE="$WORKLOADS_DIR/blk.img"
MNT_DIR="mount_image"
if [ ! -f "$BLK_IMAGE" ]; then
   pushd $WORKLOADS_DIR
   fallocate -l 16M $BLK_IMAGE
   mkfs.ext4 -j $BLK_IMAGE
   mkdir $MNT_DIR
   sudo mount -t ext4 $BLK_IMAGE $MNT_DIR
   sudo bash -c "echo bar > $MNT_DIR/foo" || exit 1
   sudo umount $BLK_IMAGE
   rm -r $MNT_DIR
   popd
fi

SHARED_DIR="$WORKLOADS_DIR/shared_dir"
if [ ! -d "$SHARED_DIR" ]; then
    mkdir -p $SHARED_DIR
    echo "foo" > "$SHARED_DIR/file1"
    echo "bar" > "$SHARED_DIR/file3" || exit 1
fi

VFIO_DIR="$WORKLOADS_DIR/vfio"
VFIO_DISK_IMAGE="$WORKLOADS_DIR/vfio.img"
rm -rf $VFIO_DIR $VFIO_DISK_IMAGE
mkdir -p $VFIO_DIR
cp $FOCAL_OS_IMAGE $VFIO_DIR
cp $FW $VFIO_DIR
cp $VMLINUX_IMAGE $VFIO_DIR || exit 1

# VFIO test network setup.
# We reserve a different IP class for it: 172.18.0.0/24.
sudo ip link add name vfio-br0 type bridge
sudo ip link set vfio-br0 up
sudo ip addr add 172.18.0.1/24 dev vfio-br0

sudo ip tuntap add vfio-tap0 mode tap
sudo ip link set vfio-tap0 master vfio-br0
sudo ip link set vfio-tap0 up

sudo ip tuntap add vfio-tap1 mode tap
sudo ip link set vfio-tap1 master vfio-br0
sudo ip link set vfio-tap1 up

sudo ip tuntap add vfio-tap2 mode tap
sudo ip link set vfio-tap2 master vfio-br0
sudo ip link set vfio-tap2 up

sudo ip tuntap add vfio-tap3 mode tap
sudo ip link set vfio-tap3 master vfio-br0
sudo ip link set vfio-tap3 up

# Create tap interface without multiple queues support for vhost_user_net test.
sudo ip tuntap add name vunet-tap0 mode tap
# Create tap interface with multiple queues support for vhost_user_net test.
sudo ip tuntap add name vunet-tap1 mode tap multi_queue

BUILD_TARGET="$(uname -m)-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

mkdir /tmp/images
# Use device mapper to create a snapshot of the Ubuntu Bionic image
cp /root/workloads/bionic-server-cloudimg-amd64.raw /tmp/images/
bionic_img_blk_size=$(du -b -B 512 /tmp/images/bionic-server-cloudimg-amd64.raw | awk '{print $1;}')
bionic_loop_device=$(losetup --find --show --read-only /tmp/images/bionic-server-cloudimg-amd64.raw)
dmsetup create bionic-base --table "0 $bionic_img_blk_size linear $bionic_loop_device 0"
dmsetup mknodes
dmsetup create bionic-snapshot-base --table "0 $bionic_img_blk_size snapshot-origin /dev/mapper/bionic-base"
dmsetup mknodes
# Use device mapper to create a snapshot of the Ubuntu Focal image
cp /root/workloads/focal-server-cloudimg-amd64-custom-20210106-1.raw /tmp/images/
focal_img_blk_size=$(du -b -B 512 /tmp/images/focal-server-cloudimg-amd64-custom-20210106-1.raw | awk '{print $1;}')
focal_loop_device=$(losetup --find --show --read-only /tmp/images/focal-server-cloudimg-amd64-custom-20210106-1.raw)
dmsetup create focal-base --table "0 $focal_img_blk_size linear $focal_loop_device 0"
dmsetup mknodes
dmsetup create focal-snapshot-base --table "0 $focal_img_blk_size snapshot-origin /dev/mapper/focal-base"
dmsetup mknodes

cargo build --all  --release $features_build --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor
strip target/$BUILD_TARGET/release/vhost_user_net
strip target/$BUILD_TARGET/release/ch-remote

# We always copy a fresh version of our binary for our L2 guest.
cp target/$BUILD_TARGET/release/cloud-hypervisor $VFIO_DIR
cp target/$BUILD_TARGET/release/ch-remote $VFIO_DIR

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

# test_vfio relies on hugepages
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

export RUST_BACKTRACE=1
time cargo test $features_test "tests::parallel::" -- --test-threads=$(($(nproc)/2))
RES=$?

# Run some tests in sequence since the result could be affected by other tests
# running in parallel.
if [ $RES -eq 0 ]; then
    export RUST_BACKTRACE=1
    time cargo test $features_test "tests::sequential::" -- --test-threads=1
    RES=$?
fi

# Cleanup device mapper images
dmsetup remove -f focal-snapshot-base
dmsetup mknodes
dmsetup remove -f focal-base
losetup -d $focal_loop_device
dmsetup remove -f bionic-snapshot-base
dmsetup mknodes
dmsetup remove -f bionic-base
losetup -d $bionic_loop_device

# Tear VFIO test network down
sudo ip link del vfio-br0
sudo ip link del vfio-tap0
sudo ip link del vfio-tap1
sudo ip link del vfio-tap2
sudo ip link del vfio-tap3

# Tear vhost_user_net test network down
sudo ip link del vunet-tap0
sudo ip link del vunet-tap1

exit $RES
