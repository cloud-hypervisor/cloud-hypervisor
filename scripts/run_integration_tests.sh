#!/bin/bash
set -x

source $HOME/.cargo/env

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
FW="$WORKLOADS_DIR/hypervisor-fw"
if [ ! -f "$FW" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FW_URL
    popd
fi

CLEAR_OS_IMAGE_NAME="clear-31310-cloudguest.img"
CLEAR_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$CLEAR_OS_IMAGE_NAME"
CLEAR_OS_IMAGE="$WORKLOADS_DIR/$CLEAR_OS_IMAGE_NAME"
if [ ! -f "$CLEAR_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $CLEAR_OS_IMAGE_URL
    popd
fi

CLEAR_OS_RAW_IMAGE_NAME="clear-31310-cloudguest-raw.img"
CLEAR_OS_RAW_IMAGE="$WORKLOADS_DIR/$CLEAR_OS_RAW_IMAGE_NAME"
if [ ! -f "$CLEAR_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $CLEAR_OS_IMAGE_NAME $CLEAR_OS_RAW_IMAGE_NAME
    popd
fi

BIONIC_OS_IMAGE_NAME="bionic-server-cloudimg-amd64.img"
BIONIC_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$BIONIC_OS_IMAGE_NAME"
BIONIC_OS_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $BIONIC_OS_IMAGE_URL
    popd
fi

BIONIC_OS_RAW_IMAGE_NAME="bionic-server-cloudimg-amd64-raw.img"
BIONIC_OS_RAW_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_RAW_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $BIONIC_OS_IMAGE_NAME $BIONIC_OS_RAW_IMAGE_NAME
    popd
fi


EOAN_OS_IMAGE_NAME="eoan-server-cloudimg-amd64.img"
EOAN_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$EOAN_OS_IMAGE_NAME"
EOAN_OS_IMAGE="$WORKLOADS_DIR/$EOAN_OS_IMAGE_NAME"
if [ ! -f "$EOAN_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $EOAN_OS_IMAGE_URL
    popd
fi

EOAN_OS_RAW_IMAGE_NAME="eoan-server-cloudimg-amd64-raw.img"
EOAN_OS_RAW_IMAGE="$WORKLOADS_DIR/$EOAN_OS_RAW_IMAGE_NAME"
if [ ! -f "$EOAN_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $EOAN_OS_IMAGE_NAME $EOAN_OS_RAW_IMAGE_NAME
    popd
fi

pushd $WORKLOADS_DIR
curl --silent "https://cloudhypervisorstorage.blob.core.windows.net/images/sha1sums" | sha1sum --check
if [ $? -ne 0 ]; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
BZIMAGE_IMAGE="$WORKLOADS_DIR/bzImage"

LINUX_CUSTOM_DIR="linux-custom"

if [ ! -f "$VMLINUX_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    time git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b "virtio-fs-virtio-iommu-topo-5.5-rc1" $LINUX_CUSTOM_DIR
    pushd $LINUX_CUSTOM_DIR
    cp $SRCDIR/resources/linux-virtio-fs-virtio-iommu-config .config
    time make bzImage -j `nproc`
    cp vmlinux $VMLINUX_IMAGE
    cp arch/x86/boot/bzImage $BZIMAGE_IMAGE
    popd
    rm -rf $LINUX_CUSTOM_DIR
    popd
fi

VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
QEMU_DIR="qemu_build"
if [ ! -f "$VIRTIOFSD" ]; then
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://github.com/sboeuf/qemu.git" -b "virtio-fs" $QEMU_DIR
    pushd $QEMU_DIR
    time ./configure --prefix=$PWD --target-list=x86_64-softmmu
    time make virtiofsd -j `nproc`
    cp virtiofsd $VIRTIOFSD
    popd
    rm -rf $QEMU_DIR
    sudo setcap cap_dac_override,cap_sys_admin+epi "virtiofsd"
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
   sudo bash -c "echo bar > $MNT_DIR/foo"
   sudo umount $BLK_IMAGE
   rm -r $MNT_DIR
   popd
fi

SHARED_DIR="$WORKLOADS_DIR/shared_dir"
if [ ! -d "$SHARED_DIR" ]; then
    mkdir -p $SHARED_DIR
    echo "foo" > "$SHARED_DIR/file1"
    echo "bar" > "$SHARED_DIR/file3"
fi

VFIO_DIR="$WORKLOADS_DIR/vfio"
if [ ! -d "$VFIO_DIR" ]; then
    mkdir -p $VFIO_DIR
    cp $CLEAR_OS_IMAGE $VFIO_DIR
    cp $FW $VFIO_DIR
    cp $VMLINUX_IMAGE $VFIO_DIR
fi

# VFIO test network setup.
# We reserve a different IP class for it: 172.17.0.0/24.
sudo ip link add name vfio-br0 type bridge
sudo ip link set vfio-br0 up
sudo ip addr add 172.17.0.1/24 dev vfio-br0

sudo ip tuntap add vfio-tap0 mode tap
sudo ip link set vfio-tap0 master vfio-br0
sudo ip link set vfio-tap0 up

sudo ip tuntap add vfio-tap1 mode tap
sudo ip link set vfio-tap1 master vfio-br0
sudo ip link set vfio-tap1 up

sudo ip tuntap add vfio-tap2 mode tap
sudo ip link set vfio-tap2 master vfio-br0
sudo ip link set vfio-tap2 up

cargo build --release
sudo setcap cap_net_admin+ep target/release/cloud-hypervisor
sudo setcap cap_net_admin+ep target/release/vhost_user_net
sudo setcap cap_dac_override,cap_sys_admin+epi target/release/vhost_user_fs

# We always copy a fresh version of our binary for our L2 guest.
cp target/release/cloud-hypervisor $VFIO_DIR

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

# Ensure test binary has the same caps as the cloud-hypervisor one
time cargo test --no-run --features "integration_tests" -- --nocapture
ls target/debug/deps/cloud_hypervisor-* | xargs -n 1 sudo setcap cap_net_admin+ep

sudo adduser $USER kvm
newgrp kvm << EOF
export RUST_BACKTRACE=1
time cargo test --features "integration_tests" "$@" -- --nocapture
EOF
RES=$?

if [ $RES -eq 0 ]; then
    # virtio-mmio based testing
    cargo build --release --no-default-features --features "mmio"
    sudo setcap cap_net_admin+ep target/release/cloud-hypervisor

    newgrp kvm << EOF
export RUST_BACKTRACE=1
time cargo test --features "integration_tests,mmio" "$@" -- --nocapture
EOF

    RES=$?
fi

# Tear VFIO test network down
sudo ip link del vfio-br0
sudo ip link del vfio-tap0
sudo ip link del vfio-tap1
sudo ip link del vfio-tap2

exit $RES
