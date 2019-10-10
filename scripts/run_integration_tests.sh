#!/bin/bash
set -x

source $HOME/.cargo/env

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

FW_URL=$(curl --silent https://api.github.com/repos/intel/rust-hypervisor-firmware/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
FW="$WORKLOADS_DIR/hypervisor-fw"
if [ ! -f "$FW" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $FW_URL
    popd
fi

CLEAR_OS_IMAGE_NAME="clear-cloudguest.img"
CLEAR_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$CLEAR_OS_IMAGE_NAME"
CLEAR_OS_IMAGE="$WORKLOADS_DIR/$CLEAR_OS_IMAGE_NAME"
if [ ! -f "$CLEAR_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $CLEAR_OS_IMAGE_URL
    popd
fi

CLEAR_OS_RAW_IMAGE_NAME="clear-cloudguest-raw.img"
CLEAR_OS_RAW_IMAGE="$WORKLOADS_DIR/$CLEAR_OS_RAW_IMAGE_NAME"
if [ ! -f "$CLEAR_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    qemu-img convert -p -f qcow2 -O raw $CLEAR_OS_IMAGE_NAME $CLEAR_OS_RAW_IMAGE_NAME
    popd
fi

BIONIC_OS_IMAGE_NAME="bionic-server-cloudimg-amd64.img"
BIONIC_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$BIONIC_OS_IMAGE_NAME"
BIONIC_OS_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $BIONIC_OS_IMAGE_URL
    popd
fi

BIONIC_OS_RAW_IMAGE_NAME="bionic-server-cloudimg-amd64-raw.img"
BIONIC_OS_RAW_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_RAW_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    qemu-img convert -p -f qcow2 -O raw $BIONIC_OS_IMAGE_NAME $BIONIC_OS_RAW_IMAGE_NAME
    popd
fi


EOAN_OS_IMAGE_NAME="eoan-server-cloudimg-amd64.img"
EOAN_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$EOAN_OS_IMAGE_NAME"
EOAN_OS_IMAGE="$WORKLOADS_DIR/$EOAN_OS_IMAGE_NAME"
if [ ! -f "$EOAN_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $EOAN_OS_IMAGE_URL
    popd
fi

EOAN_OS_RAW_IMAGE_NAME="eoan-server-cloudimg-amd64-raw.img"
EOAN_OS_RAW_IMAGE="$WORKLOADS_DIR/$EOAN_OS_RAW_IMAGE_NAME"
if [ ! -f "$EOAN_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    qemu-img convert -p -f qcow2 -O raw $EOAN_OS_IMAGE_NAME $EOAN_OS_RAW_IMAGE_NAME
    popd
fi


# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
BZIMAGE_IMAGE="$WORKLOADS_DIR/bzImage"

LINUX_CUSTOM_DIR="linux-custom"

if [ ! -f "$VMLINUX_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://github.com/sboeuf/linux.git" -b "virtio-fs-virtio-iommu" $LINUX_CUSTOM_DIR
    pushd $LINUX_CUSTOM_DIR
    cp $SRCDIR/resources/linux-virtio-fs-virtio-iommu-config .config
    make bzImage -j `nproc`
    cp vmlinux $VMLINUX_IMAGE
    cp arch/x86/boot/bzImage $BZIMAGE_IMAGE
    popd
    rm -rf $LINUX_CUSTOM_DIR
    popd
fi

VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
VUBD="$WORKLOADS_DIR/vubd"
QEMU_DIR="qemu_build"
if [ ! -f "$VIRTIOFSD" ] || [ ! -f "$VUBD" ]; then
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://github.com/sboeuf/qemu.git" -b "virtio-fs" $QEMU_DIR
    pushd $QEMU_DIR
    ./configure --prefix=$PWD --target-list=x86_64-softmmu
    make virtiofsd vhost-user-blk -j `nproc`
    cp virtiofsd $VIRTIOFSD
    cp vhost-user-blk $VUBD
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

cargo build
sudo setcap cap_net_admin+ep target/debug/cloud-hypervisor
sudo setcap cap_net_admin+ep target/debug/vhost_user_net

# We always copy a fresh version of our binary for our L2 guest.
cp target/debug/cloud-hypervisor $VFIO_DIR

sudo adduser $USER kvm
newgrp kvm << EOF
export RUST_BACKTRACE=1
cargo test --features "integration_tests" -- --nocapture
EOF
RES=$?

if [ $RES -eq 0 ]; then
    # virtio-mmio based testing
    cargo build --no-default-features --features "mmio"
    sudo setcap cap_net_admin+ep target/debug/cloud-hypervisor

    newgrp kvm << EOF
export RUST_BACKTRACE=1
cargo test --features "integration_tests,mmio" -- --nocapture
EOF

    RES=$?
fi

# Tear VFIO test network down
sudo ip link del vfio-br0
sudo ip link del vfio-tap0
sudo ip link del vfio-tap1

exit $RES
