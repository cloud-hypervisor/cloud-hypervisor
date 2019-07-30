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

OVMF_URL="https://cdn.download.clearlinux.org/image/OVMF.fd"
OVMF="$WORKLOADS_DIR/OVMF.fd"
if [ ! -f "$OVMF" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $OVMF_URL
    popd
fi

CLEAR_OS_IMAGE_NAME="clear-29810-cloud.img"
CLEAR_OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$CLEAR_OS_IMAGE_NAME.xz"
CLEAR_OS_IMAGE="$WORKLOADS_DIR/$CLEAR_OS_IMAGE_NAME"
if [ ! -f "$CLEAR_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $CLEAR_OS_IMAGE_URL
    unxz $CLEAR_OS_IMAGE_NAME.xz
    popd
fi

CLEAR_OS_RAW_IMAGE_NAME="clear-29810-cloud-raw.img"
CLEAR_OS_RAW_IMAGE="$WORKLOADS_DIR/$CLEAR_OS_RAW_IMAGE_NAME"
if [ ! -f "$CLEAR_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    qemu-img convert -p -f qcow2 -O raw $CLEAR_OS_IMAGE_NAME $CLEAR_OS_RAW_IMAGE_NAME
    popd
fi

BIONIC_OS_IMAGE_NAME="bionic-server-cloudimg-amd64.img"
BIONIC_OS_IMAGE_URL="https://cloud-images.ubuntu.com/bionic/current/$BIONIC_OS_IMAGE_NAME"
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


# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
BZIMAGE_IMAGE="$WORKLOADS_DIR/bzImage"

LINUX_CUSTOM_DIR="linux-custom"

if [ ! -f "$VMLINUX_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://github.com/sboeuf/linux.git" -b "virtio-pmem_and_virtio-fs" $LINUX_CUSTOM_DIR
    pushd $LINUX_CUSTOM_DIR
    cp $SRCDIR/resources/linux-virtio-pmem-and-virtio-fs-config .config
    make bzImage -j `nproc`
    cp vmlinux $VMLINUX_IMAGE
    cp arch/x86/boot/bzImage $BZIMAGE_IMAGE
    popd
    rm -r $LINUX_CUSTOM_DIR
    popd
fi

VIRTIOFSD_URL="$(curl --silent https://api.github.com/repos/intel/nemu/releases/latest | grep "browser_download_url" | grep "virtiofsd-x86_64" | grep -o 'https://.*[^ "]')"
VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
if [ ! -f "$VIRTIOFSD" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $VIRTIOFSD_URL -O "virtiofsd"
    chmod +x "virtiofsd"
    sudo setcap cap_sys_admin+epi "virtiofsd"
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
# We reserve a different IP class for it: 172.16.0.0/24.
sudo ip link add name vfio-br0 type bridge
sudo ip link set vfio-br0 up
sudo ip addr add 172.16.0.1/24 dev vfio-br0

sudo ip tuntap add vfio-tap0 mode tap
sudo ip link set vfio-tap0 master vfio-br0
sudo ip link set vfio-tap0 up

sudo ip tuntap add vfio-tap1 mode tap
sudo ip link set vfio-tap1 master vfio-br0
sudo ip link set vfio-tap1 up

cargo build
sudo setcap cap_net_admin+ep target/debug/cloud-hypervisor

# We always copy a fresh version of our binary for our L2 guest.
cp target/debug/cloud-hypervisor $VFIO_DIR
# We need qemu to have NET_ADMIN as well.
sudo setcap cap_net_admin+ep /usr/bin/qemu-system-x86_64

sudo adduser $USER kvm
newgrp kvm << EOF
cargo test --features "integration_tests"
EOF

# Tear VFIO test network down
sudo ip link del vfio-br0
sudo ip link del vfio-tap0
sudo ip link del vfio-tap1
