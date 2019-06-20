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

OS_IMAGE_NAME="clear-29810-cloud.img"
OS_IMAGE_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$OS_IMAGE_NAME.xz"
OS_IMAGE="$WORKLOADS_DIR/$OS_IMAGE_NAME"
if [ ! -f "$OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $OS_IMAGE_URL
    unxz $OS_IMAGE_NAME.xz
    popd
fi

OS_RAW_IMAGE_NAME="clear-29810-cloud-raw.img"
OS_RAW_IMAGE="$WORKLOADS_DIR/$OS_RAW_IMAGE_NAME"
if [ ! -f "$OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    qemu-img convert -p -f qcow2 -O raw $OS_IMAGE_NAME $OS_RAW_IMAGE_NAME
    popd
fi

# Build generic kernel
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
BZIMAGE_IMAGE="$WORKLOADS_DIR/bzImage"

if [ ! -f "$VMLINUX_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    wget --quiet https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.0.21.tar.xz
    tar xf linux-5.0.21.tar.xz
    pushd linux-5.0.21
    cp $SRCDIR/resources/linux-5.0-config .config
    make bzImage -j `nproc`
    cp vmlinux $VMLINUX_IMAGE
    cp arch/x86/boot/bzImage $BZIMAGE_IMAGE
    popd
    rm linux-5.0.21.tar.xz
    rm -r linux-5.0.21
    popd
fi

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_CUSTOM_IMAGE="$WORKLOADS_DIR/vmlinux-custom"
LINUX_CUSTOM_DIR="linux-custom"

if [ ! -f "$VMLINUX_CUSTOM_IMAGE" ]; then
    SRCDIR=$PWD
    pushd $WORKLOADS_DIR
    git clone --depth 1 "https://github.com/sboeuf/linux.git" -b "virtio-pmem_and_virtio-fs" $LINUX_CUSTOM_DIR
    pushd $LINUX_CUSTOM_DIR
    cp $SRCDIR/resources/linux-virtio-pmem-and-virtio-fs-config .config
    make bzImage -j `nproc`
    cp vmlinux $VMLINUX_CUSTOM_IMAGE
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

rm /tmp/cloudinit.img
mkdosfs -n config-2 -C /tmp/cloudinit.img 8192
mcopy -oi /tmp/cloudinit.img -s test_data/cloud-init/openstack ::

cargo build
sudo setcap cap_net_admin+ep target/debug/cloud-hypervisor

# Tests must be executed serially for now as they have a hardcoded IP address
cargo test --features "integration_tests" -- --test-threads=1
