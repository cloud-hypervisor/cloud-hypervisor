#!/bin/bash
set -x

source $HOME/.cargo/env

export BUILD_TARGET=${BUILD_TARGET-aarch64-unknown-linux-gnu}

WORKLOADS_DIR="$HOME/workloads"
WORKLOADS_LOCK="$WORKLOADS_DIR/integration_test.lock"

mkdir -p "$WORKLOADS_DIR"

update_workloads() {
    cp scripts/sha1sums-aarch64 $WORKLOADS_DIR

    BIONIC_OS_IMAGE_DOWNLOAD_NAME="bionic-server-cloudimg-arm64.img"
    BIONIC_OS_IMAGE_DOWNLOAD_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
    BIONIC_OS_DOWNLOAD_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
    if [ ! -f "$BIONIC_OS_DOWNLOAD_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $BIONIC_OS_IMAGE_DOWNLOAD_URL || exit 1
        popd
    fi

    BIONIC_OS_RAW_IMAGE_NAME="bionic-server-cloudimg-arm64.raw"
    BIONIC_OS_RAW_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_RAW_IMAGE_NAME"
    if [ ! -f "$BIONIC_OS_RAW_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time qemu-img convert -p -f qcow2 -O raw $BIONIC_OS_IMAGE_DOWNLOAD_NAME $BIONIC_OS_RAW_IMAGE_NAME || exit 1
        popd
    fi

    # Convert the raw image to qcow2 image to remove compressed blocks from the disk. Therefore letting the
    # qcow2 format image can be directly used in the integration test.
    BIONIC_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="bionic-server-cloudimg-arm64.qcow2"
    BIONIC_OS_QCOW2_UNCOMPRESSED_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
    if [ ! -f "$BIONIC_OS_QCOW2_UNCOMPRESSED_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time qemu-img convert -p -f raw -O qcow2 $BIONIC_OS_RAW_IMAGE_NAME $BIONIC_OS_QCOW2_UNCOMPRESSED_IMAGE || exit 1
        popd
    fi

    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-arm64-custom.raw"
    FOCAL_OS_RAW_IMAGE_DOWNLOAD_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$FOCAL_OS_RAW_IMAGE_NAME"
    FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
    if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $FOCAL_OS_RAW_IMAGE_DOWNLOAD_URL || exit 1
        popd
    fi

    # Convert the raw image to qcow2 image to remove compressed blocks from the disk. Therefore letting the
    # qcow2 format image can be directly used in the integration test.
    FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="focal-server-cloudimg-arm64-custom.qcow2"
    FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_DOWNLOAD_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
    FOCAL_OS_QCOW2_UNCOMPRESSED_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
    if [ ! -f "$FOCAL_OS_QCOW2_UNCOMPRESSED_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_DOWNLOAD_URL || exit 1
        popd
    fi

    ALPINE_MINIROOTFS_URL="http://dl-cdn.alpinelinux.org/alpine/v3.11/releases/aarch64/alpine-minirootfs-3.11.3-aarch64.tar.gz"
    ALPINE_MINIROOTFS_TARBALL="$WORKLOADS_DIR/alpine-minirootfs-aarch64.tar.gz"
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
    sha1sum sha1sums-aarch64 --check
    if [ $? -ne 0 ]; then
        echo "sha1sum validation of images failed, remove invalid images to fix the issue."
        exit 1
    fi
    popd

    # Build custom kernel based on virtio-pmem and virtio-fs upstream patches
    PE_IMAGE="$WORKLOADS_DIR/Image"
    LINUX_CUSTOM_DIR="$WORKLOADS_DIR/linux-custom"

    build_custom_linux_kernel() {
        pushd $LINUX_CUSTOM_DIR
        time make -j `nproc`
        cp arch/arm64/boot/Image $WORKLOADS_DIR/Image || exit 1
        popd
    }

    SRCDIR=$PWD
    if [ ! -d "$LINUX_CUSTOM_DIR" ]; then
        pushd $WORKLOADS_DIR
        time git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b "virtio-fs-virtio-iommu-5.8-rc4" $LINUX_CUSTOM_DIR
        cp $SRCDIR/resources/linux-config-aarch64 $LINUX_CUSTOM_DIR/.config
        popd
    else
        pushd $LINUX_CUSTOM_DIR
        git fetch
        git checkout -f "virtio-fs-virtio-iommu-5.8-rc4"
        cp $SRCDIR/resources/linux-config-aarch64 $LINUX_CUSTOM_DIR/.config
        popd
    fi

    build_custom_linux_kernel

    VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
    QEMU_DIR="qemu_build"

    if [ ! -f "$VIRTIOFSD" ]; then
        pushd $WORKLOADS_DIR
        git clone --depth 1 "https://gitlab.com/virtio-fs/qemu.git" -b "virtio-fs-dev" $QEMU_DIR
        pushd $QEMU_DIR
        time ./configure --prefix=$PWD --target-list=aarch64-softmmu
        time make virtiofsd -j `nproc`
        cp virtiofsd $VIRTIOFSD || exit 1
        popd
        rm -rf $QEMU_DIR
        sudo setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_setgid,cap_setuid,cap_mknod,cap_setfcap,cap_sys_admin+epi "virtiofsd" || exit 1
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
}

# lock the workloads folder to avoid parallel updating by different containers
(
    echo "try to lock $WORKLOADS_DIR folder and update"
    flock -x 12 && update_workloads
) 12>$WORKLOADS_LOCK

# Check if there is any error in the execution of `update_workloads`.
# If there is any error, then kill the shell. Otherwise the script will continue
# running even if the `update_workloads` function was failed.
RES=$?
if [ $RES -ne 0 ]; then
    exit 1
fi

# Create tap interface without multiple queues support for vhost_user_net test.
sudo ip tuntap add name vunet-tap0 mode tap
# Create tap interface with multiple queues support for vhost_user_net test.
sudo ip tuntap add name vunet-tap1 mode tap multi_queue

BUILD_TARGET="aarch64-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "aarch64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/aarch64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --all --release --no-default-features --features pci,kvm --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor
strip target/$BUILD_TARGET/release/vhost_user_net
strip target/$BUILD_TARGET/release/ch-remote

# Copy for non-privileged net test
cp target/$BUILD_TARGET/release/cloud-hypervisor target/$BUILD_TARGET/release/cloud-hypervisor-unprivileged

sudo setcap cap_net_admin+ep target/$BUILD_TARGET/release/cloud-hypervisor
sudo setcap cap_net_admin+ep target/$BUILD_TARGET/release/vhost_user_net

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

sudo adduser $USER kvm
newgrp kvm << EOF
export RUST_BACKTRACE=1
time cargo test --no-default-features --features "integration_tests,pci,kvm" "tests::parallel::$@" -- --skip test_snapshot_restore
EOF
RES=$?

if [ $RES -eq 0 ]; then
    # virtio-mmio based testing
    cargo build --release --target $BUILD_TARGET --no-default-features --features "mmio,kvm"
    strip target/$BUILD_TARGET/release/cloud-hypervisor
    strip target/$BUILD_TARGET/release/vhost_user_net
    strip target/$BUILD_TARGET/release/ch-remote

    sudo setcap cap_net_admin+ep target/$BUILD_TARGET/release/cloud-hypervisor
    sudo setcap cap_net_admin+ep target/$BUILD_TARGET/release/vhost_user_net

    # Ensure test binary has the same caps as the cloud-hypervisor one
    time cargo test --no-run --no-default-features --features "integration_tests,mmio,kvm" || exit 1
    ls target/debug/deps/cloud_hypervisor-* | xargs -n 1 sudo setcap cap_net_admin+ep

    newgrp kvm << EOF
export RUST_BACKTRACE=1
time cargo test --no-default-features --features "integration_tests,mmio,kvm" "tests::parallel::$@"
EOF

    RES=$?
fi

# Tear vhost_user_net test network down
sudo ip link del vunet-tap0
sudo ip link del vunet-tap1

exit $RES
