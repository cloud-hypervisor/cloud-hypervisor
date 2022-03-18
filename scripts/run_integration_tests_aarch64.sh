#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

export BUILD_TARGET=${BUILD_TARGET-aarch64-unknown-linux-gnu}

WORKLOADS_DIR="$HOME/workloads"
WORKLOADS_LOCK="$WORKLOADS_DIR/integration_test.lock"

mkdir -p "$WORKLOADS_DIR"

build_custom_linux() {
    SRCDIR=$PWD
    LINUX_CUSTOM_DIR="$WORKLOADS_DIR/linux-custom"
    LINUX_CUSTOM_BRANCH="ch-5.15.12"
    LINUX_CUSTOM_URL="https://github.com/cloud-hypervisor/linux.git"

    checkout_repo "$LINUX_CUSTOM_DIR" "$LINUX_CUSTOM_URL" "$LINUX_CUSTOM_BRANCH"

    if [ ! -f "$LINUX_CUSTOM_DIR/.built" ]; then
        cp $SRCDIR/resources/linux-config-aarch64 $LINUX_CUSTOM_DIR/.config

        pushd $LINUX_CUSTOM_DIR
        time make -j `nproc`
        cp arch/arm64/boot/Image "$WORKLOADS_DIR/" || exit 1
        cp arch/arm64/boot/Image.gz "$WORKLOADS_DIR/" || exit 1
        touch .built
        popd
    fi
}

build_edk2() {
    EDK2_BUILD_DIR="$WORKLOADS_DIR/edk2_build"
    EDK2_REPO="https://github.com/tianocore/edk2.git"
    EDK2_DIR="$EDK2_BUILD_DIR/edk2"
    EDK2_PLAT_REPO="https://github.com/tianocore/edk2-platforms.git"
    EDK2_PLAT_DIR="$EDK2_BUILD_DIR/edk2-platforms"
    ACPICA_REPO="https://github.com/acpica/acpica.git"
    ACPICA_DIR="$EDK2_BUILD_DIR/acpica"
    export WORKSPACE="$EDK2_BUILD_DIR"
    export PACKAGES_PATH="$EDK2_DIR:$EDK2_PLAT_DIR"
    export IASL_PREFIX="$ACPICA_DIR/generate/unix/bin/"

    if [ ! -d "$EDK2_BUILD_DIR" ]; then
        mkdir -p "$EDK2_BUILD_DIR"
    fi

    # Prepare source code
    checkout_repo "$EDK2_DIR" "$EDK2_REPO" master "46b4606ba23498d3d0e66b53e498eb3d5d592586"
    pushd "$EDK2_DIR"
    git submodule update --init
    popd
    checkout_repo "$EDK2_PLAT_DIR" "$EDK2_PLAT_REPO" master "8227e9e9f6a8aefbd772b40138f835121ccb2307"
    checkout_repo "$ACPICA_DIR" "$ACPICA_REPO" master "b9c69f81a05c45611c91ea9cbce8756078d76233"

    if [[ ! -f "$EDK2_DIR/.built" || \
          ! -f "$EDK2_PLAT_DIR/.built" || \
          ! -f "$ACPICA_DIR/.built" ]]; then
        pushd "$EDK2_BUILD_DIR"
        # Build
        make -C acpica -j `nproc`
        source edk2/edksetup.sh
        make -C edk2/BaseTools -j `nproc`
        build -a AARCH64 -t GCC5 -p ArmVirtPkg/ArmVirtCloudHv.dsc -b RELEASE -n 0
        cp Build/ArmVirtCloudHv-AARCH64/RELEASE_GCC5/FV/CLOUDHV_EFI.fd "$WORKLOADS_DIR"
        touch "$EDK2_DIR"/.built
        touch "$EDK2_PLAT_DIR"/.built
        touch "$ACPICA_DIR"/.built
        popd
    fi
}

build_spdk_nvme() {
    SPDK_DIR="$WORKLOADS_DIR/spdk"
    SPDK_REPO="https://github.com/spdk/spdk.git"
    SPDK_DEPLOY_DIR="/usr/local/bin/spdk-nvme"
    checkout_repo "$SPDK_DIR" "$SPDK_REPO" master "f9c496b8e21a8f499df268818bf8b5d8e2b19f04"

    if [ ! -f "$SPDK_DIR/.built" ]; then
        pushd $SPDK_DIR
        git submodule update --init
        apt-get update
        ./scripts/pkgdep.sh
        ./configure --with-vfio-user
        chmod +x /usr/local/lib/python3.8/dist-packages/ninja/data/bin/ninja
        make -j `nproc` || exit 1
        touch .built
        popd
    fi
    if [ ! -d "/usr/local/bin/spdk-nvme" ]; then
        mkdir -p $SPDK_DEPLOY_DIR
    fi
    cp "$WORKLOADS_DIR/spdk/build/bin/nvmf_tgt" $SPDK_DEPLOY_DIR/nvmf_tgt
    cp "$WORKLOADS_DIR/spdk/scripts/rpc.py" $SPDK_DEPLOY_DIR/rpc.py
    cp -r "$WORKLOADS_DIR/spdk/scripts/rpc" $SPDK_DEPLOY_DIR/rpc
}

build_virtiofsd() {
    VIRTIOFSD_DIR="$WORKLOADS_DIR/virtiofsd_build"
    VIRTIOFSD_REPO="https://gitlab.com/virtio-fs/virtiofsd.git"

    checkout_repo "$VIRTIOFSD_DIR" "$VIRTIOFSD_REPO" v1.1.0 "220405d7a2606c92636d31992b5cb3036a41047b"

    if [ ! -f "$VIRTIOFSD_DIR/.built" ]; then
        pushd $VIRTIOFSD_DIR
        time cargo build --release
        cp target/release/virtiofsd "$WORKLOADS_DIR/" || exit 1
        touch .built
        popd
    fi
}

update_workloads() {
    cp scripts/sha1sums-aarch64 $WORKLOADS_DIR

    BIONIC_OS_IMAGE_DOWNLOAD_NAME="bionic-server-cloudimg-arm64.img"
    BIONIC_OS_IMAGE_DOWNLOAD_URL="https://cloud-hypervisor.azureedge.net/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
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

    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-arm64-custom-20210929-0.raw"
    FOCAL_OS_RAW_IMAGE_DOWNLOAD_URL="https://cloud-hypervisor.azureedge.net/$FOCAL_OS_RAW_IMAGE_NAME"
    FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
    if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $FOCAL_OS_RAW_IMAGE_DOWNLOAD_URL || exit 1
        popd
    fi

    FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="focal-server-cloudimg-arm64-custom-20210929-0.qcow2"
    FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_DOWNLOAD_URL="https://cloud-hypervisor.azureedge.net/$FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
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

    # Build custom kernel for guest VMs
    build_custom_linux

    # Update the kernel in the cloud image for some tests that requires recent kernel version
    FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_NAME="focal-server-cloudimg-arm64-custom-20210929-0-update-kernel.raw"
    cp "$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME" "$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_NAME"
    FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_ROOT_DIR="$WORKLOADS_DIR/focal-server-cloudimg-root"
    mkdir -p "$FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_ROOT_DIR"
    # Mount the 'raw' image, replace the compressed kernel file and umount the working folder
    guestmount -a "$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_NAME" -m /dev/sda1 "$FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_ROOT_DIR" || exit 1
    cp "$WORKLOADS_DIR"/Image.gz "$FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_ROOT_DIR"/boot/vmlinuz
    guestunmount "$FOCAL_OS_RAW_IMAGE_UPDATE_KERNEL_ROOT_DIR"

    # Build virtiofsd
    build_virtiofsd

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

    # Checkout and build SPDK NVMe
    build_spdk_nvme

    # Checkout and build EDK2
    build_edk2
}

process_common_args "$@"

# aarch64 not supported for MSHV
if [[ "$hypervisor" = "mshv" ]]; then
    echo "AArch64 is not supported in Microsoft Hypervisor"
    exit 1
fi

# For now these values are deafult for kvm
features=""

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

BUILD_TARGET="aarch64-unknown-linux-${CH_LIBC}"
if [[ "${BUILD_TARGET}" == "aarch64-unknown-linux-musl" ]]; then
export TARGET_CC="musl-gcc"
export RUSTFLAGS="-C link-arg=-lgcc -C link_arg=-specs -C link_arg=/usr/lib/aarch64-linux-musl/musl-gcc.specs"
fi

export RUST_BACKTRACE=1

# Test without ACPI
cargo build --all --release $features --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor
strip target/$BUILD_TARGET/release/vhost_user_net
strip target/$BUILD_TARGET/release/ch-remote

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

# Both test_vfio and ovs-dpdk rely on hugepages
echo 6144 | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

# Run all direct kernel boot (Device Tree) test cases in mod `parallel`
time cargo test $features "parallel::$test_filter" --target $BUILD_TARGET -- ${test_binary_args[*]}
RES=$?

# Run some tests in sequence since the result could be affected by other tests
# running in parallel.
if [ $RES -eq 0 ]; then
    time cargo test $features "sequential::$test_filter" --target $BUILD_TARGET -- --test-threads=1 ${test_binary_args[*]}
    RES=$?
else
    exit $RES
fi

# Run all ACPI test cases
if [ $RES -eq 0 ]; then
    time cargo test $features "aarch64_acpi::$test_filter" --target $BUILD_TARGET -- ${test_binary_args[*]}
    RES=$?
else
    exit $RES
fi

# Run all test cases related to live migration
if [ $RES -eq 0 ]; then
    time cargo test $features "live_migration::$test_filter" --target $BUILD_TARGET -- --test-threads=1 ${test_binary_args[*]}
    RES=$?
else
    exit $RES
fi

exit $RES
