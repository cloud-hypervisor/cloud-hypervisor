#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ]; then
    test_features="--features mshv"
fi

cp scripts/sha1sums-x86_64 "$WORKLOADS_DIR"

if [ ! -f "$WORKLOADS_DIR/hypervisor-fw" ]; then
    download_hypervisor_fw
fi

if [ ! -f "$WORKLOADS_DIR/CLOUDHV.fd" ]; then
    download_ovmf
fi

download_x86_guest_images

ALPINE_MINIROOTFS_URL="http://dl-cdn.alpinelinux.org/alpine/v3.11/releases/x86_64/alpine-minirootfs-3.11.3-x86_64.tar.gz"
ALPINE_MINIROOTFS_TARBALL="$WORKLOADS_DIR/alpine-minirootfs-x86_64.tar.gz"
if [ ! -f "$ALPINE_MINIROOTFS_TARBALL" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time wget --quiet $ALPINE_MINIROOTFS_URL -O "$ALPINE_MINIROOTFS_TARBALL" || exit 1
    popd || exit
fi

ALPINE_INITRAMFS_IMAGE="$WORKLOADS_DIR/alpine_initramfs.img"
if [ ! -f "$ALPINE_INITRAMFS_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    mkdir alpine-minirootfs
    tar xf "$ALPINE_MINIROOTFS_TARBALL" -C alpine-minirootfs
    cat >alpine-minirootfs/init <<-EOF
		#! /bin/sh
		mount -t devtmpfs dev /dev
		echo \$TEST_STRING > /dev/console
		poweroff -f
	EOF
    chmod +x alpine-minirootfs/init
    cd alpine-minirootfs || exit
    find . -print0 |
        cpio --null --create --verbose --owner root:root --format=newc >"$ALPINE_INITRAMFS_IMAGE"
    popd || exit
fi

pushd "$WORKLOADS_DIR" || exit
if ! sha1sum sha1sums-x86_64 --check; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd || exit

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux-x86_64"
if [ ! -f "$VMLINUX_IMAGE" ]; then
    # Prepare linux image (build from source or download pre-built)
    prepare_linux
fi

VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
VIRTIOFSD_DIR="virtiofsd_build"
if [ ! -f "$VIRTIOFSD" ]; then
    pushd "$WORKLOADS_DIR" || exit
    git clone "https://gitlab.com/virtio-fs/virtiofsd.git" $VIRTIOFSD_DIR
    pushd $VIRTIOFSD_DIR || exit
    git checkout v1.8.0
    time cargo build --release
    cp target/release/virtiofsd "$VIRTIOFSD" || exit 1
    popd || exit
    rm -rf $VIRTIOFSD_DIR
    popd || exit
fi

BLK_IMAGE="$WORKLOADS_DIR/blk.img"
MNT_DIR="mount_image"
if [ ! -f "$BLK_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    fallocate -l 16M "$BLK_IMAGE"
    mkfs.ext4 -j "$BLK_IMAGE"
    mkdir $MNT_DIR
    sudo mount -t ext4 "$BLK_IMAGE" $MNT_DIR
    sudo bash -c "echo bar > $MNT_DIR/foo" || exit 1
    sudo umount "$BLK_IMAGE"
    rm -r $MNT_DIR
    popd || exit
fi

SHARED_DIR="$WORKLOADS_DIR/shared_dir"
if [ ! -d "$SHARED_DIR" ]; then
    mkdir -p "$SHARED_DIR"
    echo "foo" >"$SHARED_DIR/file1"
    echo "bar" >"$SHARED_DIR/file3" || exit 1
fi

VFIO_DIR="$WORKLOADS_DIR/vfio"
VFIO_DISK_IMAGE="$WORKLOADS_DIR/vfio.img"
rm -rf "$VFIO_DIR" "$VFIO_DISK_IMAGE"
mkdir -p "$VFIO_DIR"
cp "$FOCAL_OS_RAW_IMAGE" "$VFIO_DIR"
cp "$FW" "$VFIO_DIR"
cp "$VMLINUX_IMAGE" "$VFIO_DIR" || exit 1

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# We always copy a fresh version of our binary for our L2 guest.
cp target/"$BUILD_TARGET"/release/cloud-hypervisor "$VFIO_DIR"
cp target/"$BUILD_TARGET"/release/ch-remote "$VFIO_DIR"

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

# Both test_vfio, ovs-dpdk and vDPA tests rely on hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((12288 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

# Update max locked memory to 'unlimited' to avoid issues with vDPA
ulimit -l unlimited

# Set number of open descriptors high enough for VFIO tests to run
ulimit -n 4096

export RUST_BACKTRACE=1
time cargo test --release --target "$BUILD_TARGET" $test_features "common_parallel::$test_filter" -- ${test_binary_args[*]} --test-threads=$((($(nproc) * 3) / 4))
RES=$?

# Run some tests in sequence since the result could be affected by other tests
# running in parallel.
if [ $RES -eq 0 ]; then
    export RUST_BACKTRACE=1
    time cargo test --release --target "$BUILD_TARGET" $test_features "common_sequential::$test_filter" -- --test-threads=1 ${test_binary_args[*]}
    RES=$?
fi

# Run tests on dbus_api
if [ $RES -eq 0 ]; then
    cargo build --features "mshv,dbus_api" --all --release --target "$BUILD_TARGET"
    export RUST_BACKTRACE=1
    # integration tests now do not reply on build feature "dbus_api"
    time cargo test $test_features "dbus_api::$test_filter" -- ${test_binary_args[*]}
    RES=$?
fi

# Run tests on fw_cfg
if [ $RES -eq 0 ]; then
    cargo build --features "mshv,fw_cfg" --all --release --target "$BUILD_TARGET"
    export RUST_BACKTRACE=1
    time cargo test "fw_cfg::$test_filter" --target "$BUILD_TARGET" -- ${test_binary_args[*]}
    RES=$?
fi

if [ $RES -eq 0 ]; then
    cargo build --features ivshmem --all --release --target "$BUILD_TARGET"
    export RUST_BACKTRACE=1
    time cargo test $test_features "ivshmem::$test_filter" --target "$BUILD_TARGET" -- ${test_binary_args[*]}
    RES=$?
fi

exit $RES
