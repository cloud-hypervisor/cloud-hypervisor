#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"
mkdir -p "$WORKLOADS_DIR/junit"

process_common_args "$@"

# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ]; then
    test_features="--features mshv"
fi

# if migratable version is set to override the default
FW="$WORKLOADS_DIR/hypervisor-fw"
GUEST_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.qcow2"
GUEST_OS_IMAGE="$WORKLOADS_DIR/$GUEST_OS_IMAGE_NAME"
GUEST_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.raw"
GUEST_OS_RAW_IMAGE="$WORKLOADS_DIR/$GUEST_OS_RAW_IMAGE_NAME"

for required in "$FW" "$WORKLOADS_DIR/CLOUDHV.fd" "$GUEST_OS_IMAGE" \
    "$WORKLOADS_DIR/vmlinux-x86_64" "$WORKLOADS_DIR/bzImage-x86_64" \
    "$WORKLOADS_DIR/alpine-minirootfs-x86_64.tar.gz" \
    "$WORKLOADS_DIR/cloud-hypervisor-static"; do
    if [ ! -f "$required" ]; then
        echo "Missing: $required — run: python3 scripts/fetch_workloads.py --test integration"
        exit 1
    fi
done

if [ ! -f "$GUEST_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $GUEST_OS_IMAGE_NAME $GUEST_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

GUEST_OS_QCOW_ZLIB_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-zlib.qcow2"
GUEST_OS_QCOW_ZLIB_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_ZLIB_FILE_IMAGE_NAME"
if [ ! -f "$GUEST_OS_QCOW_ZLIB_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -c -f raw -O qcow2 -o compression_type=zlib \
        "$GUEST_OS_RAW_IMAGE" $GUEST_OS_QCOW_ZLIB_FILE_IMAGE_NAME
    popd || exit
fi

GUEST_OS_QCOW_ZSTD_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-zstd.qcow2"
GUEST_OS_QCOW_ZSTD_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_ZSTD_FILE_IMAGE_NAME"
if [ ! -f "$GUEST_OS_QCOW_ZSTD_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -c -f raw -O qcow2 -o compression_type=zstd \
        "$GUEST_OS_RAW_IMAGE" $GUEST_OS_QCOW_ZSTD_FILE_IMAGE_NAME
    popd || exit
fi

GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-backing-zstd.qcow2"
GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME"
if [ ! -f "$GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img create -f qcow2 \
        -b "$GUEST_OS_QCOW_ZSTD_FILE_IMAGE" \
        -F qcow2 $GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME
    popd || exit
fi

GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-backing-uncompressed.qcow2"
GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME"
if [ ! -f "$GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img create -f qcow2 \
        -b "$GUEST_OS_IMAGE" \
        -F qcow2 $GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME
    popd || exit
fi

GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-backing-raw.qcow2"
GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME"
if [ ! -f "$GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img create -f qcow2 \
        -b "$GUEST_OS_RAW_IMAGE" \
        -F raw $GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME
    popd || exit
fi

ALPINE_MINIROOTFS_TARBALL="$WORKLOADS_DIR/alpine-minirootfs-x86_64.tar.gz"
if [ ! -f "$ALPINE_MINIROOTFS_TARBALL" ]; then
    echo "Missing: $ALPINE_MINIROOTFS_TARBALL — run: python3 scripts/fetch_workloads.py --test integration"
    exit 1
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

python3 scripts/fetch_workloads.py --test integration --verify-only || exit 1

VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux-x86_64"

VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
if [ ! -f "$VIRTIOFSD" ]; then
    cp /usr/local/bin/virtiofsd "$VIRTIOFSD"
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
cp "$GUEST_OS_RAW_IMAGE" "$VFIO_DIR"
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
PAGE_NUM=$((6144 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

# Update max locked memory to 'unlimited' to avoid issues with vDPA
ulimit -l unlimited

# Set number of open descriptors high enough for VFIO tests to run
ulimit -n 4096

# Common configuration for every test run
export RUST_BACKTRACE=1
export RUSTFLAGS="$RUSTFLAGS"

TEST_THREADS_DEFAULT="$(($(nproc) / 4))"
if ! [[ "${PARALLEL_INTEGRATION_TESTS_NUM:-}" =~ ^[1-9][0-9]*$ ]]; then
    PARALLEL_INTEGRATION_TESTS_NUM="${TEST_THREADS_DEFAULT}"
fi
echo "nproc:$(nproc), parallel_integration_tests:${PARALLEL_INTEGRATION_TESTS_NUM}"
time cargo nextest run -p cloud-hypervisor $test_features --profile common_tests --no-tests=pass --test-threads="${PARALLEL_INTEGRATION_TESTS_NUM}" "$test_filter" -- ${test_binary_args[*]}
RES=$?

# Run tests on dbus_api
if [ $RES -eq 0 ]; then
    cargo build --features "mshv,dbus_api" --all --release --target "$BUILD_TARGET"
    # integration tests now do not reply on build feature "dbus_api"
    time cargo nextest run -p cloud-hypervisor $test_features --profile dbus --no-tests=pass --test-threads="$TEST_THREADS_DEFAULT" "$test_filter" -- ${test_binary_args[*]}
    RES=$?
fi

# Run tests on fw_cfg
if [ $RES -eq 0 ]; then
    cargo build --features "mshv,fw_cfg" --all --release --target "$BUILD_TARGET"
    time cargo nextest run -p cloud-hypervisor $test_features --profile fw_cfg --no-tests=pass --test-threads="$TEST_THREADS_DEFAULT" "$test_filter" -- ${test_binary_args[*]}
    RES=$?
fi

if [ $RES -eq 0 ]; then
    cargo build --features "mshv,ivshmem" --all --release --target "$BUILD_TARGET"
    time cargo nextest run -p cloud-hypervisor $test_features --profile ivshmem --no-tests=pass --test-threads="$TEST_THREADS_DEFAULT" "$test_filter" -- ${test_binary_args[*]}
    RES=$?
fi

exit $RES
