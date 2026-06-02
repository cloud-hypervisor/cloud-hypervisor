#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh
source "$(dirname "$0")"/common-aarch64.sh

WORKLOADS_LOCK="$WORKLOADS_DIR/integration_test.lock"

update_workloads() {
    GUEST_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="debian-13-generic-arm64-custom-20260602-0.qcow2"
    GUEST_OS_QCOW2_UNCOMPRESSED_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"

    GUEST_OS_RAW_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0.raw"
    GUEST_OS_RAW_IMAGE="$WORKLOADS_DIR/$GUEST_OS_RAW_IMAGE_NAME"

    for required in "$GUEST_OS_QCOW2_UNCOMPRESSED_IMAGE" \
        "$WORKLOADS_DIR/CLOUDHV_EFI.fd" \
        "$WORKLOADS_DIR/cloud-hypervisor-static-aarch64" \
        "$WORKLOADS_DIR/alpine-minirootfs-aarch64.tar.gz" \
        "$WORKLOADS_DIR/Image-arm64"; do
        if [ ! -f "$required" ]; then
            echo "Missing: $required — run: python3 scripts/fetch_workloads.py --test integration"
            exit 1
        fi
    done

    if [ ! -f "$WORKLOADS_DIR/virtiofsd" ]; then
        cp /usr/local/bin/virtiofsd "$WORKLOADS_DIR/virtiofsd"
    fi

    if [ ! -f "$GUEST_OS_RAW_IMAGE" ]; then
        pushd "$WORKLOADS_DIR" || exit
        time qemu-img convert -p -f qcow2 -O raw $GUEST_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME $GUEST_OS_RAW_IMAGE_NAME || exit 1
        popd || exit
    fi

    GUEST_OS_QCOW2_ZLIB_FILE_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0-zlib.qcow2"
    GUEST_OS_QCOW2_ZLIB_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW2_ZLIB_FILE_IMAGE_NAME"
    if [ ! -f "$GUEST_OS_QCOW2_ZLIB_FILE_IMAGE" ]; then
        pushd "$WORKLOADS_DIR" || exit
        time qemu-img convert -c -f raw -O qcow2 -o compression_type=zlib \
            "$GUEST_OS_RAW_IMAGE" $GUEST_OS_QCOW2_ZLIB_FILE_IMAGE_NAME
        popd || exit
    fi

    GUEST_OS_QCOW2_ZSTD_FILE_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0-zstd.qcow2"
    GUEST_OS_QCOW2_ZSTD_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW2_ZSTD_FILE_IMAGE_NAME"
    if [ ! -f "$GUEST_OS_QCOW2_ZSTD_FILE_IMAGE" ]; then
        pushd "$WORKLOADS_DIR" || exit
        time qemu-img convert -c -f raw -O qcow2 -o compression_type=zstd \
            "$GUEST_OS_RAW_IMAGE" $GUEST_OS_QCOW2_ZSTD_FILE_IMAGE_NAME
        popd || exit
    fi

    GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0-backing-zstd.qcow2"
    GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME"
    if [ ! -f "$GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE" ]; then
        pushd "$WORKLOADS_DIR" || exit
        time qemu-img create -f qcow2 -b "$GUEST_OS_QCOW2_ZSTD_FILE_IMAGE" -F qcow2 $GUEST_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME
        popd || exit
    fi

    GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0-backing-uncompressed.qcow2"
    GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME"
    if [ ! -f "$GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE" ]; then
        pushd "$WORKLOADS_DIR" || exit
        time qemu-img create -f qcow2 \
            -b "$GUEST_OS_QCOW2_UNCOMPRESSED_IMAGE" \
            -F qcow2 $GUEST_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME
        popd || exit
    fi

    GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME="debian-13-generic-arm64-custom-20260602-0-backing-raw.qcow2"
    GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE="$WORKLOADS_DIR/$GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME"
    if [ ! -f "$GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE" ]; then
        pushd "$WORKLOADS_DIR" || exit
        time qemu-img create -f qcow2 \
            -b "$GUEST_OS_RAW_IMAGE" \
            -F raw $GUEST_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME
        popd || exit
    fi

    ALPINE_MINIROOTFS_TARBALL="$WORKLOADS_DIR/alpine-minirootfs-aarch64.tar.gz"

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
}

process_common_args "$@"

test_features=""

if [ "$hypervisor" = "mshv" ]; then
    test_features="--features mshv"
fi

# lock the workloads folder to avoid parallel updating by different containers
(
    echo "try to lock $WORKLOADS_DIR folder and update"
    flock -x 12 && update_workloads
) 12>"$WORKLOADS_LOCK"

# Check if there is any error in the execution of `update_workloads`.
# If there is any error, then kill the shell. Otherwise the script will continue
# running even if the `update_workloads` function was failed.
RES=$?
if [ $RES -ne 0 ]; then
    exit 1
fi

# Common configuration for every test run
export RUST_BACKTRACE=1
export RUSTFLAGS="$RUSTFLAGS"

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

# Both test_vfio and ovs-dpdk rely on hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((6144 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

TEST_THREADS_DEFAULT="$(($(nproc) / 4))"
if ! [[ "${PARALLEL_INTEGRATION_TESTS_NUM:-}" =~ ^[1-9][0-9]*$ ]]; then
    PARALLEL_INTEGRATION_TESTS_NUM="${TEST_THREADS_DEFAULT}"
fi
echo "nproc:$(nproc), parallel_integration_tests:${PARALLEL_INTEGRATION_TESTS_NUM}"
# Run all direct kernel boot (Device Tree) test cases in mod `parallel`,
# `sequential`, and ACPI cases. The `common_tests` profile filter covers
# all three sets, and the per-mod `threads-required = 'num-test-threads'`
# override on `common_sequential` enforces serial scheduling within the run.
time cargo nextest run -p cloud-hypervisor $test_features --profile common_tests --no-tests=pass --test-threads="${PARALLEL_INTEGRATION_TESTS_NUM}" "$test_filter" -- ${test_binary_args[*]}
RES=$?
if [ $RES -ne 0 ]; then
    exit $RES
fi

# Run tests on dbus_api
if [ $RES -eq 0 ]; then
    cargo build --features "mshv,dbus_api" --all --release --target "$BUILD_TARGET"
    export RUST_BACKTRACE=1
    # integration tests now do not reply on build feature "dbus_api"
    time cargo nextest run -p cloud-hypervisor $test_features --profile dbus --no-tests=pass --test-threads="$TEST_THREADS_DEFAULT" "$test_filter" -- ${test_binary_args[*]}
    RES=$?
fi

# Run tests on fw_cfg
if [ $RES -eq 0 ]; then
    cargo build --features "mshv,fw_cfg" --all --release --target "$BUILD_TARGET"
    export RUST_BACKTRACE=1
    time cargo nextest run -p cloud-hypervisor $test_features --profile fw_cfg --no-tests=pass --test-threads="$TEST_THREADS_DEFAULT" "$test_filter" -- ${test_binary_args[*]}
    RES=$?
fi

if [ $RES -eq 0 ]; then
    cargo build --features "mshv,ivshmem" --all --release --target "$BUILD_TARGET"
    export RUST_BACKTRACE=1
    time cargo nextest run -p cloud-hypervisor $test_features --profile ivshmem --no-tests=pass --test-threads="$TEST_THREADS_DEFAULT" "$test_filter" -- ${test_binary_args[*]}

    RES=$?
fi

exit $RES
