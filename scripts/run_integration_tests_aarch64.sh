#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh
source "$(dirname "$0")"/common-aarch64.sh

WORKLOADS_LOCK="$WORKLOADS_DIR/integration_test.lock"

update_workloads() {
    JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-arm64-custom-20220329-0.raw"
    JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"

    JAMMY_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="jammy-server-cloudimg-arm64-custom-20220329-0.qcow2"
    JAMMY_OS_QCOW2_UNCOMPRESSED_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"

    for required in "$JAMMY_OS_RAW_IMAGE" "$JAMMY_OS_QCOW2_UNCOMPRESSED_IMAGE" \
        "$WORKLOADS_DIR/CLOUDHV_EFI.fd" \
        "$WORKLOADS_DIR/cloud-hypervisor-static-aarch64" \
        "$WORKLOADS_DIR/ch-remote-static-aarch64" \
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

    # Tests take guest images from /tmp/workloads in preference to the
    # workloads directory. When /tmp is the XFS filesystem set up by
    # dev_cli.sh --ci, their copies of the images there are reflinks rather
    # than full copies in memory.
    if [ "$(stat -f -c %T /tmp)" = xfs ]; then
        mkdir -p /tmp/workloads
        cp "$JAMMY_OS_RAW_IMAGE" "$JAMMY_OS_QCOW2_UNCOMPRESSED_IMAGE" /tmp/workloads || exit 1
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

# Set number of open descriptors high enough for VFIO tests to run
ulimit -n 4096

# Common configuration for every test run
export RUST_BACKTRACE=1
export RUSTFLAGS="$RUSTFLAGS"

cargo build --features "mshv,dbus_api,fw_cfg,ivshmem" --all --release --target "$BUILD_TARGET"

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

# Both test_vfio and ovs-dpdk rely on hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((6144 * 1024 / HUGEPAGESIZE))
setup_hugepages_pool "$HUGEPAGESIZE" "$PAGE_NUM"
sudo chmod a+rwX /dev/hugepages

TEST_THREADS_DEFAULT="$(($(nproc) / 4))"
if ! [[ "${PARALLEL_INTEGRATION_TESTS_NUM:-}" =~ ^[1-9][0-9]*$ ]]; then
    PARALLEL_INTEGRATION_TESTS_NUM="${TEST_THREADS_DEFAULT}"
fi
echo "nproc:$(nproc), parallel_integration_tests:${PARALLEL_INTEGRATION_TESTS_NUM}"
start_telemetry
# Run all direct kernel boot (Device Tree) test cases in mod `parallel`,
# `sequential`, ACPI cases and the tests of the optional features. The
# `common_tests` profile filter covers all of these, and the per-mod
# `threads-required = 'num-test-threads'` override on `common_sequential`
# enforces serial scheduling within the run.
time cargo nextest run -p cloud-hypervisor $test_features --profile common_tests --no-tests=pass --test-threads="${PARALLEL_INTEGRATION_TESTS_NUM}" "$test_filter" -- ${test_binary_args[*]}
