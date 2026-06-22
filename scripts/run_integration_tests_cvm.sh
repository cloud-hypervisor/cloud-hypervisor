#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086,SC2154,SC1094
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "${BASH_SOURCE[0]}")/test-util.sh"

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"
mkdir -p "$WORKLOADS_DIR/junit"

process_common_args "$@"

if [ "$hypervisor" = "mshv" ]; then
    build_features="mshv,igvm,sev_snp"
else # kvm
    build_features="kvm,igvm,sev_snp,fw_cfg"
fi
test_features="--features $build_features"

JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.qcow2"
JAMMY_OS_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_IMAGE" ]; then
    echo "Missing: $JAMMY_OS_IMAGE — run: python3 scripts/fetch_workloads.py --test cvm"
    exit 1
fi

JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.raw"
JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $JAMMY_OS_IMAGE_NAME $JAMMY_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

JAMMY_OS_QCOW_ZLIB_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-zlib.qcow2"
JAMMY_OS_QCOW_ZLIB_FILE_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_QCOW_ZLIB_FILE_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_QCOW_ZLIB_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -c -f raw -O qcow2 -o compression_type=zlib \
        "$JAMMY_OS_RAW_IMAGE" $JAMMY_OS_QCOW_ZLIB_FILE_IMAGE_NAME
    popd || exit
fi

JAMMY_OS_QCOW_ZSTD_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-zstd.qcow2"
JAMMY_OS_QCOW_ZSTD_FILE_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_QCOW_ZSTD_FILE_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_QCOW_ZSTD_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -c -f raw -O qcow2 -o compression_type=zstd \
        "$JAMMY_OS_RAW_IMAGE" $JAMMY_OS_QCOW_ZSTD_FILE_IMAGE_NAME
    popd || exit
fi

JAMMY_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-backing-zstd.qcow2"
JAMMY_OS_QCOW_BACKING_ZSTD_FILE_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_QCOW_BACKING_ZSTD_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img create -f qcow2 \
        -b "$JAMMY_OS_QCOW_ZSTD_FILE_IMAGE" \
        -F qcow2 $JAMMY_OS_QCOW_BACKING_ZSTD_FILE_IMAGE_NAME
    popd || exit
fi

JAMMY_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-backing-uncompressed.qcow2"
JAMMY_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img create -f qcow2 \
        -b "$JAMMY_OS_IMAGE" \
        -F qcow2 $JAMMY_OS_QCOW_BACKING_UNCOMPRESSED_FILE_IMAGE_NAME
    popd || exit
fi

JAMMY_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0-backing-raw.qcow2"
JAMMY_OS_QCOW_BACKING_RAW_FILE_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_QCOW_BACKING_RAW_FILE_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img create -f qcow2 \
        -b "$JAMMY_OS_RAW_IMAGE" \
        -F raw $JAMMY_OS_QCOW_BACKING_RAW_FILE_IMAGE_NAME
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

cargo build --features $build_features --all --release --target "$BUILD_TARGET"

export RUST_BACKTRACE=1
time cargo nextest run -p cloud-hypervisor $test_features --profile common_cvm --no-tests=pass --test-threads=$(($(nproc) / 4)) "$test_filter" -- ${test_binary_args[*]}
RES=$?

exit $RES
