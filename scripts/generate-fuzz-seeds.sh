#!/usr/bin/env bash
# Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Generates seed corpora for the disk image fuzz targets.

set -eufo pipefail

CORPUS_DIR=${1:-fuzz/corpus}
QEMU_IMG=${QEMU_IMG:-qemu-img}
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Builds a raw image with a few data regions.
make_source() {
    local source="$WORK_DIR/source.raw"

    truncate -s 1M "$source"
    printf 'cloud-hypervisor disk image fuzz seed' |
        dd of="$source" bs=1 conv=notrunc status=none
    dd if=/dev/urandom of="$source" bs=4096 count=4 seek=3 conv=notrunc status=none
    dd if=/dev/urandom of="$source" bs=4096 count=4 seek=100 conv=notrunc status=none
    dd if=/dev/urandom of="$source" bs=4096 count=1 seek=255 conv=notrunc status=none

    echo "$source"
}

# qcow2 seeds: v2 and v3, compressed, 512 byte clusters, preallocated
# metadata and empty.
seed_qcow2() {
    local source=$1
    local out="$CORPUS_DIR/disk_qcow2"

    mkdir -p "$out"
    "$QEMU_IMG" convert -O qcow2 "$source" "$out/v3.qcow2"
    "$QEMU_IMG" convert -O qcow2 -o compat=0.10 "$source" "$out/v2.qcow2"
    "$QEMU_IMG" convert -O qcow2 -c "$source" "$out/compressed.qcow2"
    "$QEMU_IMG" convert -O qcow2 -o cluster_size=512 "$source" "$out/cluster512.qcow2"
    "$QEMU_IMG" convert -O qcow2 -o preallocation=metadata "$source" "$out/prealloc.qcow2"
    "$QEMU_IMG" create -f qcow2 "$out/empty.qcow2" 1M >/dev/null
}

# VHDX seeds. The fixed subformat exercises the rejection path.
seed_vhdx() {
    local source=$1
    local out="$CORPUS_DIR/disk_vhdx"

    mkdir -p "$out"
    # The smallest block size keeps the seeds small.
    local opts=subformat=dynamic,block_size=1M

    "$QEMU_IMG" convert -O vhdx -o "$opts" "$source" "$out/dynamic.vhdx"
    "$QEMU_IMG" convert -O vhdx -o subformat=fixed,block_size=1M "$source" \
        "$out/fixed.vhdx"
    "$QEMU_IMG" create -f vhdx -o "$opts" "$out/empty.vhdx" 1M >/dev/null
}

main() {
    if ! command -v "$QEMU_IMG" >/dev/null; then
        echo "error: $QEMU_IMG not found, install qemu-utils" >&2
        exit 1
    fi

    local source
    source=$(make_source)

    seed_qcow2 "$source"
    seed_vhdx "$source"

    echo "seed corpora written under $CORPUS_DIR"
    du -sh "$CORPUS_DIR"
}

main
