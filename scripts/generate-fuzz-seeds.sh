#!/usr/bin/env bash
# Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Generates seed corpora for the disk image fuzz targets.
#
# A disk_<format> target takes its input as the disk image itself, so a seed
# is just an image of that format and qemu-img output can be used unmodified.
# Without seeds libFuzzer starts from 4 KiB of random bytes and rarely gets
# past a format header check.

set -eufo pipefail

CORPUS_DIR=${1:-fuzz/corpus}
QEMU_IMG=${QEMU_IMG:-qemu-img}
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Builds a raw image holding a few data regions, so that images converted from
# it carry populated metadata tables rather than being entirely sparse.
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

# Writes the qcow2 seeds, covering both header versions, compression, a
# non-default cluster size, preallocated metadata and an empty image.
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

# Writes the VHDX seeds. Cloud Hypervisor reads dynamic VHDX, so the fixed
# subformat is here to exercise the rejection path.
seed_vhdx() {
    local source=$1
    local out="$CORPUS_DIR/disk_vhdx"

    mkdir -p "$out"
    # The smallest block size the format allows keeps the seeds close to the
    # 8 MiB an empty VHDX already costs.
    local opts=subformat=dynamic,block_size=1M

    "$QEMU_IMG" convert -O vhdx -o "$opts" "$source" "$out/dynamic.vhdx"
    "$QEMU_IMG" convert -O vhdx -o subformat=fixed,block_size=1M "$source" \
        "$out/fixed.vhdx"
    "$QEMU_IMG" create -f vhdx -o "$opts" "$out/empty.vhdx" 1M >/dev/null
}

# Writes the VHD seeds. Cloud Hypervisor reads the fixed subformat only, so
# the dynamic one is here to exercise the rejection path.
seed_vhd() {
    local source=$1
    local out="$CORPUS_DIR/disk_vhd"

    mkdir -p "$out"
    "$QEMU_IMG" convert -O vpc -o subformat=fixed "$source" "$out/fixed.vhd"
    "$QEMU_IMG" convert -O vpc -o subformat=dynamic "$source" "$out/dynamic.vhd"
}

main() {
    if ! command -v "$QEMU_IMG" >/dev/null; then
        echo "error: $QEMU_IMG not found, install qemu-utils" >&2
        exit 1
    fi

    local source
    source=$(make_source)

    seed_qcow2 "$source"
    seed_vhd "$source"
    seed_vhdx "$source"

    echo "seed corpora written under $CORPUS_DIR"
    du -sh "$CORPUS_DIR"
}

main
