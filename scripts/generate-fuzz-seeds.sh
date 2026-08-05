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

# qcow2 chain seeds, each [u32 LE top_len][top image][backing image]: qcow2,
# raw and compressed backing files, a chain ending in leaf.raw, and a cycle.
seed_qcow2_chain() {
    local source=$1
    local out="$CORPUS_DIR/disk_qcow2_chain"
    local work="$WORK_DIR/chain"

    mkdir -p "$out" "$work"
    "$QEMU_IMG" convert -O qcow2 "$source" "$work/base.qcow2"
    "$QEMU_IMG" convert -O qcow2 -c "$source" "$work/compressed.qcow2"
    cp "$source" "$work/base.raw"
    truncate -s 1M "$work/leaf.raw"

    # Run in $work so the backing names stay relative.
    (
        cd "$work"
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b base.qcow2 qcow2-top.qcow2 1M
        "$QEMU_IMG" create -f qcow2 -F raw -b base.raw raw-top.qcow2 1M
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b compressed.qcow2 compressed-top.qcow2 1M
        # top -> backing.img -> leaf.raw
        "$QEMU_IMG" create -f qcow2 -F raw -b leaf.raw nested.qcow2 1M
        cp nested.qcow2 backing.img
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b backing.img nested-top.qcow2 1M
        # A cycle through backing.img, refused at MAX_NESTING_DEPTH.
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b backing.img cyclic.qcow2 1M
    ) >/dev/null

    pack_chain "$work/qcow2-top.qcow2" "$work/base.qcow2" "$out/qcow2-backed"
    pack_chain "$work/raw-top.qcow2" "$work/base.raw" "$out/raw-backed"
    pack_chain "$work/compressed-top.qcow2" "$work/compressed.qcow2" \
        "$out/compressed-backed"
    pack_chain "$work/nested-top.qcow2" "$work/nested.qcow2" "$out/nested"
    pack_chain "$work/cyclic.qcow2" "$work/cyclic.qcow2" "$out/cyclic"
}

# Writes [u32 LE top_len][top image][backing image] to $3.
pack_chain() {
    python3 -c 'import struct, sys
top = open(sys.argv[1], "rb").read()
backing = open(sys.argv[2], "rb").read()
open(sys.argv[3], "wb").write(struct.pack("<I", len(top)) + top + backing)' "$1" "$2" "$3"
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

# VHD seeds. The dynamic subformat exercises the rejection path.
seed_vhd() {
    local source=$1
    local out="$CORPUS_DIR/disk_vhd"

    mkdir -p "$out"
    "$QEMU_IMG" convert -O vpc -o subformat=fixed "$source" "$out/fixed.vhd"
    "$QEMU_IMG" convert -O vpc -o subformat=dynamic "$source" "$out/dynamic.vhd"
}

# VMDK seeds. The harness supplies the extent files.
seed_vmdk() {
    local source=$1
    local out="$CORPUS_DIR/disk_vmdk"
    local work="$WORK_DIR/vmdk"

    mkdir -p "$out" "$work"
    "$QEMU_IMG" convert -O vmdk -o subformat=monolithicFlat "$source" "$work/flat.vmdk"
    "$QEMU_IMG" convert -O vmdk -o subformat=twoGbMaxExtentFlat "$source" "$work/two.vmdk"
    cp "$work/flat.vmdk" "$out/monolithic.vmdk"
    cp "$work/two.vmdk" "$out/twogb.vmdk"
}

# disk_detect seeds: the seeds of every image target.
seed_detect() {
    local out="$CORPUS_DIR/disk_detect"
    local dir name

    mkdir -p "$out"
    for dir in "$CORPUS_DIR"/disk_qcow2 "$CORPUS_DIR"/disk_vhd \
        "$CORPUS_DIR"/disk_vhdx "$CORPUS_DIR"/disk_vmdk; do
        [ -d "$dir" ] || continue
        # Globbing is off, so list with find. Prefix names with their format.
        while IFS= read -r name; do
            cp "$name" "$out/$(basename "$dir")-$(basename "$name")"
        done < <(find "$dir" -maxdepth 1 -type f)
    done
}

main() {
    if ! command -v "$QEMU_IMG" >/dev/null; then
        echo "error: $QEMU_IMG not found, install qemu-utils" >&2
        exit 1
    fi

    local source
    source=$(make_source)

    seed_qcow2 "$source"
    seed_qcow2_chain "$source"
    seed_vhd "$source"
    seed_vhdx "$source"
    seed_vmdk "$source"
    seed_detect

    echo "seed corpora written under $CORPUS_DIR"
    du -sh "$CORPUS_DIR"
}

main
