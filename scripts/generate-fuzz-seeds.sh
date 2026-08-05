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

# Writes the qcow2 backing chain seeds.
#
# The disk_qcow2_chain input is two images, so a seed is a length prefixed
# pair: [u32 LE top_len][top image][backing image]. The top image names its
# backing file by a plain relative name and the harness materializes the
# second half under that name, so the pair is self contained.
#
# Four chains: a qcow2 backing file and a raw one, one per dispatch arm in
# `BackingFile::new`; a compressed backing image, which is the only way to
# reach the compressed cluster arm of `Qcow2Backing::read_clusters`; and a
# three deep chain whose middle image names leaf.raw, the fixed raw file the
# harness provides, since a chain built only out of the two images of an
# input closes on itself; and one that does close on itself, which is what
# reaches the MAX_NESTING_DEPTH refusal.
seed_qcow2_chain() {
    local source=$1
    local out="$CORPUS_DIR/disk_qcow2_chain"
    local work="$WORK_DIR/chain"

    mkdir -p "$out" "$work"
    "$QEMU_IMG" convert -O qcow2 "$source" "$work/base.qcow2"
    "$QEMU_IMG" convert -O qcow2 -c "$source" "$work/compressed.qcow2"
    cp "$source" "$work/base.raw"
    truncate -s 1M "$work/leaf.raw"

    # The backing name is stored as given, so these run inside $work to keep
    # it relative.
    (
        cd "$work"
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b base.qcow2 qcow2-top.qcow2 1M
        "$QEMU_IMG" create -f qcow2 -F raw -b base.raw raw-top.qcow2 1M
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b compressed.qcow2 compressed-top.qcow2 1M
        # The top image names backing.img, the file the harness writes the
        # backing half to, and that half names leaf.raw, which terminates the
        # chain: top, backing image, raw leaf.
        "$QEMU_IMG" create -f qcow2 -F raw -b leaf.raw nested.qcow2 1M
        cp nested.qcow2 backing.img
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b backing.img nested-top.qcow2 1M
        # Both halves name backing.img, which is where the harness writes the
        # second half, so the chain never terminates and the engine refuses
        # it at MAX_NESTING_DEPTH (block/src/formats/qcow/util.rs:13).
        "$QEMU_IMG" create -f qcow2 -F qcow2 -b backing.img cyclic.qcow2 1M
    ) >/dev/null

    pack_chain "$work/qcow2-top.qcow2" "$work/base.qcow2" "$out/qcow2-backed"
    pack_chain "$work/raw-top.qcow2" "$work/base.raw" "$out/raw-backed"
    pack_chain "$work/compressed-top.qcow2" "$work/compressed.qcow2" \
        "$out/compressed-backed"
    pack_chain "$work/nested-top.qcow2" "$work/nested.qcow2" "$out/nested"
    pack_chain "$work/cyclic.qcow2" "$work/cyclic.qcow2" "$out/cyclic"
}

# Concatenates a top image and a backing image into one seed, prefixed with
# the top image length as a little endian u32.
pack_chain() {
    python3 -c 'import struct, sys
top = open(sys.argv[1], "rb").read()
backing = open(sys.argv[2], "rb").read()
open(sys.argv[3], "wb").write(struct.pack("<I", len(top)) + top + backing)' "$1" "$2" "$3"
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

# Writes the VMDK seeds. Only the descriptor is a seed: it is what the disk
# path points at, and the fuzz harness supplies the extent files itself.
seed_vmdk() {
    local source=$1
    local out="$CORPUS_DIR/disk_vmdk"
    local work="$WORK_DIR/vmdk"

    mkdir -p "$out" "$work"
    "$QEMU_IMG" convert -O vmdk -o subformat=monolithicFlat "$source" "$work/flat.vmdk"
    "$QEMU_IMG" convert -O vmdk -o subformat=twoGbMaxExtentFlat "$source" "$work/two.vmdk"
    cp "$work/flat.vmdk" "$out/monolithic.vmdk"
    cp "$work/two.vmdk" "$out/twogb.vmdk"

    # A descriptor naming its extent by absolute path. The engine resolves an
    # absolute extent name from the filesystem root and deliberately does not
    # confine it, which is a separate arm of the extent opener
    # (block/src/formats/vmdk/flat.rs:141 and :190) and is unreachable with any
    # real path: the only absolute path a fuzzer may open is one inside its own
    # scratch directory, whose name carries the process id. The harness expands
    # the /@fuzz-scratch@ placeholder into that directory before the parser
    # reads the file.
    cat >"$out/absolute.vmdk" <<'DESCRIPTOR'
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW 2048 FLAT "/@fuzz-scratch@/image-flat.vmdk" 0

# The Disk Data Base
#DDB
ddb.virtualHWVersion = "4"
DESCRIPTOR
}

# Writes the image type detection seeds: every image the per format seed
# functions produced, in one directory. `detect_image_type` sniffs all four
# formats in sequence, so its corpus wants an example of each, and a mutation
# of one format's image is exactly what makes the sniffer look at the next
# probe in the chain.
seed_detect() {
    local out="$CORPUS_DIR/disk_detect"
    local dir name

    mkdir -p "$out"
    for dir in "$CORPUS_DIR"/disk_qcow2 "$CORPUS_DIR"/disk_vhd \
        "$CORPUS_DIR"/disk_vhdx "$CORPUS_DIR"/disk_vmdk; do
        [ -d "$dir" ] || continue
        # This script runs with globbing off, so the file list comes from
        # find. The names are prefixed with the format they came from, both
        # to make the origin obvious and so that two formats cannot collide.
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
