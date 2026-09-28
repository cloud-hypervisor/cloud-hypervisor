# Disk image fuzzing

The `disk_*` fuzz targets exercise the `block` crate's disk image engine,
from image parsing to the `AsyncFullDiskFile` and `AsyncIo` contract. The
shared framework is in `fuzz/src/disk_engine`. See [fuzzing.md](fuzzing.md)
for installing `cargo fuzz`.

| Target | Input | Covers |
| ------ | ----- | ------ |
| `disk_qcow2`, `disk_vhd`, `disk_vhdx`, `disk_vmdk` | an image | parsers |
| `disk_qcow2_ops`, `disk_vhdx_ops`, `disk_vmdk_ops` | an op program | I/O paths |
| `disk_qcow2_chain` | two qcow2 images | backing chains |
| `disk_detect` | an image of any format | image type validation |

## Running

The image targets need seeds, which `scripts/generate-fuzz-seeds.sh` writes
with `qemu-img`, and a `-max_len` of at least the largest seed. Without it
libFuzzer truncates inputs to 1 MiB, which removes the metadata of most
images:

```
scripts/generate-fuzz-seeds.sh
cargo fuzz run disk_qcow2 -j `nproc` -- -max_len=2097152 \
    -dict=fuzz/dictionaries/qcow2.dict
cargo fuzz run disk_vhd -j `nproc` -- -max_len=4194304 \
    -dict=fuzz/dictionaries/vhd.dict
cargo fuzz run disk_vhdx -j `nproc` -- -max_len=16777216 \
    -dict=fuzz/dictionaries/vhdx.dict
cargo fuzz run disk_vmdk -j `nproc` -- -max_len=1048577 \
    -dict=fuzz/dictionaries/vmdk.dict
cargo fuzz run disk_qcow2_chain -j `nproc` -- -max_len=4194312 \
    -dict=fuzz/dictionaries/qcow2_chain.dict
cargo fuzz run disk_detect -j `nproc` -- -max_len=16777216
```

The operation targets need neither:

```
cargo fuzz run disk_qcow2_ops -j `nproc`
```

Put `TMPDIR` on tmpfs: the path backed targets and the qcow2 templates fsync
files there.

## Operation targets

An operation target runs its program against a blank template and checks
every read against a shadow model of the disk. Every target also checks that
an accepted op completes exactly once, a rejected op never completes, no op
transfers more than it asked for, and the capacity only changes on resize.

Templates are built in process and are identical on every run, so a crash
reproduces from its input alone: qcow2 uses the `block` crate's image writer,
VHDX a table of the non-zero bytes of a `qemu-img` image, and flat VMDK a two
extent descriptor. A second qcow2 template has more L2 tables than the engine
caches, for the `Sweep` op to evict. Each template has a self test that it
opens, has its pinned size and reads back as zeroes. Fixed VHD has no
operation target, as its I/O is a bounds check in front of `preadv`.

## Image targets

`disk_vhd` and `disk_vhdx` use mutators that restore the format signatures
and recompute the checksums, so mutations reach the parser. One mutation in
eight skips each repair, keeping both rejection paths reachable. Inputs
without the format's magic are still opened, but few are kept in the corpus.

## Path backed targets

qcow2 backing files and VMDK extents are host paths. Production only opens
them with `backing_files=on` and treats such images as trusted, but
`disk_qcow2_chain` and `disk_vmdk` open fuzzed names. Both admit only plain
names inside a scratch directory and confine the process to it with Landlock,
refusing every input where Landlock is unavailable.

Confinement starts before libFuzzer creates threads or fork workers, avoiding
false LeakSanitizer reports and keeping workers sandboxed. Runner inputs and
temporary storage are allowed separately from image paths, so native and
OSS-Fuzz runs work without weakening image confinement.

## Adding a format

Implement `DiskFormat` in `fuzz/src/disk_engine/formats/` and set the
constants that hold for the format. Add a `disk_<format>` target calling
`fuzz_image` and, if the format has a template, a `disk_<format>_ops` target
calling `fuzz_program`. Register both in `fuzz/Cargo.toml`, then add seeds to
`scripts/generate-fuzz-seeds.sh` and a dictionary to `fuzz/dictionaries/`.
