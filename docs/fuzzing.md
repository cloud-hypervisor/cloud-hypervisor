# Fuzzing in Cloud Hypervisor

Cloud Hypervisor uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) for fuzzing individual components.

The fuzzers are in the `fuzz/fuzz_targets` directory

## Preparation

Switch to nightly: 

````
rustup override set nightly
````

Install `cargo fuzz`: 

```
cargo install cargo-fuzz
```

## Running the fuzzers

e.g. To run the `block` fuzzer using all available CPUs:

```
cargo fuzz run block -j `nproc`
```

## Adding a new fuzzer

```
cargo fuzz add <new_fuzzer>
```

Inspiration for fuzzers can be found in [crosvm](https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/master/fuzz/)

## Fuzzing disk image formats

The `disk_*` targets share a format agnostic framework in
`fuzz/src/disk_engine`. It fuzzes the disk image engine of the `block`
crate: everything between the point where untrusted image bytes are parsed
(`factory::open_disk` and the per format constructors) and the trait contract
the rest of the VMM consumes (`disk_file::AsyncFullDiskFile` and
`async_io::AsyncIo`). Virtio request parsing sits above that boundary and is
covered by the `block` target instead.

Every format has two targets, because the two interesting input spaces do not
mix well in a single one:

| Target | Input | What it finds |
| ------ | ----- | ------------- |
| `disk_<format>` | the whole input is the disk image | parser bugs: headers, tables, region descriptors |
| `disk_<format>_ops` | an operation program run against a valid image | engine bugs: offset translation, allocation, discard, resize |

The formats covered today:

| Format | Image target | Operation target |
| ------ | ------------ | ---------------- |
| qcow2 | `disk_qcow2` | `disk_qcow2_ops` |
| fixed VHD | `disk_vhd` | none |

An operation target needs a valid image that the harness can build in process
and that reads back as zeroes, which is what `DiskFormat::template` returns. A
format without one gets no operation target and so no shadow model, which
means nothing anywhere can catch it returning the *wrong bytes*: an engine
that loses or misplaces a guest write passes every other check the framework
makes.

Fixed VHD deliberately stays without one. `FixedVhdSync` is a bounds check in
front of `preadv`/`pwritev` on the image file, so a shadow model over it would
be asserting that the kernel implements `pwritev`, not that the `block` crate
is correct.

### Operation targets and the shadow model

```
cargo fuzz run disk_qcow2_ops -j `nproc`
```

None of them needs `-max_len` or a seed corpus: the input is an operation
program, not an image.

Corpus entries for `disk_<format>` are ordinary disk images, so anything
`qemu-img` can write is a usable seed. `scripts/generate-fuzz-seeds.sh` writes
a set of them per format, covering header versions, compression, cluster sizes
and preallocation:

```
scripts/generate-fuzz-seeds.sh
cargo fuzz run disk_qcow2 -j `nproc` -- -max_len=2097152 \
    -dict=fuzz/dictionaries/qcow2.dict
```

Seeds matter here: without them libFuzzer caps generated inputs at 4 KiB and
the target rarely gets past the header check. On a short run of the qcow2
target an empty corpus reached 479 edges, a single image reached 1605, and the
generated seeds with the dictionary reached 2073.

**Always pass `-max_len`.** Left to itself libFuzzer derives the limit from
the corpus but never above 1 MiB, and it truncates larger corpus entries to
that limit. A truncated image is a rejected image, so the target then fuzzes
nothing but its own rejection path. It is not hypothetical: `disk_vhdx` covers
268 edges without the flag and 1071 with it, because the VHDX layout places
its BAT region at 2 MiB and its metadata region at 3 MiB, so a parseable image
is 8 MiB when empty and 9 to 10 MiB once it holds data. A fixed VHD keeps its footer in the last 512
bytes, so truncation removes exactly the part that identifies the format. Use
at least the size of the largest seed:

```
cargo fuzz run disk_vhdx -j `nproc` -- -max_len=16777216 \
    -dict=fuzz/dictionaries/vhdx.dict
cargo fuzz run disk_vhd -j `nproc` -- -max_len=4194304 \
    -dict=fuzz/dictionaries/vhd.dict
```

A VMDK image is the text descriptor, not the data: the extents it names are
separate files that the harness provides in a scratch directory. Its inputs
are therefore small, and the limit is set accordingly:

```
cargo fuzz run disk_vmdk -j `nproc` -- -max_len=65536 \
    -dict=fuzz/dictionaries/vmdk.dict
```

The same limit is why `DiskFormat::MAX_IMAGE_LEN` is a per format constant:
the harness rejects anything larger, and a format whose metadata reaches far
into the file needs a bigger budget than the 8 MiB default.

`disk_<format>_ops` builds its own valid image, so it needs no corpus:

```
cargo fuzz run disk_qcow2_ops -j `nproc`
```

Because that image is valid and starts out reading as zeroes, the framework
keeps a shadow model of the disk contents and compares every read against it,
which turns a silent offset translation bug into a crash. Both target families
also check the trait contract itself: an accepted operation completes exactly
once and carries its own user data, a rejected operation does not complete at
all, a completion never reports more bytes than were requested, and a format
with a fixed capacity neither changes its reported size without a successful
resize nor transfers bytes beyond it. Two more invariants are opt in, because
they follow from a format's layout rather than from the trait contract: a
format whose data sits in the image file never advertises more capacity than
the file holds, and a format whose read path is all or nothing never completes
a read successfully with fewer bytes than were asked for.

### Running in OSS-Fuzz

Cloud Hypervisor is an [OSS-Fuzz](https://github.com/google/oss-fuzz) project,
which builds every target in `fuzz/fuzz_targets` and runs it continuously.
Staging these targets there - the `$OUT` layout, the seed corpora and the
dictionaries - is left to a later change. Two properties matter for a target
that runs there, and both are worth preserving when adding a format:

- A target must be self contained at run time. It may read nothing from the
  source tree, because only `$OUT` is shipped to the fuzzing machines. Images
  live in a memfd, or, for a format that has to be opened from a directory,
  in a scratch directory the target creates, and an `_ops` target builds its
  template once per process through a temporary file and keeps it in memory
  afterwards.
- A crash must reproduce in a fresh process from its input alone. A template
  image therefore has to be byte identical on every run, which rules out
  timestamps, random identifiers and anything else that varies per process.

Seed generation needs `qemu-img`, so an OSS-Fuzz build would have to install
`qemu-utils`; without it the targets still build and run, just unseeded.

### Adding a disk format

Implement `DiskFormat` in `fuzz/src/disk_engine/formats/`:

```rust
impl DiskFormat for MyFormat {
    const NAME: &'static str = "myformat";

    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        Ok(Box::new(MyDisk::new(file, config.direct)?))
    }

    fn template() -> Option<&'static [u8]> {
        // A freshly created image of this format, built once per process,
        // or None for a format the `block` crate cannot write.
    }
}
```

`path` is `Some` only when the format sets `NEEDS_PATH`, and a format whose
`template` returns `None` gets no operation target.

Set the associated constants that decide how the framework drives the format
and which invariants hold for it: `NEEDS_PATH`, `MAX_IMAGE_LEN`,
`COMPLETES_INLINE`, `PUNCH_HOLE_READS_ZEROES`, `FIXED_CAPACITY`,
`CAPACITY_FILE_TAIL` and `NO_SHORT_READS`. Each defaults to the value that
checks nothing, so a format only gains an invariant it can actually keep.
add the targets, the image target always and the operation target when there
is a template, each a single call into the framework, and register them in
`fuzz/Cargo.toml`.

