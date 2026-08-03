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

An operation target needs a valid image that the harness can build in process
and that reads back as zeroes, which is what `DiskFormat::template` returns. A
format without one gets no operation target and so no shadow model, which
means nothing anywhere can catch it returning the *wrong bytes*: an engine
that loses or misplaces a guest write passes every other check the framework
makes.

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

add the targets, the image target always and the operation target when there
is a template, each a single call into the framework, and register them in
`fuzz/Cargo.toml`.

