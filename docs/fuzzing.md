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

An operation target needs a valid image that the harness can build in process
and that reads back as zeroes, which is what `DiskFormat::template` returns. A
format without one gets no operation target and so no shadow model, which
means nothing anywhere can catch it returning the *wrong bytes*: an engine
that loses or misplaces a guest write passes every other check the framework
makes.

### Operation targets and the shadow model

Because that image is valid and starts out reading as zeroes, the framework
keeps a shadow model of the disk contents and compares every read against it,
which turns a silent offset translation bug into a crash. Both target families
also check the trait contract itself: an accepted operation completes exactly
once and carries its own user data, a rejected operation does not complete at
all, a completion never reports more bytes than were requested, and a format
with a fixed capacity neither changes its reported size without a successful
