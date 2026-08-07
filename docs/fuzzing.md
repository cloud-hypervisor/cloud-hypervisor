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

One target sits outside that scheme. `disk_detect` drives
`block::detect_image_type`, the sniffer `factory::open_disk` runs before it
chooses a parser. Its input space is every format at once, so it cannot live
inside a per format target: an input that finds a new edge in the VHD sniffer
says nothing about the VHDX parser, and keeping it in the `disk_vhdx` corpus
only spends that target's budget on images it can never open. Its seed corpus
is the union of the per format seeds, which
`scripts/generate-fuzz-seeds.sh` writes to `fuzz/corpus/disk_detect`:

```
cargo fuzz run disk_detect -j `nproc` -- -max_len=16777216
```

The formats covered today:

| Format | Image target | Operation target |
| ------ | ------------ | ---------------- |
| qcow2 | `disk_qcow2` | `disk_qcow2_ops` |
| fixed VHD | `disk_vhd` | none |

The sniffer in front of them all is fuzzed by `disk_detect`, and qcow2 backing
chains by `disk_qcow2_chain`.

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

### QCOW2 backing chains

A qcow2 image may name a backing file, and `disk_qcow2` reaches none of the
code that follows one: it opens every image with `backing_files: false`, which
leaves `BackingFile::new`, the `Raw` versus `Qcow2` dispatch, all of
`block/src/formats/qcow/backing.rs`, the `MAX_NESTING_DEPTH` recursion and the
copy on write from backing arm of `deallocate_bytes` unreachable.
`disk_qcow2_chain` covers them.

Its input is two images, because a chain needs a backing image and that image
has to be fuzzer controlled too, or the target would only ever see a valid
backing file:

```text
[u32 LE top_len][top_len bytes: the image][the rest: the backing image]
```

The harness writes the backing half into its scratch directory, under the name
the top image asks for and under `backing.img`, then writes the top image and
opens it with backing files enabled. A backing image that itself names a
backing file is what reaches the nested chain code, and one that names
`backing.img`, the file it is itself written to, recurses until the nesting
limit stops it. The directory also holds `leaf.raw`, a fixed empty file: two
fuzzer images can only build a chain that closes on itself, which the nesting
limit always refuses, so a chain that reads through three levels needs a third
file, and any file is a valid raw backing.
#### The sandbox

The backing file is named by *path*, and the engine resolves a relative name
against the directory of the image that stores it with a plain `Path::join`,
which follows `..` straight out of that directory, then opens it. A corpus
entry could therefore name any file the fuzzer can reach. That is why backing
files were excluded from the framework until this target existed, and it is
why the target needs two independent protections.

The first is a name guard in the harness. It parses `backing_file_offset` and
`backing_file_size` out of the raw input bytes itself, exactly as
`QcowHeader::new` does, because the decision has to be made before the `block`
crate opens anything, and it refuses the input unless the name is a single
`Component::Normal`: no absolute path, no `..`, no `.`, no subdirectory, no
embedded NUL. It is applied to *both* images, since the backing image's own
header can name a further file. The policy is refusal rather than clamping the
name to a safe value, for the same reason the VMDK extent guard refuses: this
is a safety check, and a check that rewrites attacker controlled offsets in
place is more code whose bugs fail open, while a refusal fails closed. The
mutation budget is protected instead by materializing the backing image under
whatever plain name the input asks for, so a mutation of the name field still
opens something.

The second is Landlock, applied once per process before the first iteration,
allowing writes only under the scratch directory and the fuzzer's own corpus
and artifact directories, and reads only under those, `/proc` and the system
library directories. It fails closed: if the kernel has no Landlock, the
target refuses every input rather than running unconfined. This second belt
exists because, unlike the VMDK extent path, the engine takes no `openat2`
`RESOLVE_BENEATH` precaution for a qcow2 backing file, deliberately, so the
harness guard would otherwise be the only thing between a corpus entry and a

#### Why it is a separate target

`Qcow2` declares `PUNCH_HOLE_READS_ZEROES`, which is true only for an image
without a backing file: with one, a discarded cluster reads *through* to the
backing data, so the shadow model would report data corruption that is not
there. `disk_qcow2_chain` therefore runs the fixed op program with the model
off, and `OpenConfig::backing` is not fuzzer selectable, so `fuzz_program`
cannot enable backing files under the model even for a format whose template
changes. `disk_qcow2` and `disk_qcow2_ops` are untouched.

### Keeping the corpus openable

A seeded corpus is not enough on its own, because libFuzzer keeps every input
that found a new edge, including the ones that only found new edges in the
rejection path. Measured on a campaign corpus, that is what the disk targets
had become: 6 of 764 `disk_vhd` entries opened (0.8%), 17 of 872 `disk_vhdx`
(1.9%) and 131 of 1198 `disk_vmdk` (10.9%). For VHD, 634 of the 666 rejections
were the `conectix` cookie alone, so nearly the whole mutation budget was
spent on byte strings that could never reach the parser.

`DiskFormat::magic_ok` is the harness side mirror of the first check the
parser makes, and `fuzz_image` uses it to decide what to retain:

| Format | Magic | Parser check it mirrors |
| ------ | ----- | ----------------------- |
| qcow2 | `QFI\xfb` at offset 0 | `QcowHeader::new` |
| VHDX | `vhdxfile` at offset 0 | `FileTypeIdentifier::new` |
| fixed VHD | `conectix` at the start of the last 512 bytes | `VhdFooter::validate_fixed` |
| flat VMDK | a first line of `# Disk DescriptorFile` | `parse_header` |

An input that fails it is still opened, so the parser's own rejection path is
still fuzzed, but it is returned as `Corpus::Reject` and never retained. It
cannot be a blanket rejection, because a parser does real work before it looks
at the magic: `VhdFooter::new` queries the device size, does the length
arithmetic that finds the footer and computes the footer checksum, and
`VhdxHeader::new` reads and checksums both headers, all before their signature
tests. Those paths are reached by exactly the inputs that then fail the magic,
and the cost of dropping them was measured per region on the campaign
corpora: 7 `block` regions lost for `disk_vhd`, 3 for `disk_vhdx`, 9 for
`disk_vmdk` and 2 for `disk_qcow2`.

So the harness keeps a bounded number of them instead: 8 distinct inputs per
length class, per process, where the class is the binary magnitude of the
input length. The budget is per class rather than flat because what the code
in front of a magic check branches on is the length, and the shortest inputs
are the rarest: a flat budget of 64 still lost the eight byte read failure in
`FileTypeIdentifier::new` and the four byte length check in the VMDK
descriptor reader. With the per class budget the retained subsets of the
campaign corpora, 110 of 764 entries for `disk_vhd`, 265 of 872 for
`disk_vhdx`, 1056 of 1198 for `disk_vmdk` and 1633 of 2129 for `disk_qcow2`,
cover every region the full corpora cover.

A checksum protected format needs one more thing: a custom mutator. `disk_vhd`
and `disk_vhdx` both have one, because their parsers verify a signature and a
checksum before they look at anything else, so a plain byte mutation is
rejected at open and the fuzzer never reaches the structure it changed. Each
target runs `libfuzzer_sys::fuzzer_mutate` and then restores the identifying
bytes and recomputes the checksums over the result:

| Target | What it restores | What it repairs | Why |
| ------ | ---------------- | --------------- | --- |
| `disk_vhdx` | the `vhdxfile` file type identifier and the `head` and `regi` signatures | the CRC-32C of both headers and both region tables | `VhdxHeader::new` refuses an image whose signatures or four checksums do not match |
| `disk_vhd` | the `conectix` cookie in the last 512 bytes | the fixed VHD footer checksum, big endian | `VhdFooter::validate_fixed` refuses an image whose cookie or footer checksum does not match |

The order matters: the identifying bytes sit inside the checksummed areas, so
they are written first and the checksum is computed over them.

The offsets and the algorithms are taken from the parser under test rather
than from the specification, so the mutator and the code it feeds cannot
disagree. Repair is necessary but not sufficient: the other validated fields
still reject a mutation on their own merits. Neither repair is unconditional,
so both rejection branches stay reachable and stay separable. One mutation in
eight keeps its mutated magic with the checksums repaired, which is the only
way to reach the signature branch with otherwise valid structures, and a
different one in eight keeps its mutated checksum with the magic restored,
which is the only way to reach the checksum branch at all, since the magic is
tested first. Both targets still take arbitrary bytes, since the corpus
holds images the mutator never produced.

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
Override `magic_ok` with the format's identifying bytes, mirroring the first
check the parser makes, so the image target does not retain inputs that can
never reach it. Then
add the targets, the image target always and the operation target when there
is a template, each a single call into the framework, and register them in
`fuzz/Cargo.toml`.

Finally give the image target something to start from: a `seed_<format>`
function in `scripts/generate-fuzz-seeds.sh` and, when the format is magic
heavy, a dictionary in `fuzz/dictionaries/`. If the parser checksums part of
the image, add a repair function next to the adapter and a `fuzz_mutator!`
that restores the magic and calls it, as `disk_vhd` and `disk_vhdx` do.

Backing files are no longer left out, but they are confined: a fuzzed image
names its backing file by path, so `disk_qcow2_chain` parses the name out of
the image itself, refuses anything but a plain file name in its scratch
directory, and confines the process with Landlock on top. A format that
resolves names out of the image needs both before it may open them.
