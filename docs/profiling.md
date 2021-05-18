# Profiling

`perf` can be used to profile the `cloud-hypervisor` binary but it is necessary to make some modifications to the build in order to produce a binary that gives useful results.

## Building a suitable binary

Modify the `Cargo.toml` file to add `debug = 1` to the `[profile.release]` block. It should look like this:

```
[profile.release]
lto = true
debug = 1
```

This adds the symbol information to the release binary but does not otherwise affect the performance.

The binary must also be built with frame pointers included so that the call graph can be captured by the profiler.

```
$ cargo clean && RUSTFLAGS='-C force-frame-pointers=y' cargo build --release
```

## Profiling

`perf` may then be used in the usual manner:

e.g.

```
$ perf record -g target/release/cloud-hypervisor \
        --kernel ~/src/linux/vmlinux \
        --pmem file=~/workloads/focal.raw \
        --cpus boot=1 --memory size=1G \
        --cmdline "root=/dev/pmem0p1 console=ttyS0" \
        --serial tty --console off \
        --api-socket=/tmp/api1
```

For analysing the samples:

```
$ perf report -g
```

If profiling with a network device attached either the TAP device must be already created and configured or the profiling must be done as root so that the TAP device can be created.
