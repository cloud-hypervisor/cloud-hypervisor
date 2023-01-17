# Heap profiling

Cloud Hypervisor supports generating a profile using
[dhat](https://docs.rs/dhat/latest/dhat/) of the heap allocations made during
the runtime of the process.

## Building a suitable binary

This adds the symbol information to the release binary but does not otherwise
affect the performance.

```
$ cargo build --profile profiling --features "dhat-heap"
```

## Generating output

Cloud Hypervisor can then be run as usual. However it is necessary to run with `--seccomp false` as the profiling requires extra syscalls.

```
$ target/profiling/cloud-hypervisor \
        --kernel ~/src/linux/vmlinux \
        --pmem file=~/workloads/focal.raw \
        --cpus boot=1 --memory size=1G \
        --cmdline "root=/dev/pmem0p1 console=ttyS0" \
        --serial tty --console off \
        --api-socket /tmp/api1 \
        --seccomp false
```

When the VMM exits a message like the following will be shown:

```
dhat: Total:     384,582 bytes in 3,512 blocks
dhat: At t-gmax: 133,885 bytes in 379 blocks
dhat: At t-end:  12,160 bytes in 20 blocks
dhat: The data has been saved to dhat-heap.json, and is viewable with dhat/dh_view.html
```

The JSON output can then be uploaded to [the dh_view tool](https://nnethercote.github.io/dh_view/dh_view.html) for analysis.

