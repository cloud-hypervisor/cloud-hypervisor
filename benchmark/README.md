# Snapshot compression benchmarks

This directory measures end-to-end offloaded snapshot and eager restore time
for raw memory, LZ4, Zstd, and Intel QPL. Results are written to
`benchmark/results/results.csv`; detailed logs are stored under
`benchmark/results/logs/`.

## Complete benchmark

The top-level benchmark entry point performs the complete workflow: build the
binaries, download canonical test assets when missing, create the TAP device,
start and prepare the source VM, run snapshot and restore matrices, clean up,
and generate the KPI report.

```bash
cp benchmark/benchmark.env.example benchmark/benchmark.env
./benchmark/benchmark.sh --dry-run
./benchmark/benchmark.sh
```

At startup, `benchmark.sh` checks host packages, Rust 1.89 or newer, and static
QPL. If anything is missing, it runs `benchmark/setup.sh`; package and QPL
installation may request `sudo`. Set `AUTO_SETUP=0` to fail instead, or run the
setup explicitly:

```bash
./benchmark/setup.sh --check
./benchmark/setup.sh
```

Creating the TAP interface may invoke `sudo`. A source VM is stopped before
restore measurements to release its disk lock, and cleanup also runs when a
stage fails. The default matrix compares raw, LZ4, Zstd, and QPL hardware in
static/dynamic and synchronous/asynchronous modes with 1 MiB chunks. The
measured defaults use four software workers, 16 synchronous QPL workers, an
async snapshot depth of 16, and an async restore depth of eight. Configure
additional chunk sizes, workers, depths, and iterations in
`benchmark/benchmark.env`.

Guest preparation defaults to a 1536 MiB random working set in a 4 GiB VM.
This reduces the zero-heavy bias of untouched guest RAM while leaving space
for the operating system and staying below the usual `/dev/shm` capacity.

Before setup and build, the benchmark stops existing processes whose executable
is named `cloud-hypervisor` and removes stale benchmark sockets. Set
`CLEANUP_EXISTING_VMS=0` when other Cloud Hypervisor VMs must remain running.
The cleanup can also be run directly:

```bash
./benchmark/cleanup-vms.sh
```

The final report is written to `benchmark/results/kpi-report.csv`. It includes:

- Snapshot and restore median and p95 latency.
- Mean stored snapshot size in MiB.
- Compression ratio and storage savings relative to raw.
- Snapshot and restore speedup relative to the raw median.

QPL hardware requires an enabled IAA work queue. Set `WITH_QPL=0` and remove
QPL codecs from `CODECS` for an LZ4/Zstd-only run.

## Build

QPL is statically linked from `/usr/local` by default:

```bash
./benchmark/build.sh
```

Override the installation directories when necessary:

```bash
QPL_INCLUDE_DIR=/path/include QPL_LIB_DIR=/path/lib64 \
  ./benchmark/build.sh
```

Set `WITH_QPL=0` for an LZ4/Zstd-only build.

## Configure

```bash
cp benchmark/benchmark.env.example benchmark/benchmark.env
```

Every script also accepts the variables directly in its environment. Set
`BENCHMARK_CONFIG=/path/to/file` to use a configuration outside this directory.

## Start the source VM

Download the repository's canonical x86_64 test kernel and Jammy image:

```bash
./benchmark/download-assets.sh
```

Set the direct-boot kernel and disk image. The lifecycle script copies the disk
by default, generates and attaches a NoCloud configuration disk, starts the VM
with shared memory, and records its PID and logs under `benchmark/results/`:

```bash
KERNEL_PATH=$HOME/workloads/vmlinux \
DISK_PATH=$HOME/workloads/jammy-server-cloudimg-amd64.raw \
MEMORY_SIZE=4G VCPUS=4 \
  ./benchmark/source-vm.sh start
```

For a qcow2 image, the image type is inferred from its filename:

```bash
KERNEL_PATH=$HOME/workloads/vmlinux \
DISK_PATH=$HOME/workloads/jammy-server-cloudimg-amd64.qcow2 \
  ./benchmark/source-vm.sh start
```

Additional Cloud Hypervisor arguments go after `--`. For example, with an
existing TAP device:

```bash
KERNEL_PATH=$HOME/workloads/vmlinux \
DISK_PATH=$HOME/workloads/jammy-server-cloudimg-amd64.raw \
  ./benchmark/source-vm.sh start -- \
  --net tap=tap0,mac=12:34:56:78:90:ab
```

One simple host TAP setup is:

```bash
sudo ip tuntap add tap0 mode tap user "$USER"
sudo ip addr add 192.168.2.1/25 dev tap0
sudo ip link set tap0 up
```

The guest must have an address and route compatible with that TAP network.
Cloud images may require cloud-init or their existing static-network setup.

Inspect lifecycle state and logs with:

```bash
./benchmark/source-vm.sh status
tail -f benchmark/results/logs/source-serial.log
```

## Prepare and pause the VM

`prepare-memory.sh` waits for SSH, writes a resident file under `/dev/shm`, and
pauses the VM. A repeating pattern approximates highly compressible application
memory. The canonical test image uses the development credentials
`cloud/cloud123`; password authentication requires `sshpass`:

```bash
GUEST_SSH_TARGET=cloud@192.168.2.2 \
SSH_PASSWORD=cloud123 \
WORKING_SET_MIB=1536 MEMORY_PATTERN=random \
  ./benchmark/prepare-memory.sh
```

For a guest configured with a public key, set `SSH_KEY` instead of
`SSH_PASSWORD`.

Other useful patterns are:

```bash
# Best-case compression
MEMORY_PATTERN=zero ./benchmark/prepare-memory.sh

# Worst-case compression
MEMORY_PATTERN=random ./benchmark/prepare-memory.sh
```

When the guest workload is already prepared manually, pause it directly:

```bash
./benchmark/source-vm.sh pause
```

Resume or stop it with:

```bash
./benchmark/source-vm.sh resume
./benchmark/source-vm.sh stop
```

The snapshot matrix uses `preserve_source=on`, so the source remains paused and
the same memory state is used for every measured configuration.

## Run snapshot benchmarks

```bash
RESET_RESULTS=1 ./benchmark/run-matrix.sh snapshot
```

The measured interval begins immediately before `send-migration` and ends after
the daemon has compressed, written, synchronized, and acknowledged the
snapshot.

## Run restore benchmarks

Stop the source VM before restore testing so it releases its disk-image locks.
If the source must remain alive, copy its disks while paused and update the
saved migration configuration to use those copies.

The restore matrix uses iteration 1 of every generated snapshot by default:

```bash
./benchmark/run-matrix.sh restore
```

Set `RESTORE_SNAPSHOT_ITERATION` to select another snapshot. `COLD_CACHE=1`
drops the host page cache before each restore and therefore requires running as
root. The measured interval includes decompression, memfd population, VM-state
restore, and the completion or resume handshake.

To limit disk usage, snapshot benchmarking retains only the iteration selected
by `RESTORE_SNAPSHOT_ITERATION`. Set `KEEP_ALL_SNAPSHOTS=1` to retain every
measured snapshot.

## Run one case

```bash
./benchmark/snapshot.sh qpl-hardware-static 1048576 8 1

./benchmark/restore.sh \
  benchmark/results/snapshots/qpl-hardware-static-c1048576-w8-i1 \
  qpl-hardware-static 1048576 8 1
```

Use `qpl-hardware-static` and `qpl-hardware-dynamic` to compare fixed and
dynamic Deflate Huffman coding on IAA. The legacy `qpl-hardware` name remains
an alias for dynamic coding so existing snapshots can still be restored.
Append `-async` to either explicit hardware codec to use a reusable rolling
pool of asynchronously submitted QPL jobs. `SOFTWARE_WORKER_COUNTS` and
`QPL_SYNC_WORKER_COUNTS` control host workers. `QPL_ASYNC_SNAPSHOT_DEPTHS` and
`QPL_ASYNC_RESTORE_DEPTHS` independently control maximum in-flight IAA jobs.
The daemon refills each completed slot immediately, bounds submission and
completion waits, reuses buffers, and divides the configured budget across
independent VM memory slots. `NUMA_NODE` binds the VM, receiver, and daemon to
the IAA-local node.

Raw snapshots ignore chunk size and worker count:

```bash
./benchmark/snapshot.sh raw 0 1 1
```

## Summarize

```bash
./benchmark/summarize.py benchmark/results/results.csv
```

The summary reports run count, mean, median, p95, minimum, and maximum latency.
Generate the raw-relative KPI report independently with:

```bash
./benchmark/report.py \
  benchmark/results/results.csv \
  benchmark/results/kpi-report.csv
```

Use at least five measured iterations. Compare codecs first with identical
chunk sizes and worker counts, then run a second matrix using each codec's
best-performing settings.