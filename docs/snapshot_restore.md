# Snapshot and Restore

The goal for the snapshot/restore feature is to provide the user with the
ability to take a snapshot of a previously paused virtual machine. This
snapshot can be used as the base for creating new identical virtual machines,
without the need to boot them from scratch. The restore codepath takes the
snapshot and creates the exact same virtual machine, restoring the previously
saved states. The new virtual machine is restored in a paused state, as it was
before the snapshot was performed.

## Snapshot a Cloud Hypervisor VM

First thing, we must run a Cloud Hypervisor VM:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --cpus boot=4 \
    --memory size=4G \
    --kernel vmlinux \
    --cmdline "root=/dev/vda1 console=hvc0 rw" \
    --disk path=focal-server-cloudimg-amd64.raw
```

At any point in time when the VM is running, one might choose to pause it:

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock pause
```

Once paused, the VM can be safely snapshot into the specified directory and
using the following command:

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock snapshot file:///home/foo/snapshot
```

Given the directory was present on the system, the snapshot will succeed and
it should contain the following files:

```bash
ll /home/foo/snapshot/
total 4194536
drwxrwxr-x  2 foo bar       4096 Jul 22 11:50 ./
drwxr-xr-x 47 foo bar       4096 Jul 22 11:47 ../
-rw-------  1 foo bar       1084 Jul 22 11:19 config.json
-rw-------  1 foo bar 4294967296 Jul 22 11:19 memory-ranges
-rw-------  1 foo bar     217853 Jul 22 11:19 state.json
```

`config.json` contains the virtual machine configuration. It is used to create
a similar virtual machine with the correct amount of CPUs, RAM, and other
expected devices. It is stored in a human readable format so that it could be
modified between the snapshot and restore phases to achieve some very special
use cases. But for most cases, manually modifying the configuration should not
be needed.

`memory-ranges` stores the content of the guest RAM.

`state.json` contains the virtual machine state. It is used to restore each
component in the state it was left before the snapshot occurred.

## Restore a Cloud Hypervisor VM

Given that one has access to an existing snapshot in `/home/foo/snapshot`,
it is possible to create a new VM based on this snapshot with the following
command:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot
```

Or using two different commands from two terminals:

```bash
# First terminal
./cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock

# Second terminal
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock restore source_url=file:///home/foo/snapshot
```

Remember the VM is restored in a `paused` state, which was the VM's state when
it was snapshot. For this reason, one must explicitly `resume` the VM before to
start using it.

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock resume
```

Alternatively, the `resume` option can be used to automatically resume the VM
after restore completes:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot,resume=true
```

At this point, the VM is fully restored and is identical to the VM which was
snapshot earlier.

See [Network Announcements After Resume](live_migration.md#network-announcements-after-resume)
for the announcement behavior after restore/resume.

Restore also supports selecting how guest memory is populated:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot,memory_restore_mode=ondemand
```

If `memory_restore_mode` is omitted, Cloud Hypervisor uses the eager-copy
restore path (`copy`).

With `memory_restore_mode=ondemand`, restore uses `userfaultfd` to fault snapshot
pages in on first access instead of copying the full `memory-ranges` file into
guest RAM before restore completes. This mode is strict: if Cloud Hypervisor
cannot enable the `userfaultfd` restore path, restore fails instead of falling
back to `copy`.

Current constraints for `memory_restore_mode=ondemand`:

- `prefault=on` is not supported
- the snapshot memory ranges must be page-aligned

### Copy-on-write restore

With `memory_restore_mode=copyonwrite`, guest RAM is created by mapping the snapshot
memory file copy-on-write before any KVM memslot or device consumes the
mapping: nothing is copied up front, pages fault in from the page cache — so
many VMs restored from the same snapshot share it — and guest writes stay
private to each VM.

Current constraints for `memory_restore_mode=copyonwrite`:

- Plain private guest RAM only. Anything else falls back to the eager copy
  (logged): `shared=on` or hugepages (global or per-zone), zones with
  `host_numa_node`, `reserve`, `mergeable` or hotplug fields (a purely static
  `id`+`size` zone is fine), resizable RAM (`hotplug_size`, virtio-mem), KSM
  (`mergeable=on`), `--pvmemcontrol`, device passthrough
  (`--device`/`--user-device`/`--vdpa`), and snapshot ranges that are not
  page-aligned single-region extents. `reserve=on` and THP are re-applied to
  the mapped region.
- A snapshot memory file shorter than the saved ranges is rejected up front (it
  would otherwise fault `SIGBUS` at run time).
- `prefault` is rejected.
- The snapshot memory file must remain on disk **and unchanged** for the
  entire lifetime of the VM. This is stronger than `ondemand`: UFFD copies each
  page into the original anonymous mapping and stops needing the file once every
  page is populated, and a read error there is a controlled VM exit; the CoW
  region stays file-backed forever, so truncating it delivers a synchronous
  `SIGBUS` and any in-place edit corrupts the guest. The length check only
  rejects a file that is already short at restore time.

## Restore a VM with new Net FDs
For a VM created with FDs explicitly passed to NetConfig, a set of valid FDs
need to be provided along with the VM restore command in the following syntax:

```bash
# First terminal
./cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock

# Second terminal
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock restore source_url=file:///home/foo/snapshot net_fds=[net1@[23,24],net2@[25,26]]
```
In the example above, the net device with id `net1` will be backed by FDs '23'
and '24', and the net device with id `net2` will be backed by FDs '25' and '26'
from the restored VM.

## VFIO devices

Snapshot and restore are supported for VFIO devices that implement the kernel
VFIO migration v2 protocol (e.g. Mellanox NICs bound to the `mlx5_vfio_pci`
driver).

See [`vfio.md`](vfio.md) for details on requirements and behavior.

## Offload Snapshot and Restore

Cloud Hypervisor can hand the snapshot payload off to a user-provided
offload daemon instead of writing files to a `file://` directory. The
daemon can transform the payload on the fly (encrypt, compress, stream
to object storage, etc.) without ever touching local disk.

There is no dedicated API surface for offload: the daemon talks to CH
over the existing local live-migration protocol, playing the migration
peer role:

- On snapshot, CH acts as the migration sender and the daemon acts as the
  receiver. The source VM shuts down on success, exactly as it would for a
  local live migration. Memory is transferred via `SCM_RIGHTS`, CH handing
  off the daemon one memfd per guest-memory slot.
- On restore, CH acts as the migration receiver and the daemon acts as the
  sender. The daemon provides one memfd per slot, populated from its
  storage, and CH uses those memfds directly as guest RAM backing.

In practice, this means offload is driven through the existing
`vm.send-migration` / `vm.receive-migration` endpoints (with `local=on`
and a `unix:<path>` URL). The daemon is just another peer of these
endpoints. This requires the VM to be configured with shared-memory
backing, which is the same precondition that applies to local live
migration today.

### Snapshot offload usage

```bash
# 1. Run a VM with shared memory.
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --cpus boot=2 \
    --memory size=1G,shared=on \
    --kernel vmlinux \
    --cmdline "root=/dev/vda1 console=hvc0 rw" \
    --disk path=focal-server-cloudimg-amd64.raw

# 2. Start your offload daemon. The reference implementation is shipped as
#    `offload_daemon` and persists snapshot data to a local directory.
./offload_daemon snapshot \
    --socket /tmp/offload.sock \
    --output-dir /var/snapshots/vm1

# 3. Issue a local live migration to the daemon's socket. CH connects to
#    /tmp/offload.sock, streams the snapshot, and exits on success.
./ch-remote --api-socket /tmp/cloud-hypervisor.sock pause
./ch-remote --api-socket /tmp/cloud-hypervisor.sock \
    send-migration destination_url=unix:/tmp/offload.sock,local=on
```

### Restore offload usage

```bash
# 1. Start a CH process.
./cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock

# 2. Tell CH to listen for an inbound migration from the offload daemon.
./ch-remote --api-socket /tmp/cloud-hypervisor.sock \
    receive-migration receiver_url=unix:/tmp/restore.sock &

# 3. Start the daemon in restore mode pointing at the same saved snapshot.
#    With --resume, the restored VM starts running on completion;
#    without it, the VM is left paused (issue `resume` to start it).
./offload_daemon restore \
    --socket /tmp/restore.sock \
    --input-dir /var/snapshots/vm1 \
    --resume
```

### On demand restore usage

For speeding up a VM restore, the daemon's `--ondemand` mode hands CH
empty memfds and serves page contents on demand via userfaultfd.

This requires `memory_mode=postcopy` on the receive-migration call so CH
registers userfaultfd on the memfds before resuming vCPUs and keeps
the daemon's socket open for `PageFault` requests:

```bash
./ch-remote --api-socket /tmp/cloud-hypervisor.sock \
    receive-migration receiver_url=unix:/tmp/restore.sock,memory_mode=postcopy &

./offload_daemon restore \
    --socket /tmp/restore.sock \
    --input-dir /var/snapshots/vm1 \
    --resume --ondemand
```

### The daemon protocol

The daemon implements the local live-migration wire protocol defined in
`vm-migration/src/protocol.rs`. Two state machines are involved:

- Snapshot mode (migration receiver): walk
  `Start → MemoryFd (×N) → Config → State → CompletePaused`. For each
  `MemoryFd` command, receive a guest-memory fd via SCM_RIGHTS on the
  same UNIX socket.
- Restore mode (migration sender): walk the same sequence in reverse,
  emitting one `MemoryFd` per slot (with the memfd attached via SCM_RIGHTS)
  before sending `Config` and `State`. Finish with either `CompletePaused`
  (restored VM remains paused) or `Complete` (restored VM resumes).

### Critical invariant on snapshot

On the snapshot path, the daemon must finish reading from every memory fd
before it ACKs `CompletePaused`. Cloud Hypervisor blocks at the
`CompletePaused` handshake until the daemon ACKs. Once it ACKs, the source
VM shuts down and the daemon's fds are the only remaining record of guest
RAM. The reference daemon dumps each slot to disk and `fsync`s before
ACKing.

### Reference daemon

The in-tree `offload_daemon` binary is intentionally minimal: it just
serialises the snapshot to a local directory and replays it back. Its
purpose is to back the offload integration test and to serve as a
working example for daemon authors. Use it as a template, not a
production backend.

### Limitations

- The VM must use shared-memory backing (`shared=on` or file-backed).
  Anonymous memory is rejected with the same error message that local
  live migration produces.
- Orchestrator-supplied network FDs (today carried by `vm.restore`'s
  `net_fds` field) are not plumbed through `vm.receive-migration`,
  so VMs whose configuration relies on externally-provided net FDs
  cannot currently be restored via the offload path.
- Confidential VMs (CVMs) inherit the live-migration restriction: offload
  is not supported for CVMs.
