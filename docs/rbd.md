# Userspace RBD disks

Cloud Hypervisor can attach a Ceph RBD image directly through `librbd`. The
image is opened inside the VMM process and the virtio-block queues submit
asynchronous I/O to librbd; no kernel RBD mapping (`/dev/rbdX`), `rbd-nbd`
daemon, SPDK bdev or hugepages are involved.

This backend is optional and disabled by default.

## Building

Build Cloud Hypervisor with the `rbd` feature:

```shell
cargo build --release --features rbd
```

The build needs the Ceph client development packages and `libclang` (the
`rbd-sys`/`rados-sys` crates generate bindings with bindgen by default) and
the resulting binary dynamically links `librbd` and `librados`.

On Debian/Ubuntu:

```shell
sudo apt install librbd-dev librados-dev libclang-dev
```

On RPM-based distributions install `librbd-devel`, `librados-devel` and
`clang-devel`. The feature is not supported for musl builds.

If the build environment has no Ceph headers, the sys crates can use their
pre-generated bindings. Set the cfg for both crates and make the client
libraries available to the linker:

```shell
RUSTFLAGS="--cfg ceph_sys_bundled -L native=/path/to/ceph/libs" \
    cargo build --release --features rbd
```

`ceph_sys_bundled` bindings are generated from a recent Ceph release; use
system headers when packaging for an older distribution.

## Usage

The disk path uses the `rbd:<pool>/<image>[@<snapshot>]` form and requires
`image_type=rbd`:

```shell
cloud-hypervisor \
    --disk path=rbd:rbd/vm-root,image_type=rbd,num_queues=4
```

A read-only snapshot must also set `readonly=on`:

```shell
cloud-hypervisor \
    --disk path=rbd:rbd/vm-root@snap-001,image_type=rbd,readonly=on
```

The JSON API uses the same values, with the serde name `Rbd`:

```json
{
  "path": "rbd:rbd/vm-root",
  "image_type": "Rbd",
  "num_queues": 4,
  "rbd_conf": "/etc/ceph/ceph.conf",
  "rbd_user": "vm001",
  "rbd_namespace": "tenants"
}
```

### RBD-specific options

| Option | Description |
|---|---|
| `rbd_conf` | Path to the Ceph configuration file. When omitted, librados searches its default locations. |
| `rbd_user` | RADOS client id passed to `rados_create`, for example `vm001` (the corresponding keyring entry is `client.vm001`). |
| `rbd_namespace` | RADOS namespace inside the pool. |
| `@<snapshot>` | Open a snapshot. Requires `readonly=on`. |

`direct=on` is rejected for RBD disks: librbd never uses the host page cache,
so the option is meaningless.

### Credentials

librados reads the keyring referenced by the configuration file. In container
deployments mount `/etc/ceph/ceph.conf` and the keyring into the VMM
container, or point `rbd_conf` at a mounted path. Client ids and keyrings are
not passed through the Cloud Hypervisor API; use the mounted configuration.

Set `client_mount_timeout` and `rados_osd_op_timeout` in the configuration
file to bound cluster connection and I/O retry times. Without a timeout a
network partition can delay VM creation or block I/O indefinitely.

## Semantics

- `flush` maps to `rbd_flush`; `discard` to `rbd_aio_discard`; `write_zeroes`
  to `rbd_aio_write_zeroes` with the thick-provision flag.
- `resize` maps to `rbd_resize`. In-flight I/O is drained before resizing.
- On pause, Cloud Hypervisor drains in-flight requests and calls
  `rbd_flush()` so that an externally created Ceph snapshot is consistent.
- Short reads are logged and reported to the guest as short completions.
- Error results are librbd's negative errno values; the guest sees
  `VIRTIO_BLK_S_IOERR` for failed requests.

## Image locking

RBD images have no host file descriptor, so Cloud Hypervisor cannot apply its
usual OFD file lock. The lock is skipped for RBD disks. Concurrent writers are
prevented by the Ceph `exclusive-lock` image feature and, for live migration,
by the platform coordinating the lock handoff. Two VMMs writing the same image
without `exclusive-lock` can corrupt data, exactly as with QEMU's RBD driver.

## Landlock

When `--landlock` is enabled, Cloud Hypervisor adds read-only rules for
`/etc/ceph`, the parent directory of `rbd_conf`, and the resolver files that
exist (`/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`). A custom
configuration or keyring outside those paths must be granted with
`--landlock-rules`. Hotplugged RBD disks cannot extend the Landlock ruleset;
pre-declare their paths with `--landlock-rules`.

## Seccomp

RBD queue workers use a dedicated seccomp profile that extends the regular
virtio-block profile with the librados socket, thread and timer syscalls.
Because librbd creates worker threads while the image is opened on the VMM
thread, the VMM filter also permits the additional network syscalls. The
filters are only relaxed when the `rbd` feature is compiled in.

If a syscall is missing, run with `--seccomp log` and inspect the kernel audit
log (`journalctl -k` or `dmesg`). Note that `--seccomp log` reports violations
through the kernel audit subsystem, not through Cloud Hypervisor's stderr.

## Snapshots and migration

Cloud Hypervisor's VM snapshot contains only memory and device state; it does
not copy disk contents. Take a Ceph `rbd snap` (or a clone) externally and
restore with `path=rbd:<pool>/<image>@<snap>,readonly=on`, or point the
restored VM at a new clone.

For live migration, both hosts open the same RBD image. The source must be
paused (and flushed) before the destination starts writing; the Ceph
exclusive lock serializes the two clients. There is no automatic reconnect
after a Ceph blocklist event; failed requests are reported to the guest and
the platform should recreate the VM.

## Licensing

`librbd` and `librados` are LGPL-2.1, and the generated `rbd-sys`/`rados-sys`
bindings are derived from LGPL Ceph headers. Cloud Hypervisor links the client
libraries dynamically; distributions shipping the `rbd` feature must include
the Ceph library and license notices and must not statically link the Ceph
client libraries.

## Limitations

- `vhost_user_block` (the in-tree vhost-user-blk backend) does not support
  RBD; use the regular virtio-block path.
- There is no `rbd_aio_cancel`; requests in flight when a device is reset
  complete asynchronously and cannot be cancelled.
- The backend uses librbd's default cache. Guest flushes are honored, but
  every image has librbd cache memory overhead; tune `rbd_cache` in
  `ceph.conf` if many images run on one host.
