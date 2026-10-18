# NBD disks

Cloud Hypervisor can back a virtio-block disk with a remote export served
over the [Network Block Device](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md)
protocol, for example by `qemu-nbd`, `qemu-storage-daemon` or `nbdkit`.
The NBD client is built into Cloud Hypervisor, so neither the host `nbd`
kernel module nor a vhost-user backend is needed.

## Usage

The export is selected with the `nbd` option of `--disk`, which takes an
[NBD URI](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/uri.md)
instead of `path`:

```shell
# TCP, default port 10809
--disk nbd=nbd://192.168.0.10/vol0

# TCP, explicit port, IPv6
--disk nbd=nbd://[fd00::10]:10900/vol0

# Unix socket
--disk nbd=nbd+unix:///vol0?socket=/run/nbd/vol0.sock
```

The export name is the URI path without the leading `/`, and may be empty.
The export is always exposed to the guest as raw data; `image_type` may be
omitted or set to `raw`. The `nbd` option cannot be combined with `path`,
`vhost_user` or `direct=on`.

The same field is available as `nbd` in the `DiskConfig` of the HTTP API,
so NBD disks can also be hot-plugged with `ch-remote add-disk nbd=...`.

## Example with qemu-nbd

```shell
qemu-img create -f raw /var/lib/images/data.img 10G
qemu-nbd --persistent -f raw -k /run/nbd/data.sock /var/lib/images/data.img

cloud-hypervisor \
    --kernel ./vmlinux \
    --disk path=focal-server-cloudimg-amd64.raw \
           nbd=nbd+unix:///?socket=/run/nbd/data.sock \
    ...
```

## Connections

Each virtio queue of a disk uses its own connection to the server. With
io_uring, requests from the guest are pipelined on each connection;
otherwise they are sent one at a time. The connection opened while
creating the disk is reused by the first queue, so a server that accepts
a single client (the `qemu-nbd` default) works with a single queue.

- `num_queues` above 1 requires the server to advertise
  `NBD_FLAG_CAN_MULTI_CONN`, which guarantees that a flush on one
  connection covers writes made on the others. Otherwise, creating the
  disk fails. `qemu-nbd` advertises it when `--shared` is 2 or more.
- The connections of the other queues are opened when the guest activates
  the device. The server must accept one client per queue, otherwise the
  device fails to activate.

```shell
qemu-nbd --persistent --shared=4 -f raw -k /run/nbd/data.sock /var/lib/images/data.img
--disk nbd=nbd+unix:///?socket=/run/nbd/data.sock,num_queues=2
```

- When the guest resets the device, for example on reboot, the disk
  reconnects. The server must keep running after the client disconnects
  (`qemu-nbd --persistent`), and the export must keep the same size and
  flags, otherwise the device fails to activate.
- An export that the server marks read-only can only be used with
  `readonly=on`.

The block size, preferred I/O size and maximum request size advertised by
the server through `NBD_INFO_BLOCK_SIZE` are honoured. Larger guest requests
are split into several NBD commands.

Discard and write zeroes are offered to the guest when the server supports
both `NBD_CMD_TRIM` and `NBD_CMD_WRITE_ZEROES`.

## Timeouts and keep-alive

By default a connection waits for the server indefinitely once the
handshake is done. The following `--disk` options bound how long a disk
waits for an unresponsive server. They are also available in the
`DiskConfig` of the HTTP API.

| Option                             | Default | Meaning                                                             |
| ---------------------------------- | ------- | ------------------------------------------------------------------- |
| `handshake_timeout=<seconds>`      | 10      | Bounds each TCP connect attempt and every handshake read or write.  |
| `socket_timeout=<seconds>`         | none    | Bounds every send and receive after the handshake.                  |
| `tcp_keepalive=on\|off`            | off     | Enables TCP keep-alive (`SO_KEEPALIVE`).                            |
| `tcp_keepalive_idle=<seconds>`     | 30      | Idle time before the first probe (`TCP_KEEPIDLE`).                  |
| `tcp_keepalive_interval=<seconds>` | 10      | Time between probes (`TCP_KEEPINTVL`).                              |
| `tcp_keepalive_count=<probes>`     | 3       | Unanswered probes before the connection is dropped (`TCP_KEEPCNT`). |

```shell
--disk nbd=nbd://192.168.0.10/vol0,socket_timeout=60,tcp_keepalive=on
```

- `socket_timeout` applies to a single socket operation, and only while
  requests are in flight, so an idle disk never times out. A server that
  makes no progress for that long, for example on a slow flush, fails the
  connection, so the value should be generous.
- TCP keep-alive detects a server that disappeared without closing the
  connection, for example after a host crash or a network partition.
  With the defaults this takes about a minute. Linux only sends probes
  while no data is unacknowledged, so a server that disappears while a
  write is in transit is detected by TCP retransmission instead, which
  takes about 15 minutes by default; `socket_timeout` covers that case.
- When a timeout expires or keep-alive gives up, the connection is
  treated as lost (see [Limitations](#limitations)).
- The options require `nbd`, and are rejected when set to 0. The
  `tcp_keepalive_*` options require `tcp_keepalive=on`, and all keep-alive
  options require a TCP URI. Linux limits `tcp_keepalive_idle` and
  `tcp_keepalive_interval` to 32767 and `tcp_keepalive_count` to 127.

## Snapshot, restore and live migration

The disk contents live on the server and are not part of a snapshot or of
the migration stream. As for raw files, writes are made durable only by
flush requests from the guest; pausing the VM does not flush the
connection. The destination of a migration or restore reconnects to the
same URI, so the server must be reachable from there and, for live
migration, accept the clients of the destination while the source is
still connected: two clients per queue (`--shared=2` or more for
`qemu-nbd` with a single queue).

## Limitations

- TLS (`nbds://`, `nbds+unix://`) is not supported.
- There is no reconnect: if a connection is lost, pending and later
  requests on that queue fail with an I/O error.
- Structured replies, block status and resizing are not used.
- Advisory host-side locking (see [disk locking](disk_locking.md)) does
  not apply, since there is no local file. The server is responsible for
  controlling concurrent access.
- With [Landlock](landlock.md) enabled, Cloud Hypervisor is granted access
  to the Unix socket of the export; TCP exports should be given as IP
  addresses since host name resolution needs files outside the sandbox.
