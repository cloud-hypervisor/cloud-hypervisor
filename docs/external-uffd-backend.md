# External userfaultfd backend

The external userfaultfd backend lets Cloud Hypervisor obtain memory contents
from a separate service on demand. The service receives a registered
userfaultfd, monitors page faults, and supplies file-backed ranges without
loading the complete image before VM startup.

The common UFFD code in `vm-device` separates stateful actions from their wire
encoding so both memory and device backends can use it. Its default transport
uses a binary format over an `AF_UNIX`, `SOCK_STREAM` socket. File descriptors
are transferred with `SCM_RIGHTS`, and all multi-byte fields are little-endian.
A caller can provide another implementation of the small `Transport`
interface without changing the actions or device code.

## Protocol overview

Every protocol message starts with a 16-byte header.

| Offset | Request field | Response field | Size |
|---:|---|---|---:|
| 0 | `command` | `status` | 2 |
| 2 | `command_headers` | `reply_type` and `reply_headers` | 6 |
| 8 | payload `length` | payload `length` | 8 |

The protocol establishes a stateful session with a `Handshake`. The Handshake
transfers a userfaultfd, regions, session flags, and effective UFFD modes. The
server then resolves faults directly or sends asynchronous `FdRanges`
responses.

| Command | Purpose |
|---|---|
| `Handshake` | Transfer the userfaultfd, regions, session flags, and effective UFFD modes |
| `AddRegion` | Add or replace a complete region in a managed session |
| `RemoveRegion` | Remove a complete region from a managed session |

| Reply type | Purpose |
|---|---|
| `Legacy` | Empty acknowledgement or generic error |
| `FdRanges` | File-backed device ranges with attached file descriptors |

The Handshake command header contains `version: u16`, `flags: u8`,
`uffd_modes: u8`, and `region_count: u16`. Each region is a 48-byte record:

| Field | Type | Purpose |
|---|---|---|
| `virt_addr` | `u64` | Start of the registered client VMA |
| `size` | `u64` | Region length |
| `offset` | `u64` | Region offset in the flattened device |
| `fault_size` | `u64` | Preferred fault resolution granularity |
| `prot` | `i32` | Effective mapping protection |
| `flags` | `i32` | Effective mapping flags |
| `backing_offset` | `u64` | Region offset in an optional client backing FD |

Handshake flags select managed fault handling, prefault, an optional Legacy
acknowledgement, and optional client backing FDs. UFFD modes independently
describe `MISSING`, `WP`, and `WP_ASYNC`. A successful Handshake requires no
response unless its `ACK_REQUIRED` flag is set. Without an acknowledgement, a
failed Handshake is reported by closing the connection. With `BACKING_FDS`,
the Handshake carries one backing FD per region after the UFFD, in region
order; `backing_offset` selects the start of each region in its backing FD.

An `FdRanges` response contains one 24-byte
`(device_offset, blob_offset, len)` record per attached FD. Its `MORE` flag
means that another response frame belongs to the same request.

Cloud Hypervisor does not currently send `AddRegion`, `RemoveRegion`, or
backing FDs for virtio-pmem.

## Cloud Hypervisor operation

1. Create a host mapping and register it with userfaultfd in missing-page mode.
2. Connect to the external service and send a Handshake with the userfaultfd
   and VMA regions, session flags, and effective UFFD modes.
3. Let the service monitor faults for the lifetime of the connection.
4. In managed mode, let the service resolve faults directly. Otherwise,
   receive asynchronous `FdRanges` responses.
5. With Cloud Hypervisor's customized handler, map the returned file ranges
   into the registered VMA and wake the faulting thread.
6. Stop monitoring and close the socket before destroying the device mapping.

An unexpected disconnect or invalid response is treated as a backend failure.

## Device support

Only `virtio-pmem` is currently supported. It uses a stateful customized
session and handles asynchronous responses in its existing device worker:

```bash
--pmem file=/run/external-uffd.sock,size=4G,backend_type=uffd,readonly=on
```

| Option | Requirement | Description |
|---|---|---|
| `file` | Required | Path of the external service's Unix socket |
| `size` | Required | PMEM size; it must be 2 MiB aligned |
| `backend_type` | `uffd` | Select the external userfaultfd backend |
| `readonly` | `on` | Expose a read-only KVM memory slot |

The PMEM mapping uses a 2 MiB fault granularity and registers
`UFFD_MODE_MISSING`. The Handshake sets `ACK_REQUIRED` and leaves `MANAGED`,
`PREFAULT`, and `BACKING_FDS` clear. Writable external PMEM and backend-specific
migration are not currently supported. `discard_writes` has no effect when
`readonly=on`.

The default PMEM backend remains `file`, so existing configurations are
unchanged.

## Minimal Rust server

A minimal Rust server for the currently supported `virtio-pmem` backend needs
a Unix socket path and a read-only PMEM image. It only implements the
customized Handshake and asynchronous `FdRanges` path.

### 1. Receive the Handshake

1. Bind `std::os::unix::net::UnixListener` and accept one client.
2. Use `recvmsg()` to receive the first frame and its `SCM_RIGHTS` userfaultfd.
3. Finish reading the 16-byte header and Handshake payload from the stream.
4. Decode the 48-byte region entries and keep them with the received UFFD.
5. Send an empty successful Legacy response to acknowledge the Handshake.

Reject the connection unless the command and version are supported, `MANAGED`
and `BACKING_FDS` are clear, `MISSING` is set in the UFFD modes, exactly one
UFFD is attached, and the payload contains the declared number of valid
regions. Cloud Hypervisor sets `ACK_REQUIRED`, so the server must acknowledge
success or return an error before it starts sending asynchronous ranges.

### 2. Read UFFD events

Use `libc::poll()` to wait for the UFFD while also monitoring the client socket
for disconnects. Linux returns a 32-byte `uffd_msg`; a page-fault message has
event type `UFFD_EVENT_PAGEFAULT` (`0x12`) at offset 0 and the faulting host
virtual address at offset 16.

Find the Handshake region containing the fault and calculate:

```text
region_offset = fault_address - region.virt_addr
range_offset  = floor(region_offset / region.fault_size) * region.fault_size
device_offset = region.offset + range_offset
range_length  = min(region.fault_size, region.size - range_offset)
blob_offset   = device_offset
```

The resulting file range must fit within the PMEM image, and `blob_offset`
must satisfy the host `mmap()` alignment requirement.

### 3. Send FdRanges

Encode an `Ok/FdRanges` response with `flags=0`, `fd_count=1`, and one 24-byte
entry containing `device_offset`, `blob_offset`, and `len`. Send the
header and entry with the PMEM image FD attached through `SCM_RIGHTS`.

Cloud Hypervisor maps the range and performs `UFFDIO_WAKE`; the server must not
wake the fault itself.

### Rust-style pseudocode

The following intentionally omits syscall wrappers and error types. It shows
the ownership and control flow expected from a minimal implementation:

```rust,ignore
fn main() -> Result<()> {
    let image = File::open(image_path)?;
    let listener = UnixListener::bind(socket_path)?;
    let (socket, _) = listener.accept()?;

    // recv_handshake() must use recvmsg() for the first read so it receives
    // the SCM_RIGHTS file descriptor attached to the Handshake.
    let handshake = recv_handshake(&socket)?;
    ensure!(handshake.flags & MANAGED == 0);
    ensure!(handshake.flags & BACKING_FDS == 0);
    ensure!(handshake.uffd_modes & MISSING != 0);
    let uffd = handshake.uffd;
    let regions = handshake.regions;
    send_handshake_ack(&socket)?;

    loop {
        match poll_uffd_and_socket(&uffd, &socket)? {
            Event::Disconnected => break,
            Event::PageFault(fault_address) => {
                let region = regions
                    .iter()
                    .find(|r| r.contains(fault_address))
                    .ok_or(Error::FaultOutsideRegions)?;

                let region_offset = fault_address - region.virt_addr;
                let range_offset =
                    region_offset / region.fault_size * region.fault_size;
                let device_offset = region.offset + range_offset;
                let range_length =
                    region.fault_size.min(region.size - range_offset);

                validate_image_range(&image, device_offset, range_length)?;
                send_fd_range(
                    &socket,
                    &image,
                    FdRange {
                        device_offset,
                        blob_offset: device_offset,
                        len: range_length,
                    },
                )?;
            }
        }
    }

    Ok(())
}
```

A first implementation can remain single-threaded and serve one VM. A
multi-VM server should keep the socket, UFFD, and regions in independent
per-connection state.
