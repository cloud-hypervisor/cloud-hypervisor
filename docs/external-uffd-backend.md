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
