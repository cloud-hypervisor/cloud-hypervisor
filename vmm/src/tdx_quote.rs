// Copyright © 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Host-side handling of the TDX `TDG.VP.VMCALL<GetQuote>` GHCI call.
//!
//! On a GetQuote request the guest places a request buffer in shared memory (a
//! 24-byte GHCI header followed by a TD report) and traps to the VMM. This
//! module reads that buffer, forwards the report to a Quote Generation Service
//! (QGS) using the QGS message framing, and writes the returned quote back into
//! the same shared buffer. The QGS endpoint may be a host Unix, AF_VSOCK or TCP
//! socket, mirroring QEMU's `SocketAddress`-typed `quote-generation-socket`.
//!
//! This is a synchronous port of QEMU's
//! `target/i386/kvm/tdx-quote-generator.c` (commit 40da501d8989). Unlike QEMU,
//! the transaction runs inline on the vCPU thread and completes before the
//! VMCALL returns, so a TD that polls the GHCI header's status field observes
//! completion immediately. TDs that strictly wait for the
//! `SetupEventNotifyInterrupt` completion interrupt are not yet supported.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use std::{fmt, mem};

use hypervisor::VmOps;
use hypervisor::kvm::TdxExitStatus;
use log::{error, warn};

use crate::vm_config::TdxQuoteGenerationSocket;

/// Size of the shared GHCI GetQuote header, in bytes.
const GHCI_HDR_SIZE: usize = 24;
/// Only GHCI GetQuote structure version 1 is defined today.
const GHCI_STRUCTURE_VERSION: u64 = 1;

// GHCI GetQuote status codes, written into the header's `error_code` field.
const GET_QUOTE_SUCCESS: u64 = 0;
const GET_QUOTE_IN_FLIGHT: u64 = u64::MAX;
const GET_QUOTE_ERROR: u64 = 0x8000_0000_0000_0000;
const GET_QUOTE_QGS_UNAVAILABLE: u64 = 0x8000_0000_0000_0001;

/// Upper bound on the shared buffer size, mirroring QEMU's safeguard.
const MAX_BUF_LEN: u64 = 128 * 1024;
/// 4 KiB alignment required for both the buffer address and its length.
const PAGE_SIZE: u64 = 4096;

/// Transaction timeout matching QEMU's 30s threshold.
const QGS_TIMEOUT: Duration = Duration::from_secs(30);

// QGS message framing (see QEMU's tdx-quote-generator.c).
const QGS_MSG_LIB_MAJOR_VER: u16 = 1;
const QGS_MSG_LIB_MINOR_VER: u16 = 1;
const QGS_MSG_GET_QUOTE_REQ: u32 = 0;
const QGS_MSG_GET_QUOTE_RESP: u32 = 1;
/// Size of the big-endian length prefix that frames each QGS message.
const QGS_FRAME_LEN_SIZE: usize = 4;
/// `qgs_msg_header_t`: major(u16) minor(u16) type(u32) size(u32) error_code(u32).
const QGS_MSG_HEADER_SIZE: usize = 16;
/// `qgs_msg_get_quote_req_t` = header + report_size(u32) + id_list_size(u32).
const QGS_GET_QUOTE_REQ_SIZE: usize = QGS_MSG_HEADER_SIZE + 8;
/// `qgs_msg_get_quote_resp_t` = header + selected_id_size(u32) + quote_size(u32).
const QGS_GET_QUOTE_RESP_SIZE: usize = QGS_MSG_HEADER_SIZE + 8;

#[derive(Debug)]
enum QuoteError {
    /// Could not connect to the QGS socket.
    Connect(io::Error),
    /// I/O error while talking to the QGS.
    Io(io::Error),
    /// The QGS reply did not conform to the expected framing.
    Protocol(String),
}

impl fmt::Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteError::Connect(e) => write!(f, "failed to connect to QGS socket: {e}"),
            QuoteError::Io(e) => write!(f, "QGS I/O error: {e}"),
            QuoteError::Protocol(msg) => write!(f, "QGS protocol error: {msg}"),
        }
    }
}

/// Shared GHCI GetQuote header. All fields are little-endian on the wire.
struct GhciHeader {
    structure_version: u64,
    error_code: u64,
    in_len: u32,
    out_len: u32,
}

impl GhciHeader {
    fn from_bytes(b: &[u8; GHCI_HDR_SIZE]) -> Self {
        Self {
            structure_version: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            error_code: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            in_len: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            out_len: u32::from_le_bytes(b[20..24].try_into().unwrap()),
        }
    }

    fn to_bytes(&self) -> [u8; GHCI_HDR_SIZE] {
        let mut b = [0u8; GHCI_HDR_SIZE];
        b[0..8].copy_from_slice(&self.structure_version.to_le_bytes());
        b[8..16].copy_from_slice(&self.error_code.to_le_bytes());
        b[16..20].copy_from_slice(&self.in_len.to_le_bytes());
        b[20..24].copy_from_slice(&self.out_len.to_le_bytes());
        b
    }
}

/// Build a framed QGS `GET_QUOTE_REQ` message wrapping `report`.
fn build_qgs_request(report: &[u8]) -> Vec<u8> {
    let msg_size = (QGS_GET_QUOTE_REQ_SIZE + report.len()) as u32;
    let mut buf = Vec::with_capacity(QGS_FRAME_LEN_SIZE + msg_size as usize);
    // 4-byte big-endian frame length prefix.
    buf.extend_from_slice(&msg_size.to_be_bytes());
    // qgs_msg_header_t
    buf.extend_from_slice(&QGS_MSG_LIB_MAJOR_VER.to_le_bytes());
    buf.extend_from_slice(&QGS_MSG_LIB_MINOR_VER.to_le_bytes());
    buf.extend_from_slice(&QGS_MSG_GET_QUOTE_REQ.to_le_bytes());
    buf.extend_from_slice(&msg_size.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // error_code
    // qgs_msg_get_quote_req_t tail
    buf.extend_from_slice(&(report.len() as u32).to_le_bytes()); // report_size
    buf.extend_from_slice(&0u32.to_le_bytes()); // id_list_size
    buf.extend_from_slice(report);
    buf
}

/// Validate a QGS `GET_QUOTE_RESP` message and extract the raw quote bytes.
fn parse_qgs_response(msg: &[u8]) -> Result<Vec<u8>, QuoteError> {
    if msg.len() < QGS_GET_QUOTE_RESP_SIZE {
        return Err(QuoteError::Protocol(format!(
            "QGS response too short: {} bytes",
            msg.len()
        )));
    }
    let major = u16::from_le_bytes(msg[0..2].try_into().unwrap());
    let minor = u16::from_le_bytes(msg[2..4].try_into().unwrap());
    if major != QGS_MSG_LIB_MAJOR_VER || minor != QGS_MSG_LIB_MINOR_VER {
        return Err(QuoteError::Protocol(format!(
            "invalid QGS message version {major}.{minor}"
        )));
    }
    let msg_type = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    if msg_type != QGS_MSG_GET_QUOTE_RESP {
        return Err(QuoteError::Protocol(format!(
            "invalid QGS message type {msg_type}"
        )));
    }
    let error_code = u32::from_le_bytes(msg[12..16].try_into().unwrap());
    if error_code != 0 {
        return Err(QuoteError::Protocol(format!("QGS error code {error_code}")));
    }
    let selected_id_size = u32::from_le_bytes(msg[16..20].try_into().unwrap());
    if selected_id_size != 0 {
        return Err(QuoteError::Protocol(format!(
            "unexpected QGS selected ID size {selected_id_size}"
        )));
    }
    let quote_size = u32::from_le_bytes(msg[20..24].try_into().unwrap()) as usize;
    let quote_start = QGS_GET_QUOTE_RESP_SIZE;
    if quote_size == 0 || quote_start + quote_size > msg.len() {
        return Err(QuoteError::Protocol(format!(
            "QGS quote size {quote_size} does not fit in {} bytes",
            msg.len().saturating_sub(quote_start)
        )));
    }
    Ok(msg[quote_start..quote_start + quote_size].to_vec())
}

/// A connected, byte-stream QGS transport (Unix, TCP or AF_VSOCK).
trait QgsStream: Read + Write {}
impl<T: Read + Write> QgsStream for T {}

/// A connected AF_VSOCK stream socket, backed by an owned file descriptor.
///
/// Rust's standard library has no AF_VSOCK support, so read/write go through
/// the raw `read(2)`/`write(2)` syscalls. The connected socket carries
/// `SO_RCVTIMEO`/`SO_SNDTIMEO`, so a stalled QGS surfaces as a `WouldBlock`
/// error just like the timeouts on the Unix/TCP transports.
struct VsockStream(OwnedFd);

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is valid for writes of `buf.len()` bytes and the fd is
        // a valid, owned, connected socket.
        let ret = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: `buf` is valid for reads of `buf.len()` bytes and the fd is a
        // valid, owned, connected socket.
        let ret = unsafe {
            libc::write(
                self.0.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Apply a send/receive timeout to a raw socket fd via `SO_SNDTIMEO`/`SO_RCVTIMEO`.
fn set_socket_timeouts(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: `tv` outlives the call and its size is passed correctly.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(tv) as *const libc::c_void,
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Connect to a QGS reachable over AF_VSOCK at `cid:port`.
fn connect_vsock(cid: u32, port: u32, timeout: Duration) -> io::Result<VsockStream> {
    // SAFETY: FFI call with constant, valid arguments; returns an fd or -1.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid socket fd owned by us from here on.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: `sockaddr_vm` is a plain-old-data struct; zeroing is a valid
    // initial state before filling in the address family, CID and port.
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;

    // SAFETY: `addr` is a properly-initialized `sockaddr_vm` and its size is
    // passed correctly; `owned` holds a valid socket fd.
    let ret = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            std::ptr::addr_of!(addr) as *const libc::sockaddr,
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    set_socket_timeouts(owned.as_raw_fd(), timeout)?;
    Ok(VsockStream(owned))
}

/// Connect to the configured QGS endpoint, applying the QGS transaction timeout.
fn connect_qgs(addr: &TdxQuoteGenerationSocket) -> io::Result<Box<dyn QgsStream>> {
    match addr {
        TdxQuoteGenerationSocket::Unix { path } => {
            let stream = UnixStream::connect(path)?;
            stream.set_read_timeout(Some(QGS_TIMEOUT))?;
            stream.set_write_timeout(Some(QGS_TIMEOUT))?;
            Ok(Box::new(stream))
        }
        TdxQuoteGenerationSocket::Inet { host, port } => {
            let stream = TcpStream::connect((host.as_str(), *port))?;
            stream.set_read_timeout(Some(QGS_TIMEOUT))?;
            stream.set_write_timeout(Some(QGS_TIMEOUT))?;
            Ok(Box::new(stream))
        }
        TdxQuoteGenerationSocket::Vsock { cid, port } => {
            Ok(Box::new(connect_vsock(*cid, *port, QGS_TIMEOUT)?))
        }
    }
}

/// Connect to the QGS, forward the TD report and return the generated quote.
fn generate_quote(addr: &TdxQuoteGenerationSocket, report: &[u8]) -> Result<Vec<u8>, QuoteError> {
    let mut stream = connect_qgs(addr).map_err(QuoteError::Connect)?;

    let request = build_qgs_request(report);
    stream.write_all(&request).map_err(QuoteError::Io)?;

    // Read the 4-byte big-endian frame length, then the message body.
    let mut len_buf = [0u8; QGS_FRAME_LEN_SIZE];
    stream.read_exact(&mut len_buf).map_err(QuoteError::Io)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_BUF_LEN as usize {
        return Err(QuoteError::Protocol(format!(
            "invalid QGS response length {resp_len}"
        )));
    }
    let mut msg = vec![0u8; resp_len];
    stream.read_exact(&mut msg).map_err(QuoteError::Io)?;

    parse_qgs_response(&msg)
}

fn write_header(vm_ops: &dyn VmOps, gpa: u64, hdr: &GhciHeader) {
    if let Err(e) = vm_ops.guest_mem_write(gpa, &hdr.to_bytes()) {
        error!("TDX GetQuote: failed to update GHCI header: {e}");
    }
}

/// Handle a `TDG.VP.VMCALL<GetQuote>` exit.
///
/// `gpa`/`buf_len` describe the shared GetQuote buffer; `socket`, when present,
/// is the host QGS endpoint (Unix, AF_VSOCK or TCP). The returned
/// [`TdxExitStatus`] is the VMCALL status reported back to the guest;
/// quote-level results are conveyed through the GHCI header written into the
/// shared buffer.
pub fn handle_get_quote(
    vm_ops: &dyn VmOps,
    gpa: u64,
    buf_len: u64,
    socket: Option<&TdxQuoteGenerationSocket>,
) -> TdxExitStatus {
    // Transport-level validation, mapped to the VMCALL status register.
    if buf_len == 0 {
        return TdxExitStatus::InvalidOperand;
    }
    if !gpa.is_multiple_of(PAGE_SIZE) || !buf_len.is_multiple_of(PAGE_SIZE) {
        return TdxExitStatus::AlignError;
    }
    if buf_len > MAX_BUF_LEN {
        return TdxExitStatus::InvalidOperand;
    }

    // Read and validate the GHCI header.
    let mut hdr_bytes = [0u8; GHCI_HDR_SIZE];
    if let Err(e) = vm_ops.guest_mem_read(gpa, &mut hdr_bytes) {
        error!("TDX GetQuote: failed to read GHCI header: {e}");
        return TdxExitStatus::InvalidOperand;
    }
    let mut hdr = GhciHeader::from_bytes(&hdr_bytes);
    if hdr.structure_version != GHCI_STRUCTURE_VERSION {
        warn!(
            "TDX GetQuote: unsupported GHCI structure version {}",
            hdr.structure_version
        );
        return TdxExitStatus::InvalidOperand;
    }
    let payload_capacity = buf_len - GHCI_HDR_SIZE as u64;
    if u64::from(hdr.in_len) > payload_capacity {
        warn!(
            "TDX GetQuote: in_len {} exceeds payload capacity {payload_capacity}",
            hdr.in_len
        );
        return TdxExitStatus::InvalidOperand;
    }

    // Without a configured QGS, report unavailability via the header and let
    // the VMCALL itself succeed.
    let Some(socket) = socket else {
        hdr.error_code = GET_QUOTE_QGS_UNAVAILABLE;
        hdr.out_len = 0;
        write_header(vm_ops, gpa, &hdr);
        return TdxExitStatus::Success;
    };

    // Read the TD report (the in-message) from the shared payload area.
    let mut report = vec![0u8; hdr.in_len as usize];
    if let Err(e) = vm_ops.guest_mem_read(gpa + GHCI_HDR_SIZE as u64, &mut report) {
        error!("TDX GetQuote: failed to read TD report: {e}");
        return TdxExitStatus::InvalidOperand;
    }

    // Mark the request in-flight for any observer before the blocking QGS
    // transaction, matching the GHCI contract.
    hdr.error_code = GET_QUOTE_IN_FLIGHT;
    hdr.out_len = 0;
    write_header(vm_ops, gpa, &hdr);

    match generate_quote(socket, &report) {
        Ok(quote) => {
            if quote.len() as u64 > payload_capacity {
                error!(
                    "TDX GetQuote: quote ({} bytes) exceeds payload capacity {payload_capacity}",
                    quote.len()
                );
                hdr.error_code = GET_QUOTE_ERROR;
                hdr.out_len = 0;
            } else if let Err(e) = vm_ops.guest_mem_write(gpa + GHCI_HDR_SIZE as u64, &quote) {
                error!("TDX GetQuote: failed to write quote: {e}");
                hdr.error_code = GET_QUOTE_ERROR;
                hdr.out_len = 0;
            } else {
                hdr.error_code = GET_QUOTE_SUCCESS;
                hdr.out_len = quote.len() as u32;
            }
        }
        Err(QuoteError::Connect(e)) => {
            warn!("TDX GetQuote: QGS unavailable: {e}");
            hdr.error_code = GET_QUOTE_QGS_UNAVAILABLE;
            hdr.out_len = 0;
        }
        Err(e) => {
            error!("TDX GetQuote: quote generation failed: {e}");
            hdr.error_code = GET_QUOTE_ERROR;
            hdr.out_len = 0;
        }
    }

    write_header(vm_ops, gpa, &hdr);
    TdxExitStatus::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghci_header_roundtrip() {
        let hdr = GhciHeader {
            structure_version: GHCI_STRUCTURE_VERSION,
            error_code: GET_QUOTE_IN_FLIGHT,
            in_len: 1024,
            out_len: 4096,
        };
        let parsed = GhciHeader::from_bytes(&hdr.to_bytes());
        assert_eq!(parsed.structure_version, GHCI_STRUCTURE_VERSION);
        assert_eq!(parsed.error_code, GET_QUOTE_IN_FLIGHT);
        assert_eq!(parsed.in_len, 1024);
        assert_eq!(parsed.out_len, 4096);
    }

    #[test]
    fn qgs_request_framing() {
        let report = vec![0xabu8; 64];
        let req = build_qgs_request(&report);
        assert_eq!(
            req.len(),
            QGS_FRAME_LEN_SIZE + QGS_GET_QUOTE_REQ_SIZE + report.len()
        );
        let frame_len = u32::from_be_bytes(req[0..4].try_into().unwrap()) as usize;
        assert_eq!(frame_len, QGS_GET_QUOTE_REQ_SIZE + report.len());
        let msg_type = u32::from_le_bytes(req[8..12].try_into().unwrap());
        assert_eq!(msg_type, QGS_MSG_GET_QUOTE_REQ);
        let report_size = u32::from_le_bytes(req[20..24].try_into().unwrap());
        assert_eq!(report_size as usize, report.len());
        assert_eq!(
            &req[QGS_FRAME_LEN_SIZE + QGS_GET_QUOTE_REQ_SIZE..],
            &report[..]
        );
    }

    fn build_qgs_response(quote: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&QGS_MSG_LIB_MAJOR_VER.to_le_bytes());
        msg.extend_from_slice(&QGS_MSG_LIB_MINOR_VER.to_le_bytes());
        msg.extend_from_slice(&QGS_MSG_GET_QUOTE_RESP.to_le_bytes());
        let size = (QGS_GET_QUOTE_RESP_SIZE + quote.len()) as u32;
        msg.extend_from_slice(&size.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes()); // error_code
        msg.extend_from_slice(&0u32.to_le_bytes()); // selected_id_size
        msg.extend_from_slice(&(quote.len() as u32).to_le_bytes()); // quote_size
        msg.extend_from_slice(quote);
        msg
    }

    #[test]
    fn qgs_response_parsing() {
        let quote = vec![0x5au8; 128];
        let msg = build_qgs_response(&quote);
        assert_eq!(parse_qgs_response(&msg).unwrap(), quote);
    }

    #[test]
    fn qgs_response_rejects_bad_type() {
        let quote = vec![0u8; 16];
        let mut msg = build_qgs_response(&quote);
        msg[4..8].copy_from_slice(&QGS_MSG_GET_QUOTE_REQ.to_le_bytes());
        assert!(parse_qgs_response(&msg).is_err());
    }
}
