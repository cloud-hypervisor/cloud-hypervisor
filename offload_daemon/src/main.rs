// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Reference offload daemon for Cloud Hypervisor snapshot/restore offload.
//!
//! The daemon plays the local live-migration peer role on the other
//! side of the existing `vm.send-migration` (with `local=on`) and
//! `vm.receive-migration` endpoints. It persists snapshot data to a
//! local directory and reads it back on restore.
//!
//! ## Snapshot mode (daemon as migration receiver)
//!
//!  * Bind a UNIX socket; CH connects via `vm.send-migration
//!    destination_url=unix:...,local=on`.
//!  * Walk the receive state machine: Start → MemoryFd × N → Config →
//!    State → CompletePaused.
//!  * Receive each per-slot memfd via SCM_RIGHTS, mmap it, dump bytes to
//!    `<output_dir>/memory_slot_<slot>.bin`.
//!  * Persist `VmMigrationConfig` to `<output_dir>/migration_config.json`
//!    and the raw state bytes to `<output_dir>/state.json`.
//!  * Only ACK `CompletePaused` after all memory dumps are flushed.
//!
//! ## Restore mode (daemon as migration sender)
//!
//!  * Connect to the UNIX socket CH listens on (after `vm.receive-migration
//!    receiver_url=unix:...`).
//!  * Walk the send state machine: Start → MemoryFd × N → Config → State →
//!    CompletePaused (or Complete with `--resume`).
//!  * Per slot: create a memfd, copy the saved bytes into it, send via
//!    SCM_RIGHTS.
//!  * Send `VmMigrationConfig` and state bytes verbatim.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use log::{debug, info};
use vm_migration::protocol::{Command, Request, Response, Status};
use vmm::VmMigrationConfig;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

const MIGRATION_CONFIG_FILENAME: &str = "migration_config.json";
const STATE_FILENAME: &str = "state.json";

fn memory_slot_filename(slot: u32) -> String {
    format!("memory_slot_{slot}.bin")
}

#[derive(Parser, Debug)]
#[command(name = "offload_daemon")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Receive a snapshot from CH and persist it to disk.
    Snapshot {
        /// Path to a UNIX socket to bind and listen on.
        #[arg(long)]
        socket: PathBuf,
        /// Directory to write snapshot artifacts into.
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Read a snapshot from disk and stream it to a listening CH instance.
    Restore {
        /// Path of the UNIX socket that CH is listening on.
        #[arg(long)]
        socket: PathBuf,
        /// Directory to read snapshot artifacts from.
        #[arg(long)]
        input_dir: PathBuf,
        /// If set, the restored VM is resumed (Complete) instead of left
        /// paused (CompletePaused).
        #[arg(long)]
        resume: bool,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    match cli.mode {
        Mode::Snapshot { socket, output_dir } => run_snapshot(&socket, &output_dir),
        Mode::Restore {
            socket,
            input_dir,
            resume,
        } => run_restore(&socket, &input_dir, resume),
    }
}

// ---------------------------------------------------------------------------
// Snapshot mode (migration receiver)
// ---------------------------------------------------------------------------

fn run_snapshot(socket_path: &Path, output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output dir {output_dir:?}"))?;

    // bind() would EADDRINUSE on a stale path.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding UNIX socket {socket_path:?}"))?;
    info!("offload daemon listening at {socket_path:?}");

    let (mut stream, _) = listener.accept().context("accepting CH connection")?;
    info!("CH connected; starting snapshot receive");

    expect_command(&mut stream, Command::Start, "Start")?;
    Response::ok()
        .write_to(&mut stream)
        .map_err(|e| anyhow!("ACKing Start: {e:?}"))?;

    let mut memory_slots: Vec<(u32, File)> = Vec::new();
    let mut migration_config: Option<VmMigrationConfig> = None;
    let mut state_bytes: Option<Vec<u8>> = None;

    loop {
        let req = Request::read_from(&mut stream).map_err(|e| anyhow!("reading request: {e:?}"))?;
        debug!("snapshot: received command {:?}", req.command());
        match req.command() {
            Command::MemoryFd => {
                let (slot, file) = recv_memory_fd(&stream)?;
                debug!("snapshot: received memory fd for slot {slot}");
                memory_slots.push((slot, file));
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(|e| anyhow!("ACKing MemoryFd: {e:?}"))?;
            }
            Command::Config => {
                let mut buf = vec![0u8; req.length() as usize];
                stream
                    .read_exact(&mut buf)
                    .context("reading Config payload")?;
                migration_config =
                    Some(serde_json::from_slice(&buf).context("deserializing VmMigrationConfig")?);
                std::fs::write(output_dir.join(MIGRATION_CONFIG_FILENAME), &buf)
                    .context("writing migration_config.json")?;
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(|e| anyhow!("ACKing Config: {e:?}"))?;
            }
            Command::State => {
                let mut buf = vec![0u8; req.length() as usize];
                stream
                    .read_exact(&mut buf)
                    .context("reading State payload")?;
                std::fs::write(output_dir.join(STATE_FILENAME), &buf)
                    .context("writing state.json")?;
                state_bytes = Some(buf);
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(|e| anyhow!("ACKing State: {e:?}"))?;
            }
            Command::CompletePaused | Command::Complete => {
                // Invariant: drain + fsync every memory fd BEFORE ACKing —
                // CH may exit right after and these fds are our only copy.
                let mm = migration_config
                    .as_ref()
                    .ok_or_else(|| anyhow!("completion without preceding Config"))?;
                let _ = state_bytes
                    .as_ref()
                    .ok_or_else(|| anyhow!("completion without preceding State"))?;
                dump_memory_slots(&memory_slots, mm, output_dir)?;
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(|e| anyhow!("ACKing completion: {e:?}"))?;
                info!("snapshot persisted to {output_dir:?}");
                break;
            }
            Command::Abandon => {
                // ACK before bailing so CH's ok_or_abandon read returns
                // cleanly instead of hitting EOF.
                Response::ok().write_to(&mut stream).ok();
                bail!("CH abandoned the snapshot");
            }
            c => bail!("unexpected command {c:?} during snapshot"),
        }
    }

    Ok(())
}

fn expect_command(stream: &mut UnixStream, want: Command, name: &str) -> Result<Request> {
    let req = Request::read_from(stream).map_err(|e| anyhow!("reading {name}: {e:?}"))?;
    if req.command() != want {
        bail!("expected {name}, got {:?}", req.command());
    }
    Ok(req)
}

fn recv_memory_fd(stream: &UnixStream) -> Result<(u32, File)> {
    let mut buf = [0u8; 4];
    let (_n, file) = stream
        .recv_with_fd(&mut buf)
        .map_err(|e| anyhow!("recv_with_fd: {e}"))?;
    let file = file.ok_or_else(|| anyhow!("no fd attached to MemoryFd"))?;
    Ok((u32::from_le_bytes(buf), file))
}

fn dump_memory_slots(
    slots: &[(u32, File)],
    config: &VmMigrationConfig,
    output_dir: &Path,
) -> Result<()> {
    let sizes = slot_sizes(config)?;
    for (expected_slot, _, _) in &sizes {
        if !slots.iter().any(|(s, _)| s == expected_slot) {
            bail!("missing MemoryFd for slot {expected_slot}");
        }
    }
    for (slot, file) in slots {
        let (size, file_offset) = sizes
            .iter()
            .find(|(s, _, _)| s == slot)
            .map(|(_, sz, fo)| (*sz, *fo))
            .ok_or_else(|| anyhow!("slot {slot} not present in MemoryManager state"))?;
        let path = output_dir.join(memory_slot_filename(*slot));
        dump_fd_to_path(file, file_offset, size, &path)
            .with_context(|| format!("dumping slot {slot} to {path:?}"))?;
        debug!("dumped {size} bytes from slot {slot} (fd offset {file_offset:#x}) to {path:?}");
    }
    Ok(())
}

fn dump_fd_to_path(file: &File, src_offset: u64, size: u64, path: &Path) -> Result<()> {
    let mut out = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    out.set_len(size)?;
    // dup so our own offset doesn't disturb CH's view of the shared fd.
    // SAFETY: dup() has no preconditions; result is checked.
    let raw = unsafe { libc::dup(file.as_raw_fd()) };
    if raw < 0 {
        bail!("dup memory fd: {}", std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh fd we now own.
    let mut src = unsafe { File::from_raw_fd(raw) };
    src.seek(SeekFrom::Start(src_offset))?;
    let mut remaining = size;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let want = std::cmp::min(remaining as usize, buf.len());
        src.read_exact(&mut buf[..want])?;
        out.write_all(&buf[..want])?;
        remaining -= want as u64;
    }
    out.sync_all()?;
    Ok(())
}

/// (slot, size, file_offset) per memory slot, parsed via JSON to avoid
/// depending on the private fields of `MemoryManagerSnapshotData`.
///
/// `file_offset` is non-zero when CH splits one memory zone across more
/// than one region (typical for boot RAM > 3 GiB which splits across the
/// below-/above-4G boundary, both regions sharing one backing memfd).
fn slot_sizes(config: &VmMigrationConfig) -> Result<Vec<(u32, u64, u64)>> {
    let value = serde_json::to_value(&config.memory_manager_data)
        .context("serializing memory_manager_data")?;
    let mappings = value
        .get("guest_ram_mappings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("missing guest_ram_mappings"))?;
    let mut out = Vec::new();
    for m in mappings {
        let slot = m
            .get("slot")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("mapping missing slot"))? as u32;
        // This reference daemon doesn't implement virtio-mem snapshot
        // semantics — neither the plugged-blocks state nor the sparse
        // (plugged-only) per-range byte transfer. Treating a virtio-mem
        // slot as a plain memfd would silently lose any plugged-in pages
        // on restore, so refuse rather than corrupt.
        if m.get("virtio_mem")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            bail!(
                "slot {slot} is virtio-mem; the reference offload daemon \
                 does not support virtio-mem snapshot/restore"
            );
        }
        let size = m
            .get("size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("mapping missing size"))?;
        let file_offset = m
            .get("file_offset")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("mapping missing file_offset"))?;
        // CH allocates one fresh memslot per GuestRegionMmap, so each
        // (slot, size, file_offset) appears at most once here.
        out.push((slot, size, file_offset));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Restore mode (migration sender)
// ---------------------------------------------------------------------------

fn run_restore(socket_path: &Path, input_dir: &Path, resume: bool) -> Result<()> {
    let migration_config_bytes = std::fs::read(input_dir.join(MIGRATION_CONFIG_FILENAME))
        .context("reading migration_config.json")?;
    let migration_config: VmMigrationConfig = serde_json::from_slice(&migration_config_bytes)
        .context("deserializing VmMigrationConfig")?;
    let state_bytes =
        std::fs::read(input_dir.join(STATE_FILENAME)).context("reading state.json")?;
    let sizes = slot_sizes(&migration_config)?;

    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to {socket_path:?}"))?;
    info!("offload daemon connected to {socket_path:?}");

    send_request_expect_ok(&mut stream, Request::start(), "Start")?;

    for (slot, size, file_offset) in &sizes {
        let memfd = create_memfd_with_contents(
            &input_dir.join(memory_slot_filename(*slot)),
            *file_offset,
            *size,
            &format!("offload-slot-{slot}"),
        )
        .with_context(|| format!("creating memfd for slot {slot}"))?;
        send_memory_fd(&mut stream, *slot, &memfd)?;
        debug!(
            "restore: sent memory fd for slot {slot} ({size} bytes at fd offset {file_offset:#x})"
        );
    }

    send_payload_expect_ok(
        &mut stream,
        Request::config(migration_config_bytes.len() as u64),
        &migration_config_bytes,
        "Config",
    )?;
    send_payload_expect_ok(
        &mut stream,
        Request::state(state_bytes.len() as u64),
        &state_bytes,
        "State",
    )?;

    let final_req = if resume {
        Request::complete()
    } else {
        Request::complete_paused()
    };
    send_request_expect_ok(&mut stream, final_req, "Complete")?;

    info!("restore replay finished");
    Ok(())
}

fn send_request_expect_ok(stream: &mut UnixStream, req: Request, name: &str) -> Result<()> {
    req.write_to(stream)
        .map_err(|e| anyhow!("sending {name}: {e:?}"))?;
    expect_ok_response(stream, name)
}

fn send_payload_expect_ok(
    stream: &mut UnixStream,
    req: Request,
    payload: &[u8],
    name: &str,
) -> Result<()> {
    req.write_to(stream)
        .map_err(|e| anyhow!("sending {name} header: {e:?}"))?;
    stream
        .write_all(payload)
        .with_context(|| format!("sending {name} payload"))?;
    expect_ok_response(stream, name)
}

fn expect_ok_response(stream: &mut UnixStream, name: &str) -> Result<()> {
    let resp = Response::read_from(stream).map_err(|e| anyhow!("reading {name} ack: {e:?}"))?;
    if resp.status() != Status::Ok {
        bail!("CH rejected {name} (non-OK status)");
    }
    Ok(())
}

fn send_memory_fd(stream: &mut UnixStream, slot: u32, memfd: &File) -> Result<()> {
    Request::memory_fd(std::mem::size_of::<u32>() as u64)
        .write_to(stream)
        .map_err(|e| anyhow!("sending MemoryFd header: {e:?}"))?;
    stream
        .send_with_fd(&slot.to_le_bytes()[..], memfd.as_raw_fd())
        .map_err(|e| anyhow!("sending memory fd: {e}"))?;
    expect_ok_response(stream, "MemoryFd")
}

fn create_empty_memfd(size: u64, name: &str) -> Result<File> {
    let cname = CString::new(name).context("memfd name")?;
    // SAFETY: memfd_create has no preconditions; we check the return value.
    let raw = unsafe { libc::memfd_create(cname.as_ptr(), 0) };
    if raw < 0 {
        bail!("memfd_create: {}", std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh fd we now own.
    let memfd = unsafe { File::from_raw_fd(raw) };
    memfd.set_len(size)?;
    Ok(memfd)
}

fn create_memfd_with_contents(
    src_path: &Path,
    file_offset: u64,
    size: u64,
    name: &str,
) -> Result<File> {
    // CH will mmap the fd at `file_offset` for `size` bytes; size the
    // memfd so that range is in-bounds. Bytes before `file_offset` are
    // zero-filled by memfd_create and never read.
    let mut memfd = create_empty_memfd(file_offset + size, name)?;
    memfd.seek(SeekFrom::Start(file_offset))?;
    let mut src = File::open(src_path).with_context(|| format!("opening {src_path:?}"))?;
    let mut remaining = size;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let want = std::cmp::min(remaining as usize, buf.len());
        src.read_exact(&mut buf[..want])
            .with_context(|| format!("reading from {src_path:?}"))?;
        memfd.write_all(&buf[..want])?;
        remaining -= want as u64;
    }
    memfd.seek(SeekFrom::Start(0))?;
    Ok(memfd)
}
