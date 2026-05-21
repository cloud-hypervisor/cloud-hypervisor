// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Reference offload daemon for Cloud Hypervisor snapshot/restore.
//!
//! It acts as the local live-migration peer of CH's existing
//! `vm.send-migration` and `vm.receive-migration` endpoints, persisting the
//! migration stream to a directory and replaying it later.
//!
//! Snapshot (daemon receives): writes each guest RAM slot to `memory-<slot>`,
//! the `VmMigrationConfig` to `migration_config.json`, and the device state to
//! `state.json`.
//!
//! Restore (daemon sends): replays those files back to CH. `--resume` resumes
//! the VM instead of leaving it paused.

use std::ffi::{CString, NulError};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::result;

use clap::{Parser, Subcommand};
use log::{debug, info};
use thiserror::Error;
use vm_migration::MigratableError;
use vm_migration::protocol::{Command, Request, Response, Status};
use vmm::VmMigrationConfig;
use vmm::migration::SNAPSHOT_STATE_FILE;
use vmm_sys_util::errno;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

const MIGRATION_CONFIG_FILENAME: &str = "migration_config.json";

#[derive(Debug, Error)]
enum Error {
    #[error("Creating the output directory")]
    CreateOutputDir(#[source] io::Error),
    #[error("Opening the socket lock file")]
    OpenLockFile(#[source] io::Error),
    #[error("Socket {0:?} is already in use by another daemon")]
    SocketInUse(PathBuf),
    #[error("Locking the socket")]
    LockSocket(#[source] io::Error),
    #[error("Binding the UNIX socket")]
    BindSocket(#[source] io::Error),
    #[error("Connecting to the CH socket")]
    Connect(#[source] io::Error),
    #[error("Accepting CH connection")]
    Accept(#[source] io::Error),
    #[error("Migration protocol")]
    Protocol(#[source] MigratableError),
    #[error("Receiving memory fd")]
    RecvMemoryFd(#[source] errno::Error),
    #[error("MemoryFd command carried no file descriptor")]
    MissingMemoryFd,
    #[error("Sending memory fd")]
    SendMemoryFd(#[source] errno::Error),
    #[error("Reading a snapshot artifact")]
    ReadFile(#[source] io::Error),
    #[error("Writing a snapshot artifact")]
    WriteFile(#[source] io::Error),
    #[error("Reading migration payload")]
    ReadPayload(#[source] io::Error),
    #[error("Sending migration payload")]
    WritePayload(#[source] io::Error),
    #[error("(De)serializing VmMigrationConfig")]
    Config(#[from] serde_json::Error),
    #[error("Unexpected command {0:?} while expecting {1}")]
    UnexpectedCommand(Command, &'static str),
    #[error("CH abandoned the snapshot")]
    Abandoned,
    #[error("CH rejected the {0} command")]
    Rejected(&'static str),
    #[error("Completion received before {0}")]
    PrematureCompletion(&'static str),
    #[error("Creating memfd")]
    MemfdCreate(#[source] io::Error),
    #[error("Invalid memfd name")]
    MemfdName(#[source] NulError),
    #[error("Sizing memfd")]
    MemfdSetLen(#[source] io::Error),
    #[error("Copying snapshot memory")]
    CopyMemory(#[source] io::Error),
    #[error("No MemoryFd received for slot {0}")]
    MissingSlot(u32),
    #[error("Field {0:?} missing from memory_manager_data")]
    MissingField(&'static str),
}

type Result<T> = result::Result<T, Error>;

fn memory_slot_filename(slot: u32) -> String {
    format!("memory-{slot}")
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

/// Take an exclusive lock on `<socket>.lock` so two daemons can't bind the same
/// socket, and so removing a stale socket file is safe.
fn acquire_socket_lock(socket_path: &Path) -> Result<File> {
    let lock_path: PathBuf = {
        let mut p = socket_path.as_os_str().to_os_string();
        p.push(".lock");
        p.into()
    };
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(Error::OpenLockFile)?;

    let flock = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0, // 0 means the whole file.
        l_pid: 0,
    };
    loop {
        // SAFETY: fcntl() with F_OFD_SETLK and a valid flock pointer on an owned fd.
        if unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_OFD_SETLK, &flock) } == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Interrupted by a signal before the lock was taken: retry.
            Some(libc::EINTR) => continue,
            // The lock is held by another daemon.
            Some(libc::EACCES) | Some(libc::EAGAIN) => {
                return Err(Error::SocketInUse(socket_path.to_path_buf()));
            }
            _ => return Err(Error::LockSocket(err)),
        }
    }
    Ok(lock)
}

// Snapshot mode (migration receiver).
fn run_snapshot(socket_path: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(Error::CreateOutputDir)?;

    // Hold the lock for the daemon's lifetime. While we hold it, any socket at
    // this path is stale from a crashed run, so removing it before bind is safe.
    let _lock = acquire_socket_lock(socket_path)?;
    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(Error::BindSocket)?;
    info!("Offload daemon listening at {socket_path:?}");

    let (mut stream, _) = listener.accept().map_err(Error::Accept)?;
    info!("CH connected; starting snapshot receive");

    expect_command(&mut stream, Command::Start, "Start")?;
    Response::ok()
        .write_to(&mut stream)
        .map_err(Error::Protocol)?;

    let mut memory_slots: Vec<(u32, File)> = Vec::new();
    let mut migration_config: Option<VmMigrationConfig> = None;
    let mut state_bytes: Option<Vec<u8>> = None;

    loop {
        let req = Request::read_from(&mut stream).map_err(Error::Protocol)?;
        debug!("snapshot: received command {:?}", req.command());
        match req.command() {
            Command::MemoryFd => {
                let (slot, file) = recv_memory_fd(&stream)?;
                debug!("snapshot: received memory fd for slot {slot}");
                memory_slots.push((slot, file));
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(Error::Protocol)?;
            }
            Command::Config => {
                let mut buf = vec![0u8; req.length() as usize];
                stream.read_exact(&mut buf).map_err(Error::ReadPayload)?;
                migration_config = Some(serde_json::from_slice(&buf)?);
                fs::write(output_dir.join(MIGRATION_CONFIG_FILENAME), &buf)
                    .map_err(Error::WriteFile)?;
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(Error::Protocol)?;
            }
            Command::State => {
                let mut buf = vec![0u8; req.length() as usize];
                stream.read_exact(&mut buf).map_err(Error::ReadPayload)?;
                fs::write(output_dir.join(SNAPSHOT_STATE_FILE), &buf).map_err(Error::WriteFile)?;
                state_bytes = Some(buf);
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(Error::Protocol)?;
            }
            Command::CompletePaused | Command::Complete => {
                // Invariant: drain + fsync every memory fd BEFORE ACKing —
                // CH may exit right after and these fds are our only copy.
                let mm = migration_config
                    .as_ref()
                    .ok_or(Error::PrematureCompletion("Config"))?;
                let _ = state_bytes
                    .as_ref()
                    .ok_or(Error::PrematureCompletion("State"))?;
                dump_memory_slots(&memory_slots, mm, output_dir)?;
                Response::ok()
                    .write_to(&mut stream)
                    .map_err(Error::Protocol)?;
                info!("Snapshot persisted to {output_dir:?}");
                break;
            }
            Command::Abandon => {
                // ACK before bailing so CH's ok_or_abandon read returns
                // cleanly instead of hitting EOF.
                Response::ok().write_to(&mut stream).ok();
                return Err(Error::Abandoned);
            }
            c => return Err(Error::UnexpectedCommand(c, "a snapshot command")),
        }
    }

    Ok(())
}

fn expect_command(stream: &mut UnixStream, want: Command, name: &'static str) -> Result<Request> {
    let req = Request::read_from(stream).map_err(Error::Protocol)?;
    if req.command() != want {
        return Err(Error::UnexpectedCommand(req.command(), name));
    }
    Ok(req)
}

fn recv_memory_fd(stream: &UnixStream) -> Result<(u32, File)> {
    let mut buf = [0u8; 4];
    let (_n, file) = stream.recv_with_fd(&mut buf).map_err(Error::RecvMemoryFd)?;
    let file = file.ok_or(Error::MissingMemoryFd)?;
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
            return Err(Error::MissingSlot(*expected_slot));
        }
    }
    for (slot, file) in slots {
        let (size, file_offset) = sizes
            .iter()
            .find(|(s, _, _)| s == slot)
            .map(|(_, sz, fo)| (*sz, *fo))
            .ok_or(Error::MissingSlot(*slot))?;
        let path = output_dir.join(memory_slot_filename(*slot));
        dump_fd_to_path(file, file_offset, size, &path)?;
        debug!("dumped {size} bytes from slot {slot} (fd offset {file_offset:#x}) to {path:?}");
    }
    Ok(())
}

fn dump_fd_to_path(file: &File, src_offset: u64, size: u64, path: &Path) -> Result<()> {
    let mut out = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(Error::WriteFile)?;
    out.set_len(size).map_err(Error::WriteFile)?;
    // dup so our own offset doesn't disturb CH's view of the shared fd.
    // SAFETY: dup() has no preconditions; result is checked.
    let raw = unsafe { libc::dup(file.as_raw_fd()) };
    if raw < 0 {
        return Err(Error::CopyMemory(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh fd we now own.
    let mut src = unsafe { File::from_raw_fd(raw) };
    src.seek(SeekFrom::Start(src_offset))
        .map_err(Error::CopyMemory)?;
    let mut remaining = size;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        src.read_exact(&mut buf[..want])
            .map_err(Error::CopyMemory)?;
        out.write_all(&buf[..want]).map_err(Error::CopyMemory)?;
        remaining -= want as u64;
    }
    out.sync_all().map_err(Error::WriteFile)?;
    Ok(())
}

/// (slot, size, file_offset) per memory slot, parsed via JSON to avoid
/// depending on the private fields of `MemoryManagerSnapshotData`.
///
/// `file_offset` is non-zero when a zone spans multiple regions sharing one
/// backing memfd.
fn slot_sizes(config: &VmMigrationConfig) -> Result<Vec<(u32, u64, u64)>> {
    parse_guest_ram_mappings(&serde_json::to_value(config.memory_manager_data())?)
}

/// Parse the `guest_ram_mappings` array out of the serialized
/// `MemoryManagerSnapshotData`.
fn parse_guest_ram_mappings(value: &serde_json::Value) -> Result<Vec<(u32, u64, u64)>> {
    let mappings = value
        .get("guest_ram_mappings")
        .and_then(|v| v.as_array())
        .ok_or(Error::MissingField("guest_ram_mappings"))?;
    let mut out = Vec::new();
    for m in mappings {
        let slot = m
            .get("slot")
            .and_then(|v| v.as_u64())
            .ok_or(Error::MissingField("slot"))? as u32;
        let size = m
            .get("size")
            .and_then(|v| v.as_u64())
            .ok_or(Error::MissingField("size"))?;
        let file_offset = m
            .get("file_offset")
            .and_then(|v| v.as_u64())
            .ok_or(Error::MissingField("file_offset"))?;
        // CH allocates one fresh memslot per GuestRegionMmap, so each
        // (slot, size, file_offset) appears at most once here.
        out.push((slot, size, file_offset));
    }
    Ok(out)
}

// Restore mode (migration sender).
fn run_restore(socket_path: &Path, input_dir: &Path, resume: bool) -> Result<()> {
    let migration_config_bytes =
        fs::read(input_dir.join(MIGRATION_CONFIG_FILENAME)).map_err(Error::ReadFile)?;
    let migration_config: VmMigrationConfig = serde_json::from_slice(&migration_config_bytes)?;
    let state_bytes = fs::read(input_dir.join(SNAPSHOT_STATE_FILE)).map_err(Error::ReadFile)?;
    let sizes = slot_sizes(&migration_config)?;

    let mut stream = UnixStream::connect(socket_path).map_err(Error::Connect)?;
    info!("Offload daemon connected to {socket_path:?}");

    send_request_expect_ok(&mut stream, Request::start(), "Start")?;

    for (slot, size, file_offset) in &sizes {
        let memfd = create_memfd_with_contents(
            &input_dir.join(memory_slot_filename(*slot)),
            *file_offset,
            *size,
            &format!("offload-slot-{slot}"),
        )?;
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

    info!("Restore replay finished");
    Ok(())
}

fn send_request_expect_ok(stream: &mut UnixStream, req: Request, name: &'static str) -> Result<()> {
    req.write_to(stream).map_err(Error::Protocol)?;
    expect_ok_response(stream, name)
}

fn send_payload_expect_ok(
    stream: &mut UnixStream,
    req: Request,
    payload: &[u8],
    name: &'static str,
) -> Result<()> {
    req.write_to(stream).map_err(Error::Protocol)?;
    stream.write_all(payload).map_err(Error::WritePayload)?;
    expect_ok_response(stream, name)
}

fn expect_ok_response(stream: &mut UnixStream, name: &'static str) -> Result<()> {
    let resp = Response::read_from(stream).map_err(Error::Protocol)?;
    if resp.status() != Status::Ok {
        return Err(Error::Rejected(name));
    }
    Ok(())
}

fn send_memory_fd(stream: &mut UnixStream, slot: u32, memfd: &File) -> Result<()> {
    Request::memory_fd(size_of::<u32>() as u64)
        .write_to(stream)
        .map_err(Error::Protocol)?;
    stream
        .send_with_fd(&slot.to_le_bytes()[..], memfd.as_raw_fd())
        .map_err(Error::SendMemoryFd)?;
    expect_ok_response(stream, "MemoryFd")
}

fn create_empty_memfd(size: u64, name: &str) -> Result<File> {
    let cname = CString::new(name).map_err(Error::MemfdName)?;
    // SAFETY: memfd_create has no preconditions. We check the return value.
    let raw = unsafe { libc::memfd_create(cname.as_ptr(), 0) };
    if raw < 0 {
        return Err(Error::MemfdCreate(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh fd we now own.
    let memfd = unsafe { File::from_raw_fd(raw) };
    memfd.set_len(size).map_err(Error::MemfdSetLen)?;
    Ok(memfd)
}

fn create_memfd_with_contents(
    src_path: &Path,
    file_offset: u64,
    size: u64,
    name: &str,
) -> Result<File> {
    // Size the memfd to cover the range CH maps at `file_offset`.
    let mut memfd = create_empty_memfd(file_offset + size, name)?;
    memfd
        .seek(SeekFrom::Start(file_offset))
        .map_err(Error::CopyMemory)?;
    let mut src = File::open(src_path).map_err(Error::ReadFile)?;
    let mut remaining = size;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        src.read_exact(&mut buf[..want])
            .map_err(Error::CopyMemory)?;
        memfd.write_all(&buf[..want]).map_err(Error::CopyMemory)?;
        remaining -= want as u64;
    }
    memfd.seek(SeekFrom::Start(0)).map_err(Error::CopyMemory)?;
    Ok(memfd)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_memory_slot_filename() {
        assert_eq!(memory_slot_filename(0), "memory-0");
        assert_eq!(memory_slot_filename(13), "memory-13");
    }

    #[test]
    fn test_parse_guest_ram_mappings() {
        let value = json!({
            "guest_ram_mappings": [
                { "slot": 0, "size": 4096u64, "file_offset": 0u64, "virtio_mem": true },
                { "slot": 1, "size": 8192u64, "file_offset": 4096u64 },
            ]
        });
        assert_eq!(
            parse_guest_ram_mappings(&value).unwrap(),
            vec![(0, 4096, 0), (1, 8192, 4096)]
        );
    }

    #[test]
    fn test_parse_guest_ram_mappings_missing_array() {
        let value = json!({});
        assert!(matches!(
            parse_guest_ram_mappings(&value),
            Err(Error::MissingField("guest_ram_mappings"))
        ));
    }

    #[test]
    fn test_parse_guest_ram_mappings_missing_field() {
        let value = json!({ "guest_ram_mappings": [{ "slot": 0, "size": 4096u64 }] });
        assert!(matches!(
            parse_guest_ram_mappings(&value),
            Err(Error::MissingField("file_offset"))
        ));
    }
}
