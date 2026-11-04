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
//! the VM, and `--ondemand` serves pages on demand over the postcopy fault
//! connection instead of preloading them.

use std::ffi::{CString, NulError};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{result, thread};

use clap::{Parser, Subcommand};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_memory::mmap::{MmapRegion, MmapRegionError};
use vm_memory::{
    Address, Bytes, FileOffset, GuestAddress, GuestMemoryError, GuestMemoryRegion, GuestRegionMmap,
    MemoryRegionAddress,
};
use vm_migration::MigratableError;
use vm_migration::protocol::{
    Command, ConnectionRole, MemoryRange, MemoryRangeTable, Request, Response, Status,
};
use vmm::VmMigrationConfig;
use vmm::api::MigrationMode;
use vmm::memory_manager::SNAPSHOT_FILENAME;
use vmm::migration::SNAPSHOT_STATE_FILE;
use vmm::sparse::copy_region;
use vmm_sys_util::errno;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

const MIGRATION_CONFIG_FILENAME: &str = "migration_config.json";
const MEMORY_DIFF_FILENAME: &str = "memory-diff.json";
const MEMORY_CHUNK_SIZE: u64 = 64 << 20;

#[derive(Debug, Error)]
enum Error {
    #[error("Invalid snapshot memory: {0}")]
    InvalidMemory(String),
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
    #[error("Serializing or deserializing snapshot metadata")]
    SnapshotMetadata(#[from] serde_json::Error),
    #[error("Unexpected command {0:?} while expecting {1}")]
    UnexpectedCommand(Command, &'static str),
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
    #[error("Mapping memfd for the on demand slot")]
    Mmap(#[source] MmapRegionError),
    #[error("Guest region does not match the mapped size")]
    GuestRegion,
    #[error("Cloning memfd for mmap")]
    CloneMemfd(#[source] io::Error),
    #[error("Spawning the fault serve thread")]
    SpawnServeThread(#[source] io::Error),
    #[error("The fault serve thread panicked")]
    ServeThreadPanic,
    #[error("PageFault gpa={0:#x} len={1} is not within any slot")]
    PageFaultUnmapped(u64, u64),
    #[error("Writing a faulted page into guest memory")]
    WriteGuestMemory(#[source] GuestMemoryError),
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
        /// On demand paging.
        #[arg(long)]
        ondemand: bool,
        #[arg(long, conflicts_with = "ondemand")]
        copy_on_write: bool,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    match cli.mode {
        Mode::Snapshot { socket, output_dir } => {
            SnapshotDirectory { path: output_dir }.receive(&socket)
        }
        Mode::Restore {
            socket,
            input_dir,
            resume,
            ondemand,
            copy_on_write,
        } => {
            SnapshotDirectory { path: input_dir }.restore(&socket, resume, ondemand, copy_on_write)
        }
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

struct SnapshotDirectory {
    path: PathBuf,
}

impl SnapshotDirectory {
    fn receive(&self, socket_path: &Path) -> Result<()> {
        let output_dir = &self.path;
        fs::create_dir_all(output_dir).map_err(Error::CreateOutputDir)?;
        for filename in [MEMORY_DIFF_FILENAME, SNAPSHOT_FILENAME] {
            if output_dir
                .join(filename)
                .try_exists()
                .map_err(Error::ReadFile)?
            {
                return Err(Error::InvalidMemory(format!(
                    "Snapshot output directory already contains {filename}"
                )));
            }
        }

        // Hold the lock for the daemon's lifetime. While we hold it, any socket at
        // this path is stale from a crashed run, so removing it before bind is safe.
        let _lock = acquire_socket_lock(socket_path)?;
        let _ = fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).map_err(Error::BindSocket)?;
        info!("Offload daemon listening at {socket_path:?}");

        let mut connection = MigrationConnection {
            stream: listener.accept().map_err(Error::Accept)?.0,
        };
        info!("CH connected; starting snapshot receive");

        connection.expect_command(Command::Start, "Start")?;
        Response::ok()
            .write_to(&mut connection.stream)
            .map_err(Error::Protocol)?;

        let mut memory_slots: Vec<(u32, File)> = Vec::new();
        let mut migration_config: Option<VmMigrationConfig> = None;
        let mut state_bytes: Option<Vec<u8>> = None;
        let mut diff_writer: Option<MemoryDiffWriter> = None;

        loop {
            let req = Request::read_from(&mut connection.stream).map_err(Error::Protocol)?;
            debug!("snapshot: received command {:?}", req.command());
            match req.command() {
                Command::MemoryFd => {
                    let (slot, file) = connection.receive_memory_fd()?;
                    debug!("snapshot: received memory fd for slot {slot}");
                    memory_slots.push((slot, file));
                    Response::ok()
                        .write_to(&mut connection.stream)
                        .map_err(Error::Protocol)?;
                }
                Command::Config => {
                    let mut buf = vec![0u8; req.length() as usize];
                    connection
                        .stream
                        .read_exact(&mut buf)
                        .map_err(Error::ReadPayload)?;
                    migration_config = Some(serde_json::from_slice(&buf)?);
                    let config = migration_config.as_ref().unwrap();
                    if config.vm_config().lock().unwrap().backed_by_shared_memory() {
                        fs::write(output_dir.join(MIGRATION_CONFIG_FILENAME), &buf)
                            .map_err(Error::WriteFile)?;
                    } else {
                        self.write_new_artifact(MIGRATION_CONFIG_FILENAME, &buf)?;
                        diff_writer = Some(MemoryDiffWriter::new(config, self, &memory_slots)?);
                    }
                    Response::ok()
                        .write_to(&mut connection.stream)
                        .map_err(Error::Protocol)?;
                }
                Command::Memory => {
                    diff_writer
                        .as_mut()
                        .ok_or(Error::PrematureCompletion("snapshot Config"))?
                        .receive(&mut connection, &req)?;
                    Response::ok()
                        .write_to(&mut connection.stream)
                        .map_err(Error::Protocol)?;
                }
                Command::State => {
                    let mut buf = vec![0u8; req.length() as usize];
                    connection
                        .stream
                        .read_exact(&mut buf)
                        .map_err(Error::ReadPayload)?;
                    if diff_writer.is_some() {
                        self.write_new_artifact(SNAPSHOT_STATE_FILE, &buf)?;
                    } else {
                        fs::write(output_dir.join(SNAPSHOT_STATE_FILE), &buf)
                            .map_err(Error::WriteFile)?;
                    }
                    state_bytes = Some(buf);
                    Response::ok()
                        .write_to(&mut connection.stream)
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
                    if let Some(memory) = diff_writer.take() {
                        memory.finish(self)?;
                    } else {
                        self.dump_memory_slots(&memory_slots, mm)?;
                    }
                    Response::ok()
                        .write_to(&mut connection.stream)
                        .map_err(Error::Protocol)?;
                    info!("Snapshot persisted to {output_dir:?}");
                    break;
                }
                c => return Err(Error::UnexpectedCommand(c, "a snapshot command")),
            }
        }

        Ok(())
    }

    fn restore(
        &self,
        socket_path: &Path,
        resume: bool,
        ondemand: bool,
        copy_on_write: bool,
    ) -> Result<()> {
        let input_dir = &self.path;
        let migration_config_bytes =
            fs::read(input_dir.join(MIGRATION_CONFIG_FILENAME)).map_err(Error::ReadFile)?;
        let mut migration_config: VmMigrationConfig =
            serde_json::from_slice(&migration_config_bytes)?;
        let state_bytes = fs::read(input_dir.join(SNAPSHOT_STATE_FILE)).map_err(Error::ReadFile)?;
        let diff: Option<MemoryDiff> = match File::open(input_dir.join(MEMORY_DIFF_FILENAME)) {
            Ok(file) => Some(serde_json::from_reader(file)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(Error::ReadFile(error)),
        };
        let is_delta = diff.is_some();
        if ondemand && is_delta {
            return Err(Error::InvalidMemory(
                "On-demand restore requires a full offload snapshot".to_owned(),
            ));
        }
        let (backing_files, delta) = if let Some(diff) = diff {
            (Some(diff.backing_files), Some(diff.ranges))
        } else if copy_on_write {
            (Some(self.backing_files(&migration_config)?), None)
        } else {
            (None, None)
        };
        if copy_on_write {
            {
                let mut config = migration_config.vm_config().lock().unwrap();
                let memory = &mut config.memory;
                memory.shared = false;
                memory.hugepages = false;
                memory.hugepage_size = None;
                memory.prefault = false;
                for zone in memory.zones.iter_mut().flatten() {
                    zone.shared = false;
                    zone.hugepages = false;
                    zone.hugepage_size = None;
                    zone.prefault = false;
                }
                config
                    .validate()
                    .map_err(|e| Error::Protocol(MigratableError::MigrateReceive(e.into())))?;
            }
            let backing_files = backing_files.as_ref().unwrap();
            for mapping in migration_config
                .memory_manager_data_mut()
                .guest_ram_mappings_mut()
            {
                let file_offset = backing_files
                    .iter()
                    .find(|memory| memory.gpa == mapping.gpa())
                    .ok_or_else(|| {
                        Error::InvalidMemory(format!(
                            "Missing file offset for guest address {:#x}",
                            mapping.gpa()
                        ))
                    })?
                    .offset;
                mapping.set_file_offset(file_offset);
            }
        }
        migration_config.set_memory_mode(if ondemand {
            MigrationMode::Postcopy
        } else if is_delta && !copy_on_write {
            MigrationMode::Precopy
        } else {
            MigrationMode::MemFDs
        });
        let migration_config_bytes = serde_json::to_vec(&migration_config)?;

        let mut connection = MigrationConnection::connect(socket_path)?;
        info!("Offload daemon connected to {socket_path:?} (ondemand={ondemand})");

        connection.send_request_expect_ok(Request::start(), "Start")?;

        let mut ondemand_slots: Vec<OnDemandSlot> = Vec::new();

        for (slot, gpa, size, file_offset) in slot_info(&migration_config)? {
            if is_delta && !copy_on_write {
                continue;
            }
            let disk_path = input_dir.join(memory_slot_filename(slot));
            let memory_file = if copy_on_write {
                let memory = backing_files
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|memory| memory.gpa == gpa && memory.size == size)
                    .ok_or(Error::MissingSlot(slot))?;
                Arc::new(memory.open()?)
            } else if ondemand {
                let memfd =
                    create_empty_memfd(file_offset + size, &format!("offload-slot-{slot}"))?;
                ondemand_slots.push(OnDemandSlot::new(
                    &memfd,
                    gpa,
                    size,
                    file_offset,
                    &disk_path,
                )?);
                Arc::new(memfd)
            } else {
                Arc::new(
                    MemoryFile {
                        gpa,
                        size,
                        offset: 0,
                        path: disk_path,
                    }
                    .copy_to_memfd(file_offset, &format!("offload-slot-{slot}"))?,
                )
            };
            connection.send_memory_fd(slot, &memory_file)?;
            debug!(
                "restore: sent memory fd for slot {slot} ({size} bytes at fd offset \
                 {file_offset:#x}, ondemand={ondemand})"
            );
        }

        connection.send_payload_expect_ok(
            Request::config(migration_config_bytes.len() as u64),
            &migration_config_bytes,
            "Config",
        )?;

        if is_delta && !copy_on_write {
            let backing_files = backing_files.as_ref().unwrap();
            let mut ranges = MemoryRangeTable::default();
            for (_, gpa, size, _) in slot_info(&migration_config)? {
                ranges.push(MemoryRange { gpa, length: size });
            }
            ranges.sort();
            connection.send_memory_contents(backing_files, ranges)?;
        }
        if let Some(delta) = delta {
            connection.send_memory_contents(&self.memory_files(&migration_config)?, delta)?;
        }

        // For on demand (postcopy) restore the fault connection must be serving before
        // CH processes State, so connect it here and serve on its own thread.
        let serve_handle = if ondemand {
            let slots = Arc::new(ondemand_slots);
            let mut fault_connection = MigrationConnection::connect(socket_path)?;
            ConnectionRole::Fault
                .write_to(&mut fault_connection.stream)
                .map_err(Error::Protocol)?;
            info!(
                "offload daemon: connected dedicated fault connection, serving {} slot(s)",
                slots.len()
            );
            let serve_slots = Arc::clone(&slots);
            let handle = thread::Builder::new()
                .name("offload-fault-serve".to_owned())
                .spawn(move || fault_connection.serve_page_faults(serve_slots.as_slice()))
                .map_err(Error::SpawnServeThread)?;
            Some(handle)
        } else {
            None
        };

        connection.send_payload_expect_ok(
            Request::state(state_bytes.len() as u64),
            &state_bytes,
            "State",
        )?;

        let final_req = if resume {
            Request::complete()
        } else {
            Request::complete_paused()
        };
        connection.send_request_expect_ok(final_req, "Complete")?;

        if let Some(handle) = serve_handle {
            info!("Offload daemon: waiting for fault serving to finish");
            handle.join().map_err(|_| Error::ServeThreadPanic)??;
        }

        info!("Restore replay finished");
        Ok(())
    }

    fn memory_files(&self, config: &VmMigrationConfig) -> Result<Vec<MemoryFile>> {
        Ok(slot_info(config)?
            .into_iter()
            .map(|(slot, gpa, size, _)| MemoryFile {
                gpa,
                size,
                offset: 0,
                path: self.path.join(memory_slot_filename(slot)),
            })
            .collect())
    }

    fn backing_files(&self, config: &VmMigrationConfig) -> Result<Vec<MemoryFile>> {
        let path = self.path.join(SNAPSHOT_FILENAME);
        if path.try_exists().map_err(Error::ReadFile)? {
            let mut slots = slot_info(config)?;
            slots.sort_unstable_by_key(|(_, gpa, _, _)| *gpa);
            let mut offset = 0u64;
            let mut memory = Vec::new();
            for (_, gpa, size, _) in slots {
                memory.push(MemoryFile {
                    gpa,
                    size,
                    offset,
                    path: path.clone(),
                });
                offset = offset.checked_add(size).ok_or_else(|| {
                    Error::InvalidMemory("Snapshot file offset overflow".to_owned())
                })?;
            }
            return Ok(memory);
        }
        self.memory_files(config)
    }

    fn write_new_artifact(&self, filename: &str, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(filename))
            .map_err(Error::WriteFile)?;
        file.write_all(bytes).map_err(Error::WriteFile)?;
        file.sync_all().map_err(Error::WriteFile)
    }

    fn dump_memory_slots(&self, slots: &[(u32, File)], config: &VmMigrationConfig) -> Result<()> {
        let mappings = slot_info(config)?;
        for (expected_slot, _, _, _) in &mappings {
            if !slots.iter().any(|(slot, _)| slot == expected_slot) {
                return Err(Error::MissingSlot(*expected_slot));
            }
        }
        for (slot, file) in slots {
            let (_, gpa, size, file_offset) = mappings
                .iter()
                .find(|(id, _, _, _)| id == slot)
                .ok_or(Error::MissingSlot(*slot))?;
            let memory = MemoryFile {
                gpa: *gpa,
                size: *size,
                offset: 0,
                path: self.path.join(memory_slot_filename(*slot)),
            };
            memory.write_from(file, *file_offset)?;
            debug!(
                "dumped {size} bytes from slot {slot} (fd offset {file_offset:#x}) to {:?}",
                memory.path
            );
        }
        Ok(())
    }
}

struct MemoryDiffWriter {
    files: Vec<(u64, u64, File)>,
    ranges: MemoryRangeTable,
    backing_files: Vec<MemoryFile>,
}

#[derive(Deserialize, Serialize)]
struct MemoryFile {
    gpa: u64,
    size: u64,
    offset: u64,
    path: PathBuf,
}

impl MemoryFile {
    fn open(&self) -> Result<File> {
        let file = File::open(&self.path).map_err(Error::ReadFile)?;
        let metadata = file.metadata().map_err(Error::ReadFile)?;
        if !metadata.is_file()
            || self
                .offset
                .checked_add(self.size)
                .is_none_or(|end| end > metadata.len())
        {
            return Err(Error::InvalidMemory(
                "RAM backing file does not cover guest memory".to_owned(),
            ));
        }
        Ok(file)
    }

    fn write_from(&self, file: &File, src_offset: u64) -> Result<()> {
        let out = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.path)
            .map_err(Error::WriteFile)?;
        out.set_len(self.size).map_err(Error::WriteFile)?;
        // Keep `out` sparse: holes are left as holes (read back as zero).
        copy_region(file, src_offset, &out, self.offset, self.size).map_err(Error::CopyMemory)?;
        out.sync_all().map_err(Error::WriteFile)?;
        Ok(())
    }

    fn copy_to_memfd(&self, file_offset: u64, name: &str) -> Result<File> {
        // Size the memfd to cover the range CH maps at `file_offset`.
        let memfd = create_empty_memfd(file_offset + self.size, name)?;
        let src = File::open(&self.path).map_err(Error::ReadFile)?;
        // Copy sparsely so the memfd keeps the snapshot's holes.
        copy_region(&src, self.offset, &memfd, file_offset, self.size)
            .map_err(Error::CopyMemory)?;
        Ok(memfd)
    }
}

#[derive(Deserialize, Serialize)]
struct MemoryDiff {
    #[serde(rename = "reference")]
    backing_files: Vec<MemoryFile>,
    ranges: MemoryRangeTable,
}

impl MemoryDiffWriter {
    fn new(
        config: &VmMigrationConfig,
        directory: &SnapshotDirectory,
        memory_slots: &[(u32, File)],
    ) -> Result<Self> {
        let mut files = Vec::new();
        let mut backing_files = Vec::new();
        for (slot, gpa, size, offset) in slot_info(config)? {
            let (_, source) = memory_slots
                .iter()
                .find(|(id, _)| *id == slot)
                .ok_or(Error::MissingSlot(slot))?;
            let memory = MemoryFile {
                gpa,
                size,
                offset,
                path: fs::read_link(format!("/proc/self/fd/{}", source.as_raw_fd()))
                    .map_err(Error::ReadFile)?,
            };
            let actual = source.metadata().map_err(Error::ReadFile)?;
            let backing = memory.open()?.metadata().map_err(Error::ReadFile)?;
            if (actual.dev(), actual.ino()) != (backing.dev(), backing.ino()) {
                return Err(Error::InvalidMemory(format!(
                    "Backing file for slot {slot} is no longer available"
                )));
            }
            backing_files.push(memory);
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.path.join(memory_slot_filename(slot)))
                .map_err(Error::WriteFile)?;
            file.set_len(size).map_err(Error::WriteFile)?;
            files.push((gpa, size, file));
        }
        Ok(Self {
            files,
            ranges: MemoryRangeTable::default(),
            backing_files,
        })
    }

    fn receive(&mut self, connection: &mut MigrationConnection, request: &Request) -> Result<()> {
        let ranges = MemoryRangeTable::read_from(&mut connection.stream, request.length())
            .map_err(Error::Protocol)?;
        let mut buffer = vec![0u8; 64 << 10];
        for range in ranges.ranges() {
            let (gpa, _, file) = self
                .files
                .iter()
                .find(|(gpa, size, _)| {
                    range.gpa >= *gpa
                        && range.length <= *size
                        && range.gpa - gpa <= size - range.length
                })
                .ok_or_else(|| {
                    Error::InvalidMemory(format!(
                        "Unmapped memory range at {:#x} of length {}",
                        range.gpa, range.length
                    ))
                })?;
            let mut copied = 0;
            while copied < range.length {
                let count = (range.length - copied).min(buffer.len() as u64) as usize;
                connection
                    .stream
                    .read_exact(&mut buffer[..count])
                    .map_err(Error::ReadPayload)?;
                file.write_all_at(&buffer[..count], range.gpa - gpa + copied)
                    .map_err(Error::WriteFile)?;
                copied += count as u64;
            }
            self.ranges.push(*range);
        }
        Ok(())
    }

    fn finish(mut self, directory: &SnapshotDirectory) -> Result<()> {
        self.ranges.sort();
        for (_, _, file) in &self.files {
            file.sync_all().map_err(Error::WriteFile)?;
        }
        directory.write_new_artifact(
            MEMORY_DIFF_FILENAME,
            &serde_json::to_vec(&MemoryDiff {
                backing_files: self.backing_files,
                ranges: self.ranges,
            })?,
        )?;
        File::open(&directory.path)
            .and_then(|file| file.sync_all())
            .map_err(Error::WriteFile)
    }
}

fn slot_info(config: &VmMigrationConfig) -> Result<Vec<(u32, u64, u64, u64)>> {
    parse_guest_ram_mappings(&serde_json::to_value(config.memory_manager_data())?)
}

/// Parse the `guest_ram_mappings` array out of the serialized
/// `MemoryManagerSnapshotData`.
fn parse_guest_ram_mappings(value: &serde_json::Value) -> Result<Vec<(u32, u64, u64, u64)>> {
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
        let gpa = m
            .get("gpa")
            .and_then(|v| v.as_u64())
            .ok_or(Error::MissingField("gpa"))?;
        let size = m
            .get("size")
            .and_then(|v| v.as_u64())
            .ok_or(Error::MissingField("size"))?;
        let file_offset = m
            .get("file_offset")
            .and_then(|v| v.as_u64())
            .ok_or(Error::MissingField("file_offset"))?;
        // CH allocates one fresh memslot per GuestRegionMmap, so each
        // (slot, gpa, size, file_offset) appears at most once here.
        out.push((slot, gpa, size, file_offset));
    }
    Ok(out)
}

struct MigrationConnection {
    stream: UnixStream,
}

impl MigrationConnection {
    fn connect(path: &Path) -> Result<Self> {
        Ok(Self {
            stream: UnixStream::connect(path).map_err(Error::Connect)?,
        })
    }

    fn expect_command(&mut self, want: Command, name: &'static str) -> Result<Request> {
        let req = Request::read_from(&mut self.stream).map_err(Error::Protocol)?;
        if req.command() != want {
            return Err(Error::UnexpectedCommand(req.command(), name));
        }
        Ok(req)
    }

    fn receive_memory_fd(&mut self) -> Result<(u32, File)> {
        let mut buf = [0u8; 4];
        let (_n, file) = self
            .stream
            .recv_with_fd(&mut buf)
            .map_err(Error::RecvMemoryFd)?;
        let file = file.ok_or(Error::MissingMemoryFd)?;
        Ok((u32::from_le_bytes(buf), file))
    }

    fn send_request_expect_ok(&mut self, req: Request, name: &'static str) -> Result<()> {
        req.write_to(&mut self.stream).map_err(Error::Protocol)?;
        self.expect_ok_response(name)
    }

    fn send_payload_expect_ok(
        &mut self,
        req: Request,
        payload: &[u8],
        name: &'static str,
    ) -> Result<()> {
        req.write_to(&mut self.stream).map_err(Error::Protocol)?;
        self.stream
            .write_all(payload)
            .map_err(Error::WritePayload)?;
        self.expect_ok_response(name)
    }

    fn expect_ok_response(&mut self, name: &'static str) -> Result<()> {
        let resp = Response::read_from(&mut self.stream).map_err(Error::Protocol)?;
        if resp.status() != Status::Ok {
            return Err(Error::Rejected(name));
        }
        Ok(())
    }

    fn send_memory_fd(&mut self, slot: u32, file: &File) -> Result<()> {
        Request::memory_fd(size_of::<u32>() as u64)
            .write_to(&mut self.stream)
            .map_err(Error::Protocol)?;
        self.stream
            .send_with_fd(&slot.to_le_bytes()[..], file.as_raw_fd())
            .map_err(Error::SendMemoryFd)?;
        self.expect_ok_response("MemoryFd")
    }

    fn send_memory_contents(
        &mut self,
        memory: &[MemoryFile],
        ranges: MemoryRangeTable,
    ) -> Result<()> {
        if ranges.ranges().iter().any(|range| {
            range.gpa.checked_add(range.length).is_none()
                || range.length.checked_add(MEMORY_CHUNK_SIZE).is_none()
        }) {
            return Err(Error::InvalidMemory("Memory range overflow".to_owned()));
        }
        let mut buffer = vec![0u8; 64 << 10];
        for chunk in ranges.partition(MEMORY_CHUNK_SIZE) {
            Request::memory(chunk.length())
                .write_to(&mut self.stream)
                .map_err(Error::Protocol)?;
            for range in chunk.ranges() {
                range.write_to(&mut self.stream).map_err(Error::Protocol)?;
            }
            for range in chunk.ranges() {
                let memory = memory
                    .iter()
                    .find(|memory| {
                        range.gpa >= memory.gpa
                            && range.length <= memory.size
                            && range.gpa - memory.gpa <= memory.size - range.length
                    })
                    .ok_or_else(|| {
                        Error::InvalidMemory(format!(
                            "Unmapped memory range at {:#x} of length {}",
                            range.gpa, range.length
                        ))
                    })?;
                let file = memory.open()?;
                let mut copied = 0;
                while copied < range.length {
                    let count = (range.length - copied).min(buffer.len() as u64) as usize;
                    file.read_exact_at(
                        &mut buffer[..count],
                        memory.offset + (range.gpa - memory.gpa) + copied,
                    )
                    .map_err(Error::ReadFile)?;
                    self.stream
                        .write_all(&buffer[..count])
                        .map_err(Error::WritePayload)?;
                    copied += count as u64;
                }
            }
            self.expect_ok_response("Memory")?;
        }
        Ok(())
    }

    fn serve_page_faults(&mut self, slots: &[OnDemandSlot]) -> Result<()> {
        let mut served: u64 = 0;
        loop {
            let req = match Request::read_from(&mut self.stream) {
                Ok(r) => r,
                Err(e) => {
                    info!("Serve loop: socket closed after {served} PageFault(s) ({e:?})");
                    return Ok(());
                }
            };
            match req.command() {
                Command::PageFault => {
                    let range =
                        MemoryRange::read_from(&mut self.stream).map_err(Error::Protocol)?;
                    served += 1;
                    if served <= 5 || served.is_power_of_two() {
                        info!(
                            "PageFault #{served}: gpa={:#x} len={}",
                            range.gpa, range.length
                        );
                    }
                    let slot = slots
                        .iter()
                        .find(|s| s.contains(range.gpa, range.length))
                        .ok_or(Error::PageFaultUnmapped(range.gpa, range.length))?;
                    let offset = range.gpa - slot.region.start_addr().raw_value();
                    // Reading a sparse hole returns zeros, so a single read+write
                    // path covers both data and unwritten pages.
                    let mut buf = vec![0u8; range.length as usize];
                    slot.disk
                        .read_exact_at(&mut buf, offset)
                        .map_err(Error::CopyMemory)?;
                    slot.region
                        .write_slice(&buf, MemoryRegionAddress(offset))
                        .map_err(Error::WriteGuestMemory)?;
                    Response::ok()
                        .write_to(&mut self.stream)
                        .map_err(Error::Protocol)?;
                }
                c => return Err(Error::UnexpectedCommand(c, "a PageFault")),
            }
        }
    }
}

/// Per-slot state for serving PageFault requests in on demand mode.
struct OnDemandSlot {
    region: GuestRegionMmap,
    disk: File,
}

impl OnDemandSlot {
    fn new(memfd: &File, gpa: u64, size: u64, file_offset: u64, disk_path: &Path) -> Result<Self> {
        // Map the same memfd CH maps, so our page writes are visible to it.
        let fo = FileOffset::new(memfd.try_clone().map_err(Error::CloneMemfd)?, file_offset);
        let mmap = MmapRegion::build(
            Some(fo),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
        )
        .map_err(Error::Mmap)?;
        let region = GuestRegionMmap::new(mmap, GuestAddress(gpa)).ok_or(Error::GuestRegion)?;
        let disk = File::open(disk_path).map_err(Error::ReadFile)?;
        Ok(Self { region, disk })
    }

    fn contains(&self, gpa: u64, len: u64) -> bool {
        let base = self.region.start_addr().raw_value();
        let end = base + self.region.len();
        gpa >= base && gpa.saturating_add(len) <= end
    }
}

fn create_empty_memfd(size: u64, name: &str) -> Result<File> {
    let cname = CString::new(name).map_err(Error::MemfdName)?;
    // SAFETY: memfd_create has no preconditions. We check the return value.
    let raw = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(Error::MemfdCreate(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh fd we now own.
    let memfd = unsafe { File::from_raw_fd(raw) };
    memfd.set_len(size).map_err(Error::MemfdSetLen)?;
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
                { "slot": 0, "gpa": 0u64, "size": 4096u64, "file_offset": 0u64, "virtio_mem": true },
                { "slot": 1, "gpa": 0x4000u64, "size": 8192u64, "file_offset": 4096u64 },
            ]
        });
        assert_eq!(
            parse_guest_ram_mappings(&value).unwrap(),
            vec![(0, 0, 4096, 0), (1, 0x4000, 8192, 4096)]
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
        let value = json!({ "guest_ram_mappings": [{ "slot": 0, "gpa": 0u64, "size": 4096u64 }] });
        assert!(matches!(
            parse_guest_ram_mappings(&value),
            Err(Error::MissingField("file_offset"))
        ));
    }
}
