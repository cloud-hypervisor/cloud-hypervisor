// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write, stdout};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::panic::AssertUnwindSafe;
#[cfg(feature = "guest_debug")]
use std::path::PathBuf;
#[cfg(feature = "guest_debug")]
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender, channel};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use std::{any, io, mem, panic, path, process, result, thread};

use anyhow::{Context, anyhow};
#[cfg(feature = "dbus_api")]
use api::dbus::{DBusApiOptions, DBusApiShutdownChannels};
use api::http::HttpApiHandle;
use console_devices::{ConsoleInfo, pre_create_console_devices};
use event_monitor::event;
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use hypervisor::arch::x86;
use landlock::LandlockError;
use libc::{EFD_NONBLOCK, SIGINT, SIGTERM, TCSANOW, tcsetattr, termios};
use log::{debug, error, info, warn};
use memory_manager::MemoryManagerSnapshotData;
use pci::PciBdf;
use seccompiler::{BpfProgram, SeccompAction, apply_filter};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use signal_hook::iterator::{Handle, Signals};
use thiserror::Error;
use tracer::trace_scoped;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::protocol::*;
use vm_migration::{
    MemoryMigrationContext, Migratable, MigratableError, OngoingMigrationContext, Pausable,
    Snapshot, Snapshottable, Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::unblock_signal;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::api::{
    ApiRequest, ApiResponse, MigrationMode, RequestHandler, TimeoutStrategy, VmInfoResponse,
    VmReceiveMigrationData, VmSendMigrationData, VmmPingResponse,
};
use crate::config::{MemoryRestoreMode, RestoreConfig, add_to_config};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::GuestDebuggable;
use crate::device_manager::DeviceManager;
use crate::landlock::Landlock;
use crate::memory_manager::MemoryManager;
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use crate::migration::get_vm_snapshot;
use crate::migration::transport::{
    self, ReceiveAdditionalConnections, ReceiveListener, SendAdditionalConnections, SocketStream,
};
use crate::migration::worker::{
    MigrationSeccompFilters, MigrationWorker, MigrationWorkerHandle, MigrationWorkerResult,
};
use crate::migration::{recv_vm_config, recv_vm_state};
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::vm::{Error as VmError, Vm, VmState};
use crate::vm_config::{
    DeviceConfig, DiskConfig, FsConfig, GenericVhostUserConfig, NetConfig, PmemConfig,
    UserDeviceConfig, VdpaConfig, VmConfig, VsockConfig,
};

mod acpi;
pub mod api;
mod clone3;
pub mod config;
pub mod console_devices;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
mod coredump;
pub mod cpu;
pub mod device_manager;
pub mod device_tree;
#[cfg(feature = "guest_debug")]
mod gdb;
#[cfg(feature = "igvm")]
mod igvm;
pub mod interrupt;
pub mod landlock;
pub mod memory_manager;
pub mod migration;
mod pci_segment;
pub mod seccomp_filters;
mod serial_manager;
#[cfg(all(feature = "kvm", feature = "sev_snp", feature = "fw_cfg"))]
pub(crate) mod sev;
mod sigwinch_listener;
pub mod sparse;
mod sync_utils;
mod uffd;
mod userfaultfd;
pub mod vm;
pub mod vm_config;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;

/// Errors associated with VMM management
#[derive(Debug, Error)]
pub enum Error {
    /// API request receive error
    #[error("Error receiving API request")]
    ApiRequestRecv(#[source] RecvError),

    /// API response send error
    #[error("Error sending API request")]
    ApiResponseSend(#[source] SendError<ApiResponse>),

    /// Cannot bind to the UNIX domain socket path
    #[error("Error binding to UNIX domain socket")]
    Bind(#[source] io::Error),

    /// Cannot clone EventFd.
    #[error("Error cloning EventFd")]
    EventFdClone(#[source] io::Error),

    /// Cannot create EventFd.
    #[error("Error creating EventFd")]
    EventFdCreate(#[source] io::Error),

    /// Cannot read from EventFd.
    #[error("Error reading from EventFd")]
    EventFdRead(#[source] io::Error),

    /// Cannot create epoll context.
    #[error("Error creating epoll context")]
    Epoll(#[source] io::Error),

    /// Cannot create HTTP thread
    #[error("Error spawning HTTP thread")]
    HttpThreadSpawn(#[source] io::Error),

    /// Cannot create D-Bus thread
    #[cfg(feature = "dbus_api")]
    #[error("Error spawning D-Bus thread")]
    DBusThreadSpawn(#[source] io::Error),

    /// Cannot start D-Bus session
    #[cfg(feature = "dbus_api")]
    #[error("Error starting D-Bus session")]
    CreateDBusSession(#[source] zbus::Error),

    /// Cannot create `event-monitor` thread
    #[error("Error spawning `event-monitor` thread")]
    EventMonitorThreadSpawn(#[source] io::Error),

    /// Cannot handle the VM STDIN stream
    #[error("Error handling VM stdin")]
    Stdin(#[source] VmError),

    /// Cannot handle the VM pty stream
    #[error("Error handling VM pty")]
    Pty(#[source] VmError),

    /// Cannot reboot the VM
    #[error("Error rebooting VM")]
    VmReboot(#[source] VmError),

    /// Cannot shut the VM down
    #[error("Error shutting down VM")]
    VmShutdown(#[source] VmError),

    /// Cannot create VMM thread
    #[error("Error spawning VMM thread")]
    VmmThreadSpawn(#[source] io::Error),

    /// Cannot shut the VMM down
    #[error("Error shutting down VMM")]
    VmmShutdown(#[source] VmError),

    /// Cannot create seccomp filter
    #[error("Error creating seccomp filter")]
    CreateSeccompFilter(#[source] seccompiler::Error),

    /// Cannot apply seccomp filter
    #[error("Error applying seccomp filter")]
    ApplySeccompFilter(#[source] seccompiler::Error),

    /// Error activating virtio devices
    #[error("Error activating virtio devices")]
    ActivateVirtioDevices(#[source] VmError),

    /// Error creating API server
    // TODO We should add #[source] here once the type implements Error.
    // Then we also can remove the `: {}` to align with the other errors.
    #[error("Error creating API server: {0}")]
    CreateApiServer(micro_http::ServerError),

    /// Error binding API server socket
    #[error("Error creation API server's socket")]
    CreateApiServerSocket(#[source] io::Error),

    /// The API server socket is already in use by another running instance
    #[error("API socket {0:?} is already in use by another running instance")]
    ApiSocketInUse(path::PathBuf),

    #[cfg(feature = "guest_debug")]
    #[error("Failed to start the GDB thread")]
    GdbThreadSpawn(#[source] io::Error),

    /// GDB request receive error
    #[cfg(feature = "guest_debug")]
    #[error("Error receiving GDB request")]
    GdbRequestRecv(#[source] RecvError),

    /// GDB response send error
    #[cfg(feature = "guest_debug")]
    #[error("Error sending GDB request")]
    GdbResponseSend(#[source] SendError<gdb::GdbResponse>),

    #[error("Cannot spawn a signal handler thread")]
    SignalHandlerSpawn(#[source] io::Error),

    #[error("Failed to join on threads: {0:?}")]
    ThreadCleanup(Box<dyn any::Any + Send>),

    /// Cannot create Landlock object
    #[error("Error creating landlock object")]
    CreateLandlock(#[source] LandlockError),

    /// Cannot apply landlock based sandboxing
    #[error("Error applying landlock")]
    ApplyLandlock(#[source] LandlockError),
}

impl From<&VmConfig> for hypervisor::HypervisorVmConfig {
    fn from(_value: &VmConfig) -> Self {
        hypervisor::HypervisorVmConfig {
            #[cfg(feature = "tdx")]
            tdx_enabled: _value.platform.as_ref().is_some_and(|p| p.tdx),
            #[cfg(feature = "sev_snp")]
            sev_snp_enabled: _value.is_sev_snp_enabled(),
            #[cfg(feature = "sev_snp")]
            mem_size: _value.memory.total_size(),
            #[cfg(feature = "sev_snp")]
            vmsa_features: 0,
            nested: _value.cpus.nested,
            smt_enabled: _value
                .cpus
                .topology
                .as_ref()
                .is_some_and(|t| t.threads_per_core > 1),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EpollDispatch {
    Exit = 0,
    Reset = 1,
    Api = 2,
    ActivateVirtioDevices = 3,
    Debug = 4,
    GuestExit = 5,
    CheckMigration = 6,
    Unknown,
}

impl From<u64> for EpollDispatch {
    fn from(v: u64) -> Self {
        use EpollDispatch::*;
        match v {
            0 => Exit,
            1 => Reset,
            2 => Api,
            3 => ActivateVirtioDevices,
            4 => Debug,
            5 => GuestExit,
            6 => CheckMigration,
            _ => Unknown,
        }
    }
}

pub struct EpollContext {
    epoll_file: File,
}

impl EpollContext {
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let epoll_fd = epoll::create(true)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: the epoll_fd returned by epoll::create is valid and owned by us.
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        Ok(EpollContext { epoll_file })
    }

    pub fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        let dispatch_index = token as u64;
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;

        Ok(())
    }

    #[cfg(fuzzing)]
    pub fn add_event_custom<T>(
        &mut self,
        fd: &T,
        id: u64,
        evts: epoll::Events,
    ) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(evts, id),
        )?;

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}

pub struct PciDeviceInfo {
    pub id: String,
    pub bdf: PciBdf,
}

impl Serialize for PciDeviceInfo {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bdf_str = self.bdf.to_string();

        // Serialize the structure.
        let mut state = serializer.serialize_struct("PciDeviceInfo", 2)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("bdf", &bdf_str)?;
        state.end()
    }
}

pub fn feature_list() -> Vec<String> {
    vec![
        #[cfg(feature = "dbus_api")]
        "dbus_api".to_string(),
        #[cfg(feature = "dhat-heap")]
        "dhat-heap".to_string(),
        #[cfg(feature = "fw_cfg")]
        "fw_cfg".to_string(),
        #[cfg(feature = "guest_debug")]
        "guest_debug".to_string(),
        #[cfg(feature = "igvm")]
        "igvm".to_string(),
        #[cfg(feature = "io_uring")]
        "io_uring".to_string(),
        #[cfg(feature = "kvm")]
        "kvm".to_string(),
        #[cfg(feature = "mshv")]
        "mshv".to_string(),
        #[cfg(feature = "sev_snp")]
        "sev_snp".to_string(),
        #[cfg(feature = "tdx")]
        "tdx".to_string(),
        #[cfg(feature = "tracing")]
        "tracing".to_string(),
        #[cfg(feature = "ivshmem")]
        "ivshmem".to_string(),
    ]
}

pub fn start_event_monitor_thread(
    mut monitor: event_monitor::Monitor,
    seccomp_action: &SeccompAction,
    landlock_enable: bool,
    exit_event: EventFd,
) -> Result<thread::JoinHandle<Result<()>>> {
    // Retrieve seccomp filter
    let seccomp_filter = get_seccomp_filter(seccomp_action, Thread::EventMonitor, None)
        .map_err(Error::CreateSeccompFilter)?;

    thread::Builder::new()
        .name("event-monitor".to_owned())
        .spawn(move || {
            // Apply seccomp filter
            if !seccomp_filter.is_empty() {
                apply_filter(&seccomp_filter)
                    .map_err(Error::ApplySeccompFilter)
                    .inspect_err(|e| {
                        error!("Error applying seccomp filter: {e:?}");
                        exit_event.write(1).ok();
                    })?;
            }
            if landlock_enable {
                Landlock::new()
                    .map_err(Error::CreateLandlock)?
                    .restrict_self()
                    .map_err(Error::ApplyLandlock)
                    .inspect_err(|e| {
                        error!("Error applying landlock to event monitor thread: {e:?}");
                        exit_event.write(1).ok();
                    })?;
            }

            panic::catch_unwind(AssertUnwindSafe(move || {
                while let Ok(event) = monitor.rx.recv() {
                    let event = Arc::new(event);

                    if let Some(ref mut file) = monitor.file {
                        file.write_all(event.as_bytes().as_ref()).ok();
                        file.write_all(b"\n\n").ok();
                    }

                    for tx in monitor.broadcast.iter() {
                        tx.send(event.clone()).ok();
                    }
                }
            }))
            .map_err(|_| {
                error!("`event-monitor` thread panicked");
                exit_event.write(1).ok();
            })
            .ok();

            Ok(())
        })
        .map_err(Error::EventMonitorThreadSpawn)
}

#[expect(clippy::too_many_arguments)]
pub fn start_vmm_thread(
    vmm_version: VmmVersionInfo,
    http_path: &Option<String>,
    http_fd: Option<RawFd>,
    #[cfg(feature = "dbus_api")] dbus_options: Option<DBusApiOptions>,
    api_event: EventFd,
    api_sender: Sender<ApiRequest>,
    api_receiver: Receiver<ApiRequest>,
    #[cfg(feature = "guest_debug")] debug_path: Option<PathBuf>,
    #[cfg(feature = "guest_debug")] debug_event: EventFd,
    #[cfg(feature = "guest_debug")] vm_debug_event: EventFd,
    exit_event: EventFd,
    seccomp_action: &SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    no_shutdown: bool,
    landlock_enable: bool,
) -> Result<VmmThreadHandle> {
    #[cfg(feature = "guest_debug")]
    let gdb_hw_breakpoints = hypervisor.get_guest_debug_hw_bps();
    #[cfg(feature = "guest_debug")]
    let (gdb_sender, gdb_receiver) = mpsc::channel();
    #[cfg(feature = "guest_debug")]
    let gdb_debug_event = debug_event.try_clone().map_err(Error::EventFdClone)?;
    #[cfg(feature = "guest_debug")]
    let gdb_vm_debug_event = vm_debug_event.try_clone().map_err(Error::EventFdClone)?;

    let api_event_clone = api_event.try_clone().map_err(Error::EventFdClone)?;
    let hypervisor_type = hypervisor.hypervisor_type();

    // Retrieve seccomp filter
    let vmm_seccomp_filter = get_seccomp_filter(seccomp_action, Thread::Vmm, Some(hypervisor_type))
        .map_err(Error::CreateSeccompFilter)?;

    let vmm_seccomp_action = seccomp_action.clone();
    let thread = {
        let exit_event = exit_event.try_clone().map_err(Error::EventFdClone)?;
        thread::Builder::new()
            .name("vmm".to_string())
            .spawn(move || {
                // Apply seccomp filter for VMM thread.
                if !vmm_seccomp_filter.is_empty() {
                    apply_filter(&vmm_seccomp_filter).map_err(Error::ApplySeccompFilter)?;
                }

                let mut vmm = Vmm::new(
                    vmm_version,
                    api_event,
                    #[cfg(feature = "guest_debug")]
                    debug_event,
                    #[cfg(feature = "guest_debug")]
                    vm_debug_event,
                    vmm_seccomp_action,
                    hypervisor,
                    exit_event,
                    no_shutdown,
                )?;

                vmm.setup_signal_handler(landlock_enable)?;

                vmm.control_loop(
                    &api_receiver,
                    #[cfg(feature = "guest_debug")]
                    &gdb_receiver,
                )
            })
            .map_err(Error::VmmThreadSpawn)?
    };

    // The VMM thread is started, we can start the dbus thread
    // and start serving HTTP requests
    #[cfg(feature = "dbus_api")]
    let dbus_shutdown_chs = match dbus_options {
        Some(opts) => {
            let (_, chs) = api::start_dbus_thread(
                opts,
                api_event_clone.try_clone().map_err(Error::EventFdClone)?,
                api_sender.clone(),
                seccomp_action,
                exit_event.try_clone().map_err(Error::EventFdClone)?,
            )?;
            Some(chs)
        }
        None => None,
    };

    let http_api_handle = if let Some(http_path) = http_path {
        Some(api::start_http_path_thread(
            http_path,
            api_event_clone,
            api_sender,
            seccomp_action,
            exit_event,
            landlock_enable,
        )?)
    } else if let Some(http_fd) = http_fd {
        Some(api::start_http_fd_thread(
            http_fd,
            api_event_clone,
            api_sender,
            seccomp_action,
            exit_event,
            landlock_enable,
        )?)
    } else {
        None
    };

    #[cfg(feature = "guest_debug")]
    if let Some(debug_path) = debug_path {
        let target = gdb::GdbStub::new(
            gdb_sender,
            gdb_debug_event,
            gdb_vm_debug_event,
            gdb_hw_breakpoints,
        );
        thread::Builder::new()
            .name("gdb".to_owned())
            .spawn(move || gdb::gdb_thread(target, &debug_path))
            .map_err(Error::GdbThreadSpawn)?;
    }

    Ok(VmmThreadHandle {
        thread_handle: thread,
        #[cfg(feature = "dbus_api")]
        dbus_shutdown_chs,
        http_api_handle,
    })
}

/// Measures the time of the callback, in case it returns `Ok`.
fn measure_ok<T, E, F>(f: F) -> result::Result<(T, Duration), E>
where
    F: FnOnce() -> result::Result<T, E>,
{
    let begin = Instant::now();
    let value = f()?;
    let duration = begin.elapsed();
    Ok((value, duration))
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VmMigrationConfig {
    vm_config: Arc<Mutex<VmConfig>>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    common_cpuid: Vec<x86::CpuIdEntry>,
    memory_manager_data: MemoryManagerSnapshotData,
}

impl VmMigrationConfig {
    pub fn memory_manager_data(&self) -> &MemoryManagerSnapshotData {
        &self.memory_manager_data
    }
}

#[derive(Debug, Clone)]
pub struct VmmVersionInfo {
    pub build_version: String,
    pub version: String,
}

impl VmmVersionInfo {
    pub fn new(build_version: &str, version: &str) -> Self {
        Self {
            build_version: build_version.to_owned(),
            version: version.to_owned(),
        }
    }
}

pub struct VmmThreadHandle {
    pub thread_handle: thread::JoinHandle<Result<()>>,
    #[cfg(feature = "dbus_api")]
    pub dbus_shutdown_chs: Option<DBusApiShutdownChannels>,
    pub http_api_handle: Option<HttpApiHandle>,
}

/// Models the current ownership and associated state of the VM from the
/// perspective of the VMM.
enum VmOwnership {
    Owned(Vm),
    /// The VM is temporarily owned by an ongoing migration worker.
    ///
    /// We deliberately do not use shared access to the VM to prevent a whole
    /// class of race conditions.
    Migration {
        migration_worker_handle: MigrationWorkerHandle,
        /// Snapshot returned while the VMM cannot inspect the worker-owned VM.
        vm_info_response: VmInfoResponse,
        /// Access to VM state needed during migration.
        device_manager: Weak<Mutex<DeviceManager>>,
    },
    None,
}

impl VmOwnership {
    /// Returns a mutable reference to the underlying VM, if available.
    fn as_mut(&mut self) -> Option<&mut Vm> {
        match self {
            VmOwnership::Owned(vm) => Some(vm),
            _ => None,
        }
    }

    /// Takes the inner VM if it is currently owned.
    fn take_owned_or(&mut self, none_error: VmError) -> result::Result<Vm, VmError> {
        match mem::replace(self, VmOwnership::None) {
            VmOwnership::Owned(vm) => Ok(vm),
            old @ VmOwnership::Migration { .. } => {
                *self = old;
                Err(VmError::VmMigrating)
            }
            VmOwnership::None => Err(none_error),
        }
    }
}

pub struct Vmm {
    epoll: EpollContext,
    exit_evt: EventFd,
    reset_evt: EventFd,
    guest_exit_evt: EventFd,
    api_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    debug_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    vm_debug_evt: EventFd,
    version: VmmVersionInfo,
    vm: VmOwnership,
    vm_config: Option<Arc<Mutex<VmConfig>>>,
    seccomp_action: SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    activate_evt: EventFd,
    signals: Option<Handle>,
    threads: Vec<thread::JoinHandle<()>>,
    original_termios_opt: Arc<Mutex<Option<termios>>>,
    console_resize_pipe: Option<Arc<File>>,
    console_info: Option<ConsoleInfo>,
    no_shutdown: bool,
    check_migration_evt: EventFd,
}

/// Time before aborting on the page fault connection.
const FAULT_CONNECTION_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Just a wrapper for the data that goes into
/// [`ReceiveMigrationState::Configured`]
struct ReceiveMigrationConfiguredData {
    memory_manager: Arc<Mutex<MemoryManager>>,
    guest_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    connections: ReceiveAdditionalConnections,
    shared_backing: bool,
    fault_rx: Receiver<SocketStream>,
}

/// The receiver's state machine behind the migration protocol.
enum ReceiveMigrationState {
    /// The connection is established and we haven't received any commands yet.
    Established,

    /// We received the start command.
    Started,

    /// We received file descriptors for memory. This can only happen on UNIX domain sockets.
    MemoryFdsReceived(Vec<(u32, File)>),

    /// We received the VM configuration. We keep a direct reference to the guest memory
    /// around to populate it without having to acquire a lock (which we would have to do
    /// when accessing the memory through the memory manager).
    ///
    /// We keep the memory manager around to pass it into the next state. From this point
    /// on, the sender can start sending memory updates.
    Configured(ReceiveMigrationConfiguredData),

    /// Memory is populated and we received the state. The VM is ready to go.
    StateReceived {
        /// The timestamp where the VMM started to receive the final state.
        state_receive_begin: Instant,
    },

    /// The migration is successful.
    Completed,

    /// The migration couldn't complete, either due to an error or because the sender abandoned the migration.
    Aborted,
}

impl ReceiveMigrationState {
    fn variant_name(&self) -> &'static str {
        match self {
            ReceiveMigrationState::Established => "Established",
            ReceiveMigrationState::Started => "Started",
            ReceiveMigrationState::MemoryFdsReceived(_) => "MemoryFdsReceived",
            ReceiveMigrationState::Configured(_) => "Configured",
            ReceiveMigrationState::StateReceived { .. } => "StateReceived",
            ReceiveMigrationState::Completed => "Completed",
            ReceiveMigrationState::Aborted => "Aborted",
        }
    }

    fn finished(&self) -> bool {
        matches!(
            self,
            ReceiveMigrationState::Completed | ReceiveMigrationState::Aborted
        )
    }
}

impl Vmm {
    pub const HANDLED_SIGNALS: [i32; 2] = [SIGTERM, SIGINT];

    fn signal_handler(
        mut signals: Signals,
        original_termios_opt: &Mutex<Option<termios>>,
        exit_evt: &EventFd,
    ) {
        for sig in &Self::HANDLED_SIGNALS {
            unblock_signal(*sig).unwrap();
        }

        for signal in signals.forever() {
            match signal {
                #[expect(clippy::collapsible_match)]
                SIGTERM | SIGINT => {
                    if exit_evt.write(1).is_err() {
                        // Resetting the terminal is usually done as the VMM exits
                        if let Ok(lock) = original_termios_opt.lock() {
                            if let Some(termios) = *lock {
                                // SAFETY: FFI call
                                let _ = unsafe {
                                    tcsetattr(stdout().lock().as_raw_fd(), TCSANOW, &termios)
                                };
                            }
                        } else {
                            warn!("Failed to lock original termios");
                        }

                        process::exit(1);
                    }
                }
                _ => (),
            }
        }
    }

    fn setup_signal_handler(&mut self, landlock_enable: bool) -> Result<()> {
        let signals = Signals::new(Self::HANDLED_SIGNALS);
        match signals {
            Ok(signals) => {
                self.signals = Some(signals.handle());
                let exit_evt = self.exit_evt.try_clone().map_err(Error::EventFdClone)?;
                let original_termios_opt = Arc::clone(&self.original_termios_opt);

                let signal_handler_seccomp_filter =
                    get_seccomp_filter(&self.seccomp_action, Thread::SignalHandler, None)
                        .map_err(Error::CreateSeccompFilter)?;
                self.threads.push(
                    thread::Builder::new()
                        .name("vmm_signal_handler".to_string())
                        .spawn(move || {
                            if !signal_handler_seccomp_filter.is_empty() && let Err(e) = apply_filter(&signal_handler_seccomp_filter)
                                    .map_err(Error::ApplySeccompFilter)
                                {
                                    error!("Error applying seccomp filter: {e:?}");
                                    exit_evt.write(1).ok();
                                    return;
                                }

                            if landlock_enable{
                                match Landlock::new() {
                                    Ok(landlock) => {
                                        let _ = landlock.restrict_self().map_err(Error::ApplyLandlock).map_err(|e| {
                                            error!("Error applying Landlock to signal handler thread: {e:?}");
                                            exit_evt.write(1).ok();
                                        });
                                    }
                                    Err(e) => {
                                        error!("Error creating Landlock object: {e:?}");
                                        exit_evt.write(1).ok();
                                    }
                                }
                            }

                            panic::catch_unwind(AssertUnwindSafe(|| {
                                Vmm::signal_handler(signals, original_termios_opt.as_ref(), &exit_evt);
                            }))
                            .map_err(|_| {
                                error!("vmm signal_handler thread panicked");
                                exit_evt.write(1).ok()
                            })
                            .ok();
                        })
                        .map_err(Error::SignalHandlerSpawn)?,
                );
            }
            Err(e) => error!("Signal not found {e}"),
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        vmm_version: VmmVersionInfo,
        api_evt: EventFd,
        #[cfg(feature = "guest_debug")] debug_evt: EventFd,
        #[cfg(feature = "guest_debug")] vm_debug_evt: EventFd,
        seccomp_action: SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        exit_evt: EventFd,
        no_shutdown: bool,
    ) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let guest_exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let activate_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let check_migration_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        epoll
            .add_event(&exit_evt, EpollDispatch::Exit)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&reset_evt, EpollDispatch::Reset)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&guest_exit_evt, EpollDispatch::GuestExit)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&activate_evt, EpollDispatch::ActivateVirtioDevices)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&api_evt, EpollDispatch::Api)
            .map_err(Error::Epoll)?;

        #[cfg(feature = "guest_debug")]
        epoll
            .add_event(&debug_evt, EpollDispatch::Debug)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&check_migration_evt, EpollDispatch::CheckMigration)
            .map_err(Error::Epoll)?;

        Ok(Vmm {
            epoll,
            exit_evt,
            reset_evt,
            guest_exit_evt,
            api_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            version: vmm_version,
            vm: VmOwnership::None,
            vm_config: None,
            seccomp_action,
            hypervisor,
            activate_evt,
            signals: None,
            threads: vec![],
            original_termios_opt: Arc::new(Mutex::new(None)),
            console_resize_pipe: None,
            console_info: None,
            no_shutdown,
            check_migration_evt,
        })
    }

    /// Try to receive a file descriptor from a socket. Returns the slot number and the file descriptor.
    fn vm_receive_memory_fd(
        socket: &mut SocketStream,
    ) -> result::Result<(u32, File), MigratableError> {
        if let SocketStream::Unix(unix_socket) = socket {
            let mut buf = [0u8; 4];
            let (_, file) = unix_socket
                .recv_with_fd(&mut buf)
                .context("Error receiving slot from socket")
                .map_err(MigratableError::MigrateReceive)?;

            file.ok_or_else(|| MigratableError::MigrateReceive(anyhow!("Failed to receive socket")))
                .map(|file| (u32::from_le_bytes(buf), file))
        } else {
            Err(MigratableError::MigrateReceive(anyhow!(
                "Unsupported socket type"
            )))
        }
    }

    /// Handle a migration command and advance the protocol state machine.
    ///
    /// **Note**: This function is responsible for consuming any payloads! It also must
    /// _not_ write any response to the socket.
    fn vm_receive_migration_step(
        &mut self,
        socket: &mut SocketStream,
        listener: &ReceiveListener,
        state: ReceiveMigrationState,
        req: &Request,
        receive_data_migration: &VmReceiveMigrationData,
    ) -> result::Result<ReceiveMigrationState, MigratableError> {
        use ReceiveMigrationState::*;

        let invalid_command = |state: &str, cmd: Command| {
            Err(MigratableError::MigrateReceive(anyhow!(
                "Can't handle command {cmd:?} in current receive state {state}"
            )))
        };

        let mode = receive_data_migration.memory_mode;
        let mut configure_vm =
            |socket: &mut SocketStream,
             memory_files: HashMap<u32, File>|
             -> result::Result<ReceiveMigrationConfiguredData, MigratableError> {
                let shared_backing = !memory_files.is_empty();
                let memory_manager = self.vm_receive_config(req, socket, memory_files, mode)?;
                let guest_memory = memory_manager.lock().unwrap().guest_memory();
                // Create the additional-connection receiver even in the single-connection case.
                // At this point the receiver does not know whether the sender will use extra TCP
                // connections. If it does not, no worker connections are accepted and memory
                // requests continue to arrive on the main connection.
                // The accept thread hands the page fault connection back via this channel.
                let (fault_tx, fault_rx) = channel();
                let connections = listener.try_clone().and_then(|l| {
                    ReceiveAdditionalConnections::new(
                        l,
                        guest_memory.clone(),
                        fault_tx,
                        &self.seccomp_action,
                    )
                })?;
                Ok(ReceiveMigrationConfiguredData {
                    memory_manager,
                    guest_memory,
                    connections,
                    shared_backing,
                    fault_rx,
                })
            };

        let recv_memory_fd = |socket: &mut SocketStream,
                              mut memory_files: Vec<(u32, File)>|
         -> result::Result<Vec<(u32, File)>, MigratableError> {
            let (slot, file) = Self::vm_receive_memory_fd(socket)?;

            memory_files.push((slot, file));
            Ok(memory_files)
        };

        if req.command() == Command::Abandon {
            info!("Abandon Command Received");
            return Ok(Aborted);
        }

        let state_name = state.variant_name();
        match state {
            Established => match req.command() {
                Command::Start => {
                    let migration_protocol_version = req.sender_protocol_version()?;
                    debug!("Using migration protocol {migration_protocol_version}");
                    Ok(Started)
                }
                c => invalid_command(state_name, c),
            },
            Started => match req.command() {
                Command::MemoryFd => recv_memory_fd(socket, Vec::new()).map(MemoryFdsReceived),
                Command::Config => configure_vm(socket, Default::default()).map(Configured),
                c => invalid_command(state_name, c),
            },
            MemoryFdsReceived(memory_files) => match req.command() {
                Command::MemoryFd => recv_memory_fd(socket, memory_files).map(MemoryFdsReceived),
                Command::Config => {
                    configure_vm(socket, HashMap::from_iter(memory_files)).map(Configured)
                }
                c => invalid_command(state_name, c),
            },
            Configured(mut config_data) => match req.command() {
                // Memory commands use the main connection only in the single-connection case.
                // When multiple TCP connections are configured, the worker connections carry
                // all memory commands and the main connection is used only for control traffic.
                Command::Memory => {
                    transport::receive_memory_ranges(&config_data.guest_memory, req, socket)
                    .inspect_err(|_| {
                        // connections.cleanup() already logs all errors that occurred in one of the
                        // threads. Furthermore, this path is only taken in the single-connection case,
                        // thus we do not expect any errors during this cleanup. The warning should
                        // reflect that.
                        if let Err(e) = config_data.connections.cleanup() {
                            warn!(
                                "Unexpected error while cleaning up migration connections after a main-connection memory receive failure: {e}"
                            );
                        }
                    })?;
                    Ok(Configured(config_data))
                }
                Command::State => {
                    self.vm_receive_state_command(req, socket, config_data, receive_data_migration)
                }
                c => invalid_command(state_name, c),
            },
            StateReceived {
                state_receive_begin,
            } => match req.command() {
                Command::CompletePaused => {
                    debug!("Migration (incoming): Receiving final state of a paused VM");
                    Ok(Completed)
                }
                Command::Complete => {
                    let vm = self
                        .vm
                        .as_mut()
                        .expect("VM should have been created by now");
                    let (_, resume_duration) = measure_ok(|| vm.resume())?;
                    debug!(
                        "Migration (incoming): resume:{}ms",
                        resume_duration.as_millis()
                    );
                    // This logs the downtime without the final memory delta, so
                    // it does not reflect the actual downtime. While we could
                    // pass along the timestamp from when the VM was paused,
                    // that would rely on both VM hosts having synchronized
                    // clocks, which we cannot guarantee. For that reason, this
                    // is logged as debug! rather than info!.
                    debug!(
                        "Migration (incoming): Receiving final state and resuming the VM took {}ms",
                        state_receive_begin.elapsed().as_millis()
                    );
                    Ok(Completed)
                }
                c => invalid_command(state_name, c),
            },
            Completed | Aborted => {
                unreachable!("Performed a step on the finished state machine")
            }
        }
    }

    fn vm_receive_state_command(
        &mut self,
        req: &Request,
        socket: &mut SocketStream,
        mut config_data: ReceiveMigrationConfiguredData,
        receive_data_migration: &VmReceiveMigrationData,
    ) -> result::Result<ReceiveMigrationState, MigratableError> {
        let state_receive_begin = Instant::now();

        // Serve faults before restore so accesses during restore resolve on demand.
        if matches!(receive_data_migration.memory_mode, MigrationMode::Postcopy) {
            let shared_backing = config_data.shared_backing;
            let fault_stream = config_data
                .fault_rx
                .recv_timeout(FAULT_CONNECTION_ACCEPT_TIMEOUT)
                .map_err(|e| {
                    config_data.connections.cleanup().ok();
                    MigratableError::MigrateReceive(anyhow!(
                        "Timed out waiting for postcopy fault connection: {e}"
                    ))
                })?;
            let mm = config_data.memory_manager.clone();
            let saved_regions = mm.lock().unwrap().memory_range_table(false)?;
            mm.lock()
                .unwrap()
                .start_postcopy_serving(
                    &saved_regions,
                    shared_backing,
                    fault_stream,
                    &self.exit_evt,
                )
                .map_err(|e| {
                    config_data.connections.cleanup().ok();
                    MigratableError::MigrateReceive(anyhow!("start_postcopy_serving: {e:?}"))
                })?;
        }

        // The fault connection is in hand, so stop the accept thread.
        config_data.connections.cleanup()?;

        let (recv_state_dur, restore_vm_dur) =
            self.vm_receive_state(req, socket, config_data.memory_manager)?;
        debug!(
            "Migration (incoming): recv_snapshot:{}ms restore:{}ms",
            recv_state_dur.as_millis(),
            restore_vm_dur.as_millis(),
        );

        Ok(ReceiveMigrationState::StateReceived {
            state_receive_begin,
        })
    }

    fn vm_receive_config<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        existing_memory_files: HashMap<u32, File>,
        mode: MigrationMode,
    ) -> result::Result<Arc<Mutex<MemoryManager>>, MigratableError>
    where
        T: Read,
    {
        // Read in config data along with memory manager data
        let mut data: Vec<u8> = Vec::new();
        data.resize_with(req.length() as usize, Default::default);
        socket
            .read_exact(&mut data)
            .map_err(MigratableError::MigrateSocket)?;

        let vm_migration_config: VmMigrationConfig = serde_json::from_slice(&data)
            .context("Error deserialising config")
            .map_err(MigratableError::MigrateReceive)?;

        // Eager prefault populates memory before UFFD is registered, so those
        // pages never fault and are never served. Reject postcopy+prefault
        // rather than serve stale data.
        if matches!(mode, MigrationMode::Postcopy) {
            let memory = &vm_migration_config.vm_config.lock().unwrap().memory;
            let prefault_enabled = memory.prefault
                || memory
                    .zones
                    .as_ref()
                    .is_some_and(|zones| zones.iter().any(|zone| zone.prefault));
            if prefault_enabled {
                return Err(MigratableError::MigrateReceive(anyhow!(
                    "postcopy migration is incompatible with memory prefault; \
                     the source VM must not be configured with prefault=on"
                )));
            }
        }

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        self.vm_check_cpuid_compatibility(
            &vm_migration_config.vm_config,
            &vm_migration_config.common_cpuid,
        )?;

        let config = vm_migration_config.vm_config.clone();
        self.vm_config = Some(vm_migration_config.vm_config);
        self.console_info = Some(
            pre_create_console_devices(self)
                .context("Error creating console devices")
                .map_err(MigratableError::MigrateReceive)?,
        );

        if self
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .landlock_enable
        {
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            apply_landlock(&mut config)
                .context("Error applying landlock")
                .map_err(MigratableError::MigrateReceive)?;
        }

        let vm = Vm::create_hypervisor_vm(
            self.hypervisor.as_ref(),
            (&*self.vm_config.as_ref().unwrap().lock().unwrap()).into(),
        )
        .map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error creating hypervisor VM from snapshot: {e:?}"
            ))
        })?;

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        if config.lock().unwrap().max_apic_id() > arch::x86_64::MAX_SUPPORTED_CPUS_LEGACY {
            vm.enable_x2apic_api().unwrap();
        }

        let phys_bits = vm::physical_bits(
            self.hypervisor.as_ref(),
            config.lock().unwrap().cpus.max_phys_bits,
        );

        let memory_manager = MemoryManager::new(
            vm,
            &config.lock().unwrap().memory.clone(),
            None,
            phys_bits,
            #[cfg(feature = "tdx")]
            false,
            Some(&vm_migration_config.memory_manager_data),
            existing_memory_files,
        )
        .context("Error creating MemoryManager from snapshot")
        .map_err(MigratableError::MigrateReceive)?;

        Ok(memory_manager)
    }

    /// Receives the final VM state (devices, vCPUs) and restores the VM.
    ///
    /// Measures the time for each step.
    fn vm_receive_state<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        mm: Arc<Mutex<MemoryManager>>,
    ) -> result::Result<
        (
            Duration, /* state receive + deserialize */
            Duration, /* restoring */
        ),
        MigratableError,
    >
    where
        T: Read,
    {
        let (snapshot, receive_duration): (Snapshot, Duration) = measure_ok(|| {
            let mut data: Vec<u8> = Vec::new();
            data.resize_with(req.length() as usize, Default::default);
            socket
                .read_exact(&mut data)
                .map_err(MigratableError::MigrateSocket)?;
            serde_json::from_slice(&data)
                .context("Error deserialising snapshot")
                .map_err(MigratableError::MigrateReceive)
        })?;

        let exit_evt = self
            .exit_evt
            .try_clone()
            .context("Error cloning exit EventFd")
            .map_err(MigratableError::MigrateReceive)?;
        let reset_evt = self
            .reset_evt
            .try_clone()
            .context("Error cloning reset EventFd")
            .map_err(MigratableError::MigrateReceive)?;
        let guest_exit_evt = self
            .guest_exit_evt
            .try_clone()
            .context("Error cloning guest exit EventFd")
            .map_err(MigratableError::MigrateReceive)?;
        #[cfg(feature = "guest_debug")]
        let debug_evt = self
            .vm_debug_evt
            .try_clone()
            .context("Error cloning debug EventFd")
            .map_err(MigratableError::MigrateReceive)?;
        let activate_evt = self
            .activate_evt
            .try_clone()
            .context("Error cloning activate EventFd")
            .map_err(MigratableError::MigrateReceive)?;

        let (vm, restore_duration) = measure_ok(|| {
            #[cfg(not(target_arch = "riscv64"))]
            let timestamp = Instant::now();
            let hypervisor_vm = mm.lock().unwrap().vm.clone();

            let mut vm = Vm::new_from_memory_manager(
                self.vm_config.clone().unwrap(),
                mm,
                hypervisor_vm,
                exit_evt,
                reset_evt,
                guest_exit_evt,
                #[cfg(feature = "guest_debug")]
                debug_evt,
                &self.seccomp_action,
                self.hypervisor.clone(),
                activate_evt,
                #[cfg(not(target_arch = "riscv64"))]
                timestamp,
                self.console_info.clone(),
                self.console_resize_pipe.clone(),
                Arc::clone(&self.original_termios_opt),
                Some(&snapshot),
                #[cfg(feature = "igvm")]
                None,
            )
            .map_err(|e| {
                MigratableError::MigrateReceive(anyhow!("Error creating VM from snapshot: {e:?}"))
            })?;

            // Create VM
            vm.restore().map_err(|e| {
                MigratableError::MigrateReceive(anyhow!("Failed restoring the Vm: {e}"))
            })?;

            Ok(vm)
        })?;

        self.vm = VmOwnership::Owned(vm);

        Ok((receive_duration, restore_duration))
    }

    /// Performs the initial memory transmission (iteration zero) plus a
    /// variable number of memory iterations with the goal to eventually migrate
    /// the VM in a reasonably small downtime.
    ///
    /// This returns as soon as the precopy migration indicates it is converged
    /// (e.g., reasonably small downtime) is reached.
    fn do_memory_iterations(
        vm: &mut Vm,
        socket: &mut SocketStream,
        ctx: &mut MemoryMigrationContext,
        is_converged: impl Fn(&MemoryMigrationContext) -> result::Result<bool, MigratableError>,
        mem_send: &mut SendAdditionalConnections,
    ) -> result::Result<MemoryRangeTable /* remaining */, MigratableError> {
        loop {
            let iteration_begin = Instant::now();

            let iteration_table = if ctx.iteration == 0 {
                vm.memory_range_table()?
            } else {
                // TODO do this in a thread #7816
                vm.dirty_log()?
            };

            ctx.update_metrics_before_transfer(iteration_begin, &iteration_table);
            if is_converged(ctx)? {
                debug!("Precopy converged: {ctx}");
                break Ok(iteration_table);
            }

            // Send the current dirty pages
            let transfer_begin = Instant::now();
            mem_send.send_memory(iteration_table, socket)?;
            let transfer_duration = transfer_begin.elapsed();
            ctx.update_metrics_after_transfer(transfer_begin, transfer_duration);

            // Log progress of the current iteration
            debug!("Precopy: {ctx}");

            // Enables management software (e.g., libvirt) to easily track forward progress.
            event!(
                "vm",
                "migration-memory-iteration",
                "id",
                ctx.iteration.to_string()
            );

            // Increment iteration last: This way we ensure that the logging
            // above matches the actual iteration.
            ctx.iteration += 1;
        }
    }

    /// Checks whether the precopy memory migration has converged and it is safe
    /// to proceed to the final (paused) memory iteration.
    ///
    /// Once this returns, the VM is expected to stop as soon as possible.
    ///
    /// Convergence is reached when any of the following criteria is met:
    ///
    /// 1. **No dirty pages remain** – the current iteration would transfer zero
    ///    bytes.
    /// 2. **Downtime budget is met** – the estimated downtime for the final
    ///    (paused) iteration is within the caller-specified
    ///    [`VmSendMigrationData::downtime`] budget.
    /// 3. **Timeout** – the precopy phase has been running for at least
    ///    [`VmSendMigrationData::timeout`]. The outcome depends on
    ///    [`VmSendMigrationData::timeout_strategy`]:
    ///    - [`TimeoutStrategy::Cancel`] – returns
    ///    - [`TimeoutStrategy::Ignore`] – the migration completes despite not
    ///      meeting the downtime budget.
    ///      [`MigratableError::MigrateSend`] so the caller can abort the
    ///      migration cleanly.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` – convergence criterion met; the caller should stop precopy
    ///   iterations.
    /// * `Ok(false)` – not yet converged; the caller should run another
    ///   dirty-page iteration.
    /// * `Err(_)` – the timeout was reached and [`TimeoutStrategy::Cancel`]
    ///   is in effect.
    fn is_precopy_converged(
        ctx: &MemoryMigrationContext,
        send_data_migration: &VmSendMigrationData,
    ) -> result::Result<bool, MigratableError> {
        if ctx.current_iteration_total_bytes == 0 {
            debug!("Precopy: No more memory to transfer");
            return Ok(true);
        }

        // We currently ignore the time required to transfer the final
        // VM state (device state and vCPUs) and the time needed on the
        // receiver to create the VM and initialize its data structures
        // before execution can resume.
        //
        // Manual testing showed that migrating an idle VM on a modern
        // AMD CPU (CHV release build) adds ~5 ms of overhead when
        // scaling from 1 to 200 vCPUs. Given this small cost, we
        // deliberately avoid additional heuristics to estimate the
        // downtime more precisely - for now. Instead, we approximate
        // the downtime just by the transfer time of the final memory
        // delta.
        if let Some(memory_downtime) = ctx.estimated_downtime
            && memory_downtime <= send_data_migration.downtime()
        {
            debug!(
                "Precopy: Target downtime can be met: {}ms <= {}ms",
                memory_downtime.as_millis(),
                send_data_migration.downtime().as_millis()
            );
            return Ok(true);
        }

        // We check the beginning of the precopy migration and not the overall migration, and
        // this is fine: precopy takes the longest and the earlier steps are negligible.
        if ctx.migration_begin.elapsed() >= send_data_migration.timeout() {
            return match send_data_migration.timeout_strategy {
                TimeoutStrategy::Cancel => {
                    let msg = format!(
                        "Precopy: Timeout reached: {}s: migration didn't converge in time",
                        send_data_migration.timeout().as_secs()
                    );
                    Err(MigratableError::MigrateSend(anyhow!("{msg}")))
                }
                TimeoutStrategy::Ignore => {
                    info!(
                        "Precopy: Pausing VM, ignoring target downtime ({}ms) due to timeout ({}s): Estimated downtime: {}ms",
                        send_data_migration.downtime().as_millis(),
                        send_data_migration.timeout().as_secs(),
                        ctx.estimated_downtime
                            .unwrap_or(Duration::from_secs(0))
                            .as_millis()
                    );
                    Ok(true)
                }
            };
        }

        Ok(false)
    }

    /// Performs the memory migration including multiple iterations.
    ///
    /// This includes:
    /// - initial memory - VM is running
    /// - multiple memory delta transmissions - VM is running
    /// - final memory iteration - VM is paused
    ///
    /// Stores the [finalized] [`MemoryMigrationContext`] in the provided
    /// [`OngoingMigrationContext`].
    ///
    /// [finalized]: MemoryMigrationContext::finalize
    fn do_memory_migration(
        vm: &mut Vm,
        socket: &mut SocketStream,
        send_data_migration: &VmSendMigrationData,
        mem_send: &mut SendAdditionalConnections,
        ctx: &mut OngoingMigrationContext,
    ) -> result::Result<(), MigratableError> {
        let mut mem_ctx = MemoryMigrationContext::new();

        vm.start_dirty_log()?;
        let remaining = Self::do_memory_iterations(
            vm,
            socket,
            &mut mem_ctx,
            // We bind send_data_migration to the callback
            |ctx| Self::is_precopy_converged(ctx, send_data_migration),
            mem_send,
        )?;
        let downtime_begin = Instant::now();
        if vm.get_state() != VmState::Paused {
            vm.pause()?;
        }

        // Send last batch of dirty pages: final iteration
        {
            let iteration_begin = Instant::now();

            let mut final_table = vm.dirty_log()?;
            final_table.extend(remaining);

            mem_ctx.update_metrics_before_transfer(iteration_begin, &final_table);
            let transfer_begin = Instant::now();
            mem_send.send_memory(final_table, socket)?;
            let transfer_duration = transfer_begin.elapsed();
            mem_ctx.update_metrics_after_transfer(transfer_begin, transfer_duration);
            mem_ctx.iteration += 1;
        }
        mem_ctx.finalize();
        info!("Precopy complete: {mem_ctx}");
        ctx.set_vm_paused(downtime_begin, mem_ctx)
            .expect("migration context should transition to VmPaused after memory migration");

        Ok(())
    }

    /// Performs a migration.
    ///
    /// Runs after-migration cleanup only on success. Callers must handle failed
    /// migrations.
    fn send_migration(
        vm: &mut Vm,
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        hypervisor: &dyn hypervisor::Hypervisor,
        send_data_migration: &VmSendMigrationData,
        initial_vm_state: VmState,
        seccomp_filters: &MigrationSeccompFilters,
    ) -> result::Result<(), MigratableError> {
        // State machine that is updated with more context as we progress.
        let mut ctx = OngoingMigrationContext::new();

        // Set up the socket connection
        let mut socket = transport::send_migration_socket(
            &send_data_migration.destination_url,
            send_data_migration.tls_dir.as_deref(),
        )?;

        // Start the migration
        transport::send_request_expect_ok(
            &mut socket,
            Request::start(),
            MigratableError::MigrateSend(anyhow!("Error starting migration")),
        )?;
        debug!("Using migration protocol {CURRENT_PROTOCOL_VERSION}");

        // Send config
        let vm_config = vm.get_config();
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        let common_cpuid = {
            #[cfg(feature = "tdx")]
            if vm_config.lock().unwrap().is_tdx_enabled() {
                return Err(MigratableError::MigrateSend(anyhow!(
                    "Live Migration is not supported when TDX is enabled"
                )));
            }

            let (amx, max_phys_bits, profile, kvm_hyperv) = {
                let guard = vm_config.lock().unwrap();
                (
                    guard.cpus.features.amx,
                    guard.cpus.max_phys_bits,
                    guard.cpus.profile,
                    guard.cpus.kvm_hyperv,
                )
            };

            let phys_bits = vm::physical_bits(hypervisor, max_phys_bits);

            arch::generate_common_cpuid(
                hypervisor,
                &arch::CpuidConfig {
                    phys_bits,
                    kvm_hyperv,
                    #[cfg(feature = "tdx")]
                    tdx: false,
                    amx,
                    profile,
                },
            )
            .context("Error generating common cpuid")
            .map_err(MigratableError::MigrateSend)?
        };

        if send_data_migration.local {
            match &mut socket {
                SocketStream::Unix(unix_socket) => {
                    // Proceed with sending memory file descriptors over UNIX socket
                    vm.send_memory_fds(unix_socket)?;
                }
                _ => {
                    return Err(MigratableError::MigrateSend(anyhow!(
                        "--local option is only supported with UNIX sockets",
                    )));
                }
            }
        }

        let vm_migration_config = VmMigrationConfig {
            vm_config,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            common_cpuid,
            memory_manager_data: vm.memory_manager_data(),
        };
        transport::send_config(&mut socket, &vm_migration_config)?;

        // Let every Migratable object know about the migration being started.
        vm.start_migration()?;

        if send_data_migration.local
            || matches!(send_data_migration.memory_mode, MigrationMode::Postcopy)
        {
            // Now pause VM (skip if already paused, e.g. migrating a paused VM)
            let downtime_begin = Instant::now();
            if vm.get_state() != VmState::Paused {
                vm.pause()?;
            }
            ctx.set_vm_paused(
                downtime_begin,
                // No memory was transferred
                MemoryMigrationContext::empty_finalized(),
            )
            .expect("migration context should transition to VmPaused for local/postcopy migration");
        } else {
            let mut mem_send = transport::SendAdditionalConnections::new(
                &send_data_migration.destination_url,
                send_data_migration.connections,
                send_data_migration.tls_dir.as_deref(),
                &vm.guest_memory(),
                &seccomp_filters.tcp_worker,
            )?;

            Self::do_memory_migration(
                vm,
                &mut socket,
                send_data_migration,
                &mut mem_send,
                &mut ctx,
            )
            .inspect_err(|_| {
                // Calling cleanup multiple times is fine, thus here we just make sure
                // that it is called.
                if let Err(e) = mem_send.cleanup() {
                    warn!("Error cleaning up migration connections: {e}");
                }
            })?;

            mem_send.cleanup()?;
        }

        // We release the locks early to enable locking them on the destination host.
        // The VM is already stopped.
        vm.release_disk_locks()
            .map_err(|e| MigratableError::UnlockError(anyhow!("{e}")))?;

        // For postcopy, serve faults before sending State so the destination
        // can fault pages in during restore.
        let postcopy_handle = if matches!(send_data_migration.memory_mode, MigrationMode::Postcopy)
        {
            let fault_stream = transport::open_fault_connection(
                &send_data_migration.destination_url,
                send_data_migration.tls_dir.as_deref(),
            )?;
            let guest_memory = vm.guest_memory();

            let seccomp_filters_clone = seccomp_filters.clone();
            let handle = thread::Builder::new()
                .name("migrate-send-postcopy".to_owned())
                .spawn(move || {
                    Self::serve_postcopy(
                        &seccomp_filters_clone.postcopy_server,
                        fault_stream,
                        guest_memory,
                    )
                })
                .context("spawning postcopy serve thread")
                .map_err(MigratableError::MigrateSend)?;
            Some(handle)
        } else {
            None
        };

        let (vm_snapshot, snapshot_duration) = measure_ok(|| {
            // Capture snapshot. This may have side effects, e.g. vhost-user backend inflight drain
            let snapshot = vm.snapshot()?;

            // One final memory iteration to handle side effects from snapshot.
            if !send_data_migration.local
                && !matches!(send_data_migration.memory_mode, MigrationMode::Postcopy)
            {
                let memory_ranges = vm.dirty_log()?;
                transport::send_memory_ranges(&vm.guest_memory(), &memory_ranges, &mut socket)?;
            }
            Ok(snapshot)
        })?;

        let (_, send_snapshot_duration) =
            measure_ok(|| transport::send_state(&mut socket, &vm_snapshot))?;

        // Complete the migration.
        // When this returns, we know the VM was resumed (if it was running
        // before the migration) and that the receiving VMM acquired disk
        // locks again.
        let complete_req = if initial_vm_state == VmState::Running {
            Request::complete()
        } else {
            Request::complete_paused()
        };
        let (_, complete_duration) = measure_ok(|| {
            transport::send_request_expect_ok(
                &mut socket,
                complete_req,
                MigratableError::MigrateSend(anyhow!("Error completing migration")),
            )
        })?;

        let ctx = ctx
            .finalize(snapshot_duration, send_snapshot_duration, complete_duration)
            .expect("migration context should finalize after memory migration completed");

        info!(
            "Migration completed after {:.1}s with a downtime of {}ms (goal was {}ms)",
            ctx.migration_dur.as_secs_f32(),
            ctx.downtime_ctx.effective_downtime.as_millis(),
            send_data_migration.downtime().as_millis()
        );
        debug!("Downtime breakdown: {}", ctx.downtime_ctx);

        // Stop logging dirty pages
        if !send_data_migration.local
            && !matches!(send_data_migration.memory_mode, MigrationMode::Postcopy)
        {
            vm.stop_dirty_log()?;
        }

        // Wait for the serve thread to drain every page
        if let Some(handle) = postcopy_handle {
            handle.join().map_err(|e| {
                MigratableError::MigrateSend(anyhow!("postcopy serve thread panicked: {e:?}"))
            })??;
            // Signal that postcopy has drained every page to the destination.
            event!("vm", "postcopy-migration-completed");
        }

        // Let every Migratable object know about the migration being complete
        vm.complete_migration()
    }

    /// Serve `Command::PageFault` requests from local guest memory on the fault
    /// connection until the destination closes it. Runs on its own thread.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "runs on a dedicated thread and must own its arguments"
    )]
    fn serve_postcopy(
        seccomp_filter: &BpfProgram,
        mut socket: SocketStream,
        guest_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), MigratableError> {
        // Apply the dedicated seccomp filter for this thread. It is empty when
        // seccomp is disabled (SeccompAction::Allow), in which case there is
        // nothing to apply.
        if !seccomp_filter.is_empty() {
            apply_filter(seccomp_filter)
                .context("applying postcopy serve seccomp filter")
                .map_err(MigratableError::MigrateSend)?;
        }

        let mut buf: Vec<u8> = Vec::new();
        info!("Postcopy: source entering PageFault serve loop");

        loop {
            let req = match Request::read_from(&mut socket) {
                Ok(r) => r,
                Err(MigratableError::MigrateSocket(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    info!("Postcopy: destination closed the fault connection — drain complete");
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            match req.command() {
                Command::PageFault => {
                    let range = MemoryRange::read_from(&mut socket)?;
                    let len = range.length as usize;
                    const MAX_PAGE: usize = 1 << 30; // 1 GiB
                    if len == 0 || len > MAX_PAGE {
                        return Err(MigratableError::MigrateSend(anyhow!(
                            "Postcopy: invalid page length {len}"
                        )));
                    }
                    buf.resize(len, 0);
                    let mem = guest_memory.memory();
                    mem.read_slice(&mut buf[..len], GuestAddress(range.gpa))
                        .map_err(|e| {
                            MigratableError::MigrateSend(anyhow!(
                                "Postcopy: reading guest memory gpa={:#x} len={}: {e}",
                                range.gpa,
                                range.length
                            ))
                        })?;
                    Response::new(Status::Ok, range.length).write_to(&mut socket)?;
                    socket
                        .write_all(&buf[..len])
                        .map_err(MigratableError::MigrateSocket)?;
                }
                Command::Abandon => {
                    Response::ok().write_to(&mut socket)?;
                    info!("Postcopy: received Abandon, exiting serve loop");
                    return Ok(());
                }
                c => {
                    return Err(MigratableError::MigrateSend(anyhow!(
                        "Postcopy: unexpected command in serve loop: {c:?}",
                    )));
                }
            }
        }
    }

    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn vm_check_cpuid_compatibility(
        &self,
        src_vm_config: &Arc<Mutex<VmConfig>>,
        src_vm_cpuid: &[x86::CpuIdEntry],
    ) -> result::Result<(), MigratableError> {
        #[cfg(feature = "tdx")]
        if src_vm_config.lock().unwrap().is_tdx_enabled() {
            return Err(MigratableError::MigrateReceive(anyhow!(
                "Live Migration is not supported when TDX is enabled"
            )));
        }

        // We check the `CPUID` compatibility of between the source vm and destination, which is
        // mostly about feature compatibility.
        let dest_cpuid = &{
            let vm_config = &src_vm_config.lock().unwrap();

            if vm_config.cpus.features.amx {
                // Need to enable AMX tile state components before generating common cpuid
                // as this affects what Hypervisor::get_supported_cpuid returns.
                self.hypervisor
                    .enable_amx_state_components()
                    .map_err(|e| MigratableError::MigrateReceive(e.into()))?;
            }

            let phys_bits =
                vm::physical_bits(self.hypervisor.as_ref(), vm_config.cpus.max_phys_bits);

            arch::generate_common_cpuid(
                self.hypervisor.as_ref(),
                &arch::CpuidConfig {
                    phys_bits,
                    kvm_hyperv: vm_config.cpus.kvm_hyperv,
                    #[cfg(feature = "tdx")]
                    tdx: false,
                    amx: vm_config.cpus.features.amx,
                    profile: vm_config.cpus.profile,
                },
            )
            .context("Error generating common cpuid")
            .map_err(MigratableError::MigrateReceive)?
        };
        arch::CpuidFeatureEntry::check_cpuid_compatibility(src_vm_cpuid, dest_cpuid)
            .context("Error checking cpu feature compatibility")
            .map_err(MigratableError::MigrateReceive)
    }

    fn vm_restore(
        &mut self,
        source_url: &str,
        vm_config: Arc<Mutex<VmConfig>>,
        prefault: bool,
        memory_restore_mode: MemoryRestoreMode,
    ) -> result::Result<(), VmError> {
        match &self.vm {
            VmOwnership::Owned(_) => Err(VmError::VmAlreadyCreated),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                let snapshot = recv_vm_state(source_url).map_err(VmError::Restore)?;
                #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
                let vm_snapshot = get_vm_snapshot(&snapshot).map_err(VmError::Restore)?;

                #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
                self.vm_check_cpuid_compatibility(&vm_config, &vm_snapshot.common_cpuid)
                    .map_err(VmError::Restore)?;

                self.vm_config = Some(Arc::clone(&vm_config));

                // Always re-populate the 'console_info' based on the new 'vm_config'
                self.console_info =
                    Some(pre_create_console_devices(self).map_err(VmError::CreateConsoleDevices)?);

                let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
                let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
                let guest_exit_evt = self
                    .guest_exit_evt
                    .try_clone()
                    .map_err(VmError::EventFdClone)?;
                #[cfg(feature = "guest_debug")]
                let debug_evt = self
                    .vm_debug_evt
                    .try_clone()
                    .map_err(VmError::EventFdClone)?;
                let activate_evt = self
                    .activate_evt
                    .try_clone()
                    .map_err(VmError::EventFdClone)?;

                let mut vm = Vm::new(
                    vm_config,
                    exit_evt,
                    reset_evt,
                    guest_exit_evt,
                    #[cfg(feature = "guest_debug")]
                    debug_evt,
                    &self.seccomp_action,
                    self.hypervisor.clone(),
                    activate_evt,
                    self.console_info.clone(),
                    self.console_resize_pipe.clone(),
                    Arc::clone(&self.original_termios_opt),
                    Some(&snapshot),
                    Some(source_url),
                    Some(prefault),
                    Some(memory_restore_mode),
                )?;

                if self
                    .vm_config
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .landlock_enable
                {
                    let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                    apply_landlock(&mut config).map_err(VmError::ApplyLandlock)?;
                }

                // Now we can restore the rest of the VM.
                // PANIC: won't panic, we just checked that the VM is there.
                vm.restore()?;
                self.vm = VmOwnership::Owned(vm);
                Ok(())
            }
        }
    }

    /// Handles the outcome of the migration worker thread.
    fn check_migration(&mut self) {
        let VmOwnership::Migration {
            migration_worker_handle,
            ..
        } = mem::replace(&mut self.vm, VmOwnership::None)
        else {
            panic!("Should only be called after a migration was started");
        };
        let MigrationWorkerResult {
            vm,
            migration_result: migration_res,
            initial_vm_state,
        } = migration_worker_handle.join();

        let mut try_resume_vm_after_failed_migration = |mut vm: Vm| {
            // A late failure may leave the VM paused.
            if initial_vm_state == VmState::Running && vm.get_state() == VmState::Paused {
                match vm.resume() {
                    Ok(_) => {
                        info!("Resumed VM successfully after failed migration");
                    }
                    Err(e) => {
                        error!("Failed resuming VM after failed migration: {e}");
                        self.exit_evt.write(1).unwrap();
                    }
                }
            }

            // Ensure full VM performance. The operation is idempotent.
            let _ = vm.stop_dirty_log().inspect_err(|e| {
                warn!("Failed stopping dirty log after resuming VM: {e} - VM performance might be slower than usual");
            });

            self.vm = VmOwnership::Owned(vm);
        };

        match migration_res {
            Ok(()) => {
                self.vm = VmOwnership::None;
                let mut vm = vm;

                // Since the VMM explicitly no longer owns the VM, the exit
                // event won't call the shutdown path automatically.
                if let Err(e) = vm.shutdown() {
                    error!("Failed shutting down the VM after migration: {e}");
                }

                if let Err(e) = self.exit_evt.write(1) {
                    error!("Failed exiting the VMM after migration: {e}");
                }
            }
            Err(e) => {
                error!(
                    "Migration failed: {}",
                    util::flatten_error_chain_to_string(&e)
                );
                try_resume_vm_after_failed_migration(vm);
            }
        }
    }

    fn control_loop(
        &mut self,
        api_receiver: &Receiver<ApiRequest>,
        #[cfg(feature = "guest_debug")] gdb_receiver: &Receiver<gdb::GdbRequest>,
    ) -> Result<()> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        'outer: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(Error::Epoll(e));
                }
            };

            for event in events.iter().take(num_events) {
                let dispatch_event: EpollDispatch = event.data.into();
                match dispatch_event {
                    EpollDispatch::Unknown => {
                        let event = event.data;
                        warn!("Unknown VMM loop event: {event}");
                    }
                    EpollDispatch::Exit => {
                        info!("VM exit event");
                        // Consume the event.
                        self.exit_evt.read().map_err(Error::EventFdRead)?;
                        // TODO: Future follow-up must resolve lifecycle handling while migrating.
                        self.vmm_shutdown().map_err(Error::VmmShutdown)?;

                        break 'outer;
                    }
                    EpollDispatch::Reset => {
                        info!("VM reset event");
                        // Consume the event.
                        self.reset_evt.read().map_err(Error::EventFdRead)?;
                        // TODO: Future follow-up must resolve lifecycle handling while migrating.
                        self.vm_reboot().map_err(Error::VmReboot)?;
                    }
                    EpollDispatch::GuestExit => {
                        info!("VM guest exit event");
                        self.guest_exit_evt.read().map_err(Error::EventFdRead)?;
                        // TODO: Future follow-up must resolve lifecycle handling while migrating.
                        if self.no_shutdown {
                            self.vm_shutdown().map_err(Error::VmShutdown)?;
                        } else {
                            self.vmm_shutdown().map_err(Error::VmmShutdown)?;
                            break 'outer;
                        }
                    }
                    EpollDispatch::ActivateVirtioDevices => {
                        let count = self.activate_evt.read().map_err(Error::EventFdRead)?;
                        info!("Trying to activate pending virtio devices: count = {count}");
                        match &self.vm {
                            VmOwnership::Owned(vm) => {
                                vm.activate_virtio_devices()
                                    .map_err(Error::ActivateVirtioDevices)?;
                            }
                            VmOwnership::Migration { device_manager, .. } => {
                                // If the VM (and thus the device manager) were
                                // dropped at this point, we'd have a serious
                                // programming bug.
                                let device_manager = device_manager
                                    .upgrade()
                                    .expect("DeviceManager should remain alive during a migration");
                                let device_manager = device_manager.lock().unwrap();
                                device_manager
                                    .activate_virtio_devices()
                                    .map_err(VmError::ActivateVirtioDevices)
                                    .map_err(Error::ActivateVirtioDevices)?;
                            }
                            VmOwnership::None => {}
                        }
                    }
                    EpollDispatch::Api => {
                        // Consume the events.
                        for _ in 0..self.api_evt.read().map_err(Error::EventFdRead)? {
                            // Read from the API receiver channel
                            let api_request = api_receiver.recv().map_err(Error::ApiRequestRecv)?;

                            if api_request(self)? {
                                break 'outer;
                            }
                        }
                    }
                    #[cfg(feature = "guest_debug")]
                    EpollDispatch::Debug => {
                        // Consume the events.
                        for _ in 0..self.debug_evt.read().map_err(Error::EventFdRead)? {
                            // Read from the API receiver channel
                            let gdb_request = gdb_receiver.recv().map_err(Error::GdbRequestRecv)?;

                            let response = match self.vm {
                                VmOwnership::Owned(ref mut vm) => {
                                    vm.debug_request(&gdb_request.payload, gdb_request.cpu_id)
                                }
                                VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
                                VmOwnership::None => Err(VmError::VmNotRunning),
                            }
                            .map_err(gdb::Error::Vm);

                            gdb_request
                                .sender
                                .send(response)
                                .map_err(Error::GdbResponseSend)?;
                        }
                    }
                    #[cfg(not(feature = "guest_debug"))]
                    EpollDispatch::Debug => {}
                    EpollDispatch::CheckMigration => {
                        info!("VM check migration event");
                        // Consume the event.
                        self.check_migration_evt
                            .read()
                            .map_err(Error::EventFdRead)?;
                        self.check_migration();
                    }
                }
            }
        }

        // Trigger the termination of the signal_handler thread
        if let Some(signals) = self.signals.take() {
            signals.close();
        }

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(Error::ThreadCleanup)?;
        }

        Ok(())
    }
}

fn apply_landlock(vm_config: &mut VmConfig) -> result::Result<(), LandlockError> {
    vm_config.apply_landlock()?;
    Ok(())
}

impl RequestHandler for Vmm {
    fn vm_create(&mut self, config: Box<VmConfig>) -> result::Result<(), VmError> {
        match &self.vm {
            VmOwnership::Migration { .. } => return Err(VmError::VmMigrating),
            VmOwnership::Owned(_) | VmOwnership::None => {}
        }

        // We only store the passed VM config.
        // The VM will be created when being asked to boot it.
        if self.vm_config.is_some() {
            return Err(VmError::VmAlreadyCreated);
        }

        self.vm_config = Some(Arc::new(Mutex::new(*config)));
        self.console_info =
            Some(pre_create_console_devices(self).map_err(VmError::CreateConsoleDevices)?);

        if self
            .vm_config
            .as_ref()
            .is_some_and(|config| config.lock().unwrap().landlock_enable)
        {
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            apply_landlock(&mut config).map_err(VmError::ApplyLandlock)?;
        }
        Ok(())
    }

    fn vm_boot(&mut self) -> result::Result<(), VmError> {
        match &self.vm {
            VmOwnership::Owned(_) => Err(VmError::VmAlreadyCreated),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                tracer::start();
                info!("Booting VM");
                event!("vm", "booting");

                let r = (|| {
                    trace_scoped!("vm_boot");
                    // If we don't have a config, we cannot boot a VM.
                    if self.vm_config.is_none() {
                        return Err(VmError::VmMissingConfig);
                    }

                    // console_info is set to None in vm_shutdown. re-populate here if empty
                    if self.console_info.is_none() {
                        self.console_info = Some(
                            pre_create_console_devices(self)
                                .map_err(VmError::CreateConsoleDevices)?,
                        );
                    }

                    // Create a new VM if we don't have one yet.
                    let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
                    let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
                    let guest_exit_evt = self
                        .guest_exit_evt
                        .try_clone()
                        .map_err(VmError::EventFdClone)?;
                    #[cfg(feature = "guest_debug")]
                    let vm_debug_evt = self
                        .vm_debug_evt
                        .try_clone()
                        .map_err(VmError::EventFdClone)?;
                    let activate_evt = self
                        .activate_evt
                        .try_clone()
                        .map_err(VmError::EventFdClone)?;

                    if let Some(ref vm_config) = self.vm_config {
                        let mut vm = Vm::new(
                            Arc::clone(vm_config),
                            exit_evt,
                            reset_evt,
                            guest_exit_evt,
                            #[cfg(feature = "guest_debug")]
                            vm_debug_evt,
                            &self.seccomp_action,
                            self.hypervisor.clone(),
                            activate_evt,
                            self.console_info.clone(),
                            self.console_resize_pipe.clone(),
                            Arc::clone(&self.original_termios_opt),
                            None,
                            None,
                            None,
                            None,
                        )?;

                        let r = vm.boot();
                        self.vm = VmOwnership::Owned(vm);
                        r
                    } else {
                        Err(VmError::VmNotCreated)
                    }
                })();

                tracer::end();
                if r.is_ok() {
                    event!("vm", "booted");
                }
                r
            }
        }
    }

    fn vm_pause(&mut self) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => vm.pause().map_err(VmError::Pause),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_resume(&mut self) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => vm.resume().map_err(VmError::Resume),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_snapshot(&mut self, destination_url: &str) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                if vm.restoring() {
                    return Err(VmError::VmRestoring);
                }
                // Drain console_info so that FDs are not reused
                let _ = self.console_info.take();
                vm.snapshot()
                    .map_err(VmError::Snapshot)
                    .and_then(|snapshot| {
                        vm.send(&snapshot, destination_url)
                            .map_err(VmError::SnapshotSend)
                    })
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_restore(&mut self, restore_cfg: RestoreConfig) -> result::Result<(), VmError> {
        match &self.vm {
            VmOwnership::Owned(_) => Err(VmError::VmAlreadyCreated),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                if self.vm_config.is_some() {
                    return Err(VmError::VmAlreadyCreated);
                }

                let source_url = restore_cfg.source_url.as_path().to_str();
                if source_url.is_none() {
                    return Err(VmError::InvalidRestoreSourceUrl);
                }
                // Safe to unwrap as we checked it was Some(&str).
                let source_url = source_url.unwrap();

                let vm_config = Arc::new(Mutex::new(
                    recv_vm_config(source_url).map_err(VmError::Restore)?,
                ));
                restore_cfg
                    .validate(&vm_config.lock().unwrap().clone())
                    .map_err(VmError::ConfigValidation)?;

                // Update VM's net configurations with new fds received for restore operation
                if let (Some(restored_nets), Some(vm_net_configs)) =
                    (restore_cfg.net_fds, &mut vm_config.lock().unwrap().net)
                {
                    for net in restored_nets.iter() {
                        for net_config in vm_net_configs.iter_mut() {
                            // update only if the net dev is backed by FDs
                            if net_config.pci_common.id.as_ref() == Some(&net.id)
                                && net_config.fds.is_some()
                            {
                                net_config.fds.clone_from(&net.fds);
                            }
                        }
                    }
                }

                self.vm_restore(
                    source_url,
                    vm_config,
                    restore_cfg.prefault,
                    restore_cfg.memory_restore_mode,
                )
                .and_then(|()| {
                    if restore_cfg.resume {
                        self.vm_resume()
                    } else {
                        Ok(())
                    }
                })
                .map_err(|e| {
                    error!("VM Restore failed: {e:?}");
                    if let Err(e) = self.vm_delete() {
                        return e;
                    }
                    e
                })?;

                Ok(())
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn vm_coredump(&mut self, destination_url: &str) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                vm.coredump(destination_url).map_err(VmError::Coredump)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_shutdown(&mut self) -> result::Result<(), VmError> {
        let mut vm = self.vm.take_owned_or(VmError::VmNotRunning)?;
        // Drain console_info so that the FDs are not reused
        let _ = self.console_info.take();
        let r = vm.shutdown();

        if r.is_ok() {
            event!("vm", "shutdown");
        }

        r
    }

    fn vm_reboot(&mut self) -> result::Result<(), VmError> {
        event!("vm", "rebooting");

        // Drop VM early to release disk locks and free other resources before
        // we reboot.
        let config = {
            let mut vm = self.vm.take_owned_or(VmError::VmNotCreated)?;
            let config = vm.get_config();
            // First we stop the current VM
            vm.shutdown()?;
            config
        };

        // vm.shutdown() closes all the console devices, so set console_info to None
        // so that the closed FD #s are not reused.
        let _ = self.console_info.take();

        let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
        let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
        let guest_exit_evt = self
            .guest_exit_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;
        #[cfg(feature = "guest_debug")]
        let debug_evt = self
            .vm_debug_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;
        let activate_evt = self
            .activate_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;

        // The Linux kernel fires off an i8042 reset after doing the ACPI reset so there may be
        // an event sitting in the shared reset_evt. Without doing this we get very early reboots
        // during the boot process.
        if self.reset_evt.read().is_ok() {
            warn!("Spurious second reset event received. Ignoring.");
        }

        self.console_info =
            Some(pre_create_console_devices(self).map_err(VmError::CreateConsoleDevices)?);

        // Then we create the new VM
        let mut vm = Vm::new(
            config,
            exit_evt,
            reset_evt,
            guest_exit_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
            self.console_info.clone(),
            self.console_resize_pipe.clone(),
            Arc::clone(&self.original_termios_opt),
            None,
            None,
            None,
            None,
        )?;

        // And we boot it
        vm.boot()?;

        self.vm = VmOwnership::Owned(vm);

        event!("vm", "rebooted");

        Ok(())
    }

    fn vm_info(&self) -> result::Result<VmInfoResponse, VmError> {
        // In case of a migration, we emit the old VM info, as the VM is
        // immutable during a migration.
        if let VmOwnership::Migration {
            vm_info_response, ..
        } = &self.vm
        {
            return Ok(vm_info_response.clone());
        }

        let vm_config = self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;
        let vm_config = vm_config.lock().unwrap().clone();

        let state = match &self.vm {
            VmOwnership::Owned(vm) => vm.get_state(),
            VmOwnership::None => VmState::Created,
            VmOwnership::Migration { .. } => unreachable!("migration path is handled above"),
        };

        let base_memory_actual_size =
            vm_config.memory.total_size() - vm_config.memory.hotplugged_size();
        let (memory_actual_size, device_tree) = match &self.vm {
            VmOwnership::Owned(vm) => (
                base_memory_actual_size.saturating_sub(vm.balloon_size())
                    + vm.virtio_mem_plugged_size(),
                Some(vm.device_tree().lock().unwrap().clone()),
            ),
            VmOwnership::None => (base_memory_actual_size, None),
            VmOwnership::Migration { .. } => unreachable!("migration path is handled above"),
        };

        Ok(VmInfoResponse {
            config: Box::new(vm_config),
            state,
            memory_actual_size,
            device_tree,
        })
    }

    fn vmm_ping(&self) -> VmmPingResponse {
        let VmmVersionInfo {
            build_version,
            version,
        } = self.version.clone();

        VmmPingResponse {
            build_version,
            version,
            pid: process::id() as i64,
            features: feature_list(),
        }
    }

    fn vm_delete(&mut self) -> result::Result<(), VmError> {
        if self.vm_config.is_none() {
            return Ok(());
        }

        match &self.vm {
            VmOwnership::Owned(_vm) => {
                // If a VM is booted, we first try to shut it down.
                self.vm_shutdown()?;
            }
            VmOwnership::Migration { .. } => return Err(VmError::VmMigrating),
            VmOwnership::None => {}
        }

        self.vm_config = None;
        event!("vm", "deleted");

        Ok(())
    }

    fn vmm_shutdown(&mut self) -> result::Result<(), VmError> {
        self.vm_delete()?;
        event!("vmm", "shutdown");
        Ok(())
    }

    fn vm_resize(
        &mut self,
        desired_vcpus: Option<u32>,
        desired_ram: Option<u64>,
        desired_balloon: Option<u64>,
    ) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        match self.vm {
            VmOwnership::Owned(ref mut vm) => vm
                .resize(desired_vcpus, desired_ram, desired_balloon)
                .inspect_err(|e| error!("Error when resizing VM: {e:?}")),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                if let Some(desired_vcpus) = desired_vcpus {
                    config.cpus.boot_vcpus = desired_vcpus;
                }
                if let Some(desired_ram) = desired_ram {
                    config.memory.size = desired_ram;
                }
                if let Some(desired_balloon) = desired_balloon
                    && let Some(balloon_config) = &mut config.balloon
                {
                    balloon_config.size = desired_balloon;
                }

                Ok(())
            }
        }
    }

    fn vm_resize_disk(&mut self, id: String, desired_size: u64) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        match self.vm {
            VmOwnership::Owned(ref mut vm) => vm.resize_disk(&id, desired_size),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::ResizeDisk),
        }
    }

    fn vm_resize_zone(&mut self, id: String, desired_ram: u64) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                vm.resize_zone(&id, desired_ram)
                    .inspect_err(|e| error!("Error when resizing zone: {e:?}"))?;
                Ok(())
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by setting the new desired ram.
                let memory_config = &mut self.vm_config.as_ref().unwrap().lock().unwrap().memory;

                if let Some(zones) = &mut memory_config.zones {
                    for zone in zones.iter_mut() {
                        if zone.id == id {
                            zone.size = desired_ram;
                            return Ok(());
                        }
                    }
                }

                error!("Could not find the memory zone {id} for the resize");
                Err(VmError::ResizeZone)
            }
        }
    }

    fn vm_add_device(
        &mut self,
        device_cfg: DeviceConfig,
    ) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.devices, device_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_device(device_cfg).inspect_err(|e| {
                    error!("Error when adding new device to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.devices, device_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_user_device(
        &mut self,
        device_cfg: UserDeviceConfig,
    ) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.user_devices, device_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_user_device(device_cfg).inspect_err(|e| {
                    error!("Error when adding new user device to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.user_devices, device_cfg);
                Ok(None)
            }
        }
    }

    fn vm_remove_device(&mut self, id: String) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                vm.remove_device(&id)
                    .inspect_err(|e| error!("Error when removing device from the VM: {e:?}"))?;
                Ok(())
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                if let Some(ref config) = self.vm_config {
                    let mut config = config.lock().unwrap();
                    if config.remove_device(&id) {
                        Ok(())
                    } else {
                        Err(VmError::NoDeviceToRemove(id))
                    }
                } else {
                    Err(VmError::VmNotCreated)
                }
            }
        }
    }

    fn vm_add_disk(&mut self, disk_cfg: DiskConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.disks, disk_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_disk(disk_cfg).inspect_err(|e| {
                    error!("Error when adding new disk to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.disks, disk_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_fs(&mut self, fs_cfg: FsConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.fs, fs_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_fs(fs_cfg).inspect_err(|e| {
                    error!("Error when adding new fs to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.fs, fs_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_generic_vhost_user(
        &mut self,
        generic_vhost_user_cfg: GenericVhostUserConfig,
    ) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(
                &mut config.generic_vhost_user,
                generic_vhost_user_cfg.clone(),
            );
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm
                    .add_generic_vhost_user(generic_vhost_user_cfg)
                    .inspect_err(|e| {
                        error!("Error when adding new generic vhost-user device to the VM: {e:?}");
                    })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.generic_vhost_user, generic_vhost_user_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_pmem(&mut self, pmem_cfg: PmemConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.pmem, pmem_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_pmem(pmem_cfg).inspect_err(|e| {
                    error!("Error when adding new pmem device to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.pmem, pmem_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_net(&mut self, net_cfg: NetConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.net, net_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_net(net_cfg).inspect_err(|e| {
                    error!("Error when adding new network device to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.net, net_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_vdpa(&mut self, vdpa_cfg: VdpaConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.vdpa, vdpa_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_vdpa(vdpa_cfg).inspect_err(|e| {
                    error!("Error when adding new vDPA device to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                add_to_config(&mut config.vdpa, vdpa_cfg);
                Ok(None)
            }
        }
    }

    fn vm_add_vsock(&mut self, vsock_cfg: VsockConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();

            if config.vsock.is_some() {
                return Err(VmError::TooManyVsockDevices);
            }

            config.vsock = Some(vsock_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.add_vsock(vsock_cfg).inspect_err(|e| {
                    error!("Error when adding new vsock device to the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => {
                // Update VmConfig by adding the new device.
                let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
                config.vsock = Some(vsock_cfg);
                Ok(None)
            }
        }
    }

    fn vm_counters(&mut self) -> result::Result<Option<Vec<u8>>, VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => {
                let info = vm.counters().inspect_err(|e| {
                    error!("Error when getting counters from the VM: {e:?}");
                })?;
                serde_json::to_vec(&info)
                    .map(Some)
                    .map_err(VmError::SerializeJson)
            }
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_power_button(&mut self) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => vm.power_button(),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_nmi(&mut self) -> result::Result<(), VmError> {
        match self.vm {
            VmOwnership::Owned(ref mut vm) => vm.nmi(),
            VmOwnership::Migration { .. } => Err(VmError::VmMigrating),
            VmOwnership::None => Err(VmError::VmNotRunning),
        }
    }

    fn vm_receive_migration(
        &mut self,
        receive_data_migration: VmReceiveMigrationData,
    ) -> result::Result<(), MigratableError> {
        match &self.vm {
            VmOwnership::Owned(_vm) => {
                return Err(MigratableError::MigrateReceive(anyhow!(
                    "Can't receive a migration when a VM is already created"
                )));
            }
            VmOwnership::Migration { .. } => {
                return Err(MigratableError::MigrateReceive(anyhow!(
                    "There is already an ongoing migration"
                )));
            }
            VmOwnership::None => {}
        }

        receive_data_migration
            .validate()
            .context("Invalid receive migration configuration")
            .map_err(MigratableError::MigrateReceive)?;

        info!(
            "Receiving migration: receiver_url={},tls={}",
            receive_data_migration.receiver_url,
            receive_data_migration.tls_dir.is_some()
        );

        let mut listener = transport::receive_migration_listener(
            &receive_data_migration.receiver_url,
            receive_data_migration.tls_dir.as_deref(),
        )?;

        if self.vm_config.is_some() {
            warn!("The existing VM config will be overwritten");
        }

        event!("vm", "migration-receive-ready");
        // Accept the connection and get the socket
        let mut socket = listener.accept()?;

        event!("vm", "migration-receive-started");

        let mut state = ReceiveMigrationState::Established;

        while !state.finished() {
            let req = Request::read_from(&mut socket).inspect_err(|error| {
                if matches!(
                    error,
                    MigratableError::MigrateSocket(io_error)
                        if io_error.kind() == io::ErrorKind::UnexpectedEof
                ) {
                    error!("Failed to read migration request: sender likely failed, aborting");
                }
            })?;
            debug!("Command '{:?}' received", req.command());

            // If sender-side migration causes any error propagated here, the
            // next loop iteration logs a helpful error when reading the next
            // request (which will fail as the sender closed the socket).
            let (response, new_state) = match self.vm_receive_migration_step(
                &mut socket,
                &listener,
                state,
                &req,
                &receive_data_migration,
            ) {
                Ok(next_state) => (Response::ok(), next_state),
                Err(err) => {
                    warn!(
                        "Migration aborted as migration command {:?} failed: {}",
                        req.command(),
                        err
                    );
                    (Response::error(), ReceiveMigrationState::Aborted)
                }
            };

            state = new_state;
            assert_eq!(response.length(), 0);
            response.write_to(&mut socket)?;
        }

        match state {
            ReceiveMigrationState::Aborted => {
                event!("vm", "migration-receive-failed");
                self.vm = VmOwnership::None;
                self.vm_config = None;
                return Err(MigratableError::CompleteMigration(anyhow!(
                    "Migration was aborted"
                )));
            }
            ReceiveMigrationState::Completed => {
                // Serving and resume already happened in the protocol loop.
                event!("vm", "migration-receive-finished");
            }
            _ => unreachable!("loop only exits in Completed or Aborted"),
        }

        Ok(())
    }

    /// Dispatches a migration.
    ///
    /// Returns an error if the migration worker cannot be spawned. Once
    /// spawned, [`Vmm::check_migration`] will be called after the thread exits
    /// (on success, cancellation, or failure).
    fn vm_send_migration(
        &mut self,
        send_data_migration: VmSendMigrationData,
    ) -> result::Result<(), MigratableError> {
        match self.vm {
            VmOwnership::Owned(ref vm) => {
                if vm.restoring() {
                    return Err(MigratableError::MigrateSend(anyhow!(
                        "Cannot migrate while on-demand memory restore is in progress"
                    )));
                }
            }
            VmOwnership::Migration { .. } => {
                return Err(MigratableError::MigrateSend(anyhow!(
                    "There is already an ongoing migration"
                )));
            }
            VmOwnership::None => {
                return Err(MigratableError::MigrateSend(anyhow!("VM is not running")));
            }
        }

        send_data_migration
            .validate()
            .context("Invalid send migration configuration")
            .map_err(MigratableError::MigrateSend)?;

        info!(
            "Sending migration: destination_url={},local={},tls={},downtime={}ms,timeout={}s,timeout_strategy={:?}",
            send_data_migration.destination_url,
            send_data_migration.local,
            send_data_migration.tls_dir.is_some(),
            send_data_migration.downtime().as_millis(),
            send_data_migration.timeout().as_secs(),
            send_data_migration.timeout_strategy
        );

        if !self
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .backed_by_shared_memory()
            && send_data_migration.local
        {
            return Err(MigratableError::MigrateSend(anyhow!(
                "Local migration requires shared memory or hugepages enabled"
            )));
        }

        let vm = self
            .vm
            .as_mut()
            .ok_or_else(|| MigratableError::MigrateSend(anyhow!("VM is not running")))?;

        let initial_vm_state = vm.get_state();
        if initial_vm_state != VmState::Running && initial_vm_state != VmState::Paused {
            return Err(MigratableError::MigrateSend(anyhow!(
                "VM is not running or paused: {initial_vm_state:?}"
            )));
        }

        let vm_info_snapshot = self.vm_info().map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Failed to query VM info snapshot: {e}"))
        })?;

        let check_migration_evt = self
            .check_migration_evt
            .try_clone()
            .with_context(|| "Failed to clone check_migration_evt FD")
            .map_err(MigratableError::MigrateSend)?;

        // We are creating all seccomp filters beforehand, as:
        // - this simplifies the code (especially error propagation)
        // - the overhead is negligible
        let seccomp_filters = {
            let worker = get_seccomp_filter(&self.seccomp_action, Thread::MigrationWorker, None)
                .map_err(|e| {
                    MigratableError::MigrateSend(anyhow!(
                        "Error creating migration seccomp filter: {e}"
                    ))
                })?;

            let tcp_worker =
                get_seccomp_filter(&self.seccomp_action, Thread::MigrationTcpWorker, None)
                    .map_err(|e| {
                        MigratableError::MigrateSend(anyhow!(
                            "Error creating migration TCP worker seccomp filter: {e}"
                        ))
                    })?;

            // Build the seccomp filter on the parent thread so any failure aborts
            // the migration before the serve thread is spawned.
            let postcopy_server =
                get_seccomp_filter(&self.seccomp_action, Thread::MigrateSendPostcopy, None)
                    .map_err(|e| {
                        MigratableError::MigrateSend(anyhow!(
                            "creating postcopy serve seccomp filter: {e}"
                        ))
                    })?;

            MigrationSeccompFilters {
                worker,
                tcp_worker,
                postcopy_server,
            }
        };

        // Take VM ownership. This also means that API events can no longer
        // change the VM (e.g. net device hotplug).
        let vm = self
            .vm
            .take_owned_or(VmError::VmNotRunning)
            .expect("should have VM ownership as we just checked it");

        let device_manager = Arc::downgrade(vm.device_manager());

        match MigrationWorker::spawn(
            vm,
            check_migration_evt,
            send_data_migration,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            self.hypervisor.clone(),
            initial_vm_state,
            seccomp_filters,
        ) {
            Ok(handle) => {
                self.vm = VmOwnership::Migration {
                    migration_worker_handle: handle,
                    vm_info_response: vm_info_snapshot,
                    device_manager,
                };
                Ok(())
            }
            Err(e) => {
                self.vm = VmOwnership::Owned(e.vm);
                Err(MigratableError::MigrateSend(e.spawn_error.into()))
            }
        }
    }
}

const CPU_MANAGER_SNAPSHOT_ID: &str = "cpu-manager";
const MEMORY_MANAGER_SNAPSHOT_ID: &str = "memory-manager";
const DEVICE_MANAGER_SNAPSHOT_ID: &str = "device-manager";

mod util {
    use std::error::Error as StdError;
    use std::iter;

    /// Creates in iterator over the [`Display`]-formatted representations of
    /// the chain of errors of a [`StdError`].
    ///
    /// The first index is the top error, the last index is the root cause.
    ///
    /// This mimics the error chain that we print on exit in CH or ch-remote for
    /// situations where we do not exit the program.
    pub fn error_chain_messages(top_error: &dyn StdError) -> Vec<String> {
        iter::successors(Some(top_error), |sub_error| {
            // Dereference necessary to mitigate rustc compiler bug.
            // See <https://github.com/rust-lang/rust/issues/141673>
            (*sub_error).source()
        })
        // Important to use the plain Display impl to not interfere
        // with anyhow's "smart" printing
        .map(|e| format!("{e}"))
        .collect()
    }

    /// Flattens the chain of errors of a [`StdError`] into a single printable
    /// line.
    pub fn flatten_error_chain_to_string(top_error: &dyn StdError) -> String {
        // Separator discussed here: https://github.com/cloud-hypervisor/cloud-hypervisor/issues/8510
        error_chain_messages(top_error).join(": ")
    }
}
#[cfg(test)]
mod unit_tests {
    use std::path::PathBuf;

    use arch::CpuProfile;

    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::vm_config::DebugConsoleConfig;
    use crate::vm_config::{
        CommonConsoleConfig, ConsoleConfig, ConsoleOutputMode, CoreScheduling, CpuFeatures,
        CpusConfig, HotplugMethod, MemoryConfig, PayloadConfig, PciDeviceCommonConfig, RngConfig,
        SerialConfig,
    };

    fn create_dummy_vmm() -> Vmm {
        Vmm::new(
            VmmVersionInfo::new("dummy", "dummy"),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            #[cfg(feature = "guest_debug")]
            EventFd::new(EFD_NONBLOCK).unwrap(),
            #[cfg(feature = "guest_debug")]
            EventFd::new(EFD_NONBLOCK).unwrap(),
            SeccompAction::Allow,
            hypervisor::new().unwrap(),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            false,
        )
        .unwrap()
    }

    fn create_dummy_vm_config() -> Box<VmConfig> {
        Box::new(VmConfig {
            cpus: CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                topology: None,
                kvm_hyperv: false,
                max_phys_bits: 46,
                affinity: None,
                features: CpuFeatures::default(),
                nested: true,
                core_scheduling: CoreScheduling::default(),
                profile: CpuProfile::default(),
            },
            memory: MemoryConfig {
                size: 536_870_912,
                mergeable: false,
                hotplug_method: HotplugMethod::Acpi,
                hotplug_size: None,
                hotplugged_size: None,
                shared: true,
                hugepages: false,
                hugepage_size: None,
                prefault: false,
                reserve: false,
                zones: None,
                thp: true,
            },
            payload: Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                firmware: None,
                cmdline: None,
                initramfs: None,
                #[cfg(feature = "igvm")]
                igvm: None,
                #[cfg(feature = "sev_snp")]
                host_data: None,
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config: None,
            }),
            rate_limit_groups: None,
            disks: None,
            net: None,
            rng: RngConfig {
                src: PathBuf::from("/dev/urandom"),
                pci_common: PciDeviceCommonConfig::default(),
            },
            balloon: None,
            fs: None,
            generic_vhost_user: None,
            pmem: None,
            serial: SerialConfig {
                common: CommonConsoleConfig {
                    file: None,
                    mode: ConsoleOutputMode::Null,
                    socket: None,
                },
            },
            console: ConsoleConfig {
                common: CommonConsoleConfig {
                    file: None,
                    // Caution: Don't use `Tty` to not mess with users terminal
                    mode: ConsoleOutputMode::Off,
                    socket: None,
                },
                pci_common: PciDeviceCommonConfig::default(),
            },
            #[cfg(target_arch = "x86_64")]
            debug_console: DebugConsoleConfig::default(),
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: None,
            pvpanic: false,
            iommu: false,
            numa: None,
            watchdog: false,
            rtc: None,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            pci_segments: None,
            platform: None,
            tpm: None,
            preserved_fds: None,
            landlock_enable: false,
            landlock_rules: None,
            #[cfg(feature = "ivshmem")]
            ivshmem: None,
        })
    }

    #[test]
    fn test_vmm_vm_create() {
        let mut vmm = create_dummy_vmm();
        let config = create_dummy_vm_config();

        assert!(matches!(vmm.vm_create(config.clone()), Ok(())));
        assert!(matches!(
            vmm.vm_create(config),
            Err(VmError::VmAlreadyCreated)
        ));
    }

    #[test]
    fn test_vmm_vm_cold_add_device() {
        let mut vmm = create_dummy_vmm();
        let device_config = DeviceConfig::parse("path=/path/to/device").unwrap();

        assert!(matches!(
            vmm.vm_add_device(device_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .devices
                .is_none()
        );

        assert!(vmm.vm_add_device(device_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .devices
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .devices
                .clone()
                .unwrap()[0],
            device_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_user_device() {
        let mut vmm = create_dummy_vmm();
        let user_device_config = UserDeviceConfig::parse("socket=/path/to/socket,id=8").unwrap();

        assert!(matches!(
            vmm.vm_add_user_device(user_device_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .user_devices
                .is_none()
        );

        assert!(
            vmm.vm_add_user_device(user_device_config.clone())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .user_devices
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .user_devices
                .clone()
                .unwrap()[0],
            user_device_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_disk() {
        let mut vmm = create_dummy_vmm();
        let disk_config = DiskConfig::parse("path=/path/to_file").unwrap();

        assert!(matches!(
            vmm.vm_add_disk(disk_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .disks
                .is_none()
        );

        assert!(vmm.vm_add_disk(disk_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .disks
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .disks
                .clone()
                .unwrap()[0],
            disk_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_fs() {
        let mut vmm = create_dummy_vmm();
        let fs_config = FsConfig::parse("tag=mytag,socket=/tmp/sock").unwrap();

        assert!(matches!(
            vmm.vm_add_fs(fs_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(vmm.vm_config.as_ref().unwrap().lock().unwrap().fs.is_none());

        assert!(vmm.vm_add_fs(fs_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .fs
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .fs
                .clone()
                .unwrap()[0],
            fs_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_generic_vhost_user() {
        let mut vmm = create_dummy_vmm();
        let generic_vhost_user_config =
            GenericVhostUserConfig::parse("device_type=26,socket=/tmp/sock,queue_sizes=[1024]")
                .unwrap();

        assert!(matches!(
            vmm.vm_add_generic_vhost_user(generic_vhost_user_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .generic_vhost_user
                .is_none()
        );

        assert!(
            vmm.vm_add_generic_vhost_user(generic_vhost_user_config.clone())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .generic_vhost_user
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .generic_vhost_user
                .clone()
                .unwrap()[0],
            generic_vhost_user_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_pmem() {
        let mut vmm = create_dummy_vmm();
        let pmem_config = PmemConfig::parse("file=/tmp/pmem,size=128M").unwrap();

        assert!(matches!(
            vmm.vm_add_pmem(pmem_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .pmem
                .is_none()
        );

        assert!(vmm.vm_add_pmem(pmem_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .pmem
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .pmem
                .clone()
                .unwrap()[0],
            pmem_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_net() {
        let mut vmm = create_dummy_vmm();
        let net_config = NetConfig::parse(
            "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,vhost_user=true,socket=/tmp/sock",
        )
        .unwrap();

        assert!(matches!(
            vmm.vm_add_net(net_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .net
                .is_none()
        );

        assert!(vmm.vm_add_net(net_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .net
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .net
                .clone()
                .unwrap()[0],
            net_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_vdpa() {
        let mut vmm = create_dummy_vmm();
        let vdpa_config = VdpaConfig::parse("path=/dev/vhost-vdpa,num_queues=2").unwrap();

        assert!(matches!(
            vmm.vm_add_vdpa(vdpa_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .vdpa
                .is_none()
        );

        assert!(vmm.vm_add_vdpa(vdpa_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .vdpa
                .clone()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .vdpa
                .clone()
                .unwrap()[0],
            vdpa_config
        );
    }

    #[test]
    fn test_vmm_vm_cold_add_vsock() {
        let mut vmm = create_dummy_vmm();
        let vsock_config = VsockConfig::parse("socket=/tmp/sock,cid=3,iommu=on").unwrap();

        assert!(matches!(
            vmm.vm_add_vsock(vsock_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .vsock
                .is_none()
        );

        assert!(vmm.vm_add_vsock(vsock_config.clone()).unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .vsock
                .clone()
                .unwrap(),
            vsock_config
        );
    }
}
