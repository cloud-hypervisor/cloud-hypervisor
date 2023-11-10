// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate event_monitor;
#[macro_use]
extern crate log;

use crate::api::{
    ApiRequest, ApiResponse, RequestHandler, VmInfoResponse, VmReceiveMigrationData,
    VmSendMigrationData, VmmPingResponse,
};
use crate::config::{
    add_to_config, DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, RestoreConfig,
    UserDeviceConfig, VdpaConfig, VmConfig, VsockConfig,
};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::GuestDebuggable;
use crate::memory_manager::MemoryManager;
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use crate::migration::get_vm_snapshot;
use crate::migration::{recv_vm_config, recv_vm_state};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vm::{Error as VmError, Vm, VmState};
use anyhow::anyhow;
#[cfg(feature = "dbus_api")]
use api::dbus::{DBusApiOptions, DBusApiShutdownChannels};
use libc::{tcsetattr, termios, EFD_NONBLOCK, SIGINT, SIGTERM, TCSANOW};
use memory_manager::MemoryManagerSnapshotData;
use pci::PciBdf;
use seccompiler::{apply_filter, SeccompAction};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use signal_hook::iterator::{Handle, Signals};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{stdout, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{result, thread};
use thiserror::Error;
use tracer::trace_scoped;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{ReadVolatile, WriteVolatile};
use vm_migration::{protocol::*, Migratable};
use vm_migration::{MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::unblock_signal;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

mod acpi;
pub mod api;
mod clone3;
pub mod config;
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
pub mod memory_manager;
pub mod migration;
mod pci_segment;
pub mod seccomp_filters;
mod serial_manager;
mod sigwinch_listener;
pub mod vm;
pub mod vm_config;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;

/// Errors associated with VMM management
#[derive(Debug, Error)]
pub enum Error {
    /// API request receive error
    #[error("Error receiving API request: {0}")]
    ApiRequestRecv(#[source] RecvError),

    /// API response send error
    #[error("Error sending API request: {0}")]
    ApiResponseSend(#[source] SendError<ApiResponse>),

    /// Cannot bind to the UNIX domain socket path
    #[error("Error binding to UNIX domain socket: {0}")]
    Bind(#[source] io::Error),

    /// Cannot clone EventFd.
    #[error("Error cloning EventFd: {0}")]
    EventFdClone(#[source] io::Error),

    /// Cannot create EventFd.
    #[error("Error creating EventFd: {0}")]
    EventFdCreate(#[source] io::Error),

    /// Cannot read from EventFd.
    #[error("Error reading from EventFd: {0}")]
    EventFdRead(#[source] io::Error),

    /// Cannot create epoll context.
    #[error("Error creating epoll context: {0}")]
    Epoll(#[source] io::Error),

    /// Cannot create HTTP thread
    #[error("Error spawning HTTP thread: {0}")]
    HttpThreadSpawn(#[source] io::Error),

    /// Cannot create D-Bus thread
    #[cfg(feature = "dbus_api")]
    #[error("Error spawning D-Bus thread: {0}")]
    DBusThreadSpawn(#[source] io::Error),

    /// Cannot start D-Bus session
    #[cfg(feature = "dbus_api")]
    #[error("Error starting D-Bus session: {0}")]
    CreateDBusSession(#[source] zbus::Error),

    /// Cannot create `event-monitor` thread
    #[error("Error spawning `event-monitor` thread: {0}")]
    EventMonitorThreadSpawn(#[source] io::Error),

    /// Cannot handle the VM STDIN stream
    #[error("Error handling VM stdin: {0:?}")]
    Stdin(VmError),

    /// Cannot handle the VM pty stream
    #[error("Error handling VM pty: {0:?}")]
    Pty(VmError),

    /// Cannot reboot the VM
    #[error("Error rebooting VM: {0:?}")]
    VmReboot(VmError),

    /// Cannot create VMM thread
    #[error("Error spawning VMM thread {0:?}")]
    VmmThreadSpawn(#[source] io::Error),

    /// Cannot shut the VMM down
    #[error("Error shutting down VMM: {0:?}")]
    VmmShutdown(VmError),

    /// Cannot create seccomp filter
    #[error("Error creating seccomp filter: {0}")]
    CreateSeccompFilter(seccompiler::Error),

    /// Cannot apply seccomp filter
    #[error("Error applying seccomp filter: {0}")]
    ApplySeccompFilter(seccompiler::Error),

    /// Error activating virtio devices
    #[error("Error activating virtio devices: {0:?}")]
    ActivateVirtioDevices(VmError),

    /// Error creating API server
    #[error("Error creating API server {0:?}")]
    CreateApiServer(micro_http::ServerError),

    /// Error binding API server socket
    #[error("Error creation API server's socket {0:?}")]
    CreateApiServerSocket(#[source] io::Error),

    #[cfg(feature = "guest_debug")]
    #[error("Failed to start the GDB thread: {0}")]
    GdbThreadSpawn(io::Error),

    /// GDB request receive error
    #[cfg(feature = "guest_debug")]
    #[error("Error receiving GDB request: {0}")]
    GdbRequestRecv(#[source] RecvError),

    /// GDB response send error
    #[cfg(feature = "guest_debug")]
    #[error("Error sending GDB request: {0}")]
    GdbResponseSend(#[source] SendError<gdb::GdbResponse>),

    #[error("Cannot spawn a signal handler thread: {0}")]
    SignalHandlerSpawn(#[source] io::Error),

    #[error("Failed to join on threads: {0:?}")]
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
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
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
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
    ]
}

pub fn start_event_monitor_thread(
    mut monitor: event_monitor::Monitor,
    seccomp_action: &SeccompAction,
    hypervisor_type: hypervisor::HypervisorType,
    exit_event: EventFd,
) -> Result<thread::JoinHandle<Result<()>>> {
    // Retrieve seccomp filter
    let seccomp_filter = get_seccomp_filter(seccomp_action, Thread::EventMonitor, hypervisor_type)
        .map_err(Error::CreateSeccompFilter)?;

    thread::Builder::new()
        .name("event-monitor".to_owned())
        .spawn(move || {
            // Apply seccomp filter
            if !seccomp_filter.is_empty() {
                apply_filter(&seccomp_filter)
                    .map_err(Error::ApplySeccompFilter)
                    .map_err(|e| {
                        error!("Error applying seccomp filter: {:?}", e);
                        exit_event.write(1).ok();
                        e
                    })?;
            }

            std::panic::catch_unwind(AssertUnwindSafe(move || {
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

#[allow(unused_variables)]
#[allow(clippy::too_many_arguments)]
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
) -> Result<VmmThreadHandle> {
    #[cfg(feature = "guest_debug")]
    let gdb_hw_breakpoints = hypervisor.get_guest_debug_hw_bps();
    #[cfg(feature = "guest_debug")]
    let (gdb_sender, gdb_receiver) = std::sync::mpsc::channel();
    #[cfg(feature = "guest_debug")]
    let gdb_debug_event = debug_event.try_clone().map_err(Error::EventFdClone)?;
    #[cfg(feature = "guest_debug")]
    let gdb_vm_debug_event = vm_debug_event.try_clone().map_err(Error::EventFdClone)?;

    let api_event_clone = api_event.try_clone().map_err(Error::EventFdClone)?;
    let hypervisor_type = hypervisor.hypervisor_type();

    // Retrieve seccomp filter
    let vmm_seccomp_filter = get_seccomp_filter(seccomp_action, Thread::Vmm, hypervisor_type)
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
                )?;

                vmm.setup_signal_handler()?;

                vmm.control_loop(
                    Rc::new(api_receiver),
                    #[cfg(feature = "guest_debug")]
                    Rc::new(gdb_receiver),
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
                hypervisor_type,
            )?;
            Some(chs)
        }
        None => None,
    };

    if let Some(http_path) = http_path {
        api::start_http_path_thread(
            http_path,
            api_event_clone,
            api_sender,
            seccomp_action,
            exit_event,
            hypervisor_type,
        )?;
    } else if let Some(http_fd) = http_fd {
        api::start_http_fd_thread(
            http_fd,
            api_event_clone,
            api_sender,
            seccomp_action,
            exit_event,
            hypervisor_type,
        )?;
    }

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
    })
}

#[derive(Clone, Deserialize, Serialize)]
struct VmMigrationConfig {
    vm_config: Arc<Mutex<VmConfig>>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    common_cpuid: Vec<hypervisor::arch::x86::CpuIdEntry>,
    memory_manager_data: MemoryManagerSnapshotData,
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
}

pub struct Vmm {
    epoll: EpollContext,
    exit_evt: EventFd,
    reset_evt: EventFd,
    api_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    debug_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    vm_debug_evt: EventFd,
    version: VmmVersionInfo,
    vm: Option<Vm>,
    vm_config: Option<Arc<Mutex<VmConfig>>>,
    seccomp_action: SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    activate_evt: EventFd,
    signals: Option<Handle>,
    threads: Vec<thread::JoinHandle<()>>,
    original_termios_opt: Arc<Mutex<Option<termios>>>,
}

impl Vmm {
    pub const HANDLED_SIGNALS: [i32; 2] = [SIGTERM, SIGINT];

    fn signal_handler(
        mut signals: Signals,
        original_termios_opt: Arc<Mutex<Option<termios>>>,
        exit_evt: &EventFd,
    ) {
        for sig in &Self::HANDLED_SIGNALS {
            unblock_signal(*sig).unwrap();
        }

        for signal in signals.forever() {
            match signal {
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

                        std::process::exit(1);
                    }
                }
                _ => (),
            }
        }
    }

    fn setup_signal_handler(&mut self) -> Result<()> {
        let signals = Signals::new(Self::HANDLED_SIGNALS);
        match signals {
            Ok(signals) => {
                self.signals = Some(signals.handle());
                let exit_evt = self.exit_evt.try_clone().map_err(Error::EventFdClone)?;
                let original_termios_opt = Arc::clone(&self.original_termios_opt);

                let signal_handler_seccomp_filter = get_seccomp_filter(
                    &self.seccomp_action,
                    Thread::SignalHandler,
                    self.hypervisor.hypervisor_type(),
                )
                .map_err(Error::CreateSeccompFilter)?;
                self.threads.push(
                    thread::Builder::new()
                        .name("vmm_signal_handler".to_string())
                        .spawn(move || {
                            if !signal_handler_seccomp_filter.is_empty() {
                                if let Err(e) = apply_filter(&signal_handler_seccomp_filter)
                                    .map_err(Error::ApplySeccompFilter)
                                {
                                    error!("Error applying seccomp filter: {:?}", e);
                                    exit_evt.write(1).ok();
                                    return;
                                }
                            }
                            std::panic::catch_unwind(AssertUnwindSafe(|| {
                                Vmm::signal_handler(signals, original_termios_opt, &exit_evt);
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
            Err(e) => error!("Signal not found {}", e),
        }
        Ok(())
    }

    fn new(
        vmm_version: VmmVersionInfo,
        api_evt: EventFd,
        #[cfg(feature = "guest_debug")] debug_evt: EventFd,
        #[cfg(feature = "guest_debug")] vm_debug_evt: EventFd,
        seccomp_action: SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        exit_evt: EventFd,
    ) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let activate_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        epoll
            .add_event(&exit_evt, EpollDispatch::Exit)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&reset_evt, EpollDispatch::Reset)
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

        Ok(Vmm {
            epoll,
            exit_evt,
            reset_evt,
            api_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            version: vmm_version,
            vm: None,
            vm_config: None,
            seccomp_action,
            hypervisor,
            activate_evt,
            signals: None,
            threads: vec![],
            original_termios_opt: Arc::new(Mutex::new(None)),
        })
    }

    fn vm_receive_config<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        existing_memory_files: Option<HashMap<u32, File>>,
    ) -> std::result::Result<Arc<Mutex<MemoryManager>>, MigratableError>
    where
        T: Read + Write,
    {
        // Read in config data along with memory manager data
        let mut data: Vec<u8> = Vec::new();
        data.resize_with(req.length() as usize, Default::default);
        socket
            .read_exact(&mut data)
            .map_err(MigratableError::MigrateSocket)?;

        let vm_migration_config: VmMigrationConfig =
            serde_json::from_slice(&data).map_err(|e| {
                MigratableError::MigrateReceive(anyhow!("Error deserialising config: {}", e))
            })?;

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        self.vm_check_cpuid_compatibility(
            &vm_migration_config.vm_config,
            &vm_migration_config.common_cpuid,
        )?;

        let config = vm_migration_config.vm_config.clone();
        self.vm_config = Some(vm_migration_config.vm_config);

        let vm = Vm::create_hypervisor_vm(
            &self.hypervisor,
            #[cfg(feature = "tdx")]
            false,
            #[cfg(feature = "sev_snp")]
            false,
        )
        .map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error creating hypervisor VM from snapshot: {:?}",
                e
            ))
        })?;

        let phys_bits =
            vm::physical_bits(&self.hypervisor, config.lock().unwrap().cpus.max_phys_bits);

        let memory_manager = MemoryManager::new(
            vm,
            &config.lock().unwrap().memory.clone(),
            None,
            phys_bits,
            #[cfg(feature = "tdx")]
            false,
            Some(&vm_migration_config.memory_manager_data),
            existing_memory_files,
            #[cfg(target_arch = "x86_64")]
            None,
            #[cfg(target_arch = "x86_64")]
            self.hypervisor.get_cpu_vendor(),
        )
        .map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error creating MemoryManager from snapshot: {:?}",
                e
            ))
        })?;

        Response::ok().write_to(socket)?;

        Ok(memory_manager)
    }

    fn vm_receive_state<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        mm: Arc<Mutex<MemoryManager>>,
    ) -> std::result::Result<(), MigratableError>
    where
        T: Read + Write,
    {
        // Read in state data
        let mut data: Vec<u8> = Vec::new();
        data.resize_with(req.length() as usize, Default::default);
        socket
            .read_exact(&mut data)
            .map_err(MigratableError::MigrateSocket)?;
        let snapshot: Snapshot = serde_json::from_slice(&data).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error deserialising snapshot: {}", e))
        })?;

        let exit_evt = self.exit_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning exit EventFd: {}", e))
        })?;
        let reset_evt = self.reset_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning reset EventFd: {}", e))
        })?;
        #[cfg(feature = "guest_debug")]
        let debug_evt = self.vm_debug_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning debug EventFd: {}", e))
        })?;
        let activate_evt = self.activate_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning activate EventFd: {}", e))
        })?;

        let timestamp = Instant::now();
        let hypervisor_vm = mm.lock().unwrap().vm.clone();
        let mut vm = Vm::new_from_memory_manager(
            self.vm_config.clone().unwrap(),
            mm,
            hypervisor_vm,
            exit_evt,
            reset_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
            timestamp,
            None,
            None,
            None,
            None,
            Arc::clone(&self.original_termios_opt),
            Some(snapshot),
        )
        .map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error creating VM from snapshot: {:?}", e))
        })?;

        // Create VM
        vm.restore().map_err(|e| {
            Response::error().write_to(socket).ok();
            MigratableError::MigrateReceive(anyhow!("Failed restoring the Vm: {}", e))
        })?;
        self.vm = Some(vm);

        Response::ok().write_to(socket)?;

        Ok(())
    }

    fn vm_receive_memory<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        memory_manager: &mut MemoryManager,
    ) -> std::result::Result<(), MigratableError>
    where
        T: Read + ReadVolatile + Write,
    {
        // Read table
        let table = MemoryRangeTable::read_from(socket, req.length())?;

        // And then read the memory itself
        memory_manager
            .receive_memory_regions(&table, socket)
            .map_err(|e| {
                Response::error().write_to(socket).ok();
                e
            })?;
        Response::ok().write_to(socket)?;
        Ok(())
    }

    fn socket_url_to_path(url: &str) -> result::Result<PathBuf, MigratableError> {
        url.strip_prefix("unix:")
            .ok_or_else(|| {
                MigratableError::MigrateSend(anyhow!("Could not extract path from URL: {}", url))
            })
            .map(|s| s.into())
    }

    // Returns true if there were dirty pages to send
    fn vm_maybe_send_dirty_pages<T>(
        vm: &mut Vm,
        socket: &mut T,
    ) -> result::Result<bool, MigratableError>
    where
        T: Read + Write + WriteVolatile,
    {
        // Send (dirty) memory table
        let table = vm.dirty_log()?;

        // But if there are no regions go straight to pause
        if table.regions().is_empty() {
            return Ok(false);
        }

        Request::memory(table.length()).write_to(socket).unwrap();
        table.write_to(socket)?;
        // And then the memory itself
        vm.send_memory_regions(&table, socket)?;
        let res = Response::read_from(socket)?;
        if res.status() != Status::Ok {
            warn!("Error during dirty memory migration");
            Request::abandon().write_to(socket)?;
            Response::read_from(socket).ok();
            return Err(MigratableError::MigrateSend(anyhow!(
                "Error during dirty memory migration"
            )));
        }

        Ok(true)
    }

    fn send_migration(
        vm: &mut Vm,
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))] hypervisor: Arc<
            dyn hypervisor::Hypervisor,
        >,
        send_data_migration: VmSendMigrationData,
    ) -> result::Result<(), MigratableError> {
        let path = Self::socket_url_to_path(&send_data_migration.destination_url)?;
        let mut socket = UnixStream::connect(path).map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Error connecting to UNIX socket: {}", e))
        })?;

        // Start the migration
        Request::start().write_to(&mut socket)?;
        let res = Response::read_from(&mut socket)?;
        if res.status() != Status::Ok {
            warn!("Error starting migration");
            Request::abandon().write_to(&mut socket)?;
            Response::read_from(&mut socket).ok();
            return Err(MigratableError::MigrateSend(anyhow!(
                "Error starting migration"
            )));
        }

        // Send config
        let vm_config = vm.get_config();
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        let common_cpuid = {
            #[cfg(feature = "tdx")]
            if vm_config.lock().unwrap().is_tdx_enabled() {
                return Err(MigratableError::MigrateSend(anyhow!(
                    "Live Migration is not supported when TDX is enabled"
                )));
            };

            let amx = vm_config.lock().unwrap().cpus.features.amx;
            let phys_bits =
                vm::physical_bits(&hypervisor, vm_config.lock().unwrap().cpus.max_phys_bits);
            arch::generate_common_cpuid(
                &hypervisor,
                &arch::CpuidConfig {
                    sgx_epc_sections: None,
                    phys_bits,
                    kvm_hyperv: vm_config.lock().unwrap().cpus.kvm_hyperv,
                    #[cfg(feature = "tdx")]
                    tdx: false,
                    amx,
                },
            )
            .map_err(|e| {
                MigratableError::MigrateSend(anyhow!("Error generating common cpuid': {:?}", e))
            })?
        };

        if send_data_migration.local {
            vm.send_memory_fds(&mut socket)?;
        }

        let vm_migration_config = VmMigrationConfig {
            vm_config,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            common_cpuid,
            memory_manager_data: vm.memory_manager_data(),
        };
        let config_data = serde_json::to_vec(&vm_migration_config).unwrap();
        Request::config(config_data.len() as u64).write_to(&mut socket)?;
        socket
            .write_all(&config_data)
            .map_err(MigratableError::MigrateSocket)?;
        let res = Response::read_from(&mut socket)?;
        if res.status() != Status::Ok {
            warn!("Error during config migration");
            Request::abandon().write_to(&mut socket)?;
            Response::read_from(&mut socket).ok();
            return Err(MigratableError::MigrateSend(anyhow!(
                "Error during config migration"
            )));
        }

        // Let every Migratable object know about the migration being started.
        vm.start_migration()?;

        if send_data_migration.local {
            // Now pause VM
            vm.pause()?;
        } else {
            // Start logging dirty pages
            vm.start_dirty_log()?;

            // Send memory table
            let table = vm.memory_range_table()?;
            Request::memory(table.length())
                .write_to(&mut socket)
                .unwrap();
            table.write_to(&mut socket)?;
            // And then the memory itself
            vm.send_memory_regions(&table, &mut socket)?;
            let res = Response::read_from(&mut socket)?;
            if res.status() != Status::Ok {
                warn!("Error during memory migration");
                Request::abandon().write_to(&mut socket)?;
                Response::read_from(&mut socket).ok();
                return Err(MigratableError::MigrateSend(anyhow!(
                    "Error during memory migration"
                )));
            }

            // Try at most 5 passes of dirty memory sending
            const MAX_DIRTY_MIGRATIONS: usize = 5;
            for i in 0..MAX_DIRTY_MIGRATIONS {
                info!("Dirty memory migration {} of {}", i, MAX_DIRTY_MIGRATIONS);
                if !Self::vm_maybe_send_dirty_pages(vm, &mut socket)? {
                    break;
                }
            }

            // Now pause VM
            vm.pause()?;

            // Send last batch of dirty pages
            Self::vm_maybe_send_dirty_pages(vm, &mut socket)?;

            // Stop logging dirty pages
            vm.stop_dirty_log()?;
        }
        // Capture snapshot and send it
        let vm_snapshot = vm.snapshot()?;
        let snapshot_data = serde_json::to_vec(&vm_snapshot).unwrap();
        Request::state(snapshot_data.len() as u64).write_to(&mut socket)?;
        socket
            .write_all(&snapshot_data)
            .map_err(MigratableError::MigrateSocket)?;
        let res = Response::read_from(&mut socket)?;
        if res.status() != Status::Ok {
            warn!("Error during state migration");
            Request::abandon().write_to(&mut socket)?;
            Response::read_from(&mut socket).ok();
            return Err(MigratableError::MigrateSend(anyhow!(
                "Error during state migration"
            )));
        }

        // Complete the migration
        Request::complete().write_to(&mut socket)?;
        let res = Response::read_from(&mut socket)?;
        if res.status() != Status::Ok {
            warn!("Error completing migration");
            Request::abandon().write_to(&mut socket)?;
            Response::read_from(&mut socket).ok();
            return Err(MigratableError::MigrateSend(anyhow!(
                "Error completing migration"
            )));
        }
        info!("Migration complete");

        // Let every Migratable object know about the migration being complete
        vm.complete_migration()
    }

    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn vm_check_cpuid_compatibility(
        &self,
        src_vm_config: &Arc<Mutex<VmConfig>>,
        src_vm_cpuid: &[hypervisor::arch::x86::CpuIdEntry],
    ) -> result::Result<(), MigratableError> {
        #[cfg(feature = "tdx")]
        if src_vm_config.lock().unwrap().is_tdx_enabled() {
            return Err(MigratableError::MigrateReceive(anyhow!(
                "Live Migration is not supported when TDX is enabled"
            )));
        };

        // We check the `CPUID` compatibility of between the source vm and destination, which is
        // mostly about feature compatibility and "topology/sgx" leaves are not relevant.
        let dest_cpuid = &{
            let vm_config = &src_vm_config.lock().unwrap();

            let phys_bits = vm::physical_bits(&self.hypervisor, vm_config.cpus.max_phys_bits);
            arch::generate_common_cpuid(
                &self.hypervisor.clone(),
                &arch::CpuidConfig {
                    sgx_epc_sections: None,
                    phys_bits,
                    kvm_hyperv: vm_config.cpus.kvm_hyperv,
                    #[cfg(feature = "tdx")]
                    tdx: false,
                    amx: vm_config.cpus.features.amx,
                },
            )
            .map_err(|e| {
                MigratableError::MigrateReceive(anyhow!("Error generating common cpuid: {:?}", e))
            })?
        };
        arch::CpuidFeatureEntry::check_cpuid_compatibility(src_vm_cpuid, dest_cpuid).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error checking cpu feature compatibility': {:?}",
                e
            ))
        })
    }

    fn control_loop(
        &mut self,
        api_receiver: Rc<Receiver<ApiRequest>>,
        #[cfg(feature = "guest_debug")] gdb_receiver: Rc<Receiver<gdb::GdbRequest>>,
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
                        warn!("Unknown VMM loop event: {}", event);
                    }
                    EpollDispatch::Exit => {
                        info!("VM exit event");
                        // Consume the event.
                        self.exit_evt.read().map_err(Error::EventFdRead)?;
                        self.vmm_shutdown().map_err(Error::VmmShutdown)?;

                        break 'outer;
                    }
                    EpollDispatch::Reset => {
                        info!("VM reset event");
                        // Consume the event.
                        self.reset_evt.read().map_err(Error::EventFdRead)?;
                        self.vm_reboot().map_err(Error::VmReboot)?;
                    }
                    EpollDispatch::ActivateVirtioDevices => {
                        if let Some(ref vm) = self.vm {
                            let count = self.activate_evt.read().map_err(Error::EventFdRead)?;
                            info!(
                                "Trying to activate pending virtio devices: count = {}",
                                count
                            );
                            vm.activate_virtio_devices()
                                .map_err(Error::ActivateVirtioDevices)?;
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

                            let response = if let Some(ref mut vm) = self.vm {
                                vm.debug_request(&gdb_request.payload, gdb_request.cpu_id)
                            } else {
                                Err(VmError::VmNotRunning)
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
                }
            }
        }

        // Trigger the termination of the signal_handler thread
        if let Some(signals) = self.signals.take() {
            signals.close();
        }

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(Error::ThreadCleanup)?
        }

        Ok(())
    }
}

impl RequestHandler for Vmm {
    fn vm_create(&mut self, config: Arc<Mutex<VmConfig>>) -> result::Result<(), VmError> {
        // We only store the passed VM config.
        // The VM will be created when being asked to boot it.
        if self.vm_config.is_none() {
            self.vm_config = Some(config);
            Ok(())
        } else {
            Err(VmError::VmAlreadyCreated)
        }
    }

    fn vm_boot(&mut self) -> result::Result<(), VmError> {
        tracer::start();
        let r = {
            trace_scoped!("vm_boot");
            // If we don't have a config, we can not boot a VM.
            if self.vm_config.is_none() {
                return Err(VmError::VmMissingConfig);
            };

            // Create a new VM if we don't have one yet.
            if self.vm.is_none() {
                let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
                let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
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
                    let vm = Vm::new(
                        Arc::clone(vm_config),
                        exit_evt,
                        reset_evt,
                        #[cfg(feature = "guest_debug")]
                        vm_debug_evt,
                        &self.seccomp_action,
                        self.hypervisor.clone(),
                        activate_evt,
                        None,
                        None,
                        None,
                        None,
                        Arc::clone(&self.original_termios_opt),
                        None,
                        None,
                        None,
                    )?;

                    self.vm = Some(vm);
                }
            }

            // Now we can boot the VM.
            if let Some(ref mut vm) = self.vm {
                vm.boot()
            } else {
                Err(VmError::VmNotCreated)
            }
        };
        tracer::end();
        r
    }

    fn vm_pause(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.pause().map_err(VmError::Pause)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_resume(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.resume().map_err(VmError::Resume)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_snapshot(&mut self, destination_url: &str) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.snapshot()
                .map_err(VmError::Snapshot)
                .and_then(|snapshot| {
                    vm.send(&snapshot, destination_url)
                        .map_err(VmError::SnapshotSend)
                })
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_restore(&mut self, restore_cfg: RestoreConfig) -> result::Result<(), VmError> {
        if self.vm.is_some() || self.vm_config.is_some() {
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
        let snapshot = recv_vm_state(source_url).map_err(VmError::Restore)?;
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        let vm_snapshot = get_vm_snapshot(&snapshot).map_err(VmError::Restore)?;

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        self.vm_check_cpuid_compatibility(&vm_config, &vm_snapshot.common_cpuid)
            .map_err(VmError::Restore)?;

        self.vm_config = Some(Arc::clone(&vm_config));

        let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
        let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
        #[cfg(feature = "guest_debug")]
        let debug_evt = self
            .vm_debug_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;
        let activate_evt = self
            .activate_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;

        let vm = Vm::new(
            vm_config,
            exit_evt,
            reset_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
            None,
            None,
            None,
            None,
            Arc::clone(&self.original_termios_opt),
            Some(snapshot),
            Some(source_url),
            Some(restore_cfg.prefault),
        )?;
        self.vm = Some(vm);

        // Now we can restore the rest of the VM.
        if let Some(ref mut vm) = self.vm {
            vm.restore()
        } else {
            Err(VmError::VmNotCreated)
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn vm_coredump(&mut self, destination_url: &str) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.coredump(destination_url).map_err(VmError::Coredump)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_shutdown(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm.take() {
            vm.shutdown()
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_reboot(&mut self) -> result::Result<(), VmError> {
        // First we stop the current VM
        let (config, serial_pty, console_pty, debug_console_pty, console_resize_pipe) =
            if let Some(mut vm) = self.vm.take() {
                let config = vm.get_config();
                let serial_pty = vm.serial_pty();
                let console_pty = vm.console_pty();
                let debug_console_pty = vm.debug_console_pty();
                let console_resize_pipe = vm
                    .console_resize_pipe()
                    .as_ref()
                    .map(|pipe| pipe.try_clone().unwrap());
                vm.shutdown()?;
                (
                    config,
                    serial_pty,
                    console_pty,
                    debug_console_pty,
                    console_resize_pipe,
                )
            } else {
                return Err(VmError::VmNotCreated);
            };

        let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
        let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
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

        // Then we create the new VM
        let mut vm = Vm::new(
            config,
            exit_evt,
            reset_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
            serial_pty,
            console_pty,
            debug_console_pty,
            console_resize_pipe,
            Arc::clone(&self.original_termios_opt),
            None,
            None,
            None,
        )?;

        // And we boot it
        vm.boot()?;

        self.vm = Some(vm);

        Ok(())
    }

    fn vm_info(&self) -> result::Result<VmInfoResponse, VmError> {
        match &self.vm_config {
            Some(config) => {
                let state = match &self.vm {
                    Some(vm) => vm.get_state()?,
                    None => VmState::Created,
                };

                let config = Arc::clone(config);

                let mut memory_actual_size = config.lock().unwrap().memory.total_size();
                if let Some(vm) = &self.vm {
                    memory_actual_size -= vm.balloon_size();
                }

                let device_tree = self.vm.as_ref().map(|vm| vm.device_tree());

                Ok(VmInfoResponse {
                    config,
                    state,
                    memory_actual_size,
                    device_tree,
                })
            }
            None => Err(VmError::VmNotCreated),
        }
    }

    fn vmm_ping(&self) -> VmmPingResponse {
        let VmmVersionInfo {
            build_version,
            version,
        } = self.version.clone();

        VmmPingResponse {
            build_version,
            version,
            pid: std::process::id() as i64,
            features: feature_list(),
        }
    }

    fn vm_delete(&mut self) -> result::Result<(), VmError> {
        if self.vm_config.is_none() {
            return Ok(());
        }

        // If a VM is booted, we first try to shut it down.
        if self.vm.is_some() {
            self.vm_shutdown()?;
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
        desired_vcpus: Option<u8>,
        desired_ram: Option<u64>,
        desired_balloon: Option<u64>,
    ) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.resize(desired_vcpus, desired_ram, desired_balloon) {
                error!("Error when resizing VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            if let Some(desired_vcpus) = desired_vcpus {
                config.cpus.boot_vcpus = desired_vcpus;
            }
            if let Some(desired_ram) = desired_ram {
                config.memory.size = desired_ram;
            }
            if let Some(desired_balloon) = desired_balloon {
                if let Some(balloon_config) = &mut config.balloon {
                    balloon_config.size = desired_balloon;
                }
            }
            Ok(())
        }
    }

    fn vm_resize_zone(&mut self, id: String, desired_ram: u64) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.resize_zone(id, desired_ram) {
                error!("Error when resizing VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
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

            error!("Could not find the memory zone {} for the resize", id);
            Err(VmError::ResizeZone)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_device(device_cfg).map_err(|e| {
                error!("Error when adding new device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.devices, device_cfg);
            Ok(None)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_user_device(device_cfg).map_err(|e| {
                error!("Error when adding new user device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.user_devices, device_cfg);
            Ok(None)
        }
    }

    fn vm_remove_device(&mut self, id: String) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.remove_device(id) {
                error!("Error when removing device from the VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else if let Some(ref config) = self.vm_config {
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

    fn vm_add_disk(&mut self, disk_cfg: DiskConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();
            add_to_config(&mut config.disks, disk_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_disk(disk_cfg).map_err(|e| {
                error!("Error when adding new disk to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.disks, disk_cfg);
            Ok(None)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_fs(fs_cfg).map_err(|e| {
                error!("Error when adding new fs to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.fs, fs_cfg);
            Ok(None)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_pmem(pmem_cfg).map_err(|e| {
                error!("Error when adding new pmem device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.pmem, pmem_cfg);
            Ok(None)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_net(net_cfg).map_err(|e| {
                error!("Error when adding new network device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.net, net_cfg);
            Ok(None)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_vdpa(vdpa_cfg).map_err(|e| {
                error!("Error when adding new vDPA device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            add_to_config(&mut config.vdpa, vdpa_cfg);
            Ok(None)
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

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_vsock(vsock_cfg).map_err(|e| {
                error!("Error when adding new vsock device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            config.vsock = Some(vsock_cfg);
            Ok(None)
        }
    }

    fn vm_counters(&mut self) -> result::Result<Option<Vec<u8>>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.counters().map_err(|e| {
                error!("Error when getting counters from the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_power_button(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.power_button()
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_receive_migration(
        &mut self,
        receive_data_migration: VmReceiveMigrationData,
    ) -> result::Result<(), MigratableError> {
        info!(
            "Receiving migration: receiver_url = {}",
            receive_data_migration.receiver_url
        );

        let path = Self::socket_url_to_path(&receive_data_migration.receiver_url)?;
        let listener = UnixListener::bind(&path).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error binding to UNIX socket: {}", e))
        })?;
        let (mut socket, _addr) = listener.accept().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error accepting on UNIX socket: {}", e))
        })?;
        std::fs::remove_file(&path).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error unlinking UNIX socket: {}", e))
        })?;

        let mut started = false;
        let mut memory_manager: Option<Arc<Mutex<MemoryManager>>> = None;
        let mut existing_memory_files = None;
        loop {
            let req = Request::read_from(&mut socket)?;
            match req.command() {
                Command::Invalid => info!("Invalid Command Received"),
                Command::Start => {
                    info!("Start Command Received");
                    started = true;

                    Response::ok().write_to(&mut socket)?;
                }
                Command::Config => {
                    info!("Config Command Received");

                    if !started {
                        warn!("Migration not started yet");
                        Response::error().write_to(&mut socket)?;
                        continue;
                    }
                    memory_manager = Some(self.vm_receive_config(
                        &req,
                        &mut socket,
                        existing_memory_files.take(),
                    )?);
                }
                Command::State => {
                    info!("State Command Received");

                    if !started {
                        warn!("Migration not started yet");
                        Response::error().write_to(&mut socket)?;
                        continue;
                    }
                    if let Some(mm) = memory_manager.take() {
                        self.vm_receive_state(&req, &mut socket, mm)?;
                    } else {
                        warn!("Configuration not sent yet");
                        Response::error().write_to(&mut socket)?;
                    }
                }
                Command::Memory => {
                    info!("Memory Command Received");

                    if !started {
                        warn!("Migration not started yet");
                        Response::error().write_to(&mut socket)?;
                        continue;
                    }
                    if let Some(mm) = memory_manager.as_ref() {
                        self.vm_receive_memory(&req, &mut socket, &mut mm.lock().unwrap())?;
                    } else {
                        warn!("Configuration not sent yet");
                        Response::error().write_to(&mut socket)?;
                    }
                }
                Command::MemoryFd => {
                    info!("MemoryFd Command Received");

                    if !started {
                        warn!("Migration not started yet");
                        Response::error().write_to(&mut socket)?;
                        continue;
                    }

                    let mut buf = [0u8; 4];
                    let (_, file) = socket.recv_with_fd(&mut buf).map_err(|e| {
                        MigratableError::MigrateReceive(anyhow!(
                            "Error receiving slot from socket: {}",
                            e
                        ))
                    })?;

                    if existing_memory_files.is_none() {
                        existing_memory_files = Some(HashMap::default())
                    }

                    if let Some(ref mut existing_memory_files) = existing_memory_files {
                        let slot = u32::from_le_bytes(buf);
                        existing_memory_files.insert(slot, file.unwrap());
                    }

                    Response::ok().write_to(&mut socket)?;
                }
                Command::Complete => {
                    info!("Complete Command Received");
                    if let Some(ref mut vm) = self.vm.as_mut() {
                        vm.resume()?;
                        Response::ok().write_to(&mut socket)?;
                    } else {
                        warn!("VM not created yet");
                        Response::error().write_to(&mut socket)?;
                    }
                    break;
                }
                Command::Abandon => {
                    info!("Abandon Command Received");
                    self.vm = None;
                    self.vm_config = None;
                    Response::ok().write_to(&mut socket).ok();
                    break;
                }
            }
        }

        Ok(())
    }

    fn vm_send_migration(
        &mut self,
        send_data_migration: VmSendMigrationData,
    ) -> result::Result<(), MigratableError> {
        info!(
            "Sending migration: destination_url = {}, local = {}",
            send_data_migration.destination_url, send_data_migration.local
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

        if let Some(vm) = self.vm.as_mut() {
            Self::send_migration(
                vm,
                #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
                self.hypervisor.clone(),
                send_data_migration,
            )
            .map_err(|migration_err| {
                error!("Migration failed: {:?}", migration_err);

                // Stop logging dirty pages
                if let Err(e) = vm.stop_dirty_log() {
                    return e;
                }

                if vm.get_state().unwrap() == VmState::Paused {
                    if let Err(e) = vm.resume() {
                        return e;
                    }
                }

                migration_err
            })?;

            // Shutdown the VM after the migration succeeded
            self.exit_evt.write(1).map_err(|e| {
                MigratableError::MigrateSend(anyhow!(
                    "Failed shutting down the VM after migration: {:?}",
                    e
                ))
            })
        } else {
            Err(MigratableError::MigrateSend(anyhow!("VM is not running")))
        }
    }
}

const CPU_MANAGER_SNAPSHOT_ID: &str = "cpu-manager";
const MEMORY_MANAGER_SNAPSHOT_ID: &str = "memory-manager";
const DEVICE_MANAGER_SNAPSHOT_ID: &str = "device-manager";

#[cfg(test)]
mod unit_tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::config::DebugConsoleConfig;
    use config::{
        ConsoleConfig, ConsoleOutputMode, CpusConfig, HotplugMethod, MemoryConfig, PayloadConfig,
        RngConfig, VmConfig,
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
        )
        .unwrap()
    }

    fn create_dummy_vm_config() -> Arc<Mutex<VmConfig>> {
        Arc::new(Mutex::new(VmConfig {
            cpus: CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                topology: None,
                kvm_hyperv: false,
                max_phys_bits: 46,
                affinity: None,
                features: config::CpuFeatures::default(),
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
            }),
            rate_limit_groups: None,
            disks: None,
            net: None,
            rng: RngConfig {
                src: PathBuf::from("/dev/urandom"),
                iommu: false,
            },
            balloon: None,
            fs: None,
            pmem: None,
            serial: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Null,
                iommu: false,
                socket: None,
            },
            console: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                socket: None,
            },
            #[cfg(target_arch = "x86_64")]
            debug_console: DebugConsoleConfig::default(),
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            pvpanic: false,
            iommu: false,
            #[cfg(target_arch = "x86_64")]
            sgx_epc: None,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            platform: None,
            tpm: None,
            preserved_fds: None,
        }))
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
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .devices
            .is_none());

        let result = vmm.vm_add_device(device_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
        let user_device_config =
            UserDeviceConfig::parse("socket=/path/to/socket,id=8,pci_segment=2").unwrap();

        assert!(matches!(
            vmm.vm_add_user_device(user_device_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .user_devices
            .is_none());

        let result = vmm.vm_add_user_device(user_device_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .disks
            .is_none());

        let result = vmm.vm_add_disk(disk_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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

        let result = vmm.vm_add_fs(fs_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
    fn test_vmm_vm_cold_add_pmem() {
        let mut vmm = create_dummy_vmm();
        let pmem_config = PmemConfig::parse("file=/tmp/pmem,size=128M").unwrap();

        assert!(matches!(
            vmm.vm_add_pmem(pmem_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .pmem
            .is_none());

        let result = vmm.vm_add_pmem(pmem_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .net
            .is_none());

        let result = vmm.vm_add_net(net_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .vdpa
            .is_none());

        let result = vmm.vm_add_vdpa(vdpa_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .vsock
            .is_none());

        let result = vmm.vm_add_vsock(vsock_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
