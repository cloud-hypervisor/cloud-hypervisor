// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate event_monitor;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate credibility;

use crate::api::{
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, VmInfo, VmReceiveMigrationData,
    VmSendMigrationData, VmmPingResponse,
};
use crate::config::{
    DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, RestoreConfig, VmConfig, VsockConfig,
};
use crate::migration::{get_vm_snapshot, recv_vm_snapshot};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vm::{Error as VmError, Vm, VmState};
use anyhow::anyhow;
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};
use std::sync::{Arc, Mutex};
use std::{result, thread};
use thiserror::Error;
use vm_memory::bitmap::AtomicBitmap;
use vm_migration::protocol::*;
use vm_migration::{MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

pub mod api;
pub mod config;
pub mod cpu;
pub mod device_manager;
pub mod device_tree;
pub mod interrupt;
pub mod memory_manager;
pub mod migration;
pub mod seccomp_filters;
pub mod vm;

#[cfg(feature = "acpi")]
mod acpi;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;

/// Errors associated with VMM management
#[derive(Debug, Error)]
#[allow(clippy::large_enum_variant)]
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
    CreateSeccompFilter(seccomp::SeccompError),

    /// Cannot apply seccomp filter
    #[error("Error applying seccomp filter: {0}")]
    ApplySeccompFilter(seccomp::Error),

    /// Error activating virtio devices
    #[error("Error activating virtio devices: {0:?}")]
    ActivateVirtioDevices(VmError),

    /// Error creating API server
    #[error("Error creating API server {0:?}")]
    CreateApiServer(micro_http::ServerError),

    /// Error binding API server socket
    #[error("Error creation API server's socket {0:?}")]
    CreateApiServerSocket(#[source] io::Error),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    Exit,
    Reset,
    Stdin,
    Api,
    ActivateVirtioDevices,
    Pty,
}

pub struct EpollContext {
    epoll_file: File,
    dispatch_table: Vec<Option<EpollDispatch>>,
}

impl EpollContext {
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let epoll_fd = epoll::create(true)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 reset event
        // * 1 stdin event
        // * 1 API event
        let mut dispatch_table = Vec::with_capacity(5);
        dispatch_table.push(None);

        Ok(EpollContext {
            epoll_file,
            dispatch_table,
        })
    }

    pub fn add_stdin(&mut self) -> result::Result<(), io::Error> {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;

        self.dispatch_table.push(Some(EpollDispatch::Stdin));

        Ok(())
    }

    fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;
        self.dispatch_table.push(Some(token));

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
    pub bdf: u32,
}

impl Serialize for PciDeviceInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Transform the PCI b/d/f into a standardized string.
        let segment = (self.bdf >> 16) & 0xffff;
        let bus = (self.bdf >> 8) & 0xff;
        let device = (self.bdf >> 3) & 0x1f;
        let function = self.bdf & 0x7;
        let bdf_str = format!(
            "{:04x}:{:02x}:{:02x}.{:01x}",
            segment, bus, device, function
        );

        // Serialize the structure.
        let mut state = serializer.serialize_struct("PciDeviceInfo", 2)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("bdf", &bdf_str)?;
        state.end()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start_vmm_thread(
    vmm_version: String,
    http_path: &Option<String>,
    http_fd: Option<RawFd>,
    api_event: EventFd,
    api_sender: Sender<ApiRequest>,
    api_receiver: Receiver<ApiRequest>,
    seccomp_action: &SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
) -> Result<thread::JoinHandle<Result<()>>> {
    let http_api_event = api_event.try_clone().map_err(Error::EventFdClone)?;

    // Retrieve seccomp filter
    let vmm_seccomp_filter =
        get_seccomp_filter(seccomp_action, Thread::Vmm).map_err(Error::CreateSeccompFilter)?;

    let vmm_seccomp_action = seccomp_action.clone();
    let thread = thread::Builder::new()
        .name("vmm".to_string())
        .spawn(move || {
            // Apply seccomp filter for VMM thread.
            SeccompFilter::apply(vmm_seccomp_filter).map_err(Error::ApplySeccompFilter)?;

            let mut vmm = Vmm::new(
                vmm_version.to_string(),
                api_event,
                vmm_seccomp_action,
                hypervisor,
            )?;

            vmm.control_loop(Arc::new(api_receiver))
        })
        .map_err(Error::VmmThreadSpawn)?;

    // The VMM thread is started, we can start serving HTTP requests
    if let Some(http_path) = http_path {
        api::start_http_path_thread(http_path, http_api_event, api_sender, seccomp_action)?;
    } else if let Some(http_fd) = http_fd {
        api::start_http_fd_thread(http_fd, http_api_event, api_sender, seccomp_action)?;
    }
    Ok(thread)
}

pub struct Vmm {
    epoll: EpollContext,
    exit_evt: EventFd,
    reset_evt: EventFd,
    api_evt: EventFd,
    version: String,
    vm: Option<Vm>,
    vm_config: Option<Arc<Mutex<VmConfig>>>,
    seccomp_action: SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    activate_evt: EventFd,
}

impl Vmm {
    fn new(
        vmm_version: String,
        api_evt: EventFd,
        seccomp_action: SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
    ) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let activate_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        if unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0 {
            epoll.add_stdin().map_err(Error::Epoll)?;
        }

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

        Ok(Vmm {
            epoll,
            exit_evt,
            reset_evt,
            api_evt,
            version: vmm_version,
            vm: None,
            vm_config: None,
            seccomp_action,
            hypervisor,
            activate_evt,
        })
    }

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
        // Create a new VM if we don't have one yet.
        if self.vm.is_none() {
            let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
            let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
            let activate_evt = self
                .activate_evt
                .try_clone()
                .map_err(VmError::EventFdClone)?;

            if let Some(ref vm_config) = self.vm_config {
                let vm = Vm::new(
                    Arc::clone(vm_config),
                    exit_evt,
                    reset_evt,
                    &self.seccomp_action,
                    self.hypervisor.clone(),
                    activate_evt,
                    None,
                    None,
                )?;
                if let Some(serial_pty) = vm.serial_pty() {
                    self.epoll
                        .add_event(&serial_pty.main, EpollDispatch::Pty)
                        .map_err(VmError::EventfdError)?;
                };
                if let Some(console_pty) = vm.console_pty() {
                    self.epoll
                        .add_event(&console_pty.main, EpollDispatch::Pty)
                        .map_err(VmError::EventfdError)?;
                };
                self.vm = Some(vm);
            }
        }

        // Now we can boot the VM.
        if let Some(ref mut vm) = self.vm {
            vm.boot()
        } else {
            Err(VmError::VmNotCreated)
        }
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
            return Err(VmError::RestoreSourceUrlPathToStr);
        }
        // Safe to unwrap as we checked it was Some(&str).
        let source_url = source_url.unwrap();

        let snapshot = recv_vm_snapshot(source_url).map_err(VmError::Restore)?;
        let vm_snapshot = get_vm_snapshot(&snapshot).map_err(VmError::Restore)?;

        self.vm_config = Some(Arc::clone(&vm_snapshot.config));

        let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
        let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
        let activate_evt = self
            .activate_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;

        let vm = Vm::new_from_snapshot(
            &snapshot,
            exit_evt,
            reset_evt,
            Some(source_url),
            restore_cfg.prefault,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
        )?;
        self.vm = Some(vm);

        // Now we can restore the rest of the VM.
        if let Some(ref mut vm) = self.vm {
            vm.restore(snapshot).map_err(VmError::Restore)
        } else {
            Err(VmError::VmNotCreated)
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
        // Without ACPI, a reset is equivalent to a shutdown
        // On AArch64, before ACPI is supported, we simply jump over this check and continue to reset.
        #[cfg(all(target_arch = "x86_64", not(feature = "acpi")))]
        {
            if self.vm.is_some() {
                self.exit_evt.write(1).unwrap();
                return Ok(());
            }
        }

        // First we stop the current VM and create a new one.
        if let Some(ref mut vm) = self.vm {
            let config = vm.get_config();
            let serial_pty = vm.serial_pty();
            let console_pty = vm.console_pty();
            self.vm_shutdown()?;

            let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
            let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
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
            self.vm = Some(Vm::new(
                config,
                exit_evt,
                reset_evt,
                &self.seccomp_action,
                self.hypervisor.clone(),
                activate_evt,
                serial_pty,
                console_pty,
            )?);
        }

        // Then we start the new VM.
        if let Some(ref mut vm) = self.vm {
            vm.boot()
        } else {
            Err(VmError::VmNotCreated)
        }
    }

    fn vm_info(&self) -> result::Result<VmInfo, VmError> {
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

                Ok(VmInfo {
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
        VmmPingResponse {
            version: self.version.clone(),
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
        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.resize(desired_vcpus, desired_ram, desired_balloon) {
                error!("Error when resizing VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_resize_zone(&mut self, id: String, desired_ram: u64) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.resize_zone(id, desired_ram) {
                error!("Error when resizing VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_add_device(&mut self, device_cfg: DeviceConfig) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.add_device(device_cfg).map_err(|e| {
                error!("Error when adding new device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_remove_device(&mut self, id: String) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.remove_device(id) {
                error!("Error when removing new device to the VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_add_disk(&mut self, disk_cfg: DiskConfig) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.add_disk(disk_cfg).map_err(|e| {
                error!("Error when adding new disk to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_add_fs(&mut self, fs_cfg: FsConfig) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.add_fs(fs_cfg).map_err(|e| {
                error!("Error when adding new fs to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_add_pmem(&mut self, pmem_cfg: PmemConfig) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.add_pmem(pmem_cfg).map_err(|e| {
                error!("Error when adding new pmem device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_add_net(&mut self, net_cfg: NetConfig) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.add_net(net_cfg).map_err(|e| {
                error!("Error when adding new network device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_add_vsock(&mut self, vsock_cfg: VsockConfig) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.add_vsock(vsock_cfg).map_err(|e| {
                error!("Error when adding new vsock device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_counters(&mut self) -> result::Result<Vec<u8>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.counters().map_err(|e| {
                error!("Error when getting counters from the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info).map_err(VmError::SerializeJson)
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

    fn vm_receive_config<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
    ) -> std::result::Result<Vm, MigratableError>
    where
        T: Read + Write,
    {
        // Read in config data
        let mut data = Vec::with_capacity(req.length() as usize);
        unsafe {
            data.set_len(req.length() as usize);
        }
        socket
            .read_exact(&mut data)
            .map_err(MigratableError::MigrateSocket)?;
        let config: VmConfig = serde_json::from_slice(&data).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error deserialising config: {}", e))
        })?;

        let exit_evt = self.exit_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning exit EventFd: {}", e))
        })?;
        let reset_evt = self.reset_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning reset EventFd: {}", e))
        })?;
        let activate_evt = self.activate_evt.try_clone().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error cloning activate EventFd: {}", e))
        })?;

        self.vm_config = Some(Arc::new(Mutex::new(config)));
        let vm = Vm::new_from_migration(
            self.vm_config.clone().unwrap(),
            exit_evt,
            reset_evt,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
        )
        .map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error creating VM from snapshot: {:?}", e))
        })?;

        Response::ok().write_to(socket)?;

        Ok(vm)
    }

    fn vm_receive_state<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        mut vm: Vm,
    ) -> std::result::Result<(), MigratableError>
    where
        T: Read + Write,
    {
        // Read in state data
        let mut data = Vec::with_capacity(req.length() as usize);
        unsafe {
            data.set_len(req.length() as usize);
        }
        socket
            .read_exact(&mut data)
            .map_err(MigratableError::MigrateSocket)?;
        let snapshot: Snapshot = serde_json::from_slice(&data).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error deserialising snapshot: {}", e))
        })?;

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        vm.load_clock_from_snapshot(&snapshot)
            .map_err(|e| MigratableError::MigrateReceive(anyhow!("Error resume clock: {:?}", e)))?;

        // Create VM
        vm.restore(snapshot).map_err(|e| {
            Response::error().write_to(socket).ok();
            e
        })?;
        self.vm = Some(vm);

        Response::ok().write_to(socket)?;

        Ok(())
    }

    fn vm_receive_memory<T>(
        &mut self,
        req: &Request,
        socket: &mut T,
        vm: &mut Vm,
    ) -> std::result::Result<(), MigratableError>
    where
        T: Read + Write,
    {
        // Read table
        let table = MemoryRangeTable::read_from(socket, req.length())?;

        // And then read the memory itself
        vm.receive_memory_regions(&table, socket).map_err(|e| {
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
        let mut vm: Option<Vm> = None;

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
                    vm = Some(self.vm_receive_config(&req, &mut socket)?);
                }
                Command::State => {
                    info!("State Command Received");

                    if !started {
                        warn!("Migration not started yet");
                        Response::error().write_to(&mut socket)?;
                        continue;
                    }
                    if let Some(vm) = vm.take() {
                        self.vm_receive_state(&req, &mut socket, vm)?;
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
                    if let Some(ref mut vm) = vm.as_mut() {
                        self.vm_receive_memory(&req, &mut socket, vm)?;
                    } else {
                        warn!("Configuration not sent yet");
                        Response::error().write_to(&mut socket)?;
                    }
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

    // Returns true if there were dirty pages to send
    fn vm_maybe_send_dirty_pages<T>(
        vm: &mut Vm,
        socket: &mut T,
    ) -> result::Result<bool, MigratableError>
    where
        T: Read + Write,
    {
        // Send (dirty) memory table
        let table = vm.dirty_memory_range_table()?;

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

    fn vm_send_migration(
        &mut self,
        send_data_migration: VmSendMigrationData,
    ) -> result::Result<(), MigratableError> {
        info!(
            "Sending migration: destination_url = {}",
            send_data_migration.destination_url
        );
        if let Some(ref mut vm) = self.vm {
            let path = Self::socket_url_to_path(&send_data_migration.destination_url)?;
            let mut socket = UnixStream::connect(&path).map_err(|e| {
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
            let config_data = serde_json::to_vec(&vm.get_config()).unwrap();
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

            // Start logging dirty pages
            vm.start_memory_dirty_log()?;

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
            Ok(())
        } else {
            Err(MigratableError::MigrateSend(anyhow!("VM is not running")))
        }
    }

    fn control_loop(&mut self, api_receiver: Arc<Receiver<ApiRequest>>) -> Result<()> {
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
                let dispatch_idx = event.data as usize;

                if let Some(dispatch_type) = self.epoll.dispatch_table[dispatch_idx] {
                    match dispatch_type {
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
                        EpollDispatch::Stdin => {
                            if let Some(ref vm) = self.vm {
                                vm.handle_stdin().map_err(Error::Stdin)?;
                            }
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
                        EpollDispatch::Pty => {
                            if let Some(ref vm) = self.vm {
                                vm.handle_pty().map_err(Error::Pty)?;
                            }
                        }
                        EpollDispatch::Api => {
                            // Consume the event.
                            self.api_evt.read().map_err(Error::EventFdRead)?;

                            // Read from the API receiver channel
                            let api_request = api_receiver.recv().map_err(Error::ApiRequestRecv)?;

                            info!("API request event: {:?}", api_request);
                            match api_request {
                                ApiRequest::VmCreate(config, sender) => {
                                    let response = self
                                        .vm_create(config)
                                        .map_err(ApiError::VmCreate)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmDelete(sender) => {
                                    let response = self
                                        .vm_delete()
                                        .map_err(ApiError::VmDelete)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmBoot(sender) => {
                                    // If we don't have a config, we can not boot a VM.
                                    if self.vm_config.is_none() {
                                        sender
                                            .send(Err(ApiError::VmMissingConfig))
                                            .map_err(Error::ApiResponseSend)?;
                                        continue;
                                    }

                                    let response = self
                                        .vm_boot()
                                        .map_err(ApiError::VmBoot)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmShutdown(sender) => {
                                    let response = self
                                        .vm_shutdown()
                                        .map_err(ApiError::VmShutdown)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmReboot(sender) => {
                                    let response = self
                                        .vm_reboot()
                                        .map_err(ApiError::VmReboot)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmInfo(sender) => {
                                    let response = self
                                        .vm_info()
                                        .map_err(ApiError::VmInfo)
                                        .map(ApiResponsePayload::VmInfo);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmmPing(sender) => {
                                    let response = ApiResponsePayload::VmmPing(self.vmm_ping());

                                    sender.send(Ok(response)).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmPause(sender) => {
                                    let response = self
                                        .vm_pause()
                                        .map_err(ApiError::VmPause)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmResume(sender) => {
                                    let response = self
                                        .vm_resume()
                                        .map_err(ApiError::VmResume)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmSnapshot(snapshot_data, sender) => {
                                    let response = self
                                        .vm_snapshot(&snapshot_data.destination_url)
                                        .map_err(ApiError::VmSnapshot)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmRestore(restore_data, sender) => {
                                    let response = self
                                        .vm_restore(restore_data.as_ref().clone())
                                        .map_err(ApiError::VmRestore)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmmShutdown(sender) => {
                                    let response = self
                                        .vmm_shutdown()
                                        .map_err(ApiError::VmmShutdown)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;

                                    break 'outer;
                                }
                                ApiRequest::VmResize(resize_data, sender) => {
                                    let response = self
                                        .vm_resize(
                                            resize_data.desired_vcpus,
                                            resize_data.desired_ram,
                                            resize_data.desired_balloon,
                                        )
                                        .map_err(ApiError::VmResize)
                                        .map(|_| ApiResponsePayload::Empty);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmResizeZone(resize_zone_data, sender) => {
                                    let response = self
                                        .vm_resize_zone(
                                            resize_zone_data.id.clone(),
                                            resize_zone_data.desired_ram,
                                        )
                                        .map_err(ApiError::VmResizeZone)
                                        .map(|_| ApiResponsePayload::Empty);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddDevice(add_device_data, sender) => {
                                    let response = self
                                        .vm_add_device(add_device_data.as_ref().clone())
                                        .map_err(ApiError::VmAddDevice)
                                        .map(ApiResponsePayload::VmAction);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmRemoveDevice(remove_device_data, sender) => {
                                    let response = self
                                        .vm_remove_device(remove_device_data.id.clone())
                                        .map_err(ApiError::VmRemoveDevice)
                                        .map(|_| ApiResponsePayload::Empty);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddDisk(add_disk_data, sender) => {
                                    let response = self
                                        .vm_add_disk(add_disk_data.as_ref().clone())
                                        .map_err(ApiError::VmAddDisk)
                                        .map(ApiResponsePayload::VmAction);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddFs(add_fs_data, sender) => {
                                    let response = self
                                        .vm_add_fs(add_fs_data.as_ref().clone())
                                        .map_err(ApiError::VmAddFs)
                                        .map(ApiResponsePayload::VmAction);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddPmem(add_pmem_data, sender) => {
                                    let response = self
                                        .vm_add_pmem(add_pmem_data.as_ref().clone())
                                        .map_err(ApiError::VmAddPmem)
                                        .map(ApiResponsePayload::VmAction);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddNet(add_net_data, sender) => {
                                    let response = self
                                        .vm_add_net(add_net_data.as_ref().clone())
                                        .map_err(ApiError::VmAddNet)
                                        .map(ApiResponsePayload::VmAction);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddVsock(add_vsock_data, sender) => {
                                    let response = self
                                        .vm_add_vsock(add_vsock_data.as_ref().clone())
                                        .map_err(ApiError::VmAddVsock)
                                        .map(ApiResponsePayload::VmAction);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmCounters(sender) => {
                                    let response = self
                                        .vm_counters()
                                        .map_err(ApiError::VmInfo)
                                        .map(ApiResponsePayload::VmAction);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmReceiveMigration(receive_migration_data, sender) => {
                                    let response = self
                                        .vm_receive_migration(
                                            receive_migration_data.as_ref().clone(),
                                        )
                                        .map_err(ApiError::VmReceiveMigration)
                                        .map(|_| ApiResponsePayload::Empty);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmSendMigration(send_migration_data, sender) => {
                                    let response = self
                                        .vm_send_migration(send_migration_data.as_ref().clone())
                                        .map_err(ApiError::VmSendMigration)
                                        .map(|_| ApiResponsePayload::Empty);
                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmPowerButton(sender) => {
                                    let response = self
                                        .vm_power_button()
                                        .map_err(ApiError::VmPowerButton)
                                        .map(|_| ApiResponsePayload::Empty);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

const CPU_MANAGER_SNAPSHOT_ID: &str = "cpu-manager";
const MEMORY_MANAGER_SNAPSHOT_ID: &str = "memory-manager";
const DEVICE_MANAGER_SNAPSHOT_ID: &str = "device-manager";
