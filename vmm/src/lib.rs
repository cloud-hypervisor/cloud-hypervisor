// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate anyhow;
extern crate arc_swap;
extern crate hypervisor;
extern crate option_parser;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tempfile;
extern crate url;
extern crate vmm_sys_util;
#[cfg(test)]
#[macro_use]
extern crate credibility;

use crate::api::{ApiError, ApiRequest, ApiResponse, ApiResponsePayload, VmInfo, VmmPingResponse};
use crate::config::{
    DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, RestoreConfig, VmConfig, VsockConfig,
};
use crate::migration::{get_vm_snapshot, recv_vm_snapshot};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vm::{Error as VmError, Vm, VmState};
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};
use std::sync::{Arc, Mutex};
use std::{result, thread};
use vm_migration::{Pausable, Snapshottable, Transportable};
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

/// Errors associated with VMM management
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// API request receive error
    ApiRequestRecv(RecvError),

    /// API response send error
    ApiResponseSend(SendError<ApiResponse>),

    /// Cannot bind to the UNIX domain socket path
    Bind(io::Error),

    /// Cannot clone EventFd.
    EventFdClone(io::Error),

    /// Cannot create EventFd.
    EventFdCreate(io::Error),

    /// Cannot read from EventFd.
    EventFdRead(io::Error),

    /// Cannot create epoll context.
    Epoll(io::Error),

    /// Cannot create HTTP thread
    HttpThreadSpawn(io::Error),

    /// Cannot handle the VM STDIN stream
    Stdin(VmError),

    /// Cannot reboot the VM
    VmReboot(VmError),

    /// Cannot shut a VM down
    VmShutdown(VmError),

    /// Cannot create VMM thread
    VmmThreadSpawn(io::Error),

    /// Cannot shut the VMM down
    VmmShutdown(VmError),

    // Error following "exe" link
    ExePathReadLink(io::Error),

    /// Cannot create seccomp filter
    CreateSeccompFilter(seccomp::SeccompError),

    /// Cannot apply seccomp filter
    ApplySeccompFilter(seccomp::Error),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    Exit,
    Reset,
    Stdin,
    Api,
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

pub fn start_vmm_thread(
    vmm_version: String,
    http_path: &str,
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

    // Find the path that the "/proc/<pid>/exe" symlink points to. Must be done before spawning
    // a thread as Rust does not put the child threads in the same thread group which prevents the
    // link from being followed as per PTRACE_MODE_READ_FSCREDS (see proc(5) and ptrace(2)). The
    // alternative is to run always with CAP_SYS_PTRACE but that is not a good idea.
    let self_path = format!("/proc/{}/exe", std::process::id());
    let vmm_path = std::fs::read_link(PathBuf::from(self_path)).map_err(Error::ExePathReadLink)?;
    let vmm_seccomp_action = seccomp_action.clone();
    let thread = thread::Builder::new()
        .name("vmm".to_string())
        .spawn(move || {
            // Apply seccomp filter for VMM thread.
            SeccompFilter::apply(vmm_seccomp_filter).map_err(Error::ApplySeccompFilter)?;

            let mut vmm = Vmm::new(
                vmm_version.to_string(),
                api_event,
                vmm_path,
                vmm_seccomp_action,
                hypervisor,
            )?;

            vmm.control_loop(Arc::new(api_receiver))
        })
        .map_err(Error::VmmThreadSpawn)?;

    // The VMM thread is started, we can start serving HTTP requests
    api::start_http_thread(http_path, http_api_event, api_sender, seccomp_action)?;

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
    vmm_path: PathBuf,
    seccomp_action: SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
}

impl Vmm {
    fn new(
        vmm_version: String,
        api_evt: EventFd,
        vmm_path: PathBuf,
        seccomp_action: SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
    ) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

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
            vmm_path,
            seccomp_action,
            hypervisor,
        })
    }

    fn vm_boot(&mut self) -> result::Result<(), VmError> {
        // Create a new VM is we don't have one yet.
        if self.vm.is_none() {
            let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
            let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;

            if let Some(ref vm_config) = self.vm_config {
                let vm = Vm::new(
                    Arc::clone(vm_config),
                    exit_evt,
                    reset_evt,
                    self.vmm_path.clone(),
                    &self.seccomp_action,
                    self.hypervisor.clone(),
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

        let vm = Vm::new_from_snapshot(
            &snapshot,
            exit_evt,
            reset_evt,
            self.vmm_path.clone(),
            source_url,
            restore_cfg.prefault,
            &self.seccomp_action,
            self.hypervisor.clone(),
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
        #[cfg(not(feature = "acpi"))]
        {
            if self.vm.is_some() {
                self.exit_evt.write(1).unwrap();
                return Ok(());
            }
        }

        // First we stop the current VM and create a new one.
        if let Some(ref mut vm) = self.vm {
            let config = vm.get_config();
            self.vm_shutdown()?;

            let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
            let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;

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
                self.vmm_path.clone(),
                &self.seccomp_action,
                self.hypervisor.clone(),
            )?);
        }

        // Then we start the new VM.
        if let Some(ref mut vm) = self.vm {
            vm.boot()?;
        } else {
            return Err(VmError::VmNotCreated);
        }

        Ok(())
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

                Ok(VmInfo {
                    config,
                    state,
                    memory_actual_size,
                })
            }
            None => Err(VmError::VmNotCreated),
        }
    }

    fn vmm_ping(&self) -> result::Result<VmmPingResponse, ApiError> {
        Ok(VmmPingResponse {
            version: self.version.clone(),
        })
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

        Ok(())
    }

    fn vmm_shutdown(&mut self) -> result::Result<(), VmError> {
        self.vm_delete()
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
                            // Consume the event.
                            self.exit_evt.read().map_err(Error::EventFdRead)?;
                            self.vmm_shutdown().map_err(Error::VmmShutdown)?;

                            break 'outer;
                        }
                        EpollDispatch::Reset => {
                            // Consume the event.
                            self.reset_evt.read().map_err(Error::EventFdRead)?;
                            self.vm_reboot().map_err(Error::VmReboot)?;
                        }
                        EpollDispatch::Stdin => {
                            if let Some(ref vm) = self.vm {
                                vm.handle_stdin().map_err(Error::Stdin)?;
                            }
                        }
                        EpollDispatch::Api => {
                            // Consume the event.
                            self.api_evt.read().map_err(Error::EventFdRead)?;

                            // Read from the API receiver channel
                            let api_request = api_receiver.recv().map_err(Error::ApiRequestRecv)?;

                            match api_request {
                                ApiRequest::VmCreate(config, sender) => {
                                    // We only store the passed VM config.
                                    // The VM will be created when being asked to boot it.
                                    let response = if self.vm_config.is_none() {
                                        self.vm_config = Some(config);
                                        Ok(ApiResponsePayload::Empty)
                                    } else {
                                        Err(ApiError::VmAlreadyCreated)
                                    };

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
                                    let response = self.vmm_ping().map(ApiResponsePayload::VmmPing);

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
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
