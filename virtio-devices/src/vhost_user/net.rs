// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vhost_user::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use crate::vhost_user::{Error, Inflight, Result, VhostUserEpollHandler};
use crate::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterrupt, EPOLL_HELPER_EVENT_LAST,
    VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1,
};
use crate::{GuestMemoryMmap, GuestRegionMmap};
use anyhow::anyhow;
use net_util::{build_net_config_space, CtrlQueue, MacAddr, VirtioNetConfig};
use seccomp::{SeccompAction, SeccompFilter};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::vec::Vec;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler};
use virtio_bindings::bindings::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF,
};
use vm_memory::{Address, ByteValued, GuestAddressSpace, GuestMemory, GuestMemoryAtomic};
use vm_migration::{
    protocol::MemoryRangeTable, Migratable, MigratableError, Pausable, Snapshot, Snapshottable,
    Transportable, VersionMapped,
};
use vmm_sys_util::eventfd::EventFd;

const DEFAULT_QUEUE_NUMBER: usize = 2;

#[derive(Versionize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioNetConfig,
}

impl VersionMapped for State {}

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

/// Control queue
// Event available on the control queue.
const CTRL_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

pub struct NetCtrlEpollHandler {
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub ctrl_q: CtrlQueue,
    pub queue_evt: EventFd,
    pub queue: Queue,
}

impl NetCtrlEpollHandler {
    pub fn run_ctrl(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), CTRL_QUEUE_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for NetCtrlEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            CTRL_QUEUE_EVENT => {
                let mem = self.mem.memory();
                if let Err(e) = self.queue_evt.read() {
                    error!("failed to get ctl queue event: {:?}", e);
                    return true;
                }
                if let Err(e) = self.ctrl_q.process(&mem, &mut self.queue) {
                    error!("failed to process ctrl queue: {:?}", e);
                    return true;
                }
            }
            _ => {
                error!("Unknown event for virtio-net");
                return true;
            }
        }

        false
    }
}

pub struct Net {
    common: VirtioCommon,
    id: String,
    vu: Option<Arc<Mutex<VhostUserHandle>>>,
    config: VirtioNetConfig,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    acked_protocol_features: u64,
    socket_path: String,
    server: bool,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<()>>,
    epoll_thread: Option<thread::JoinHandle<()>>,
    seccomp_action: SeccompAction,
    vu_num_queues: usize,
    migration_started: bool,
}

impl Net {
    /// Create a new vhost-user-net device
    pub fn new(
        id: String,
        mac_addr: MacAddr,
        vu_cfg: VhostUserConfig,
        server: bool,
        seccomp_action: SeccompAction,
    ) -> Result<Net> {
        let mut num_queues = vu_cfg.num_queues;

        // Filling device and vring features VMM supports.
        let mut avail_features = 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_TSO6
            | 1 << VIRTIO_NET_F_GUEST_ECN
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO6
            | 1 << VIRTIO_NET_F_HOST_ECN
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_NET_F_MRG_RXBUF
            | 1 << VIRTIO_NET_F_CTRL_VQ
            | 1 << VIRTIO_F_RING_EVENT_IDX
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let mut config = VirtioNetConfig::default();
        build_net_config_space(&mut config, mac_addr, num_queues, &mut avail_features);

        let mut vu =
            VhostUserHandle::connect_vhost_user(server, &vu_cfg.socket, num_queues as u64, false)?;

        let avail_protocol_features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::INFLIGHT_SHMFD
            | VhostUserProtocolFeatures::LOG_SHMFD;

        let (mut acked_features, acked_protocol_features) =
            vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

        let backend_num_queues =
            if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                vu.socket_handle()
                    .get_queue_num()
                    .map_err(Error::VhostUserGetQueueMaxNum)? as usize
            } else {
                DEFAULT_QUEUE_NUMBER
            };

        if num_queues > backend_num_queues {
            error!("vhost-user-net requested too many queues ({}) since the backend only supports {}\n",
                num_queues, backend_num_queues);
            return Err(Error::BadQueueNum);
        }

        // If the control queue feature has been negotiated, let's increase
        // the number of queues.
        let vu_num_queues = num_queues;
        if acked_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
            num_queues += 1;
        }

        // Make sure the virtio feature to set the MAC address is exposed to
        // the guest, even if it hasn't been negotiated with the backend.
        acked_features |= 1 << VIRTIO_NET_F_MAC;

        Ok(Net {
            id,
            common: VirtioCommon {
                device_type: VirtioDeviceType::Net as u32,
                queue_sizes: vec![vu_cfg.queue_size; num_queues],
                avail_features: acked_features,
                acked_features: 0,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: DEFAULT_QUEUE_NUMBER as u16,
                ..Default::default()
            },
            vu: Some(Arc::new(Mutex::new(vu))),
            config,
            guest_memory: None,
            acked_protocol_features,
            socket_path: vu_cfg.socket,
            server,
            ctrl_queue_epoll_thread: None,
            epoll_thread: None,
            seccomp_action,
            vu_num_queues,
            migration_started: false,
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &State) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.config = state.config;
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill vhost-user-net: {:?}", e);
            }
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        self.guest_memory = Some(mem.clone());

        let num_queues = queues.len();
        if self.common.feature_acked(VIRTIO_NET_F_CTRL_VQ.into()) && num_queues % 2 != 0 {
            let cvq_queue = queues.remove(num_queues - 1);
            let cvq_queue_evt = queue_evts.remove(num_queues - 1);

            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt,
                pause_evt,
                ctrl_q: CtrlQueue::new(Vec::new()),
                queue: cvq_queue,
                queue_evt: cvq_queue_evt,
            };

            let paused = self.common.paused.clone();
            // Let's update the barrier as we need 1 for the control queue
            // thread + 1 for the common vhost-user thread + 1 for the main
            // thread signalling the pause.
            self.common.paused_sync = Some(Arc::new(Barrier::new(3)));
            let paused_sync = self.common.paused_sync.clone();

            // Retrieve seccomp filter for virtio_net_ctl thread
            let virtio_vhost_net_ctl_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioVhostNetCtl)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name(format!("{}_ctrl", self.id))
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_vhost_net_ctl_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = ctrl_handler.run_ctrl(paused, paused_sync.unwrap()) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| self.ctrl_queue_epoll_thread = Some(thread))
                .map_err(|e| {
                    error!("failed to clone queue EventFd: {}", e);
                    ActivateError::BadActivate
                })?;
        }

        let slave_req_handler: Option<MasterReqHandler<SlaveReqHandler>> = None;

        // The backend acknowledged features must contain the protocol feature
        // bit in case it was initially set but lost through the features
        // negotiation with the guest. Additionally, it must not contain
        // VIRTIO_NET_F_MAC since we don't expect the backend to handle it.
        let backend_acked_features = self.common.acked_features & !(1 << VIRTIO_NET_F_MAC)
            | (self.common.avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits());

        let mut inflight: Option<Inflight> =
            if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() != 0
            {
                Some(Inflight::default())
            } else {
                None
            };

        if self.vu.is_none() {
            error!("Missing vhost-user handle");
            return Err(ActivateError::BadActivate);
        }
        let vu = self.vu.as_ref().unwrap();
        vu.lock()
            .unwrap()
            .setup_vhost_user(
                &mem.memory(),
                queues.clone(),
                queue_evts.iter().map(|q| q.try_clone().unwrap()).collect(),
                &interrupt_cb,
                backend_acked_features,
                &slave_req_handler,
                inflight.as_mut(),
            )
            .map_err(ActivateError::VhostUserNetSetup)?;

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler: VhostUserEpollHandler<SlaveReqHandler> = VhostUserEpollHandler {
            vu: vu.clone(),
            mem,
            kill_evt,
            pause_evt,
            queues,
            queue_evts,
            virtio_interrupt: interrupt_cb,
            acked_features: backend_acked_features,
            acked_protocol_features: self.acked_protocol_features,
            socket_path: self.socket_path.clone(),
            server: self.server,
            slave_req_handler: None,
            inflight,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        thread::Builder::new()
            .name(self.id.to_string())
            .spawn(move || {
                if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running vhost-user-net worker: {:?}", e);
                }
            })
            .map(|thread| self.epoll_thread = Some(thread))
            .map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?;

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(vu) = &self.vu {
            if let Err(e) = vu
                .lock()
                .unwrap()
                .reset_vhost_user(self.common.queue_sizes.len())
            {
                error!("Failed to reset vhost-user daemon: {:?}", e);
                return None;
            }
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        if let Some(vu) = &self.vu {
            let _ = unsafe { libc::close(vu.lock().unwrap().socket_handle().as_raw_fd()) };
        }

        // Remove socket path if needed
        if self.server {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(vu) = &self.vu {
            if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                != 0
            {
                return vu
                    .lock()
                    .unwrap()
                    .add_memory_region(region)
                    .map_err(crate::Error::VhostUserAddMemoryRegion);
            } else if let Some(guest_memory) = &self.guest_memory {
                return vu
                    .lock()
                    .unwrap()
                    .update_mem_table(guest_memory.memory().deref())
                    .map_err(crate::Error::VhostUserUpdateMemory);
            }
        }
        Ok(())
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            vu.lock()
                .unwrap()
                .pause_vhost_user(self.vu_num_queues)
                .map_err(|e| {
                    MigratableError::Pause(anyhow!("Error pausing vhost-user-net backend: {:?}", e))
                })?;
        }

        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }

        if let Some(ctrl_queue_epoll_thread) = &self.ctrl_queue_epoll_thread {
            ctrl_queue_epoll_thread.thread().unpark();
        }

        if let Some(vu) = &self.vu {
            vu.lock()
                .unwrap()
                .resume_vhost_user(self.vu_num_queues)
                .map_err(|e| {
                    MigratableError::Resume(anyhow!(
                        "Error resuming vhost-user-net backend: {:?}",
                        e
                    ))
                })
        } else {
            Ok(())
        }
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot = Snapshot::new_from_versioned_state(&self.id(), &self.state())?;

        if self.migration_started {
            self.shutdown();
        }

        Ok(snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}
impl Transportable for Net {}

impl Migratable for Net {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = true;
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock()
                    .unwrap()
                    .start_dirty_log(last_ram_addr)
                    .map_err(|e| {
                        MigratableError::StartDirtyLog(anyhow!(
                            "Error starting migration for vhost-user-net backend: {:?}",
                            e
                        ))
                    })
            } else {
                Err(MigratableError::StartDirtyLog(anyhow!(
                    "Missing guest memory"
                )))
            }
        } else {
            Ok(())
        }
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = false;
        if let Some(vu) = &self.vu {
            vu.lock().unwrap().stop_dirty_log().map_err(|e| {
                MigratableError::StopDirtyLog(anyhow!(
                    "Error stopping migration for vhost-user-net backend: {:?}",
                    e
                ))
            })
        } else {
            Ok(())
        }
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock().unwrap().dirty_log(last_ram_addr).map_err(|e| {
                    MigratableError::DirtyLog(anyhow!(
                        "Error retrieving dirty ranges from vhost-user-net backend: {:?}",
                        e
                    ))
                })
            } else {
                Err(MigratableError::DirtyLog(anyhow!("Missing guest memory")))
            }
        } else {
            Ok(MemoryRangeTable::default())
        }
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        // Make sure the device thread is killed in order to prevent from
        // reconnections to the socket.
        if let Some(kill_evt) = self.common.kill_evt.take() {
            kill_evt.write(1).map_err(|e| {
                MigratableError::CompleteMigration(anyhow!(
                    "Error killing vhost-user-net threads: {:?}",
                    e
                ))
            })?;
        }

        // Drop the vhost-user handler to avoid further calls to fail because
        // the connection with the backend has been closed.
        self.vu = None;

        Ok(())
    }
}
