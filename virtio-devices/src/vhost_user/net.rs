// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use log::{error, info};
use net_util::{CtrlQueue, MacAddr, VirtioNetConfig, build_net_config_space};
use seccompiler::SeccompAction;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6,
    VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_MTU,
    VIRTIO_NET_F_STATUS, VIRTIO_NET_S_ANNOUNCE, VIRTIO_NET_S_LINK_UP,
};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::QueueT;
use vm_memory::ByteValued;
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::timerfd::TimerFd;

use crate::device::ActivationContext;
use crate::net::{AnnounceOps, AnnouncementState, Announcer, VirtioNetGuestAnnounceOps};
use crate::seccomp_filters::Thread;
use crate::vhost_user::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use crate::vhost_user::{DEFAULT_VIRTIO_FEATURES, Error, Result, VhostUserCommon, VhostUserState};
use crate::{
    ActivateError, ActivateResult, GuestRegionMmap, NetCtrlEpollHandler, VIRTIO_F_ACCESS_PLATFORM,
    VirtioCommon, VirtioDevice, VirtioDeviceType,
};

const DEFAULT_QUEUE_NUMBER: usize = 2;

pub type State = VhostUserState<VirtioNetConfig>;

struct BackendReqHandler {}
impl VhostUserFrontendReqHandler for BackendReqHandler {}

pub struct Net {
    vu_common: VhostUserCommon,
    id: String,
    config: VirtioNetConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    access_platform_enabled: bool,
    announce: AnnouncementState,
}

impl Net {
    /// Derive the guest-visible feature set from the backend-negotiated
    /// features plus frontend-only bits that Cloud Hypervisor implements
    /// locally, such as `VIRTIO_NET_F_MAC`, `VIRTIO_NET_F_STATUS`, and
    /// `VIRTIO_NET_F_GUEST_ANNOUNCE`.
    fn frontend_avail_features(backend_acked_features: u64) -> u64 {
        let mut guest_avail_features = backend_acked_features | (1 << VIRTIO_NET_F_MAC);

        // Guest announce is implemented by the frontend through config
        // changes and the locally handled control queue.
        if guest_avail_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
            guest_avail_features |= 1 << VIRTIO_NET_F_STATUS;
            guest_avail_features |= 1 << VIRTIO_NET_F_GUEST_ANNOUNCE;
        }

        guest_avail_features
    }

    /// Create a new vhost-user-net device
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        mac_addr: MacAddr,
        mtu: Option<u16>,
        vu_cfg: VhostUserConfig,
        server: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Net> {
        let mut num_queues = vu_cfg.num_queues;

        let mut vu = VhostUserHandle::connect_vhost_user(
            server,
            &vu_cfg.socket,
            num_queues as u64,
            false,
            None,
        )?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            config,
            paused,
            vring_bases,
            announce_pending,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-net {id}");

            // The backend acknowledged features must not contain frontend-only
            // bits since we don't expect the backend to handle them.
            let backend_acked_features = state.acked_features
                & !((1 << VIRTIO_NET_F_MAC)
                    | (1 << VIRTIO_NET_F_STATUS)
                    | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE));

            vu.set_protocol_features_vhost_user(
                backend_acked_features,
                state.acked_protocol_features,
            )?;

            vu.restore_state(&state)?;

            // If the control queue feature has been negotiated, let's
            // increase the number of queues.
            if state.acked_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
                num_queues += 1;
            }

            // Always set the announcement pending if the device was restored and
            // VIRTIO_NET_F_GUEST_ANNOUNCE was negotiated, to make sure the device announces itself.
            let announce_pending =
                (state.acked_features & (1u64 << VIRTIO_NET_F_GUEST_ANNOUNCE)) != 0;

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                state.config,
                true,
                state.vring_bases,
                announce_pending,
            )
        } else {
            // Filling device and vring features VMM supports.
            let mut avail_features = (1 << VIRTIO_NET_F_MRG_RXBUF)
                | (1 << VIRTIO_NET_F_CTRL_VQ)
                | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE)
                | DEFAULT_VIRTIO_FEATURES;

            if mtu.is_some() {
                avail_features |= 1u64 << VIRTIO_NET_F_MTU;
            }

            // Configure TSO/UFO features when hardware checksum offload is enabled.
            if offload_csum {
                avail_features |= (1 << VIRTIO_NET_F_CSUM) | (1 << VIRTIO_NET_F_GUEST_CSUM);

                if offload_tso {
                    avail_features |= (1 << VIRTIO_NET_F_HOST_ECN)
                        | (1 << VIRTIO_NET_F_HOST_TSO4)
                        | (1 << VIRTIO_NET_F_HOST_TSO6)
                        | (1 << VIRTIO_NET_F_GUEST_ECN)
                        | (1 << VIRTIO_NET_F_GUEST_TSO4)
                        | (1 << VIRTIO_NET_F_GUEST_TSO6);
                }

                if offload_ufo {
                    avail_features |= (1 << VIRTIO_NET_F_HOST_UFO) | (1 << VIRTIO_NET_F_GUEST_UFO);
                }
            }

            let mut config = VirtioNetConfig::default();
            build_net_config_space(&mut config, mac_addr, num_queues, mtu, &mut avail_features);

            let avail_protocol_features = VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD
                | VhostUserProtocolFeatures::DEVICE_STATE;

            let (acked_features, acked_protocol_features) =
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
                error!(
                    "vhost-user-net requested too many queues ({num_queues}) since the backend only supports {backend_num_queues}\n"
                );
                return Err(Error::BadQueueNum);
            }

            // If the control queue feature has been negotiated, let's increase
            // the number of queues.
            let vu_num_queues = num_queues;
            if acked_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
                num_queues += 1;
            }

            // Build the feature set that gets exposed to the guest. Some frontend available
            // features are dependent on the features the backend supports.
            let guest_avail_features = Self::frontend_avail_features(acked_features);

            (
                guest_avail_features,
                // If part of the available features that have been acked,
                // the PROTOCOL_FEATURES bit must be already set through
                // the VIRTIO acked features as we know the guest would
                // never ack it, thus the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                vu_num_queues,
                config,
                false,
                None,
                false,
            )
        };

        Ok(Net {
            id,
            vu_common: VhostUserCommon {
                virtio_common: VirtioCommon {
                    device_type: VirtioDeviceType::Net as u32,
                    queue_sizes: vec![vu_cfg.queue_size; num_queues],
                    avail_features,
                    acked_features,
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    min_queues: DEFAULT_QUEUE_NUMBER as u16,
                    paused: Arc::new(AtomicBool::new(paused)),
                    ..Default::default()
                },
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: vu_cfg.socket,
                vu_num_queues,
                server,
                vring_bases,
                ..Default::default()
            },
            config,
            seccomp_action,
            exit_evt,
            access_platform_enabled,
            announce: AnnouncementState::new(announce_pending).map_err(Error::CreateEventFd)?,
        })
    }

    fn state(&self) -> result::Result<State, MigratableError> {
        self.vu_common.state(self.config)
    }

    /// Compute the guest-visible virtio-net status field.
    fn guest_visible_status(&self) -> u16 {
        let mut status = 0;

        if self
            .vu_common
            .virtio_common
            .feature_acked(VIRTIO_NET_F_STATUS.into())
        {
            status |= VIRTIO_NET_S_LINK_UP as u16;

            if self
                .vu_common
                .virtio_common
                .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into())
                && self.announce.pending.load(Ordering::Acquire)
            {
                status |= VIRTIO_NET_S_ANNOUNCE as u16;
            }
        }

        status
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.vu_common.shutdown();
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        self.vu_common.virtio_common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.vu_common.virtio_common.queue_sizes
    }

    fn features(&self) -> u64 {
        let mut features = self.vu_common.virtio_common.avail_features;
        if self.access_platform_enabled {
            features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }
        features
    }

    fn ack_features(&mut self, value: u64) {
        self.vu_common.virtio_common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = self.config;
        config.status = self.guest_visible_status();
        self.read_config_from_slice(config.as_slice(), offset, data);
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.vu_common
            .virtio_common
            .activate(&queues, interrupt_cb.clone())?;

        let num_queues = queues.len();
        let event_idx = self
            .vu_common
            .virtio_common
            .feature_acked(VIRTIO_RING_F_EVENT_IDX.into());
        if self
            .vu_common
            .virtio_common
            .feature_acked(VIRTIO_NET_F_CTRL_VQ.into())
            && !num_queues.is_multiple_of(2)
        {
            let ctrl_queue_index = num_queues - 1;
            let (_, mut ctrl_queue, ctrl_queue_evt) = queues.remove(ctrl_queue_index);

            ctrl_queue.set_event_idx(event_idx);

            let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds()?;

            let announce_ops = VirtioNetGuestAnnounceOps::new(
                interrupt_cb.clone(),
                self.vu_common
                    .virtio_common
                    .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
                &self.announce,
            );

            let announcer = Announcer::new(
                &self.announce,
                vec![Box::new(announce_ops) as Box<dyn AnnounceOps>].into_boxed_slice(),
            );

            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt,
                pause_evt,
                ctrl_q: CtrlQueue::new(Vec::new(), self.announce.pending.clone()),
                queue: ctrl_queue,
                queue_evt: ctrl_queue_evt,
                access_platform: None,
                interrupt_cb: interrupt_cb.clone(),
                queue_index: ctrl_queue_index as u16,
                announce_evt: self
                    .announce
                    .evt
                    .try_clone()
                    .map_err(ActivateError::CloneEventFd)?,
                announce_retry_timer: TimerFd::new().map_err(ActivateError::CreateTimerFd)?,
                announcer,
            };

            let paused = self.vu_common.virtio_common.paused.clone();
            // Let's update the barrier as we need 1 for the control queue
            // thread + 1 for the common vhost-user thread + 1 for the main
            // thread signalling the pause.
            self.vu_common.virtio_common.paused_sync = Some(Arc::new(Barrier::new(3)));
            let paused_sync = self.vu_common.virtio_common.paused_sync.clone();

            self.vu_common.virtio_common.spawn_worker(
                &format!("{}_ctrl", self.id),
                &self.seccomp_action,
                Thread::VirtioVhostNetCtl,
                &self.exit_evt,
                device_status.clone(),
                interrupt_cb.clone(),
                move || ctrl_handler.run_ctrl(&paused, paused_sync.as_ref().unwrap()),
            )?;
        }

        let backend_req_handler: Option<FrontendReqHandler<BackendReqHandler>> = None;

        // The backend acknowledged features must not contain frontend-only
        // features since we don't expect the backend to handle them.
        let backend_acked_features = self.vu_common.virtio_common.acked_features
            & !((1 << VIRTIO_NET_F_MAC)
                | (1 << VIRTIO_NET_F_STATUS)
                | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE));

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds()?;

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            interrupt_cb.clone(),
            backend_acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = self.vu_common.virtio_common.paused.clone();
        let paused_sync = self.vu_common.virtio_common.paused_sync.clone();

        self.vu_common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostNet,
            &self.exit_evt,
            device_status.clone(),
            interrupt_cb.clone(),
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;

        self.announce.notify(
            self.vu_common
                .virtio_common
                .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
        );

        Ok(())
    }

    fn reset(&mut self) {
        self.vu_common.reset(&self.id);
        self.announce.reset();
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(region)
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.announce.invalidate();
        self.vu_common.pause()?;
        self.vu_common.virtio_common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.virtio_common.resume()?;
        self.vu_common.resume()?;
        self.announce.notify(
            self.vu_common
                .virtio_common
                .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
        );
        Ok(())
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state()?)
    }
}
impl Transportable for Net {}

impl Migratable for Net {
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log()
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log()
    }

    fn start_migration(&mut self) -> result::Result<(), MigratableError> {
        self.announce.invalidate();
        self.vu_common.start_migration()
    }

    fn complete_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.complete_migration()
    }
}

#[cfg(test)]
mod unit_tests {
    use std::mem::{offset_of, size_of};

    use seccompiler::SeccompAction;
    use virtio_bindings::virtio_net::{VIRTIO_NET_F_STATUS, VIRTIO_NET_S_LINK_UP};
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::VirtioInterrupt;

    fn test_net(
        acked_features: u64,
        interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    ) -> Result<Net> {
        Ok(Net {
            vu_common: VhostUserCommon {
                virtio_common: VirtioCommon {
                    acked_features,
                    interrupt_cb,
                    ..Default::default()
                },
                ..Default::default()
            },
            id: "test-vu-net".to_string(),
            config: VirtioNetConfig::default(),
            seccomp_action: SeccompAction::Allow,
            exit_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            access_platform_enabled: false,
            announce: AnnouncementState::new(false).map_err(Error::CreateEventFd)?,
        })
    }

    const STATUS_OFFSET: usize = offset_of!(VirtioNetConfig, status);
    fn read_status(device: &Net) -> u16 {
        let mut data = vec![0; size_of::<VirtioNetConfig>()];
        device.read_config(0, &mut data);

        u16::from_le_bytes(
            data[STATUS_OFFSET..STATUS_OFFSET + size_of::<u16>()]
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn test_status_feature_reports_link_up() {
        // The current implementation should always report "link up" if
        // VIRTIO_NET_F_STATUS has been negotiated.
        let net = test_net(1 << VIRTIO_NET_F_STATUS, None).unwrap();

        assert_eq!(read_status(&net), VIRTIO_NET_S_LINK_UP as u16);
    }
}
