// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::net_util::{
    build_net_config_space, CtrlVirtio, NetCtrlEpollHandler, VirtioNetConfig,
};
use super::super::{
    ActivateError, ActivateResult, Queue, VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use super::handler::*;
use super::vu_common_ctrl::*;
use super::{Error, Result};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::VirtioInterrupt;
use net_util::MacAddr;
use seccomp::{SeccompAction, SeccompFilter};
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{Arc, Barrier};
use std::thread;
use std::vec::Vec;
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_rs::vhost_user::{Master, VhostUserMaster, VhostUserMasterReqHandler};
use vhost_rs::VhostBackend;
use virtio_bindings::bindings::virtio_net;
use virtio_bindings::bindings::virtio_ring;
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const DEFAULT_QUEUE_NUMBER: usize = 2;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Net {
    common: VirtioCommon,
    id: String,
    vhost_user_net: Master,
    backend_features: u64,
    config: VirtioNetConfig,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<()>>,
    seccomp_action: SeccompAction,
}

impl Net {
    /// Create a new vhost-user-net device
    /// Create a new vhost-user-net device
    pub fn new(
        id: String,
        mac_addr: MacAddr,
        vu_cfg: VhostUserConfig,
        seccomp_action: SeccompAction,
    ) -> Result<Net> {
        let mut vhost_user_net = Master::connect(&vu_cfg.socket, vu_cfg.num_queues as u64)
            .map_err(Error::VhostUserCreateMaster)?;

        // Filling device and vring features VMM supports.
        let mut avail_features = 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO6
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_ECN
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO6
            | 1 << virtio_net::VIRTIO_NET_F_HOST_ECN
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF
            | 1 << virtio_net::VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << virtio_net::VIRTIO_F_VERSION_1
            | 1 << virtio_ring::VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        vhost_user_net
            .set_owner()
            .map_err(Error::VhostUserSetOwner)?;

        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = vhost_user_net
            .get_features()
            .map_err(Error::VhostUserGetFeatures)?;
        avail_features &= backend_features;
        // Set features back is required by the vhost crate mechanism, since the
        // later vhost call will check if features is filled in master before execution.
        vhost_user_net
            .set_features(avail_features)
            .map_err(Error::VhostUserSetFeatures)?;

        let protocol_features;
        let mut acked_features = 0;
        if avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            acked_features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            protocol_features = vhost_user_net
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
        } else {
            return Err(Error::VhostUserProtocolNotSupport);
        }

        let max_queue_number =
            if protocol_features.bits() & VhostUserProtocolFeatures::MQ.bits() != 0 {
                vhost_user_net
                    .set_protocol_features(protocol_features & VhostUserProtocolFeatures::MQ)
                    .map_err(Error::VhostUserSetProtocolFeatures)?;
                match vhost_user_net.get_queue_num() {
                    Ok(qn) => qn,
                    Err(_) => DEFAULT_QUEUE_NUMBER as u64,
                }
            } else {
                DEFAULT_QUEUE_NUMBER as u64
            };
        if vu_cfg.num_queues > max_queue_number as usize {
            error!("vhost-user-net has queue number: {} larger than the max queue number: {} backend allowed\n",
                vu_cfg.num_queues, max_queue_number);
            return Err(Error::BadQueueNum);
        }

        avail_features |= 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ;
        let queue_num = vu_cfg.num_queues + 1;

        let mut config = VirtioNetConfig::default();
        build_net_config_space(
            &mut config,
            mac_addr,
            vu_cfg.num_queues,
            &mut avail_features,
        );

        // Send set_vring_base here, since it could tell backends, like OVS + DPDK,
        // how many virt queues to be handled, which backend required to know at early stage.
        for i in 0..vu_cfg.num_queues {
            vhost_user_net
                .set_vring_base(i, 0)
                .map_err(Error::VhostUserSetVringBase)?;
        }

        Ok(Net {
            id,
            common: VirtioCommon {
                device_type: VirtioDeviceType::TYPE_NET as u32,
                queue_sizes: vec![vu_cfg.queue_size; queue_num],
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new((vu_cfg.num_queues / 2) + 1))),
                ..Default::default()
            },
            vhost_user_net,
            backend_features,
            config,
            ctrl_queue_epoll_thread: None,
            seccomp_action,
        })
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

        let queue_num = self.common.queue_evts.as_ref().unwrap().len();

        if self
            .common
            .feature_acked(virtio_net::VIRTIO_NET_F_CTRL_VQ.into())
            && queue_num % 2 != 0
        {
            let cvq_queue = queues.remove(queue_num - 1);
            let cvq_queue_evt = queue_evts.remove(queue_num - 1);

            let kill_evt = self
                .common
                .kill_evt
                .as_ref()
                .unwrap()
                .try_clone()
                .map_err(|e| {
                    error!("failed to clone kill_evt eventfd: {}", e);
                    ActivateError::BadActivate
                })?;
            let pause_evt = self
                .common
                .pause_evt
                .as_ref()
                .unwrap()
                .try_clone()
                .map_err(|e| {
                    error!("failed to clone pause_evt eventfd: {}", e);
                    ActivateError::BadActivate
                })?;

            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt,
                pause_evt,
                ctrl_q: CtrlVirtio::new(cvq_queue, cvq_queue_evt),
                epoll_fd: 0,
            };

            let paused = self.common.paused.clone();
            // Let's update the barrier as we need 1 for each RX/TX pair +
            // 1 for the control queue + 1 for the main thread signalling
            // the pause.
            self.common.paused_sync = Some(Arc::new(Barrier::new((queue_num / 2) + 2)));
            let paused_sync = self.common.paused_sync.clone();
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

        let mut vu_interrupt_list = setup_vhost_user(
            &mut self.vhost_user_net,
            &mem.memory(),
            queues,
            queue_evts,
            &interrupt_cb,
            self.common.acked_features & self.backend_features,
        )
        .map_err(ActivateError::VhostUserNetSetup)?;

        let mut epoll_threads = Vec::new();
        for i in 0..vu_interrupt_list.len() / 2 {
            let mut interrupt_list_sub: Vec<(Option<EventFd>, Queue)> = Vec::with_capacity(2);
            interrupt_list_sub.push(vu_interrupt_list.remove(0));
            interrupt_list_sub.push(vu_interrupt_list.remove(0));

            let kill_evt = self
                .common
                .kill_evt
                .as_ref()
                .unwrap()
                .try_clone()
                .map_err(|e| {
                    error!("failed to clone kill_evt eventfd: {}", e);
                    ActivateError::BadActivate
                })?;
            let pause_evt = self
                .common
                .pause_evt
                .as_ref()
                .unwrap()
                .try_clone()
                .map_err(|e| {
                    error!("failed to clone pause_evt eventfd: {}", e);
                    ActivateError::BadActivate
                })?;

            let mut handler = VhostUserEpollHandler::<SlaveReqHandler>::new(VhostUserEpollConfig {
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                vu_interrupt_list: interrupt_list_sub,
                slave_req_handler: None,
            });

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();
            let virtio_vhost_net_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioVhostNet)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name(format!("{}_qp{}", self.id.clone(), i))
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_vhost_net_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone queue EventFd: {}", e);
                    ActivateError::BadActivate
                })?;
        }

        self.common.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Err(e) = reset_vhost_user(&mut self.vhost_user_net, self.common.queue_sizes.len()) {
            error!("Failed to reset vhost-user daemon: {:?}", e);
            return None;
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        let _ = unsafe { libc::close(self.vhost_user_net.as_raw_fd()) };
    }

    fn update_memory(&mut self, mem: &GuestMemoryMmap) -> std::result::Result<(), crate::Error> {
        update_mem_table(&mut self.vhost_user_net, mem).map_err(crate::Error::VhostUserUpdateMemory)
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }
}
impl Transportable for Net {}
impl Migratable for Net {}
