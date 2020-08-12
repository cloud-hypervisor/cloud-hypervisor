// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::net_util::{
    build_net_config_space, CtrlVirtio, NetCtrlEpollHandler, VirtioNetConfig,
};
use super::super::{
    ActivateError, ActivateResult, EpollHelperError, Queue, VirtioDevice, VirtioDeviceType,
};
use super::handler::*;
use super::vu_common_ctrl::*;
use super::{Error, Result};
use crate::VirtioInterrupt;
use libc::EFD_NONBLOCK;
use net_util::MacAddr;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
    id: String,
    vhost_user_net: Master,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
    backend_features: u64,
    config: VirtioNetConfig,
    queue_sizes: Vec<u16>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), EpollHelperError>>>>,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<result::Result<(), EpollHelperError>>>,
    paused: Arc<AtomicBool>,
}

impl Net {
    /// Create a new vhost-user-net device
    /// Create a new vhost-user-net device
    pub fn new(id: String, mac_addr: MacAddr, vu_cfg: VhostUserConfig) -> Result<Net> {
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
            vhost_user_net,
            kill_evt: None,
            pause_evt: None,
            avail_features,
            acked_features,
            backend_features,
            config,
            queue_sizes: vec![vu_cfg.queue_size; queue_num],
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            ctrl_queue_epoll_thread: None,
            paused: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill vhost-user-net: {:?}", e);
            }
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_NET as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
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
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_sizes.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        let queue_num = queue_evts.len();

        if (self.acked_features & 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ) != 0 && queue_num % 2 != 0
        {
            let cvq_queue = queues.remove(queue_num - 1);
            let cvq_queue_evt = queue_evts.remove(queue_num - 1);

            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt: kill_evt.try_clone().unwrap(),
                pause_evt: pause_evt.try_clone().unwrap(),
                ctrl_q: CtrlVirtio::new(cvq_queue, cvq_queue_evt),
                epoll_fd: 0,
            };

            let paused = self.paused.clone();
            thread::Builder::new()
                .name("virtio_net".to_string())
                .spawn(move || ctrl_handler.run_ctrl(paused))
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
            self.acked_features & self.backend_features,
        )
        .map_err(ActivateError::VhostUserNetSetup)?;

        let mut epoll_threads = Vec::new();
        for _ in 0..vu_interrupt_list.len() / 2 {
            let mut interrupt_list_sub: Vec<(Option<EventFd>, Queue)> = Vec::with_capacity(2);
            interrupt_list_sub.push(vu_interrupt_list.remove(0));
            interrupt_list_sub.push(vu_interrupt_list.remove(0));

            let mut handler = VhostUserEpollHandler::<SlaveReqHandler>::new(VhostUserEpollConfig {
                interrupt_cb: interrupt_cb.clone(),
                kill_evt: kill_evt.try_clone().unwrap(),
                pause_evt: pause_evt.try_clone().unwrap(),
                vu_interrupt_list: interrupt_list_sub,
                slave_req_handler: None,
            });

            let paused = self.paused.clone();
            thread::Builder::new()
                .name("vhost_user_net".to_string())
                .spawn(move || handler.run(paused))
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone queue EventFd: {}", e);
                    ActivateError::BadActivate
                })?;
        }

        self.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Err(e) = reset_vhost_user(&mut self.vhost_user_net, self.queue_sizes.len()) {
            error!("Failed to reset vhost-user daemon: {:?}", e);
            return None;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }

    fn shutdown(&mut self) {
        let _ = unsafe { libc::close(self.vhost_user_net.as_raw_fd()) };
    }

    fn update_memory(&mut self, mem: &GuestMemoryMmap) -> std::result::Result<(), crate::Error> {
        update_mem_table(&mut self.vhost_user_net, mem).map_err(crate::Error::VhostUserUpdateMemory)
    }
}

virtio_ctrl_q_pausable!(Net);
impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }
}
impl Transportable for Net {}
impl Migratable for Net {}
