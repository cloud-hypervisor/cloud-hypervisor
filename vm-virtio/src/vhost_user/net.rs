// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Write;
use std::sync::{Arc, RwLock};
use std::thread;
use std::vec::Vec;

use crate::VirtioInterrupt;
use net_util::{MacAddr, MAC_ADDR_LEN};

use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use super::super::{
    ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType, VirtioInterruptType,
    VirtioResetData,
};
use super::handler::*;
use super::vu_common_ctrl::*;
use super::{Error, Result};
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_rs::vhost_user::{Master, VhostUserMaster, VhostUserMasterReqHandler};
use vhost_rs::VhostBackend;
use virtio_bindings::bindings::virtio_net;
use virtio_bindings::bindings::virtio_ring;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Net {
    vhost_user_net: Master,
    kill_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
    backend_features: u64,
    config_space: Vec<u8>,
    queue_sizes: Vec<u16>,
    queue_evts: Option<Vec<EventFd>>,
    msix_interrupt_cb: Option<Arc<VirtioInterrupt>>,
    isr_interrupt_cb: Option<Arc<VirtioInterrupt>>,
}

impl Net {
    /// Create a new vhost-user-net device
    pub fn new(mac_addr: MacAddr, vu_cfg: VhostUserConfig) -> Result<Net> {
        let mut vhost_user_net = Master::connect(&vu_cfg.sock, vu_cfg.num_queues as u64)
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

        let mut acked_features = 0;
        if avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            acked_features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let mut protocol_features = vhost_user_net
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
            protocol_features &= VhostUserProtocolFeatures::MQ;
            vhost_user_net
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;
        } else {
            return Err(Error::VhostUserProtocolNotSupport);
        }

        let mut config_space = Vec::with_capacity(MAC_ADDR_LEN);
        unsafe { config_space.set_len(MAC_ADDR_LEN) }
        config_space[..].copy_from_slice(mac_addr.get_bytes());
        avail_features |= 1 << virtio_net::VIRTIO_NET_F_MAC;

        // Send set_vring_base here, since it could tell backends, like OVS + DPDK,
        // how many virt queues to be handled, which backend required to know at early stage.
        for i in 0..vu_cfg.num_queues {
            vhost_user_net
                .set_vring_base(i, 0)
                .map_err(Error::VhostUserSetVringBase)?;
        }

        Ok(Net {
            vhost_user_net,
            kill_evt: None,
            avail_features,
            acked_features,
            backend_features,
            config_space,
            queue_sizes: vec![vu_cfg.queue_size; vu_cfg.num_queues],
            queue_evts: None,
            msix_interrupt_cb: None,
            isr_interrupt_cb: None,
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

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = self.config_space.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        mem: Arc<RwLock<GuestMemoryMmap>>,
        mut msix_interrupt_cb: Option<Arc<VirtioInterrupt>>,
        mut isr_interrupt_cb: Option<Arc<VirtioInterrupt>>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if msix_interrupt_cb.is_none() && isr_interrupt_cb.is_none() {
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) =
            match EventFd::new(EFD_NONBLOCK).and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed creating kill EventFd pair: {}", e);
                    return Err(ActivateError::BadActivate);
                }
            };
        self.kill_evt = Some(self_kill_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.msix_interrupt_cb = msix_interrupt_cb.clone();
        self.isr_interrupt_cb = isr_interrupt_cb.clone();

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

        let vu_interrupt_list = setup_vhost_user(
            &mut self.vhost_user_net,
            &mem.read().unwrap(),
            queues,
            queue_evts,
            self.acked_features & self.backend_features,
        )
        .map_err(ActivateError::VhostUserNetSetup)?;

        let interrupt_cb = if let Some(msix_interrupt_cb) = msix_interrupt_cb.take() {
            msix_interrupt_cb
        } else if let Some(isr_interrupt_cb) = isr_interrupt_cb.take() {
            isr_interrupt_cb
        } else {
            // It will never go here.
            Arc::new(
                Box::new(move |_: &VirtioInterruptType, _: Option<&Queue>| Ok(()))
                    as VirtioInterrupt,
            )
        };

        let mut handler = VhostUserEpollHandler::<SlaveReqHandler>::new(VhostUserEpollConfig {
            interrupt_cb,
            kill_evt,
            vu_interrupt_list,
            slave_req_handler: None,
        });

        let handler_result = thread::Builder::new()
            .name("vhost_user_net".to_string())
            .spawn(move || {
                if let Err(e) = handler.run() {
                    error!("net worker thread exited with error {:?}!", e);
                }
            });
        if let Err(e) = handler_result {
            error!("vhost-user net thread create failed with error {:?}", e);
        }

        Ok(())
    }

    fn reset(&mut self) -> Option<VirtioResetData> {
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
            self.msix_interrupt_cb.take(),
            self.isr_interrupt_cb.take(),
            self.queue_evts.take().unwrap(),
        ))
    }
}
