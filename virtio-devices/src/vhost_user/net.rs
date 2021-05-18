// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::net_util::{build_net_config_space, VirtioNetConfig};
use super::super::{
    ActivateError, ActivateResult, Queue, VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use super::vu_common_ctrl::*;
use super::{Error, Result};
use crate::VirtioInterrupt;
use net_util::MacAddr;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::result;
use std::sync::{Arc, Barrier};
use std::vec::Vec;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{Master, VhostUserMaster, VhostUserMasterReqHandler};
use vhost::VhostBackend;
use virtio_bindings::bindings::virtio_net;
use virtio_bindings::bindings::virtio_ring;
use vm_memory::{
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap, GuestRegionMmap,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const DEFAULT_QUEUE_NUMBER: usize = 2;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Net {
    common: VirtioCommon,
    id: String,
    vhost_user_net: Master,
    config: VirtioNetConfig,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    acked_protocol_features: u64,
    socket_path: Option<String>,
}

impl Net {
    /// Create a new vhost-user-net device
    pub fn new(
        id: String,
        mac_addr: MacAddr,
        vu_cfg: VhostUserConfig,
        server: bool,
    ) -> Result<Net> {
        let mut socket_path: Option<String> = None;

        let mut num_queues = vu_cfg.num_queues;

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
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ
            | 1 << virtio_net::VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << virtio_net::VIRTIO_F_VERSION_1
            | 1 << virtio_ring::VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let mut config = VirtioNetConfig::default();
        build_net_config_space(&mut config, mac_addr, num_queues, &mut avail_features);

        // Adding one potential queue for the control queue.
        num_queues += 1;

        let mut vhost_user_net = if server {
            info!("Binding vhost-user-net listener...");
            let listener = UnixListener::bind(&vu_cfg.socket).map_err(Error::BindSocket)?;
            info!("Waiting for incoming vhost-user-net connection...");
            let (stream, _) = listener.accept().map_err(Error::AcceptConnection)?;

            socket_path = Some(vu_cfg.socket.clone());

            Master::from_stream(stream, num_queues as u64)
        } else {
            Master::connect(&vu_cfg.socket, num_queues as u64)
                .map_err(Error::VhostUserCreateMaster)?
        };

        vhost_user_net
            .set_owner()
            .map_err(Error::VhostUserSetOwner)?;

        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = vhost_user_net
            .get_features()
            .map_err(Error::VhostUserGetFeatures)?;
        let acked_features = avail_features & backend_features;
        // Set features back is required by the vhost crate mechanism, since the
        // later vhost call will check if features is filled in master before execution.
        vhost_user_net
            .set_features(acked_features)
            .map_err(Error::VhostUserSetFeatures)?;

        let avail_protocol_features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
            | VhostUserProtocolFeatures::REPLY_ACK;
        let backend_protocol_features =
            if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
                vhost_user_net
                    .get_protocol_features()
                    .map_err(Error::VhostUserGetProtocolFeatures)?
            } else {
                return Err(Error::VhostUserProtocolNotSupport);
            };
        let acked_protocol_features = avail_protocol_features & backend_protocol_features;

        vhost_user_net
            .set_protocol_features(acked_protocol_features)
            .map_err(Error::VhostUserSetProtocolFeatures)?;

        // If the control queue feature has not been negotiated, let's decrease
        // the number of queues.
        if acked_features & (1 << virtio_net::VIRTIO_NET_F_CTRL_VQ) == 0 {
            num_queues -= 1;
        }

        let backend_num_queues =
            if acked_protocol_features.bits() & VhostUserProtocolFeatures::MQ.bits() != 0 {
                vhost_user_net
                    .get_queue_num()
                    .map_err(Error::VhostUserGetQueueMaxNum)? as usize
            } else if backend_features & (1 << virtio_net::VIRTIO_NET_F_CTRL_VQ) != 0 {
                DEFAULT_QUEUE_NUMBER + 1
            } else {
                DEFAULT_QUEUE_NUMBER
            };

        if num_queues > backend_num_queues {
            error!("vhost-user-net requested too many queues ({}) since the backend only supports {}\n",
                num_queues, backend_num_queues);
            return Err(Error::BadQueueNum);
        }

        // Send set_vring_base here, since it could tell backends, like OVS + DPDK,
        // how many virt queues to be handled, which backend required to know at early stage.
        for i in 0..num_queues {
            vhost_user_net
                .set_vring_base(i, 0)
                .map_err(Error::VhostUserSetVringBase)?;
        }

        Ok(Net {
            id,
            common: VirtioCommon {
                device_type: VirtioDeviceType::Net as u32,
                queue_sizes: vec![vu_cfg.queue_size; num_queues],
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(1))),
                min_queues: DEFAULT_QUEUE_NUMBER as u16,
                ..Default::default()
            },
            vhost_user_net,
            config,
            guest_memory: None,
            acked_protocol_features: acked_protocol_features.bits(),
            socket_path,
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
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;

        self.guest_memory = Some(mem.clone());

        setup_vhost_user(
            &mut self.vhost_user_net,
            &mem.memory(),
            queues,
            queue_evts,
            &interrupt_cb,
            self.common.acked_features,
        )
        .map_err(ActivateError::VhostUserNetSetup)?;

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

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        let _ = unsafe { libc::close(self.vhost_user_net.as_raw_fd()) };

        // Remove socket path if needed
        if let Some(socket_path) = &self.socket_path {
            let _ = std::fs::remove_file(socket_path);
        }
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() != 0
        {
            add_memory_region(&mut self.vhost_user_net, region)
                .map_err(crate::Error::VhostUserAddMemoryRegion)
        } else if let Some(guest_memory) = &self.guest_memory {
            update_mem_table(&mut self.vhost_user_net, guest_memory.memory().deref())
                .map_err(crate::Error::VhostUserUpdateMemory)
        } else {
            Ok(())
        }
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
