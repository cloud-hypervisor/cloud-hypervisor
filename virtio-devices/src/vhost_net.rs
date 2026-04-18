// Copyright 2026 Cloudflare, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Kernel vhost-net backend for virtio-net. Offloads packet I/O from
// userspace to the kernel vhost module via /dev/vhost-net, matching
// the approach used by Firecracker for high-throughput networking.

use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use event_monitor::event;
use log::{error, info};
use net_util::open_tap;
use net_util::Tap;
use net_util::{MacAddr, VirtioNetConfig, build_net_config_space, build_net_config_space_with_mq};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vhost::net::VhostNet as VhostNetTrait;
use vhost::vhost_kern::net::Net as VhostKernNet;
use vhost::{VhostBackend, VringConfigData};
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::Translatable;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    ActivateError, ActivateResult, GuestMemoryMmap, VIRTIO_F_ACCESS_PLATFORM, VirtioCommon,
    VirtioDevice, VirtioDeviceType, VirtioInterrupt, VirtioInterruptType,
};

const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_NET_F_CSUM: u32 = 0;
const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
const VIRTIO_NET_F_CTRL_GUEST_OFFLOADS: u32 = 2;
const VIRTIO_NET_F_MTU: u32 = 3;
const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
const VIRTIO_NET_F_HOST_ECN: u32 = 13;
const VIRTIO_NET_F_HOST_UFO: u32 = 14;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
const VIRTIO_RING_F_EVENT_IDX: u32 = 29;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create taps")]
    CreateTap(#[source] net_util::OpenTapError),
    #[error("Failed to open /dev/vhost-net")]
    OpenVhostNet(#[source] vhost::Error),
    #[error("Failed to get vhost-net features")]
    GetFeatures(#[source] vhost::Error),
    #[error("Failed to set vhost-net features")]
    SetFeatures(#[source] vhost::Error),
    #[error("Failed to set vhost-net owner")]
    SetOwner(#[source] vhost::Error),
    #[error("Failed to set vring num")]
    SetVringNum(#[source] vhost::Error),
    #[error("Failed to set vring addr")]
    SetVringAddr(#[source] vhost::Error),
    #[error("Failed to set vring base")]
    SetVringBase(#[source] vhost::Error),
    #[error("Failed to set vring kick")]
    SetVringKick(#[source] vhost::Error),
    #[error("Failed to set vring call")]
    SetVringCall(#[source] vhost::Error),
    #[error("Failed to set backend")]
    SetBackend(#[source] vhost::Error),
    #[error("Failed to get available index")]
    GetAvailableIndex(#[source] virtio_queue::Error),
    #[error("Failed to translate GPA")]
    TranslateAddress(#[source] std::io::Error),
    #[error("Failed to get tap MTU")]
    TapMtu(#[source] net_util::TapError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize)]
pub struct VhostNetState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioNetConfig,
    pub queue_sizes: Vec<u16>,
}

pub struct VhostNet {
    common: VirtioCommon,
    id: String,
    taps: Vec<Tap>,
    config: VirtioNetConfig,
    vhost_handles: Vec<VhostKernNet<GuestMemoryAtomic<GuestMemoryMmap>>>,
}

impl VhostNet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        if_name: Option<&str>,
        ip_addr: Option<std::net::IpAddr>,
        netmask: Option<std::net::IpAddr>,
        guest_mac: Option<MacAddr>,
        host_mac: &mut Option<MacAddr>,
        mtu: Option<u16>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        state: Option<VhostNetState>,
    ) -> Result<Self> {
        let taps = open_tap(
            if_name,
            ip_addr,
            netmask,
            host_mac,
            mtu,
            num_queues / 2,
            None,
        )
        .map_err(Error::CreateTap)?;

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            iommu,
            num_queues,
            queue_size,
            offload_tso,
            offload_ufo,
            offload_csum,
            mem,
            state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tap(
        id: String,
        taps: Vec<Tap>,
        guest_mac: Option<MacAddr>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        state: Option<VhostNetState>,
    ) -> Result<Self> {
        assert!(!taps.is_empty());

        let tap_mtu = taps[0].mtu().map_err(Error::TapMtu)? as u16;

        // Open one /dev/vhost-net per queue pair.
        let mut vhost_handles = Vec::with_capacity(taps.len());
        for _ in 0..taps.len() {
            let vhost = VhostKernNet::new(mem.clone()).map_err(Error::OpenVhostNet)?;
            vhost.set_owner().map_err(Error::SetOwner)?;
            vhost_handles.push(vhost);
        }

        let (avail_features, acked_features, config, queue_sizes, paused) =
            if let Some(state) = state {
                info!("Restoring vhost-net {id}");
                (
                    state.avail_features,
                    state.acked_features,
                    state.config,
                    state.queue_sizes,
                    true,
                )
            } else {
                let vhost_features = vhost_handles[0]
                    .get_features()
                    .map_err(Error::GetFeatures)?;

                // Intersect kernel vhost-net features with what we want to expose.
                let mut avail_features = vhost_features
                    & ((1u64 << VIRTIO_NET_F_MRG_RXBUF)
                        | (1u64 << VIRTIO_NET_F_MTU)
                        | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                        | (1u64 << VIRTIO_F_VERSION_1));

                if iommu {
                    avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
                }

                if offload_csum {
                    avail_features |= vhost_features
                        & ((1u64 << VIRTIO_NET_F_CSUM)
                            | (1u64 << VIRTIO_NET_F_GUEST_CSUM)
                            | (1u64 << VIRTIO_NET_F_CTRL_GUEST_OFFLOADS));

                    if offload_tso {
                        avail_features |= vhost_features
                            & ((1u64 << VIRTIO_NET_F_HOST_ECN)
                                | (1u64 << VIRTIO_NET_F_HOST_TSO4)
                                | (1u64 << VIRTIO_NET_F_HOST_TSO6)
                                | (1u64 << VIRTIO_NET_F_GUEST_ECN)
                                | (1u64 << VIRTIO_NET_F_GUEST_TSO4)
                                | (1u64 << VIRTIO_NET_F_GUEST_TSO6));
                    }

                    if offload_ufo {
                        avail_features |= vhost_features
                            & ((1u64 << VIRTIO_NET_F_HOST_UFO) | (1u64 << VIRTIO_NET_F_GUEST_UFO));
                    }
                }

                let mut config = VirtioNetConfig::default();
                if let Some(mac) = guest_mac {
                    build_net_config_space(
                        &mut config,
                        mac,
                        num_queues,
                        Some(tap_mtu),
                        &mut avail_features,
                    );
                } else {
                    build_net_config_space_with_mq(
                        &mut config,
                        num_queues,
                        Some(tap_mtu),
                        &mut avail_features,
                    );
                }

                (
                    avail_features,
                    0,
                    config,
                    vec![queue_size; num_queues],
                    false,
                )
            };

        Ok(VhostNet {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Net as u32,
                avail_features,
                acked_features,
                queue_sizes,
                min_queues: 2,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            taps,
            config,
            vhost_handles,
        })
    }

    fn activate_vhost(
        &mut self,
        mem: &GuestMemoryMmap,
        virtio_interrupt: &dyn VirtioInterrupt,
        queues: Vec<(usize, Queue, EventFd)>,
    ) -> Result<()> {
        for vhost in &self.vhost_handles {
            vhost
                .set_features(self.common.acked_features)
                .map_err(Error::SetFeatures)?;
        }

        for (queue_index, queue, queue_evt) in queues.iter() {
            let vhost_idx = *queue_index / 2;
            let vring_idx = *queue_index % 2;
            let vhost = &self.vhost_handles[vhost_idx];

            vhost
                .set_vring_num(vring_idx, queue.size())
                .map_err(Error::SetVringNum)?;

            let config_data = VringConfigData {
                queue_max_size: queue.max_size(),
                queue_size: queue.size(),
                flags: 0u32,
                desc_table_addr: queue.desc_table().translate_gpa(
                    self.common.access_platform.as_deref(),
                    queue.size() as usize
                        * std::mem::size_of::<virtio_queue::desc::RawDescriptor>(),
                ).map_err(Error::TranslateAddress)?,
                used_ring_addr: queue.used_ring().translate_gpa(
                    self.common.access_platform.as_deref(),
                    4 + queue.size() as usize * 8,
                ).map_err(Error::TranslateAddress)?,
                avail_ring_addr: queue.avail_ring().translate_gpa(
                    self.common.access_platform.as_deref(),
                    4 + queue.size() as usize * 2,
                ).map_err(Error::TranslateAddress)?,
                log_addr: None,
            };

            vhost
                .set_vring_addr(vring_idx, &config_data)
                .map_err(Error::SetVringAddr)?;
            vhost
                .set_vring_base(
                    vring_idx,
                    queue
                        .avail_idx(mem, Ordering::Acquire)
                        .map_err(Error::GetAvailableIndex)?
                        .0,
                )
                .map_err(Error::SetVringBase)?;

            if let Some(eventfd) =
                virtio_interrupt.notifier(VirtioInterruptType::Queue(*queue_index as u16))
            {
                vhost
                    .set_vring_call(vring_idx, &eventfd)
                    .map_err(Error::SetVringCall)?;
            }

            vhost
                .set_vring_kick(vring_idx, queue_evt)
                .map_err(Error::SetVringKick)?;

            // Pass the tap fd to the kernel vhost-net module. We create a
            // temporary File from the raw fd. We must forget() it to avoid
            // double-closing the fd since the Tap still owns it.
            let tap_file = unsafe { std::fs::File::from_raw_fd(self.taps[vhost_idx].as_raw_fd()) };
            let result = vhost.set_backend(vring_idx, Some(&tap_file));
            std::mem::forget(tap_file);
            result.map_err(Error::SetBackend)?;
        }

        info!(
            "vhost-net {} activated with {} queues",
            self.id,
            queues.len()
        );
        Ok(())
    }
}

impl VirtioDevice for VhostNet {
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

    fn activate(&mut self, context: crate::device::ActivationContext) -> ActivateResult {
        let crate::device::ActivationContext {
            mem,
            interrupt_cb,
            queues,
            ..
        } = context;
        self.common.activate(&queues, interrupt_cb.clone())?;
        let mem_ref = mem.memory();

        self.activate_vhost(&mem_ref, interrupt_cb.as_ref(), queues)
            .map_err(|e| {
                error!("vhost-net activation failed: {e}");
                ActivateError::BadActivate
            })
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        for (idx, vhost) in self.vhost_handles.iter().enumerate() {
            for vring_idx in 0..2 {
                if let Err(e) = vhost.set_backend(vring_idx, None) {
                    error!("Failed to reset vhost-net backend {idx}/{vring_idx}: {e}");
                }
            }
        }

        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn vm_virtio::AccessPlatform>) {
        self.common.set_access_platform(access_platform)
    }
}

impl Pausable for VhostNet {}
impl Snapshottable for VhostNet {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&VhostNetState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            queue_sizes: self.common.queue_sizes.clone(),
        })
    }
}
impl Transportable for VhostNet {}
impl Migratable for VhostNet {}
