// Copyright (c) 2019 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{EpollHelper, EpollHelperError, EpollHelperHandler, Queue, EPOLL_HELPER_EVENT_LAST};
use net_util::MacAddr;
use net_util::Tap;
use std::os::raw::c_uint;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use virtio_bindings::bindings::virtio_net::*;
use vm_memory::{
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError, GuestMemoryMmap,
};
use vmm_sys_util::eventfd::EventFd;

type Result<T> = std::result::Result<T, Error>;

const QUEUE_SIZE: usize = 256;

// Event available on the control queue.
const CTRL_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirtioNetConfig {
    pub mac: [u8; 6],
    pub status: u16,
    pub max_virtqueue_pairs: u16,
    pub mtu: u16,
    pub speed: u32,
    pub duplex: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Debug)]
pub enum Error {
    /// Read queue failed.
    GuestMemory(GuestMemoryError),
    /// No queue pairs number.
    NoQueuePairsDescriptor,
    /// No status descriptor
    NoStatusDescriptor,
}

pub struct NetCtrl {
    pub queue_evt: EventFd,
    pub queue: Queue,
    pub taps: Option<Vec<Tap>>,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlHeader {
    pub class: u8,
    pub cmd: u8,
}

unsafe impl ByteValued for ControlHeader {}

impl NetCtrl {
    pub fn new(queue: Queue, queue_evt: EventFd, taps: Option<Vec<Tap>>) -> Self {
        NetCtrl {
            queue_evt,
            queue,
            taps,
        }
    }

    pub fn process_cvq(&mut self, mem: &GuestMemoryMmap) -> Result<()> {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE];
        let mut used_count = 0;
        let queue = &mut self.queue;
        for avail_desc in queue.iter(&mem) {
            let ctrl_hdr: ControlHeader =
                mem.read_obj(avail_desc.addr).map_err(Error::GuestMemory)?;
            let data_desc = avail_desc
                .next_descriptor()
                .ok_or(Error::NoQueuePairsDescriptor)?;
            let status_desc = data_desc
                .next_descriptor()
                .ok_or(Error::NoStatusDescriptor)?;

            let ok = match u32::from(ctrl_hdr.class) {
                VIRTIO_NET_CTRL_MQ => {
                    let queue_pairs = mem
                        .read_obj::<u16>(data_desc.addr)
                        .map_err(Error::GuestMemory)?;
                    if u32::from(ctrl_hdr.cmd) != VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    } else if (queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN as u16)
                        || (queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX as u16)
                    {
                        warn!("Number of MQ pairs out of range: {}", queue_pairs);
                        false
                    } else {
                        info!("Number of MQ pairs requested: {}", queue_pairs);
                        true
                    }
                }
                VIRTIO_NET_CTRL_GUEST_OFFLOADS => {
                    let features = mem
                        .read_obj::<u64>(data_desc.addr)
                        .map_err(Error::GuestMemory)?;
                    if u32::from(ctrl_hdr.cmd) != VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    } else {
                        let mut ok = true;
                        if let Some(ref mut taps) = &mut self.taps {
                            for tap in taps.iter_mut() {
                                info!("Reprogramming tap offload with features: {}", features);
                                tap.set_offload(virtio_features_to_tap_offload(features))
                                    .map_err(|e| {
                                        error!("Error programming tap offload: {:?}", e);
                                        ok = false
                                    })
                                    .ok();
                            }
                        }
                        ok
                    }
                }
                _ => {
                    warn!("Unsupported command {:?}", ctrl_hdr);
                    false
                }
            };

            mem.write_obj(
                if ok { VIRTIO_NET_OK } else { VIRTIO_NET_ERR } as u8,
                status_desc.addr,
            )
            .map_err(Error::GuestMemory)?;
            used_desc_heads[used_count] = (avail_desc.index, avail_desc.len);
            used_count += 1;
        }
        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queue.add_used(&mem, desc_index, len);
            self.queue.update_avail_event(&mem);
        }

        Ok(())
    }
}

pub struct NetCtrlEpollHandler {
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub ctrl_q: NetCtrl,
}

impl NetCtrlEpollHandler {
    pub fn run_ctrl(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.ctrl_q.queue_evt.as_raw_fd(), CTRL_QUEUE_EVENT)?;
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
                if let Err(e) = self.ctrl_q.queue_evt.read() {
                    error!("failed to get ctl queue event: {:?}", e);
                    return true;
                }
                if let Err(e) = self.ctrl_q.process_cvq(&mem) {
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

pub fn build_net_config_space(
    mut config: &mut VirtioNetConfig,
    mac: MacAddr,
    num_queues: usize,
    mut avail_features: &mut u64,
) {
    config.mac.copy_from_slice(mac.get_bytes());
    *avail_features |= 1 << VIRTIO_NET_F_MAC;

    build_net_config_space_with_mq(&mut config, num_queues, &mut avail_features);
}

pub fn build_net_config_space_with_mq(
    config: &mut VirtioNetConfig,
    num_queues: usize,
    avail_features: &mut u64,
) {
    let num_queue_pairs = (num_queues / 2) as u16;
    if (num_queue_pairs >= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN as u16)
        && (num_queue_pairs <= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX as u16)
    {
        config.max_virtqueue_pairs = num_queue_pairs;
        *avail_features |= 1 << VIRTIO_NET_F_MQ;
    }
}

pub fn virtio_features_to_tap_offload(features: u64) -> c_uint {
    let mut tap_offloads: c_uint = 0;
    if features & (1 << VIRTIO_NET_F_GUEST_CSUM) != 0 {
        tap_offloads |= net_gen::TUN_F_CSUM;
    }
    if features & (1 << VIRTIO_NET_F_GUEST_TSO4) != 0 {
        tap_offloads |= net_gen::TUN_F_TSO4;
    }
    if features & (1 << VIRTIO_NET_F_GUEST_TSO6) != 0 {
        tap_offloads |= net_gen::TUN_F_TSO6;
    }
    if features & (1 << VIRTIO_NET_F_GUEST_ECN) != 0 {
        tap_offloads |= net_gen::TUN_F_TSO_ECN;
    }
    if features & (1 << VIRTIO_NET_F_GUEST_UFO) != 0 {
        tap_offloads |= net_gen::TUN_F_UFO;
    }

    tap_offloads
}
