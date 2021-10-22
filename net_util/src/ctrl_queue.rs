// Copyright (c) 2021 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::GuestMemoryMmap;
use crate::Tap;
use libc::c_uint;
use virtio_bindings::bindings::virtio_net::{
    VIRTIO_NET_CTRL_GUEST_OFFLOADS, VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET, VIRTIO_NET_CTRL_MQ,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_ERR, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_OK,
};
use virtio_queue::Queue;
use vm_memory::{ByteValued, Bytes, GuestMemoryAtomic, GuestMemoryError};

#[derive(Debug)]
pub enum Error {
    /// Read queue failed.
    GuestMemory(GuestMemoryError),
    /// No control header descriptor
    NoControlHeaderDescriptor,
    /// Missing the data descriptor in the chain.
    NoDataDescriptor,
    /// No status descriptor
    NoStatusDescriptor,
    /// Failed adding used index
    QueueAddUsed(virtio_queue::Error),
    /// Failed creating an iterator over the queue
    QueueIterator(virtio_queue::Error),
    /// Failed enabling notification for the queue
    QueueEnableNotification(virtio_queue::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlHeader {
    pub class: u8,
    pub cmd: u8,
}

unsafe impl ByteValued for ControlHeader {}

pub struct CtrlQueue {
    pub taps: Vec<Tap>,
}

impl CtrlQueue {
    pub fn new(taps: Vec<Tap>) -> Self {
        CtrlQueue { taps }
    }

    pub fn process(
        &mut self,
        queue: &mut Queue<GuestMemoryAtomic<GuestMemoryMmap>>,
    ) -> Result<bool> {
        let mut used_desc_heads = Vec::new();
        for mut desc_chain in queue.iter().map_err(Error::QueueIterator)? {
            let ctrl_desc = desc_chain.next().ok_or(Error::NoControlHeaderDescriptor)?;

            let ctrl_hdr: ControlHeader = desc_chain
                .memory()
                .read_obj(ctrl_desc.addr())
                .map_err(Error::GuestMemory)?;
            let data_desc = desc_chain.next().ok_or(Error::NoDataDescriptor)?;
            let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;

            let ok = match u32::from(ctrl_hdr.class) {
                VIRTIO_NET_CTRL_MQ => {
                    let queue_pairs = desc_chain
                        .memory()
                        .read_obj::<u16>(data_desc.addr())
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
                    let features = desc_chain
                        .memory()
                        .read_obj::<u64>(data_desc.addr())
                        .map_err(Error::GuestMemory)?;
                    if u32::from(ctrl_hdr.cmd) != VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    } else {
                        let mut ok = true;
                        for tap in self.taps.iter_mut() {
                            info!("Reprogramming tap offload with features: {}", features);
                            tap.set_offload(virtio_features_to_tap_offload(features))
                                .map_err(|e| {
                                    error!("Error programming tap offload: {:?}", e);
                                    ok = false
                                })
                                .ok();
                        }
                        ok
                    }
                }
                _ => {
                    warn!("Unsupported command {:?}", ctrl_hdr);
                    false
                }
            };

            desc_chain
                .memory()
                .write_obj(
                    if ok { VIRTIO_NET_OK } else { VIRTIO_NET_ERR } as u8,
                    status_desc.addr(),
                )
                .map_err(Error::GuestMemory)?;
            let len = ctrl_desc.len() + data_desc.len() + status_desc.len();
            used_desc_heads.push((desc_chain.head_index(), len));
        }

        for (desc_index, len) in used_desc_heads.iter() {
            queue
                .add_used(*desc_index, *len)
                .map_err(Error::QueueAddUsed)?;
            queue
                .enable_notification()
                .map_err(Error::QueueEnableNotification)?;
        }

        Ok(!used_desc_heads.is_empty())
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
