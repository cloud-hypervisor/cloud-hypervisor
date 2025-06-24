// Copyright (c) 2021 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::Arc;

use thiserror::Error;
use virtio_bindings::virtio_net::{
    VIRTIO_NET_CTRL_GUEST_OFFLOADS, VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET, VIRTIO_NET_CTRL_MQ,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_ERR, VIRTIO_NET_OK,
};
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, Bytes, GuestMemoryError};
use vm_virtio::{AccessPlatform, Translatable};

use super::virtio_features_to_tap_offload;
use crate::{GuestMemoryMmap, Tap};

#[derive(Error, Debug)]
pub enum Error {
    /// Read queue failed.
    #[error("Read queue failed")]
    GuestMemory(#[source] GuestMemoryError),
    /// No control header descriptor
    #[error("No control header descriptor")]
    NoControlHeaderDescriptor,
    /// Missing the data descriptor in the chain.
    #[error("Missing the data descriptor in the chain")]
    NoDataDescriptor,
    /// No status descriptor
    #[error("No status descriptor")]
    NoStatusDescriptor,
    /// Failed adding used index
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    /// Failed creating an iterator over the queue
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
    /// Failed enabling notification for the queue
    #[error("Failed enabling notification for the queue")]
    QueueEnableNotification(#[source] virtio_queue::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlHeader {
    pub class: u8,
    pub cmd: u8,
}

// SAFETY: ControlHeader only contains a series of integers
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
        mem: &GuestMemoryMmap,
        queue: &mut Queue,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
    ) -> Result<()> {
        while let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) {
            let ctrl_desc = desc_chain.next().ok_or(Error::NoControlHeaderDescriptor)?;

            let ctrl_hdr: ControlHeader = desc_chain
                .memory()
                .read_obj(
                    ctrl_desc
                        .addr()
                        .translate_gva(access_platform, ctrl_desc.len() as usize),
                )
                .map_err(Error::GuestMemory)?;
            let data_desc = desc_chain.next().ok_or(Error::NoDataDescriptor)?;

            let data_desc_addr = data_desc
                .addr()
                .translate_gva(access_platform, data_desc.len() as usize);

            let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;

            let ok = match u32::from(ctrl_hdr.class) {
                VIRTIO_NET_CTRL_MQ => {
                    let queue_pairs = desc_chain
                        .memory()
                        .read_obj::<u16>(data_desc_addr)
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
                        .read_obj::<u64>(data_desc_addr)
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
                    status_desc
                        .addr()
                        .translate_gva(access_platform, status_desc.len() as usize),
                )
                .map_err(Error::GuestMemory)?;
            let len = ctrl_desc.len() + data_desc.len() + status_desc.len();

            queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                .map_err(Error::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(Error::QueueEnableNotification)?
            {
                break;
            }
        }

        Ok(())
    }
}
