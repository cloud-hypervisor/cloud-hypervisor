// Copyright (c) 2019 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{DescriptorChain, Queue};
use vm_memory::{Bytes, GuestMemoryError, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use virtio_bindings::bindings::virtio_net::*;
type Result<T> = std::result::Result<T, Error>;

const VIRTIO_NET_CTRL_MQ: u8 = 4;
const QUEUE_SIZE: usize = 256;

#[derive(Debug)]
pub enum Error {
    /// Read process MQ.
    FailedProcessMQ,
    /// Read queue failed.
    GuestMemory(GuestMemoryError),
    /// Invalid ctrl command
    InvalidCtlCmd,
    /// Invalid descriptor
    InvalidDesc,
    /// Invalid queue pairs number
    InvalidQueuePairsNum,
    /// No memory passed in.
    NoMemory,
    /// No ueue pairs nummber.
    NoQueuePairsNum,
}

pub struct CtrlVirtio {
    pub queue_evt: EventFd,
    pub queue: Queue,
}

impl std::clone::Clone for CtrlVirtio {
    fn clone(&self) -> Self {
        CtrlVirtio {
            queue_evt: self.queue_evt.try_clone().unwrap(),
            queue: self.queue.clone(),
        }
    }
}

impl CtrlVirtio {
    pub fn new(queue: Queue, queue_evt: EventFd) -> Self {
        CtrlVirtio { queue_evt, queue }
    }

    fn process_mq(&self, mem: &GuestMemoryMmap, avail_desc: DescriptorChain) -> Result<()> {
        let mq_desc = if avail_desc.has_next() {
            avail_desc.next_descriptor().unwrap()
        } else {
            return Err(Error::NoQueuePairsNum);
        };
        let queue_pairs = mem
            .read_obj::<u16>(mq_desc.addr)
            .map_err(Error::GuestMemory)?;
        if (queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN as u16)
            || (queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX as u16)
        {
            return Err(Error::InvalidQueuePairsNum);
        }
        let status_desc = if mq_desc.has_next() {
            mq_desc.next_descriptor().unwrap()
        } else {
            return Err(Error::NoQueuePairsNum);
        };
        mem.write_obj::<u8>(0, status_desc.addr)
            .map_err(Error::GuestMemory)?;

        Ok(())
    }

    pub fn process_cvq(&mut self, mem: &mut GuestMemoryMmap) -> Result<()> {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE];
        let mut used_count = 0;
        if let Some(avail_desc) = self.queue.iter(&mem).next() {
            used_desc_heads[used_count] = (avail_desc.index, avail_desc.len);
            used_count += 1;
            let class = mem
                .read_obj::<u8>(avail_desc.addr)
                .map_err(Error::GuestMemory)?;
            match class {
                VIRTIO_NET_CTRL_MQ => {
                    if let Err(_e) = self.process_mq(&mem, avail_desc) {
                        return Err(Error::FailedProcessMQ);
                    }
                }
                _ => return Err(Error::InvalidCtlCmd),
            }
        } else {
            return Err(Error::InvalidDesc);
        }
        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queue.add_used(&mem, desc_index, len);
        }

        Ok(())
    }
}
