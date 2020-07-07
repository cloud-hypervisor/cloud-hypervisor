// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{vnet_hdr_len, Tap};
use std::cmp;
use std::io::Write;
use std::num::Wrapping;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vm_virtio::{DescriptorChain, Queue};

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
const MAX_BUFFER_SIZE: usize = 65562;

#[derive(Clone)]
pub struct TxVirtio {
    pub iovec: Vec<(GuestAddress, usize)>,
    pub frame_buf: [u8; MAX_BUFFER_SIZE],
    pub counter_bytes: Wrapping<u64>,
    pub counter_frames: Wrapping<u64>,
}

impl Default for TxVirtio {
    fn default() -> Self {
        Self::new()
    }
}

impl TxVirtio {
    pub fn new() -> Self {
        TxVirtio {
            iovec: Vec::new(),
            frame_buf: [0u8; MAX_BUFFER_SIZE],
            counter_bytes: Wrapping(0),
            counter_frames: Wrapping(0),
        }
    }

    pub fn process_desc_chain(&mut self, mem: &GuestMemoryMmap, tap: &mut Tap, queue: &mut Queue) {
        while let Some(avail_desc) = queue.iter(&mem).next() {
            let head_index = avail_desc.index;
            let mut read_count = 0;
            let mut next_desc = Some(avail_desc);

            self.iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    break;
                }
                self.iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            read_count = 0;
            // Copy buffer from across multiple descriptors.
            // TODO(performance - Issue #420): change this to use `writev()` instead of `write()`
            // and get rid of the intermediate buffer.
            for (desc_addr, desc_len) in self.iovec.drain(..) {
                let limit = cmp::min((read_count + desc_len) as usize, self.frame_buf.len());

                let read_result =
                    mem.read_slice(&mut self.frame_buf[read_count..limit as usize], desc_addr);
                match read_result {
                    Ok(_) => {
                        // Increment by number of bytes actually read
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        println!("Failed to read slice: {:?}", e);
                        break;
                    }
                }
            }

            let write_result = tap.write(&self.frame_buf[..read_count]);
            match write_result {
                Ok(_) => {}
                Err(e) => {
                    println!("net: tx: error failed to write to tap: {}", e);
                }
            };

            self.counter_bytes += Wrapping((read_count - vnet_hdr_len()) as u64);
            self.counter_frames += Wrapping(1);

            queue.add_used(&mem, head_index, 0);
            queue.update_avail_event(&mem);
        }
    }
}

#[derive(Clone)]
pub struct RxVirtio {
    pub deferred_frame: bool,
    pub deferred_irqs: bool,
    pub bytes_read: usize,
    pub frame_buf: [u8; MAX_BUFFER_SIZE],
    pub counter_bytes: Wrapping<u64>,
    pub counter_frames: Wrapping<u64>,
}

impl Default for RxVirtio {
    fn default() -> Self {
        Self::new()
    }
}

impl RxVirtio {
    pub fn new() -> Self {
        RxVirtio {
            deferred_frame: false,
            deferred_irqs: false,
            bytes_read: 0,
            frame_buf: [0u8; MAX_BUFFER_SIZE],
            counter_bytes: Wrapping(0),
            counter_frames: Wrapping(0),
        }
    }

    pub fn process_desc_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        mut next_desc: Option<DescriptorChain>,
        queue: &mut Queue,
    ) -> bool {
        let head_index = next_desc.as_ref().unwrap().index;
        let mut write_count = 0;

        // Copy from frame into buffer, which may span multiple descriptors.
        loop {
            match next_desc {
                Some(desc) => {
                    if !desc.is_write_only() {
                        break;
                    }
                    let limit = cmp::min(write_count + desc.len as usize, self.bytes_read);
                    let source_slice = &self.frame_buf[write_count..limit];
                    let write_result = mem.write_slice(source_slice, desc.addr);

                    match write_result {
                        Ok(_) => {
                            write_count = limit;
                        }
                        Err(e) => {
                            error!("Failed to write slice: {:?}", e);
                            break;
                        }
                    };

                    if write_count >= self.bytes_read {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    warn!("Receiving buffer is too small to hold frame of current size");
                    break;
                }
            }
        }

        self.counter_bytes += Wrapping((write_count - vnet_hdr_len()) as u64);
        self.counter_frames += Wrapping(1);

        queue.add_used(&mem, head_index, write_count as u32);
        queue.update_avail_event(&mem);

        // Mark that we have at least one pending packet and we need to interrupt the guest.
        self.deferred_irqs = true;

        // Update the frame_buf buffer.
        if write_count < self.bytes_read {
            self.frame_buf.copy_within(write_count..self.bytes_read, 0);
            self.bytes_read -= write_count;
            false
        } else {
            self.bytes_read = 0;
            true
        }
    }
}
