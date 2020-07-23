// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{register_listener, unregister_listener, vnet_hdr_len, Tap};
use libc::EAGAIN;
use std::cmp;
use std::io;
use std::io::{Read, Write};
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
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

#[derive(Default, Clone)]
pub struct NetCounters {
    pub tx_bytes: Arc<AtomicU64>,
    pub tx_frames: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
    pub rx_frames: Arc<AtomicU64>,
}

#[derive(Debug)]
pub enum NetQueuePairError {
    /// No memory configured
    NoMemoryConfigured,
    /// Error registering listener
    RegisterListener(io::Error),
    /// Error unregistering listener
    UnregisterListener(io::Error),
    /// Error reading from the TAP device
    FailedReadTap,
}

pub struct NetQueuePair {
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    pub tap: Tap,
    pub rx: RxVirtio,
    pub tx: TxVirtio,
    pub epoll_fd: Option<RawFd>,
    pub rx_tap_listening: bool,
    pub counters: NetCounters,
    pub tap_event_id: u16,
}

impl NetQueuePair {
    // Copies a single frame from `self.rx.frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self, mut queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        let mem = self
            .mem
            .as_ref()
            .ok_or(NetQueuePairError::NoMemoryConfigured)
            .map(|m| m.memory())?;
        let next_desc = queue.iter(&mem).next();

        if next_desc.is_none() {
            // Queue has no available descriptors
            if self.rx_tap_listening {
                unregister_listener(
                    self.epoll_fd.unwrap(),
                    self.tap.as_raw_fd(),
                    epoll::Events::EPOLLIN,
                    u64::from(self.tap_event_id),
                )
                .map_err(NetQueuePairError::UnregisterListener)?;
                self.rx_tap_listening = false;
                info!("Listener unregistered");
            }
            return Ok(false);
        }

        Ok(self.rx.process_desc_chain(&mem, next_desc, &mut queue))
    }

    fn process_rx(&mut self, queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        // Read as many frames as possible.
        loop {
            match self.read_tap() {
                Ok(count) => {
                    self.rx.bytes_read = count;
                    if !self.rx_single_frame(queue)? {
                        self.rx.deferred_frame = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", e);
                            return Err(NetQueuePairError::FailedReadTap);
                        }
                    };
                    break;
                }
            }
        }

        // Consume the counters from the Rx/Tx queues and accumulate into
        // the counters for the device as whole. This consumption is needed
        // to handle MQ.
        self.counters
            .rx_bytes
            .fetch_add(self.rx.counter_bytes.0, Ordering::AcqRel);
        self.counters
            .rx_frames
            .fetch_add(self.rx.counter_frames.0, Ordering::AcqRel);
        self.rx.counter_bytes = Wrapping(0);
        self.rx.counter_frames = Wrapping(0);

        if self.rx.deferred_irqs {
            self.rx.deferred_irqs = false;
            let mem = self
                .mem
                .as_ref()
                .ok_or(NetQueuePairError::NoMemoryConfigured)
                .map(|m| m.memory())?;
            Ok(queue.needs_notification(&mem, queue.next_used))
        } else {
            Ok(false)
        }
    }

    pub fn resume_rx(&mut self, queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        if !self.rx_tap_listening {
            register_listener(
                self.epoll_fd.unwrap(),
                self.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.tap_event_id),
            )
            .map_err(NetQueuePairError::RegisterListener)?;
            self.rx_tap_listening = true;
            info!("Listener registered");
        }
        if self.rx.deferred_frame {
            if self.rx_single_frame(queue)? {
                self.rx.deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx(queue)
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                let mem = self
                    .mem
                    .as_ref()
                    .ok_or(NetQueuePairError::NoMemoryConfigured)
                    .map(|m| m.memory())?;
                Ok(queue.needs_notification(&mem, queue.next_used))
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    pub fn process_tx(&mut self, mut queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        let mem = self
            .mem
            .as_ref()
            .ok_or(NetQueuePairError::NoMemoryConfigured)
            .map(|m| m.memory())?;
        self.tx.process_desc_chain(&mem, &mut self.tap, &mut queue);

        self.counters
            .tx_bytes
            .fetch_add(self.tx.counter_bytes.0, Ordering::AcqRel);
        self.counters
            .tx_frames
            .fetch_add(self.tx.counter_frames.0, Ordering::AcqRel);
        self.tx.counter_bytes = Wrapping(0);
        self.tx.counter_frames = Wrapping(0);

        Ok(queue.needs_notification(&mem, queue.next_used))
    }

    pub fn process_rx_tap(&mut self, mut queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        if self.rx.deferred_frame
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        {
            if self.rx_single_frame(&mut queue)? {
                self.rx.deferred_frame = false;
                self.process_rx(&mut queue)
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            self.process_rx(&mut queue)
        }
    }

    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx.frame_buf)
    }
}
