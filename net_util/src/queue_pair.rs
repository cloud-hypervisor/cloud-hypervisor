// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{unregister_listener, vnet_hdr_len, Tap};
use crate::GuestMemoryMmap;
use rate_limiter::{RateLimiter, TokenType};
use std::io;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemory, GuestMemoryAtomic};
use vm_virtio::Queue;

#[derive(Clone)]
pub struct TxVirtio {
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
            counter_bytes: Wrapping(0),
            counter_frames: Wrapping(0),
        }
    }

    pub fn process_desc_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        tap: &mut Tap,
        queue: &mut Queue,
        rate_limiter: &mut Option<RateLimiter>,
    ) -> Result<(), NetQueuePairError> {
        while let Some(avail_desc) = queue.iter(mem).next() {
            let head_index = avail_desc.index;
            let mut next_desc = Some(avail_desc);

            if let Some(rate_limiter) = rate_limiter {
                if !rate_limiter.consume(1, TokenType::Ops) {
                    queue.go_to_previous_position();
                    break;
                }

                let mut bytes = Wrapping(0);
                let mut tmp_next_desc = next_desc.clone();
                while let Some(desc) = tmp_next_desc {
                    if !desc.is_write_only() {
                        bytes += Wrapping(desc.len as u64);
                    }
                    tmp_next_desc = desc.next_descriptor();
                }
                bytes -= Wrapping(vnet_hdr_len() as u64);
                if !rate_limiter.consume(bytes.0, TokenType::Bytes) {
                    // Revert the OPS consume().
                    rate_limiter.manual_replenish(1, TokenType::Ops);
                    queue.go_to_previous_position();
                    break;
                }
            }

            let mut iovecs = Vec::new();
            while let Some(desc) = next_desc {
                if !desc.is_write_only() && desc.len > 0 {
                    let buf = mem
                        .get_slice(desc.addr, desc.len as usize)
                        .map_err(NetQueuePairError::GuestMemory)?
                        .as_ptr();
                    let iovec = libc::iovec {
                        iov_base: buf as *mut libc::c_void,
                        iov_len: desc.len as libc::size_t,
                    };
                    iovecs.push(iovec);
                }
                next_desc = desc.next_descriptor();
            }

            if !iovecs.is_empty() {
                let result = unsafe {
                    libc::writev(
                        tap.as_raw_fd() as libc::c_int,
                        iovecs.as_ptr() as *const libc::iovec,
                        iovecs.len() as libc::c_int,
                    )
                };
                if result < 0 {
                    let e = std::io::Error::last_os_error();
                    queue.go_to_previous_position();

                    /* EAGAIN */
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        warn!("net: tx: (recoverable) failed writing to tap: {}", e);
                        break;
                    }
                    error!("net: tx: failed writing to tap: {}", e);
                    return Err(NetQueuePairError::WriteTap(e));
                }

                self.counter_bytes += Wrapping(result as u64 - vnet_hdr_len() as u64);
                self.counter_frames += Wrapping(1);
            }

            queue.add_used(mem, head_index, 0);
            queue.update_avail_event(mem);
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RxVirtio {
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
            counter_bytes: Wrapping(0),
            counter_frames: Wrapping(0),
        }
    }

    pub fn process_desc_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        tap: &mut Tap,
        queue: &mut Queue,
        rate_limiter: &mut Option<RateLimiter>,
    ) -> Result<bool, NetQueuePairError> {
        let mut exhausted_descs = true;
        let mut rate_limit_reached = false;

        while let Some(avail_desc) = queue.iter(mem).next() {
            if rate_limit_reached {
                exhausted_descs = false;
                queue.go_to_previous_position();
                break;
            }

            let head_index = avail_desc.index;
            let num_buffers_addr = mem.checked_offset(avail_desc.addr, 10).unwrap();
            let mut next_desc = Some(avail_desc);

            let mut iovecs = Vec::new();
            while let Some(desc) = next_desc {
                if desc.is_write_only() && desc.len > 0 {
                    let buf = mem
                        .get_slice(desc.addr, desc.len as usize)
                        .map_err(NetQueuePairError::GuestMemory)?
                        .as_ptr();
                    let iovec = libc::iovec {
                        iov_base: buf as *mut libc::c_void,
                        iov_len: desc.len as libc::size_t,
                    };
                    iovecs.push(iovec);
                }
                next_desc = desc.next_descriptor();
            }

            let len = if !iovecs.is_empty() {
                let result = unsafe {
                    libc::readv(
                        tap.as_raw_fd() as libc::c_int,
                        iovecs.as_ptr() as *const libc::iovec,
                        iovecs.len() as libc::c_int,
                    )
                };
                if result < 0 {
                    let e = std::io::Error::last_os_error();
                    exhausted_descs = false;
                    queue.go_to_previous_position();

                    /* EAGAIN */
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }

                    error!("net: rx: failed reading from tap: {}", e);
                    return Err(NetQueuePairError::ReadTap(e));
                }

                // Write num_buffers to guest memory. We simply write 1 as we
                // never spread the frame over more than one descriptor chain.
                mem.write_obj(1u16, num_buffers_addr)
                    .map_err(NetQueuePairError::GuestMemory)?;

                self.counter_bytes += Wrapping(result as u64 - vnet_hdr_len() as u64);
                self.counter_frames += Wrapping(1);

                result as u32
            } else {
                0
            };

            queue.add_used(mem, head_index, len);
            queue.update_avail_event(mem);

            // For the sake of simplicity (keeping the handling of RX_QUEUE_EVENT and
            // RX_TAP_EVENT totally asynchronous), we always let the 'last' descriptor
            // chain go-through even if it was over the rate limit, and simply stop
            // processing oncoming `avail_desc` if any.
            if let Some(rate_limiter) = rate_limiter {
                rate_limit_reached = !rate_limiter.consume(1, TokenType::Ops)
                    || !rate_limiter.consume(len as u64, TokenType::Bytes);
            }
        }

        Ok(exhausted_descs)
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
    /// Error writing to the TAP device
    WriteTap(io::Error),
    /// Error reading from the TAP device
    ReadTap(io::Error),
    /// Error related to guest memory
    GuestMemory(vm_memory::GuestMemoryError),
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
    pub rx_desc_avail: bool,
    pub rx_rate_limiter: Option<RateLimiter>,
    pub tx_rate_limiter: Option<RateLimiter>,
}

impl NetQueuePair {
    pub fn process_tx(&mut self, mut queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        let mem = self
            .mem
            .as_ref()
            .ok_or(NetQueuePairError::NoMemoryConfigured)
            .map(|m| m.memory())?;

        self.tx
            .process_desc_chain(&mem, &mut self.tap, &mut queue, &mut self.tx_rate_limiter)?;

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

    pub fn process_rx(&mut self, mut queue: &mut Queue) -> Result<bool, NetQueuePairError> {
        let mem = self
            .mem
            .as_ref()
            .ok_or(NetQueuePairError::NoMemoryConfigured)
            .map(|m| m.memory())?;

        self.rx_desc_avail = !self.rx.process_desc_chain(
            &mem,
            &mut self.tap,
            &mut queue,
            &mut self.rx_rate_limiter,
        )?;
        let rate_limit_reached = self
            .rx_rate_limiter
            .as_ref()
            .map_or(false, |r| r.is_blocked());

        // Stop listening on the `RX_TAP_EVENT` when:
        // 1) there is no available describles, or
        // 2) the RX rate limit is reached.
        if self.rx_tap_listening && (!self.rx_desc_avail || rate_limit_reached) {
            unregister_listener(
                self.epoll_fd.unwrap(),
                self.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.tap_event_id),
            )
            .map_err(NetQueuePairError::UnregisterListener)?;
            self.rx_tap_listening = false;
        }

        self.counters
            .rx_bytes
            .fetch_add(self.rx.counter_bytes.0, Ordering::AcqRel);
        self.counters
            .rx_frames
            .fetch_add(self.rx.counter_frames.0, Ordering::AcqRel);
        self.rx.counter_bytes = Wrapping(0);
        self.rx.counter_frames = Wrapping(0);

        Ok(queue.needs_notification(&mem, queue.next_used))
    }
}
