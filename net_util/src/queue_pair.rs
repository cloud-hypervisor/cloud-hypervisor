// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rate_limiter::{RateLimiter, TokenType};
use thiserror::Error;
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::bitmap::Bitmap;
use vm_memory::{Bytes, GuestMemory};
use vm_virtio::{AccessPlatform, Translatable};

use super::{Tap, register_listener, unregister_listener, vnet_hdr_len};

#[derive(Clone)]
pub struct TxVirtio {
    pub counter_bytes: Wrapping<u64>,
    pub counter_frames: Wrapping<u64>,
    iovecs: IovecBuffer,
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
            iovecs: IovecBuffer::new(),
        }
    }

    pub fn process_desc_chain<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        tap: &Tap,
        queue: &mut Queue,
        rate_limiter: &mut Option<RateLimiter>,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
    ) -> Result<bool, NetQueuePairError> {
        let mut retry_write = false;
        let mut rate_limit_reached = false;

        while let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) {
            if rate_limit_reached {
                queue.go_to_previous_position();
                break;
            }

            let mut next_desc = desc_chain.next();

            let mut iovecs = self.iovecs.borrow();
            while let Some(desc) = next_desc {
                let desc_addr = desc
                    .addr()
                    .translate_gva(access_platform, desc.len() as usize);
                if !desc.is_write_only() && desc.len() > 0 {
                    let buf = desc_chain
                        .memory()
                        .get_slice(desc_addr, desc.len() as usize)
                        .map_err(NetQueuePairError::GuestMemory)?
                        .ptr_guard_mut();
                    let iovec = libc::iovec {
                        iov_base: buf.as_ptr() as *mut libc::c_void,
                        iov_len: desc.len() as libc::size_t,
                    };
                    iovecs.push(iovec);
                } else {
                    error!(
                        "Invalid descriptor chain: address = 0x{:x} length = {} write_only = {}",
                        desc_addr.0,
                        desc.len(),
                        desc.is_write_only()
                    );
                    return Err(NetQueuePairError::DescriptorChainInvalid);
                }
                next_desc = desc_chain.next();
            }

            let len = if !iovecs.is_empty() {
                // SAFETY: FFI call with correct arguments
                let result = unsafe {
                    libc::writev(
                        tap.as_raw_fd() as libc::c_int,
                        iovecs.as_ptr(),
                        iovecs.len() as libc::c_int,
                    )
                };

                if result < 0 {
                    let e = std::io::Error::last_os_error();

                    /* EAGAIN */
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        queue.go_to_previous_position();
                        retry_write = true;
                        break;
                    }
                    error!("net: tx: failed writing to tap: {}", e);
                    return Err(NetQueuePairError::WriteTap(e));
                }

                if (result as usize) < vnet_hdr_len() {
                    return Err(NetQueuePairError::InvalidVirtioNetHeader);
                }

                self.counter_bytes += Wrapping(result as u64 - vnet_hdr_len() as u64);
                self.counter_frames += Wrapping(1);

                result as u32
            } else {
                0
            };

            // For the sake of simplicity (similar to the RX rate limiting), we always
            // let the 'last' descriptor chain go-through even if it was over the rate
            // limit, and simply stop processing oncoming `avail_desc` if any.
            if let Some(rate_limiter) = rate_limiter {
                rate_limit_reached = !rate_limiter.consume(1, TokenType::Ops)
                    || !rate_limiter.consume(len as u64, TokenType::Bytes);
            }

            queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                .map_err(NetQueuePairError::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(NetQueuePairError::QueueEnableNotification)?
            {
                break;
            }
        }

        Ok(retry_write)
    }
}

#[derive(Clone)]
pub struct RxVirtio {
    pub counter_bytes: Wrapping<u64>,
    pub counter_frames: Wrapping<u64>,
    iovecs: IovecBuffer,
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
            iovecs: IovecBuffer::new(),
        }
    }

    pub fn process_desc_chain<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        tap: &Tap,
        queue: &mut Queue,
        rate_limiter: &mut Option<RateLimiter>,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
    ) -> Result<bool, NetQueuePairError> {
        let mut exhausted_descs = true;
        let mut rate_limit_reached = false;

        while let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) {
            if rate_limit_reached {
                exhausted_descs = false;
                queue.go_to_previous_position();
                break;
            }

            let desc = desc_chain
                .next()
                .ok_or(NetQueuePairError::DescriptorChainTooShort)?;

            let num_buffers_addr = desc_chain
                .memory()
                .checked_offset(
                    desc.addr()
                        .translate_gva(access_platform, desc.len() as usize),
                    10,
                )
                .ok_or(NetQueuePairError::DescriptorInvalidHeader)?;
            let mut next_desc = Some(desc);

            let mut iovecs = self.iovecs.borrow();
            while let Some(desc) = next_desc {
                let desc_addr = desc
                    .addr()
                    .translate_gva(access_platform, desc.len() as usize);
                if desc.is_write_only() && desc.len() > 0 {
                    let buf = desc_chain
                        .memory()
                        .get_slice(desc_addr, desc.len() as usize)
                        .map_err(NetQueuePairError::GuestMemory)?
                        .ptr_guard_mut();
                    let iovec = libc::iovec {
                        iov_base: buf.as_ptr() as *mut libc::c_void,
                        iov_len: desc.len() as libc::size_t,
                    };
                    iovecs.push(iovec);
                } else {
                    error!(
                        "Invalid descriptor chain: address = 0x{:x} length = {} write_only = {}",
                        desc_addr.0,
                        desc.len(),
                        desc.is_write_only()
                    );
                    return Err(NetQueuePairError::DescriptorChainInvalid);
                }
                next_desc = desc_chain.next();
            }

            let len = if !iovecs.is_empty() {
                // SAFETY: FFI call with correct arguments
                let result = unsafe {
                    libc::readv(
                        tap.as_raw_fd() as libc::c_int,
                        iovecs.as_ptr(),
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

                if (result as usize) < vnet_hdr_len() {
                    return Err(NetQueuePairError::InvalidVirtioNetHeader);
                }

                // Write num_buffers to guest memory. We simply write 1 as we
                // never spread the frame over more than one descriptor chain.
                desc_chain
                    .memory()
                    .write_obj(1u16, num_buffers_addr)
                    .map_err(NetQueuePairError::GuestMemory)?;

                self.counter_bytes += Wrapping(result as u64 - vnet_hdr_len() as u64);
                self.counter_frames += Wrapping(1);

                result as u32
            } else {
                0
            };

            // For the sake of simplicity (keeping the handling of RX_QUEUE_EVENT and
            // RX_TAP_EVENT totally asynchronous), we always let the 'last' descriptor
            // chain go-through even if it was over the rate limit, and simply stop
            // processing oncoming `avail_desc` if any.
            if let Some(rate_limiter) = rate_limiter {
                rate_limit_reached = !rate_limiter.consume(1, TokenType::Ops)
                    || !rate_limiter.consume(len as u64, TokenType::Bytes);
            }

            queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                .map_err(NetQueuePairError::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(NetQueuePairError::QueueEnableNotification)?
            {
                break;
            }
        }

        Ok(exhausted_descs)
    }
}

#[derive(Default, Clone)]
struct IovecBuffer(Vec<libc::iovec>);

// SAFETY: Implementing Send for IovecBuffer is safe as the pointer inside is iovec.
// The iovecs are usually constructed from virtio descriptors, which are safe to send across
// threads.
unsafe impl Send for IovecBuffer {}
// SAFETY: Implementing Sync for IovecBuffer is safe as the pointer inside is iovec.
// The iovecs are usually constructed from virtio descriptors, which are safe to access from
// multiple threads.
unsafe impl Sync for IovecBuffer {}

impl IovecBuffer {
    fn new() -> Self {
        // Here we use 4 as the default capacity because it is enough for most cases.
        const DEFAULT_CAPACITY: usize = 4;
        IovecBuffer(Vec::with_capacity(DEFAULT_CAPACITY))
    }

    fn borrow(&mut self) -> IovecBufferBorrowed<'_> {
        IovecBufferBorrowed(&mut self.0)
    }
}

struct IovecBufferBorrowed<'a>(&'a mut Vec<libc::iovec>);

impl std::ops::Deref for IovecBufferBorrowed<'_> {
    type Target = Vec<libc::iovec>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for IovecBufferBorrowed<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl Drop for IovecBufferBorrowed<'_> {
    fn drop(&mut self) {
        // Clear the buffer to make sure old values are not used after
        self.0.clear();
    }
}

#[derive(Default, Clone)]
pub struct NetCounters {
    pub tx_bytes: Arc<AtomicU64>,
    pub tx_frames: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
    pub rx_frames: Arc<AtomicU64>,
}

#[derive(Error, Debug)]
pub enum NetQueuePairError {
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Error registering listener")]
    RegisterListener(#[source] io::Error),
    #[error("Error unregistering listener")]
    UnregisterListener(#[source] io::Error),
    #[error("Error writing to the TAP device")]
    WriteTap(#[source] io::Error),
    #[error("Error reading from the TAP device")]
    ReadTap(#[source] io::Error),
    #[error("Error related to guest memory")]
    GuestMemory(#[source] vm_memory::GuestMemoryError),
    #[error("Returned an error while iterating through the queue")]
    QueueIteratorFailed(#[source] virtio_queue::Error),
    #[error("Descriptor chain is too short")]
    DescriptorChainTooShort,
    #[error("Descriptor chain does not contain valid descriptors")]
    DescriptorChainInvalid,
    #[error("Failed to determine if queue needed notification")]
    QueueNeedsNotification(#[source] virtio_queue::Error),
    #[error("Failed to enable notification on the queue")]
    QueueEnableNotification(#[source] virtio_queue::Error),
    #[error("Failed to add used index to the queue")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Descriptor with invalid virtio-net header")]
    DescriptorInvalidHeader,
    #[error("Invalid virtio-net header")]
    InvalidVirtioNetHeader,
}

pub struct NetQueuePair {
    pub tap: Tap,
    // With epoll each FD must be unique. So in order to filter the
    // events we need to get a second FD responding to the original
    // device so that we can send EPOLLOUT and EPOLLIN to separate
    // events.
    pub tap_for_write_epoll: Tap,
    pub rx: RxVirtio,
    pub tx: TxVirtio,
    pub epoll_fd: Option<RawFd>,
    pub rx_tap_listening: bool,
    pub tx_tap_listening: bool,
    pub counters: NetCounters,
    pub tap_rx_event_id: u16,
    pub tap_tx_event_id: u16,
    pub rx_desc_avail: bool,
    pub rx_rate_limiter: Option<RateLimiter>,
    pub tx_rate_limiter: Option<RateLimiter>,
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl NetQueuePair {
    pub fn process_tx<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        queue: &mut Queue,
    ) -> Result<bool, NetQueuePairError> {
        let tx_tap_retry = self.tx.process_desc_chain(
            mem,
            &self.tap,
            queue,
            &mut self.tx_rate_limiter,
            self.access_platform.as_ref(),
        )?;

        // We got told to try again when writing to the tap. Wait for the TAP to be writable
        if tx_tap_retry && !self.tx_tap_listening {
            register_listener(
                self.epoll_fd.unwrap(),
                self.tap_for_write_epoll.as_raw_fd(),
                epoll::Events::EPOLLOUT,
                u64::from(self.tap_tx_event_id),
            )
            .map_err(NetQueuePairError::RegisterListener)?;
            self.tx_tap_listening = true;
            info!("Writing to TAP returned EAGAIN. Listening for TAP to become writable.");
        } else if !tx_tap_retry && self.tx_tap_listening {
            unregister_listener(
                self.epoll_fd.unwrap(),
                self.tap_for_write_epoll.as_raw_fd(),
                epoll::Events::EPOLLOUT,
                u64::from(self.tap_tx_event_id),
            )
            .map_err(NetQueuePairError::UnregisterListener)?;
            self.tx_tap_listening = false;
            info!("Writing to TAP succeeded. No longer listening for TAP to become writable.");
        }

        self.counters
            .tx_bytes
            .fetch_add(self.tx.counter_bytes.0, Ordering::AcqRel);
        self.counters
            .tx_frames
            .fetch_add(self.tx.counter_frames.0, Ordering::AcqRel);
        self.tx.counter_bytes = Wrapping(0);
        self.tx.counter_frames = Wrapping(0);

        queue
            .needs_notification(mem)
            .map_err(NetQueuePairError::QueueNeedsNotification)
    }

    pub fn process_rx<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        queue: &mut Queue,
    ) -> Result<bool, NetQueuePairError> {
        self.rx_desc_avail = !self.rx.process_desc_chain(
            mem,
            &self.tap,
            queue,
            &mut self.rx_rate_limiter,
            self.access_platform.as_ref(),
        )?;
        let rate_limit_reached = self
            .rx_rate_limiter
            .as_ref()
            .is_some_and(|r| r.is_blocked());

        // Stop listening on the `RX_TAP_EVENT` when:
        // 1) there is no available describes, or
        // 2) the RX rate limit is reached.
        if self.rx_tap_listening && (!self.rx_desc_avail || rate_limit_reached) {
            unregister_listener(
                self.epoll_fd.unwrap(),
                self.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.tap_rx_event_id),
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

        queue
            .needs_notification(mem)
            .map_err(NetQueuePairError::QueueNeedsNotification)
    }
}
