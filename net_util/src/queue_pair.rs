// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io;
use std::num::Wrapping;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use log::{debug, error, info};
use rate_limiter::{RateLimiter, TokenType};
use smallvec::SmallVec;
use thiserror::Error;
use virtio_bindings::virtio_net::{
    VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, virtio_net_hdr_v1,
};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::bitmap::Bitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend};
use vm_virtio::{AccessPlatform, Translatable};

use super::{Tap, register_listener, unregister_listener, vnet_hdr_len};

/// Linux sets MAX_SKB_FRAGS + 2 descriptors per RX chain when guest offloads
/// are on and mergeable RX buffers are off, as with this device [0, 1, 2].
///
/// [0]: https://elixir.bootlin.com/linux/v7.2/source/include/linux/skbuff.h#L354
/// [1]: https://elixir.bootlin.com/linux/v7.2/source/drivers/net/virtio_net.c#L6695
/// [2]: https://elixir.bootlin.com/linux/v7.2/source/drivers/net/virtio_net.c#L2647
const RX_CHAIN_INLINE_DESCS: usize = 19;

#[derive(Clone)]
pub struct TxVirtio {
    pub counter_bytes: Wrapping<u64>,
    pub counter_frames: Wrapping<u64>,
    iovecs: IovecBuffer,
    host_checksum_offload: bool,
}

impl TxVirtio {
    /// Create a TX queue with the negotiated VIRTIO_NET_F_CSUM policy.
    pub fn new(host_checksum_offload: bool) -> Self {
        TxVirtio {
            counter_bytes: Wrapping(0),
            counter_frames: Wrapping(0),
            iovecs: IovecBuffer::new(),
            host_checksum_offload,
        }
    }

    pub fn set_host_checksum_offload(&mut self, host_checksum_offload: bool) {
        self.host_checksum_offload = host_checksum_offload;
    }

    fn tx_is_header_valid(
        header: &[u8; size_of::<virtio_net_hdr_v1>()],
        header_len: usize,
        host_checksum_offload: bool,
    ) -> bool {
        // Segmentation offloads also require checksum offload support.
        header_len == header.len()
            && (host_checksum_offload
                || (u32::from(header[0]) & VIRTIO_NET_HDR_F_NEEDS_CSUM == 0
                    && u32::from(header[1]) == VIRTIO_NET_HDR_GSO_NONE))
    }

    pub fn process_desc_chain<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        tap: &Tap,
        queue: &mut Queue,
        rate_limiter: &mut Option<RateLimiter>,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<bool, NetQueuePairError> {
        let mut retry_write = false;
        let mut rate_limit_reached = false;

        loop {
            let mut iter = queue
                .iter(mem)
                .map_err(NetQueuePairError::QueueIteratorFailed)?;
            let Some(mut desc_chain) = iter.next() else {
                break;
            };
            if rate_limit_reached {
                queue.go_to_previous_position();
                break;
            }

            let mut next_desc = desc_chain.next();

            let mut header = [0u8; size_of::<virtio_net_hdr_v1>()];
            let mut header_len = 0;
            let mut iovecs = self.iovecs.borrow();
            // Parse the descriptor chain into an iovec array. On error, the
            // offending head descriptor is still added to the used ring with
            // len 0 below, so the guest does not see a descriptor leak.
            let parse_result: Result<(), NetQueuePairError> = (|| {
                while let Some(desc) = next_desc {
                    let desc_addr = desc
                        .addr()
                        .translate_gva(access_platform, desc.len() as usize)
                        .map_err(|e| {
                            NetQueuePairError::GuestMemory(vm_memory::GuestMemoryError::IOError(e))
                        })?;
                    if !desc.is_write_only() && desc.len() > 0 {
                        let buf = desc_chain
                            .memory()
                            .get_slice(desc_addr, desc.len() as usize)
                            .map_err(NetQueuePairError::GuestMemory)?;
                        assert!(buf.len() >= desc.len() as usize);
                        // Copy the header because the guest can modify its buffers
                        // between validation and the TAP write.
                        let copied = buf.copy_to(&mut header[header_len..]);
                        header_len += copied;
                        let buf = buf.ptr_guard_mut();
                        if copied < desc.len() as usize {
                            iovecs.push(libc::iovec {
                                iov_base: buf.as_ptr().wrapping_add(copied).cast(),
                                iov_len: desc.len() as libc::size_t - copied,
                            });
                        }
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
                Ok(())
            })();

            if let Err(e) = parse_result {
                // Surface the bad descriptor to the guest with len 0 so the
                // used ring stays consistent before bailing.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
                    .map_err(NetQueuePairError::QueueAddUsed)?;
                return Err(e);
            }

            if Self::tx_is_header_valid(&header, header_len, self.host_checksum_offload) {
                iovecs.insert(
                    0,
                    libc::iovec {
                        iov_base: header.as_mut_ptr().cast(),
                        iov_len: header.len(),
                    },
                );
            } else {
                // Do not send invalid guest packets to TAP.
                debug!("Dropping TX packets due to invalid header");
                iovecs.clear();
            }

            let bytes_sent = if iovecs.is_empty() {
                0
            } else {
                // SAFETY: The iovecs refer to checked guest memory ranges and
                // the private header. All remain valid for the duration of the write.
                let result = unsafe {
                    libc::writev(
                        tap.as_raw_fd() as libc::c_int,
                        iovecs.as_ptr(),
                        iovecs.len() as libc::c_int,
                    )
                };

                if result < 0 {
                    let e = io::Error::last_os_error();

                    /* EAGAIN */
                    if e.kind() == io::ErrorKind::WouldBlock {
                        queue.go_to_previous_position();
                        retry_write = true;
                        break;
                    }

                    if e.raw_os_error() == Some(libc::EINVAL) {
                        error!("net: tx: dropping malformed packet: {e}");
                        0
                    } else if e.raw_os_error() == Some(libc::EIO) {
                        error!("net: tx: dropping frame, tap I/O error: {e}");
                        0
                    } else {
                        error!("net: tx: failed writing to tap: {e}");
                        return Err(NetQueuePairError::WriteTap(e));
                    }
                } else if (result as usize) < vnet_hdr_len() {
                    error!("net: tx: short tap write ({result} < {})", vnet_hdr_len());
                    0
                } else {
                    self.counter_bytes += Wrapping(result as u64 - vnet_hdr_len() as u64);
                    self.counter_frames += Wrapping(1);

                    result as u64
                }
            };

            // For the sake of simplicity (similar to the RX rate limiting), we always
            // let the 'last' descriptor chain go-through even if it was over the rate
            // limit, and simply stop processing oncoming `avail_desc` if any.
            if let Some(rate_limiter) = rate_limiter {
                rate_limit_reached = !rate_limiter.consume(1, TokenType::Ops)
                    || !rate_limiter.consume(bytes_sent, TokenType::Bytes);
            }

            // TX descriptors are device-readable only; the device wrote
            // nothing back to guest memory, so per the virtio spec the used
            // length is 0.
            queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
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

    pub fn process_desc_chain<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        tap: &Tap,
        queue: &mut Queue,
        rate_limiter: &mut Option<RateLimiter>,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<bool, NetQueuePairError> {
        let mut exhausted_descs = true;
        let mut rate_limit_reached = false;

        loop {
            let mut iter = queue
                .iter(mem)
                .map_err(NetQueuePairError::QueueIteratorFailed)?;
            let Some(mut desc_chain) = iter.next() else {
                break;
            };
            if rate_limit_reached {
                exhausted_descs = false;
                queue.go_to_previous_position();
                break;
            }

            // Ranges for translation into host iovecs and for dirty tracking after readv()
            let mut guest_ranges: SmallVec<[(GuestAddress, usize); RX_CHAIN_INLINE_DESCS]> =
                SmallVec::new();
            let mut iovecs: SmallVec<[libc::iovec; RX_CHAIN_INLINE_DESCS]> = SmallVec::new();

            // Parse the descriptor chain into an iovec array. On error, the
            // offending head descriptor is still added to the used ring with
            // len 0 below, so the guest does not see a descriptor leak.
            let parse_result: Result<GuestAddress, NetQueuePairError> = (|| {
                let desc = desc_chain
                    .next()
                    .ok_or(NetQueuePairError::DescriptorChainTooShort)?;

                let num_buffers_addr = desc_chain
                    .memory()
                    .checked_offset(
                        desc.addr()
                            .translate_gva(access_platform, vnet_hdr_len())
                            .map_err(|e| {
                                NetQueuePairError::GuestMemory(
                                    vm_memory::GuestMemoryError::IOError(e),
                                )
                            })?,
                        10,
                    )
                    .ok_or(NetQueuePairError::DescriptorInvalidHeader)?;
                let mut next_desc = Some(desc);

                while let Some(desc) = next_desc {
                    let desc_addr = desc
                        .addr()
                        .translate_gva(access_platform, desc.len() as usize)
                        .map_err(|e| {
                            NetQueuePairError::GuestMemory(vm_memory::GuestMemoryError::IOError(e))
                        })?;
                    if desc.is_write_only() && desc.len() > 0 {
                        guest_ranges.push((desc_addr, desc.len() as usize));
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

                // Translate guest_ranges into host_iovecs.
                for (addr, len) in &guest_ranges {
                    let buf = desc_chain
                        .memory()
                        .get_slice(*addr, *len)
                        .map_err(NetQueuePairError::GuestMemory)?;
                    assert!(buf.len() >= *len);
                    let buf = buf.ptr_guard_mut();
                    iovecs.push(libc::iovec {
                        iov_base: buf.as_ptr().cast(),
                        iov_len: *len,
                    });
                }
                Ok(num_buffers_addr)
            })();

            let num_buffers_addr = match parse_result {
                Ok(addr) => addr,
                Err(e) => {
                    queue
                        .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
                        .map_err(NetQueuePairError::QueueAddUsed)?;
                    return Err(e);
                }
            };

            let len = if iovecs.is_empty() {
                0
            } else {
                // SAFETY: FFI call with correct arguments
                let result = unsafe {
                    libc::readv(
                        tap.as_raw_fd() as libc::c_int,
                        iovecs.as_ptr(),
                        iovecs.len() as libc::c_int,
                    )
                };
                if result < 0 {
                    let e = io::Error::last_os_error();

                    /* EAGAIN */
                    if e.kind() == io::ErrorKind::WouldBlock {
                        exhausted_descs = false;
                        queue.go_to_previous_position();
                        break;
                    }

                    if e.raw_os_error() == Some(libc::EINVAL) {
                        error!("net: rx: dropping undersized buffer: {e}");
                        desc_chain
                            .memory()
                            .write_obj(0u16, num_buffers_addr)
                            .map_err(NetQueuePairError::GuestMemory)?;
                        0
                    } else {
                        queue.go_to_previous_position();
                        error!("net: rx: failed reading from tap: {e}");
                        return Err(NetQueuePairError::ReadTap(e));
                    }
                } else if (result as usize) < vnet_hdr_len() {
                    error!(
                        "net: rx: buffer too short for virtio_net_hdr ({result} < {})",
                        vnet_hdr_len()
                    );
                    desc_chain
                        .memory()
                        .write_obj(0u16, num_buffers_addr)
                        .map_err(NetQueuePairError::GuestMemory)?;
                    0
                } else {
                    // readv() bypasses dirty bitmap. Update the touched pages manually
                    let mut remaining = result as usize;
                    for (addr, len) in &guest_ranges {
                        if *len == 0 {
                            continue;
                        }
                        if remaining == 0 {
                            break;
                        }
                        let n = remaining.min(*len);
                        if let Ok(buf) = desc_chain.memory().get_slice(*addr, n) {
                            buf.bitmap().mark_dirty(0, n);
                        }
                        remaining -= n;
                    }

                    // Write num_buffers to guest memory. Always 1 because the
                    // frame is never spread over more than one descriptor chain.
                    if let Err(e) = desc_chain.memory().write_obj(1u16, num_buffers_addr) {
                        // Surface the bad descriptor to the guest with len 0 so
                        // the used ring stays consistent before bailing.
                        queue
                            .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
                            .map_err(NetQueuePairError::QueueAddUsed)?;
                        return Err(NetQueuePairError::GuestMemory(e));
                    }

                    self.counter_bytes += Wrapping(result as u64 - vnet_hdr_len() as u64);
                    self.counter_frames += Wrapping(1);

                    result as u32
                }
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

impl Deref for IovecBufferBorrowed<'_> {
    type Target = Vec<libc::iovec>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for IovecBufferBorrowed<'_> {
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
            self.access_platform.as_deref(),
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
            self.access_platform.as_deref(),
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

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;

    use virtio_bindings::virtio_net::{VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_GSO_TCPV4};
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::desc::RawDescriptor;
    use virtio_queue::desc::split::Descriptor;
    use virtio_queue::mock::MockSplitQueue;
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{GuestMemoryMmap, GuestMemoryRegion};

    use super::*;

    #[test]
    fn tx_header_must_be_complete() {
        let header = [0; size_of::<virtio_net_hdr_v1>()];
        let len = header.len();
        assert!(!TxVirtio::tx_is_header_valid(&header, len - 1, true));
        assert!(!TxVirtio::tx_is_header_valid(&header, len - 1, false));
        assert!(TxVirtio::tx_is_header_valid(&header, len, false));
    }

    #[test]
    fn tx_header_respects_checksum_offload() {
        let mut header = [0; size_of::<virtio_net_hdr_v1>()];
        let len = header.len();
        header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM as u8;
        assert!(!TxVirtio::tx_is_header_valid(&header, len, false));
        assert!(TxVirtio::tx_is_header_valid(&header, len, true));

        header[0] = VIRTIO_NET_HDR_F_DATA_VALID as u8;
        assert!(TxVirtio::tx_is_header_valid(&header, len, false));

        header[1] = VIRTIO_NET_HDR_GSO_TCPV4 as u8;
        assert!(!TxVirtio::tx_is_header_valid(&header, len, false));
        assert!(TxVirtio::tx_is_header_valid(&header, len, true));
    }

    #[test]
    fn rx_marks_all_written_pages_dirty() {
        const BUF0: u64 = 0x10000;
        const BUF1: u64 = 0x20000;
        const FILL: u8 = 0xab;

        let mem =
            GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        // One RX chain: one page at BUF0, two pages at BUF1
        let vq = MockSplitQueue::new(&mem, 16);
        vq.add_desc_chains(
            &[
                RawDescriptor::from(Descriptor::new(
                    BUF0,
                    0x1000,
                    (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                    1,
                )),
                RawDescriptor::from(Descriptor::new(BUF1, 0x2000, VRING_DESC_F_WRITE as u16, 0)),
            ],
            0,
        )
        .unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();
        // A frame that spills from the first buffer into the second one
        let tap = {
            let (tx, rx) = UnixDatagram::pair().unwrap();
            rx.set_nonblocking(true).unwrap();
            tx.send(&[FILL; 6000]).unwrap();
            Tap::new_for_fuzzing(File::from(OwnedFd::from(rx)), "test")
        };

        // readv() writes into guest memory through raw pointers, which the
        // vm-memory dirty bitmap cannot see. The device must mark those bytes
        // itself, or a live migration never resends them.
        RxVirtio::new()
            .process_desc_chain(&mem, &tap, &mut queue, &mut None, None)
            .unwrap();

        // readv() fills BUF0 (4096 bytes) and spills the remaining 1904 bytes into BUF1
        assert_eq!(mem.read_obj::<u8>(GuestAddress(BUF1 + 100)).unwrap(), FILL);
        let bitmap = mem.find_region(GuestAddress(0)).unwrap().bitmap();
        assert!(bitmap.dirty_at(BUF0 as usize));
        assert!(bitmap.dirty_at(BUF1 as usize));
        // Only 6000 - 4096 bytes were written to the second buffer
        assert!(!bitmap.dirty_at(BUF1 as usize + 0x1000));
    }
}
