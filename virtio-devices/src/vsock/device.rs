// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::{VsockBackend, VsockPacket};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::Error as DeviceError;
use crate::VirtioInterrupt;
use crate::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
    VIRTIO_F_IN_ORDER, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use anyhow::anyhow;
/// This is the `VirtioDevice` implementation for our vsock device. It handles the virtio-level
/// device logic: feature negotiation, device configuration, and device activation.
/// The run-time device logic (i.e. event-driven data handling) is implemented by
/// `super::epoll_handler::EpollHandler`.
///
/// We aim to conform to the VirtIO v1.1 spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html
///
/// The vsock device has two input parameters: a CID to identify the device, and a `VsockBackend`
/// to use for offloading vsock traffic.
///
/// Upon its activation, the vsock device creates its `EpollHandler`, passes it the event-interested
/// file descriptors, and registers these descriptors with the VMM `EpollContext`. Going forward,
/// the `EpollHandler` will get notified whenever an event occurs on the just-registered FDs:
/// - an RX queue FD;
/// - a TX queue FD;
/// - an event queue FD; and
/// - a backend FD.
///
use byteorder::{ByteOrder, LittleEndian};
use seccomp::{SeccompAction, SeccompFilter};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, RwLock};
use std::thread;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 3;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// New descriptors are pending on the rx queue.
pub const RX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New descriptors are pending on the tx queue.
pub const TX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// New descriptors are pending on the event queue.
pub const EVT_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// Notification coming from the backend.
pub const BACKEND_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;

/// The `VsockEpollHandler` implements the runtime logic of our vsock device:
/// 1. Respond to TX queue events by wrapping virtio buffers into `VsockPacket`s, then sending those
///    packets to the `VsockBackend`;
/// 2. Forward backend FD event notifications to the `VsockBackend`;
/// 3. Fetch incoming packets from the `VsockBackend` and place them into the virtio RX queue;
/// 4. Whenever we have processed some virtio buffers (either TX or RX), let the driver know by
///    raising our assigned IRQ.
///
/// In a nutshell, the `VsockEpollHandler` logic looks like this:
/// - on TX queue event:
///   - fetch all packets from the TX queue and send them to the backend; then
///   - if the backend has queued up any incoming packets, fetch them into any available RX buffers.
/// - on RX queue event:
///   - fetch any incoming packets, queued up by the backend, into newly available RX buffers.
/// - on backend event:
///   - forward the event to the backend; then
///   - again, attempt to fetch any incoming packets queued by the backend into virtio RX buffers.
///
pub struct VsockEpollHandler<B: VsockBackend> {
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub queues: Vec<Queue>,
    pub queue_evts: Vec<EventFd>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub backend: Arc<RwLock<B>>,
}

impl<B> VsockEpollHandler<B>
where
    B: VsockBackend,
{
    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    ///
    fn signal_used_queue(&self, queue: &Queue) -> result::Result<(), DeviceError> {
        debug!("vsock: raising IRQ");

        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(queue))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending.
    ///
    fn process_rx(&mut self) -> result::Result<(), DeviceError> {
        debug!("vsock: epoll_handler::process_rx()");

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in self.queues[0].iter(&mem) {
            let used_len = match VsockPacket::from_rx_virtq_head(&avail_desc) {
                Ok(mut pkt) => {
                    if self.backend.write().unwrap().recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        self.queues[0].go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            used_desc_heads[used_count] = (avail_desc.index, used_len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queues[0].add_used(&mem, desc_index, len);
        }

        if used_count > 0 {
            self.signal_used_queue(&self.queues[0])
        } else {
            Ok(())
        }
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them to
    /// the backend for processing.
    ///
    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        debug!("vsock: epoll_handler::process_tx()");

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in self.queues[1].iter(&mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&avail_desc) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("vsock: error reading TX packet: {:?}", e);
                    used_desc_heads[used_count] = (avail_desc.index, 0);
                    used_count += 1;
                    continue;
                }
            };

            if self.backend.write().unwrap().send_pkt(&pkt).is_err() {
                self.queues[1].go_to_previous_position();
                break;
            }

            used_desc_heads[used_count] = (avail_desc.index, 0);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queues[1].add_used(&mem, desc_index, len);
        }

        if used_count > 0 {
            self.signal_used_queue(&self.queues[1])
        } else {
            Ok(())
        }
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evts[0].as_raw_fd(), RX_QUEUE_EVENT)?;
        helper.add_event(self.queue_evts[1].as_raw_fd(), TX_QUEUE_EVENT)?;
        helper.add_event(self.queue_evts[2].as_raw_fd(), EVT_QUEUE_EVENT)?;
        helper.add_event(self.backend.read().unwrap().get_polled_fd(), BACKEND_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl<B> EpollHelperHandler for VsockEpollHandler<B>
where
    B: VsockBackend,
{
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let evset = match epoll::Events::from_bits(event.events) {
            Some(evset) => evset,
            None => {
                let evbits = event.events;
                warn!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                return false;
            }
        };

        let ev_type = event.data as u16;
        match ev_type {
            RX_QUEUE_EVENT => {
                debug!("vsock: RX queue event");
                if let Err(e) = self.queue_evts[0].read() {
                    error!("Failed to get RX queue event: {:?}", e);
                    return true;
                } else if self.backend.read().unwrap().has_pending_rx() {
                    if let Err(e) = self.process_rx() {
                        error!("Failed to process RX queue: {:?}", e);
                        return true;
                    }
                }
            }
            TX_QUEUE_EVENT => {
                debug!("vsock: TX queue event");
                if let Err(e) = self.queue_evts[1].read() {
                    error!("Failed to get TX queue event: {:?}", e);
                    return true;
                } else {
                    if let Err(e) = self.process_tx() {
                        error!("Failed to process TX queue: {:?}", e);
                        return true;
                    }
                    // The backend may have queued up responses to the packets we sent during TX queue
                    // processing. If that happened, we need to fetch those responses and place them
                    // into RX buffers.
                    if self.backend.read().unwrap().has_pending_rx() {
                        if let Err(e) = self.process_rx() {
                            error!("Failed to process RX queue: {:?}", e);
                            return true;
                        }
                    }
                }
            }
            EVT_QUEUE_EVENT => {
                debug!("vsock: EVT queue event");
                if let Err(e) = self.queue_evts[2].read() {
                    error!("Failed to get EVT queue event: {:?}", e);
                    return true;
                }
            }
            BACKEND_EVENT => {
                debug!("vsock: backend event");
                self.backend.write().unwrap().notify(evset);
                // After the backend has been kicked, it might've freed up some resources, so we
                // can attempt to send it more data to process.
                // In particular, if `self.backend.send_pkt()` halted the TX queue processing (by
                // returning an error) at some point in the past, now is the time to try walking the
                // TX queue again.
                if let Err(e) = self.process_tx() {
                    error!("Failed to process TX queue: {:?}", e);
                    return true;
                }
                if self.backend.read().unwrap().has_pending_rx() {
                    if let Err(e) = self.process_rx() {
                        error!("Failed to process RX queue: {:?}", e);
                        return true;
                    }
                }
            }
            _ => {
                error!("Unknown event for virtio-vsock");
                return true;
            }
        }

        false
    }
}

/// Virtio device exposing virtual socket to the guest.
pub struct Vsock<B: VsockBackend> {
    common: VirtioCommon,
    id: String,
    cid: u64,
    backend: Arc<RwLock<B>>,
    path: PathBuf,
    seccomp_action: SeccompAction,
}

#[derive(Serialize, Deserialize)]
pub struct VsockState {
    pub avail_features: u64,
    pub acked_features: u64,
}

impl<B> Vsock<B>
where
    B: VsockBackend,
{
    /// Create a new virtio-vsock device with the given VM CID and vsock
    /// backend.
    pub fn new(
        id: String,
        cid: u64,
        path: PathBuf,
        backend: B,
        iommu: bool,
        seccomp_action: SeccompAction,
    ) -> io::Result<Vsock<B>> {
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_F_IN_ORDER;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        Ok(Vsock {
            common: VirtioCommon {
                device_type: VirtioDeviceType::TYPE_VSOCK as u32,
                avail_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes: QUEUE_SIZES.to_vec(),
                min_queues: NUM_QUEUES as u16,
                ..Default::default()
            },
            id,
            cid,
            backend: Arc::new(RwLock::new(backend)),
            path,
            seccomp_action,
        })
    }

    fn state(&self) -> VsockState {
        VsockState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
        }
    }

    fn set_state(&mut self, state: &VsockState) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
    }
}

impl<B> Drop for Vsock<B>
where
    B: VsockBackend,
{
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl<B> VirtioDevice for Vsock<B>
where
    B: VsockBackend + Sync + 'static,
{
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
        match offset {
            0 if data.len() == 8 => LittleEndian::write_u64(data, self.cid),
            0 if data.len() == 4 => LittleEndian::write_u32(data, (self.cid & 0xffff_ffff) as u32),
            4 if data.len() == 4 => {
                LittleEndian::write_u32(data, ((self.cid >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let kill_evt = self
            .common
            .kill_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("failed to clone kill_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;
        let pause_evt = self
            .common
            .pause_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("failed to clone pause_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;

        let mut handler = VsockEpollHandler {
            mem,
            queues,
            queue_evts,
            kill_evt,
            pause_evt,
            interrupt_cb,
            backend: self.backend.clone(),
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        // Retrieve seccomp filter for virtio_vsock thread
        let virtio_vsock_seccomp_filter =
            get_seccomp_filter(&self.seccomp_action, Thread::VirtioVsock)
                .map_err(ActivateError::CreateSeccompFilter)?;
        thread::Builder::new()
            .name(self.id.clone())
            .spawn(move || {
                if let Err(e) = SeccompFilter::apply(virtio_vsock_seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running worker: {:?}", e);
                }
            })
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone the vsock epoll thread: {}", e);
                ActivateError::BadActivate
            })?;

        self.common.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        self.common.reset()
    }

    fn shutdown(&mut self) {
        std::fs::remove_file(&self.path).ok();
    }
}

impl<B> Pausable for Vsock<B>
where
    B: VsockBackend + Sync + 'static,
{
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl<B> Snapshottable for Vsock<B>
where
    B: VsockBackend + Sync + 'static,
{
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut vsock_snapshot = Snapshot::new(self.id.as_str());
        vsock_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(vsock_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(vsock_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id)) {
            let vsock_state = match serde_json::from_slice(&vsock_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize VSOCK {}",
                        error
                    )))
                }
            };

            self.set_state(&vsock_state);
            return Ok(());
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find VSOCK snapshot section"
        )))
    }
}
impl<B> Transportable for Vsock<B> where B: VsockBackend + Sync + 'static {}
impl<B> Migratable for Vsock<B> where B: VsockBackend + Sync + 'static {}

#[cfg(test)]
mod tests {
    use super::super::tests::{NoopVirtioInterrupt, TestContext};
    use super::super::*;
    use super::*;
    use crate::vsock::device::{BACKEND_EVENT, EVT_QUEUE_EVENT, RX_QUEUE_EVENT, TX_QUEUE_EVENT};
    use libc::EFD_NONBLOCK;

    #[test]
    fn test_virtio_device() {
        let mut ctx = TestContext::new();
        let avail_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_F_IN_ORDER;
        let device_features = avail_features;
        let driver_features: u64 = avail_features | 1 | (1 << 32);
        let device_pages = [
            (device_features & 0xffff_ffff) as u32,
            (device_features >> 32) as u32,
        ];
        let driver_pages = [
            (driver_features & 0xffff_ffff) as u32,
            (driver_features >> 32) as u32,
        ];
        assert_eq!(
            ctx.device.device_type(),
            VirtioDeviceType::TYPE_VSOCK as u32
        );
        assert_eq!(ctx.device.queue_max_sizes(), QUEUE_SIZES);
        assert_eq!(ctx.device.features() as u32, device_pages[0]);
        assert_eq!((ctx.device.features() >> 32) as u32, device_pages[1]);

        // Ack device features, page 0.
        ctx.device.ack_features(u64::from(driver_pages[0]));
        // Ack device features, page 1.
        ctx.device.ack_features(u64::from(driver_pages[1]) << 32);
        // Check that no side effect are present, and that the acked features are exactly the same
        // as the device features.
        assert_eq!(
            ctx.device.common.acked_features,
            device_features & driver_features
        );

        // Test reading 32-bit chunks.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data[..4]);
        assert_eq!(
            u64::from(LittleEndian::read_u32(&data)),
            ctx.cid & 0xffff_ffff
        );
        ctx.device.read_config(4, &mut data[4..]);
        assert_eq!(
            u64::from(LittleEndian::read_u32(&data[4..])),
            (ctx.cid >> 32) & 0xffff_ffff
        );

        // Test reading 64-bit.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data);
        assert_eq!(LittleEndian::read_u64(&data), ctx.cid);

        // Check that out-of-bounds reading doesn't mutate the destination buffer.
        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ctx.device.read_config(2, &mut data);
        assert_eq!(data, [0u8, 1, 2, 3, 4, 5, 6, 7]);

        // Just covering lines here, since the vsock device has no writable config.
        // A warning is, however, logged, if the guest driver attempts to write any config data.
        ctx.device.write_config(0, &data[..4]);

        // Test a bad activation.
        let bad_activate = ctx.device.activate(
            GuestMemoryAtomic::new(ctx.mem.clone()),
            Arc::new(NoopVirtioInterrupt {}),
            Vec::new(),
            Vec::new(),
        );
        match bad_activate {
            Err(ActivateError::BadActivate) => (),
            other => panic!("{:?}", other),
        }

        // Test a correct activation.
        ctx.device
            .activate(
                GuestMemoryAtomic::new(ctx.mem.clone()),
                Arc::new(NoopVirtioInterrupt {}),
                vec![Queue::new(256), Queue::new(256), Queue::new(256)],
                vec![
                    EventFd::new(EFD_NONBLOCK).unwrap(),
                    EventFd::new(EFD_NONBLOCK).unwrap(),
                    EventFd::new(EFD_NONBLOCK).unwrap(),
                ],
            )
            .unwrap();
    }

    #[test]
    fn test_irq() {
        // Test case: successful IRQ signaling.
        {
            let test_ctx = TestContext::new();
            let ctx = test_ctx.create_epoll_handler_context();

            let queue = Queue::new(256);
            assert!(ctx.handler.signal_used_queue(&queue).is_ok());
        }
    }

    #[test]
    fn test_txq_event() {
        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend has no pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(false);
            ctx.signal_txq_event();

            // The available TX descriptor should have been used.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The available RX descriptor should be untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend also has some pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(true);
            ctx.signal_txq_event();

            // Both available RX and TX descriptors should have been used.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend errors out and cannot process the TX queue.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(false);
            ctx.handler
                .backend
                .write()
                .unwrap()
                .set_tx_err(Some(VsockError::NoData));
            ctx.signal_txq_event();

            // Both RX and TX queues should be untouched.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 0);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - the driver supplied a malformed TX buffer.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            // Invalidate the packet header descriptor, by setting its length to 0.
            ctx.guest_txvq.dtable[0].len.set(0);
            ctx.signal_txq_event();

            // The available descriptor should have been consumed, but no packet should have
            // reached the backend.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.handler.backend.read().unwrap().tx_ok_cnt, 0);
        }

        // Test case: spurious TXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            let events = epoll::Events::EPOLLIN;
            let event = epoll::Event::new(events, TX_QUEUE_EVENT as u64);
            let mut epoll_helper =
                EpollHelper::new(&ctx.handler.kill_evt, &ctx.handler.pause_evt).unwrap();

            if !ctx.handler.handle_event(&mut epoll_helper, &event) {
                panic!("handle_event() should have failed");
            }
        }
    }

    #[test]
    fn test_rxq_event() {
        // Test case:
        // - there is pending RX data in the backend; and
        // - the driver makes RX buffers available; and
        // - the backend successfully places its RX data into the queue.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(true);
            ctx.handler
                .backend
                .write()
                .unwrap()
                .set_rx_err(Some(VsockError::NoData));
            ctx.signal_rxq_event();

            // The available RX buffer should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - there is pending RX data in the backend; and
        // - the driver makes RX buffers available; and
        // - the backend errors out, when attempting to receive data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(true);
            ctx.signal_rxq_event();

            // The available RX buffer should have been used.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case: the driver provided a malformed RX descriptor chain.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            // Invalidate the packet header descriptor, by setting its length to 0.
            ctx.guest_rxvq.dtable[0].len.set(0);

            // The chain should've been processed, without employing the backend.
            assert!(ctx.handler.process_rx().is_ok());
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
            assert_eq!(ctx.handler.backend.read().unwrap().rx_ok_cnt, 0);
        }

        // Test case: spurious RXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();
            ctx.handler.backend.write().unwrap().set_pending_rx(false);

            let events = epoll::Events::EPOLLIN;
            let event = epoll::Event::new(events, RX_QUEUE_EVENT as u64);
            let mut epoll_helper =
                EpollHelper::new(&ctx.handler.kill_evt, &ctx.handler.pause_evt).unwrap();

            if !ctx.handler.handle_event(&mut epoll_helper, &event) {
                panic!("handle_event() should have failed");
            }
        }
    }

    #[test]
    fn test_evq_event() {
        // Test case: spurious EVQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();
            ctx.handler.backend.write().unwrap().set_pending_rx(false);

            let events = epoll::Events::EPOLLIN;
            let event = epoll::Event::new(events, EVT_QUEUE_EVENT as u64);
            let mut epoll_helper =
                EpollHelper::new(&ctx.handler.kill_evt, &ctx.handler.pause_evt).unwrap();

            if !ctx.handler.handle_event(&mut epoll_helper, &event) {
                panic!("handle_event() should have failed");
            }
        }
    }

    #[test]
    fn test_backend_event() {
        // Test case:
        // - a backend event is received; and
        // - the backend has pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(true);

            let events = epoll::Events::EPOLLIN;
            let event = epoll::Event::new(events, BACKEND_EVENT as u64);
            let mut epoll_helper =
                EpollHelper::new(&ctx.handler.kill_evt, &ctx.handler.pause_evt).unwrap();
            ctx.handler.handle_event(&mut epoll_helper, &event);

            // The backend should've received this event.
            assert_eq!(
                ctx.handler.backend.read().unwrap().evset,
                Some(epoll::Events::EPOLLIN)
            );
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // RX queue processing should've been triggered.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case:
        // - a backend event is received; and
        // - the backend doesn't have any pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_epoll_handler_context();

            ctx.handler.backend.write().unwrap().set_pending_rx(false);

            let events = epoll::Events::EPOLLIN;
            let event = epoll::Event::new(events, BACKEND_EVENT as u64);
            let mut epoll_helper =
                EpollHelper::new(&ctx.handler.kill_evt, &ctx.handler.pause_evt).unwrap();
            ctx.handler.handle_event(&mut epoll_helper, &event);

            // The backend should've received this event.
            assert_eq!(
                ctx.handler.backend.read().unwrap().evset,
                Some(epoll::Events::EPOLLIN)
            );
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The RX queue should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }
    }

    #[test]
    fn test_unknown_event() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_epoll_handler_context();

        let events = epoll::Events::EPOLLIN;
        let event = epoll::Event::new(events, 0xff);
        let mut epoll_helper =
            EpollHelper::new(&ctx.handler.kill_evt, &ctx.handler.pause_evt).unwrap();

        if !ctx.handler.handle_event(&mut epoll_helper, &event) {
            panic!("handle_event() should have failed");
        }
    }
}
