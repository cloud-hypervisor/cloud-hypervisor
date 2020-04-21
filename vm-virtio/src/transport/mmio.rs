// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::transport::{VirtioTransport, NOTIFY_REG_OFFSET};
use crate::{
    Queue, VirtioDevice, VirtioDeviceType, VirtioInterrupt, VirtioInterruptType,
    DEVICE_ACKNOWLEDGE, DEVICE_DRIVER, DEVICE_DRIVER_OK, DEVICE_FAILED, DEVICE_FEATURES_OK,
    DEVICE_INIT, INTERRUPT_STATUS_CONFIG_CHANGED, INTERRUPT_STATUS_USED_RING,
};
use anyhow::anyhow;
use byteorder::{ByteOrder, LittleEndian};
use devices::BusDevice;
use libc::EFD_NONBLOCK;
use std::num::Wrapping;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use vm_device::interrupt::InterruptSourceGroup;
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::{errno::Result, eventfd::EventFd};

const VENDOR_ID: u32 = 0;

const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
const MMIO_VERSION: u32 = 2;

#[derive(Debug)]
enum Error {
    /// Failed to retrieve queue ring's index.
    QueueRingIndex(crate::queue::Error),
}

pub struct VirtioInterruptIntx {
    interrupt_status: Arc<AtomicUsize>,
    interrupt: Arc<Box<dyn InterruptSourceGroup>>,
}

impl VirtioInterruptIntx {
    pub fn new(
        interrupt_status: Arc<AtomicUsize>,
        interrupt: Arc<Box<dyn InterruptSourceGroup>>,
    ) -> Self {
        VirtioInterruptIntx {
            interrupt_status,
            interrupt,
        }
    }
}

impl VirtioInterrupt for VirtioInterruptIntx {
    fn trigger(
        &self,
        int_type: &VirtioInterruptType,
        _queue: Option<&Queue>,
    ) -> std::result::Result<(), std::io::Error> {
        let status = match int_type {
            VirtioInterruptType::Config => INTERRUPT_STATUS_CONFIG_CHANGED,
            VirtioInterruptType::Queue => INTERRUPT_STATUS_USED_RING,
        };
        self.interrupt_status
            .fetch_or(status as usize, Ordering::SeqCst);

        self.interrupt.trigger(0)
    }
}

#[derive(Serialize, Deserialize)]
struct VirtioMmioDeviceState {
    device_activated: bool,
    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    interrupt_status: usize,
    driver_status: u32,
    queues: Vec<Queue>,
    shm_region_select: u32,
}

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioDevice {
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: bool,

    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    driver_status: u32,
    config_generation: u32,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    shm_region_select: u32,
}

impl MmioDevice {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<MmioDevice> {
        let device_clone = device.clone();
        let locked_device = device_clone.lock().unwrap();
        let mut queue_evts = Vec::new();
        for _ in locked_device.queue_max_sizes().iter() {
            queue_evts.push(EventFd::new(EFD_NONBLOCK)?)
        }
        let queues = locked_device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();
        Ok(MmioDevice {
            device,
            device_activated: false,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_cb: None,
            driver_status: DEVICE_INIT,
            config_generation: 0,
            queues,
            queue_evts,
            mem: Some(mem),
            shm_region_select: 0,
        })
    }

    fn state(&self) -> VirtioMmioDeviceState {
        VirtioMmioDeviceState {
            device_activated: self.device_activated,
            features_select: self.features_select,
            acked_features_select: self.acked_features_select,
            queue_select: self.queue_select,
            interrupt_status: self.interrupt_status.load(Ordering::SeqCst),
            driver_status: self.driver_status,
            queues: self.queues.clone(),
            shm_region_select: self.shm_region_select,
        }
    }

    fn set_state(&mut self, state: &VirtioMmioDeviceState) -> std::result::Result<(), Error> {
        self.device_activated = state.device_activated;
        self.features_select = state.features_select;
        self.acked_features_select = state.acked_features_select;
        self.queue_select = state.queue_select;
        self.interrupt_status
            .store(state.interrupt_status, Ordering::SeqCst);
        self.driver_status = state.driver_status;
        self.queues = state.queues.clone();

        // Update virtqueues indexes for both available and used rings.
        if let Some(mem) = self.mem.as_ref() {
            let mem = mem.memory();
            for queue in self.queues.iter_mut() {
                queue.next_avail = Wrapping(
                    queue
                        .used_index_from_memory(&mem)
                        .map_err(Error::QueueRingIndex)?,
                );
                queue.next_used = Wrapping(
                    queue
                        .used_index_from_memory(&mem)
                        .map_err(Error::QueueRingIndex)?,
                );
            }
        }

        self.shm_region_select = state.shm_region_select;

        Ok(())
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `virtio::NOTIFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK;
        self.driver_status == ready_bits && self.driver_status & DEVICE_FAILED == 0
    }

    fn are_queues_valid(&self) -> bool {
        if let Some(mem) = self.mem.as_ref() {
            self.queues.iter().all(|q| q.is_valid(&mem.memory()))
        } else {
            false
        }
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match self.queues.get(self.queue_select as usize) {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self.queues.get_mut(self.queue_select as usize) {
            f(queue);
            true
        } else {
            false
        }
    }

    pub fn assign_interrupt(&mut self, interrupt: Arc<Box<dyn InterruptSourceGroup>>) {
        self.interrupt_cb = Some(Arc::new(VirtioInterruptIntx::new(
            self.interrupt_status.clone(),
            interrupt,
        )));
    }
}

impl VirtioTransport for MmioDevice {
    fn ioeventfds(&self, base_addr: u64) -> Vec<(&EventFd, u64)> {
        let notify_base = base_addr + u64::from(NOTIFY_REG_OFFSET);
        self.queue_evts()
            .iter()
            .map(|event| (event, notify_base))
            .collect()
    }
}

impl BusDevice for MmioDevice {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.device.lock().unwrap().device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        if self.features_select < 2 {
                            (self.device.lock().unwrap().features() >> (self.features_select * 32))
                                as u32
                        } else {
                            0
                        }
                    }
                    0x34 => self.with_queue(0, |q| u32::from(q.get_max_size())),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt_status.load(Ordering::SeqCst) as u32,
                    0x70 => self.driver_status,
                    0xfc => self.config_generation,
                    0xb0..=0xbc => {
                        // For no SHM region or invalid region the kernel looks for length of -1
                        let (shm_offset, shm_len) = if let Some(shm_regions) =
                            self.device.lock().unwrap().get_shm_regions()
                        {
                            if self.shm_region_select as usize > shm_regions.region_list.len() {
                                (0, !0 as u64)
                            } else {
                                (
                                    shm_regions.region_list[self.shm_region_select as usize].offset
                                        + shm_regions.addr.0,
                                    shm_regions.region_list[self.shm_region_select as usize].len,
                                )
                            }
                        } else {
                            (0, !0 as u64)
                        };
                        match offset {
                            0xb0 => shm_len as u32,
                            0xb4 => (shm_len >> 32) as u32,
                            0xb8 => shm_offset as u32,
                            0xbc => (shm_offset >> 32) as u32,
                            _ => {
                                error!("invalid shm region offset");
                                0
                            }
                        }
                    }
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{:x}", offset);
                        return;
                    }
                };
                LittleEndian::write_u32(data, v);
            }
            0x100..=0xfff => self
                .device
                .lock()
                .unwrap()
                .read_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        let mut mut_q = false;
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = LittleEndian::read_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => {
                        if self.acked_features_select < 2 {
                            self.device
                                .lock()
                                .unwrap()
                                .ack_features(u64::from(v) << (self.acked_features_select * 32));
                        } else {
                            warn!(
                                "invalid ack_features (page {}, value 0x{:x})",
                                self.acked_features_select, v
                            );
                        }
                    }
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => mut_q = self.with_queue_mut(|q| q.size = v as u16),
                    0x44 => mut_q = self.with_queue_mut(|q| q.ready = v == 1),
                    0x64 => {
                        self.interrupt_status
                            .fetch_and(!(v as usize), Ordering::SeqCst);
                    }
                    0x70 => self.driver_status = v,
                    0x80 => mut_q = self.with_queue_mut(|q| lo(&mut q.desc_table, v)),
                    0x84 => mut_q = self.with_queue_mut(|q| hi(&mut q.desc_table, v)),
                    0x90 => mut_q = self.with_queue_mut(|q| lo(&mut q.avail_ring, v)),
                    0x94 => mut_q = self.with_queue_mut(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => mut_q = self.with_queue_mut(|q| lo(&mut q.used_ring, v)),
                    0xa4 => mut_q = self.with_queue_mut(|q| hi(&mut q.used_ring, v)),
                    0xac => self.shm_region_select = v,
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{:x}", offset);
                        return;
                    }
                }
            }
            0x100..=0xfff => {
                return self
                    .device
                    .lock()
                    .unwrap()
                    .write_config(offset - 0x100, data)
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
                return;
            }
        }

        if self.device_activated && mut_q {
            warn!("virtio queue was changed after device was activated");
        }

        if !self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
            if let Some(interrupt_cb) = self.interrupt_cb.take() {
                if self.mem.is_some() {
                    let mem = self.mem.as_ref().unwrap().clone();
                    self.device
                        .lock()
                        .unwrap()
                        .activate(
                            mem,
                            interrupt_cb,
                            self.queues.clone(),
                            self.queue_evts.split_off(0),
                        )
                        .expect("Failed to activate device");
                    self.device_activated = true;
                }
            }
        }
    }
}

impl Pausable for MmioDevice {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }
}

const VIRTIO_MMIO_DEV_SNAPSHOT_ID: &str = "virtio_mmio_device";
impl Snapshottable for MmioDevice {
    fn id(&self) -> String {
        format!(
            "{}-{}",
            VIRTIO_MMIO_DEV_SNAPSHOT_ID,
            VirtioDeviceType::from(self.device.lock().unwrap().device_type())
        )
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let snapshot_id = self.id();
        let mut virtio_mmio_dev_snapshot = Snapshot::new(&snapshot_id);
        virtio_mmio_dev_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", snapshot_id),
            snapshot,
        });

        Ok(virtio_mmio_dev_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        let snapshot_id = self.id();
        if let Some(virtio_mmio_dev_section) = snapshot
            .snapshot_data
            .get(&format!("{}-section", snapshot_id))
        {
            let virtio_mmio_dev_state =
                match serde_json::from_slice(&virtio_mmio_dev_section.snapshot) {
                    Ok(state) => state,
                    Err(error) => {
                        return Err(MigratableError::Restore(anyhow!(
                            "Could not deserialize VIRTIO_MMIO_DEVICE {}",
                            error
                        )))
                    }
                };

            // First restore the status of the virtqueues.
            self.set_state(&virtio_mmio_dev_state).map_err(|e| {
                MigratableError::Restore(anyhow!(
                    "Could not restore VIRTIO_MMIO_DEVICE state {:?}",
                    e
                ))
            })?;

            // Then we can activate the device, as we know at this point that
            // the virtqueues are in the right state and the device is ready
            // to be activated, which will spawn each virtio worker thread.
            if self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
                if let Some(interrupt_cb) = self.interrupt_cb.take() {
                    if self.mem.is_some() {
                        let mem = self.mem.as_ref().unwrap().clone();
                        self.device
                            .lock()
                            .unwrap()
                            .activate(
                                mem,
                                interrupt_cb,
                                self.queues.clone(),
                                self.queue_evts.split_off(0),
                            )
                            .map_err(|e| {
                                MigratableError::Restore(anyhow!(
                                    "Failed activating the device: {:?}",
                                    e
                                ))
                            })?;
                    }
                }
            }

            return Ok(());
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find VIRTIO_MMIO_DEVICE snapshot section"
        )))
    }
}

impl Transportable for MmioDevice {}
impl Migratable for MmioDevice {}
