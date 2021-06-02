// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::{Queue, VirtioDevice};
use byteorder::{ByteOrder, LittleEndian};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::GuestAddress;
use vm_migration::{MigratableError, Pausable, Snapshot, Snapshottable, VersionMapped};

#[derive(Clone, Versionize)]
pub struct VirtioPciCommonConfigState {
    pub driver_status: u8,
    pub config_generation: u8,
    pub device_feature_select: u32,
    pub driver_feature_select: u32,
    pub queue_select: u16,
    pub msix_config: u16,
}

impl VersionMapped for VirtioPciCommonConfigState {}

/// Contains the data for reading and writing the common configuration structure of a virtio PCI
/// device.
///
/// * Registers:
/// ** About the whole device.
/// le32 device_feature_select;     // 0x00 // read-write
/// le32 device_feature;            // 0x04 // read-only for driver
/// le32 driver_feature_select;     // 0x08 // read-write
/// le32 driver_feature;            // 0x0C // read-write
/// le16 msix_config;               // 0x10 // read-write
/// le16 num_queues;                // 0x12 // read-only for driver
/// u8 device_status;               // 0x14 // read-write (driver_status)
/// u8 config_generation;           // 0x15 // read-only for driver
/// ** About a specific virtqueue.
/// le16 queue_select;              // 0x16 // read-write
/// le16 queue_size;                // 0x18 // read-write, power of 2, or 0.
/// le16 queue_msix_vector;         // 0x1A // read-write
/// le16 queue_enable;              // 0x1C // read-write (Ready)
/// le16 queue_notify_off;          // 0x1E // read-only for driver
/// le64 queue_desc;                // 0x20 // read-write
/// le64 queue_avail;               // 0x28 // read-write
/// le64 queue_used;                // 0x30 // read-write
pub struct VirtioPciCommonConfig {
    pub driver_status: u8,
    pub config_generation: u8,
    pub device_feature_select: u32,
    pub driver_feature_select: u32,
    pub queue_select: u16,
    pub msix_config: Arc<AtomicU16>,
}

impl VirtioPciCommonConfig {
    fn state(&self) -> VirtioPciCommonConfigState {
        VirtioPciCommonConfigState {
            driver_status: self.driver_status,
            config_generation: self.config_generation,
            device_feature_select: self.device_feature_select,
            driver_feature_select: self.driver_feature_select,
            queue_select: self.queue_select,
            msix_config: self.msix_config.load(Ordering::Acquire),
        }
    }

    fn set_state(&mut self, state: &VirtioPciCommonConfigState) {
        self.driver_status = state.driver_status;
        self.config_generation = state.config_generation;
        self.device_feature_select = state.device_feature_select;
        self.driver_feature_select = state.driver_feature_select;
        self.queue_select = state.queue_select;
        self.msix_config.store(state.msix_config, Ordering::Release);
    }

    pub fn read(
        &mut self,
        offset: u64,
        data: &mut [u8],
        queues: &mut Vec<Queue>,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) {
        assert!(data.len() <= 8);

        match data.len() {
            1 => {
                let v = self.read_common_config_byte(offset);
                data[0] = v;
            }
            2 => {
                let v = self.read_common_config_word(offset, queues);
                LittleEndian::write_u16(data, v);
            }
            4 => {
                let v = self.read_common_config_dword(offset, device);
                LittleEndian::write_u32(data, v);
            }
            8 => {
                let v = self.read_common_config_qword(offset);
                LittleEndian::write_u64(data, v);
            }
            _ => error!("invalid data length for virtio read: len {}", data.len()),
        }
    }

    pub fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        queues: &mut Vec<Queue>,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) {
        assert!(data.len() <= 8);

        match data.len() {
            1 => self.write_common_config_byte(offset, data[0]),
            2 => self.write_common_config_word(offset, LittleEndian::read_u16(data), queues),
            4 => {
                self.write_common_config_dword(offset, LittleEndian::read_u32(data), queues, device)
            }
            8 => self.write_common_config_qword(offset, LittleEndian::read_u64(data), queues),
            _ => error!("invalid data length for virtio write: len {}", data.len()),
        }
    }

    fn read_common_config_byte(&self, offset: u64) -> u8 {
        debug!("read_common_config_byte: offset 0x{:x}", offset);
        // The driver is only allowed to do aligned, properly sized access.
        match offset {
            0x14 => self.driver_status,
            0x15 => self.config_generation,
            _ => {
                warn!("invalid virtio config byte read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_byte(&mut self, offset: u64, value: u8) {
        debug!("write_common_config_byte: offset 0x{:x}", offset);
        match offset {
            0x14 => self.driver_status = value,
            _ => {
                warn!("invalid virtio config byte write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_word(&self, offset: u64, queues: &[Queue]) -> u16 {
        debug!("read_common_config_word: offset 0x{:x}", offset);
        match offset {
            0x10 => self.msix_config.load(Ordering::Acquire),
            0x12 => queues.len() as u16, // num_queues
            0x16 => self.queue_select,
            0x18 => self.with_queue(queues, |q| q.size).unwrap_or(0),
            0x1a => self.with_queue(queues, |q| q.vector).unwrap_or(0),
            0x1c => {
                if self.with_queue(queues, |q| q.ready).unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            0x1e => self.queue_select, // notify_off
            _ => {
                warn!("invalid virtio register word read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_word(&mut self, offset: u64, value: u16, queues: &mut Vec<Queue>) {
        debug!("write_common_config_word: offset 0x{:x}", offset);
        match offset {
            0x10 => self.msix_config.store(value, Ordering::Release),
            0x16 => self.queue_select = value,
            0x18 => self.with_queue_mut(queues, |q| q.size = value),
            0x1a => self.with_queue_mut(queues, |q| q.vector = value),
            0x1c => self.with_queue_mut(queues, |q| q.enable(value == 1)),
            _ => {
                warn!("invalid virtio register word write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_dword(&self, offset: u64, device: Arc<Mutex<dyn VirtioDevice>>) -> u32 {
        debug!("read_common_config_dword: offset 0x{:x}", offset);
        match offset {
            0x00 => self.device_feature_select,
            0x04 => {
                let locked_device = device.lock().unwrap();
                // Only 64 bits of features (2 pages) are defined for now, so limit
                // device_feature_select to avoid shifting by 64 or more bits.
                if self.device_feature_select < 2 {
                    (locked_device.features() >> (self.device_feature_select * 32)) as u32
                } else {
                    0
                }
            }
            0x08 => self.driver_feature_select,
            _ => {
                warn!("invalid virtio register dword read: 0x{:x}", offset);
                0
            }
        }
    }

    fn write_common_config_dword(
        &mut self,
        offset: u64,
        value: u32,
        queues: &mut Vec<Queue>,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) {
        debug!("write_common_config_dword: offset 0x{:x}", offset);
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | ((u64::from(x)) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | (u64::from(x))
        }

        match offset {
            0x00 => self.device_feature_select = value,
            0x08 => self.driver_feature_select = value,
            0x0c => {
                if self.driver_feature_select < 2 {
                    let mut locked_device = device.lock().unwrap();
                    locked_device
                        .ack_features(u64::from(value) << (self.driver_feature_select * 32));
                } else {
                    warn!(
                        "invalid ack_features (page {}, value 0x{:x})",
                        self.driver_feature_select, value
                    );
                }
            }
            0x20 => self.with_queue_mut(queues, |q| lo(&mut q.desc_table, value)),
            0x24 => self.with_queue_mut(queues, |q| hi(&mut q.desc_table, value)),
            0x28 => self.with_queue_mut(queues, |q| lo(&mut q.avail_ring, value)),
            0x2c => self.with_queue_mut(queues, |q| hi(&mut q.avail_ring, value)),
            0x30 => self.with_queue_mut(queues, |q| lo(&mut q.used_ring, value)),
            0x34 => self.with_queue_mut(queues, |q| hi(&mut q.used_ring, value)),
            _ => {
                warn!("invalid virtio register dword write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_qword(&self, _offset: u64) -> u64 {
        debug!("read_common_config_qword: offset 0x{:x}", _offset);
        0 // Assume the guest has no reason to read write-only registers.
    }

    fn write_common_config_qword(&mut self, offset: u64, value: u64, queues: &mut Vec<Queue>) {
        debug!("write_common_config_qword: offset 0x{:x}", offset);
        match offset {
            0x20 => self.with_queue_mut(queues, |q| q.desc_table = GuestAddress(value)),
            0x28 => self.with_queue_mut(queues, |q| q.avail_ring = GuestAddress(value)),
            0x30 => self.with_queue_mut(queues, |q| q.used_ring = GuestAddress(value)),
            _ => {
                warn!("invalid virtio register qword write: 0x{:x}", offset);
            }
        }
    }

    fn with_queue<U, F>(&self, queues: &[Queue], f: F) -> Option<U>
    where
        F: FnOnce(&Queue) -> U,
    {
        queues.get(self.queue_select as usize).map(f)
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&self, queues: &mut Vec<Queue>, f: F) {
        if let Some(queue) = queues.get_mut(self.queue_select as usize) {
            f(queue);
        }
    }
}

impl Pausable for VirtioPciCommonConfig {}

impl Snapshottable for VirtioPciCommonConfig {
    fn id(&self) -> String {
        String::from("virtio_pci_common_config")
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_versioned_state(&self.id(), &self.state())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id())?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GuestMemoryMmap;
    use crate::{ActivateResult, VirtioInterrupt};
    use std::sync::Arc;
    use vm_memory::GuestMemoryAtomic;
    use vmm_sys_util::eventfd::EventFd;

    struct DummyDevice(u32);
    const QUEUE_SIZE: u16 = 256;
    const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];
    const DUMMY_FEATURES: u64 = 0x5555_aaaa;
    impl VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            self.0
        }
        fn queue_max_sizes(&self) -> &[u16] {
            QUEUE_SIZES
        }
        fn activate(
            &mut self,
            _mem: GuestMemoryAtomic<GuestMemoryMmap>,
            _interrupt_evt: Arc<dyn VirtioInterrupt>,
            _queues: Vec<Queue>,
            _queue_evts: Vec<EventFd>,
        ) -> ActivateResult {
            Ok(())
        }

        fn features(&self) -> u64 {
            DUMMY_FEATURES
        }

        fn ack_features(&mut self, _value: u64) {}

        fn read_config(&self, _offset: u64, _data: &mut [u8]) {}

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    }

    #[test]
    fn write_base_regs() {
        let mut regs = VirtioPciCommonConfig {
            driver_status: 0xaa,
            config_generation: 0x55,
            device_feature_select: 0x0,
            driver_feature_select: 0x0,
            queue_select: 0xff,
            msix_config: Arc::new(AtomicU16::new(0)),
        };

        let dev = Arc::new(Mutex::new(DummyDevice(0)));
        let mut queues = Vec::new();

        // Can set all bits of driver_status.
        regs.write(0x14, &[0x55], &mut queues, dev.clone());
        let mut read_back = vec![0x00];
        regs.read(0x14, &mut read_back, &mut queues, dev.clone());
        assert_eq!(read_back[0], 0x55);

        // The config generation register is read only.
        regs.write(0x15, &[0xaa], &mut queues, dev.clone());
        let mut read_back = vec![0x00];
        regs.read(0x15, &mut read_back, &mut queues, dev.clone());
        assert_eq!(read_back[0], 0x55);

        // Device features is read-only and passed through from the device.
        regs.write(0x04, &[0, 0, 0, 0], &mut queues, dev.clone());
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(0x04, &mut read_back, &mut queues, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), DUMMY_FEATURES as u32);

        // Feature select registers are read/write.
        regs.write(0x00, &[1, 2, 3, 4], &mut queues, dev.clone());
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(0x00, &mut read_back, &mut queues, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0x0403_0201);
        regs.write(0x08, &[1, 2, 3, 4], &mut queues, dev.clone());
        let mut read_back = vec![0, 0, 0, 0];
        regs.read(0x08, &mut read_back, &mut queues, dev.clone());
        assert_eq!(LittleEndian::read_u32(&read_back), 0x0403_0201);

        // 'queue_select' can be read and written.
        regs.write(0x16, &[0xaa, 0x55], &mut queues, dev.clone());
        let mut read_back = vec![0x00, 0x00];
        regs.read(0x16, &mut read_back, &mut queues, dev);
        assert_eq!(read_back[0], 0xaa);
        assert_eq!(read_back[1], 0x55);
    }
}
