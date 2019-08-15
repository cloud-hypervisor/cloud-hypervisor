// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Handles routing to devices in an address space.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::result;
use std::sync::{Arc, Mutex};

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Reads at `offset` from this device
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, base: u64, offset: u64, data: &[u8]) {}
    /// Triggers the `irq_mask` interrupt on this device
    fn interrupt(&self, irq_mask: u32) {}
}

#[derive(Debug)]
pub enum Error {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
}

pub type Result<T> = result::Result<T, Error>;

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    pub base: u64,
    pub len: u64,
}

impl BusRange {
    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        self.base < (base + len) && base < self.base + self.len
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        self.base.partial_cmp(&other.base)
    }
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Clone, Default)]
pub struct Bus {
    devices: BTreeMap<BusRange, Arc<Mutex<dyn BusDevice>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: BTreeMap::new(),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, &Mutex<dyn BusDevice>)> {
        let (range, dev) = self
            .devices
            .range(..=BusRange { base: addr, len: 1 })
            .rev()
            .next()?;
        Some((*range, dev))
    }

    pub fn resolve(&self, addr: u64) -> Option<(u64, u64, &Mutex<dyn BusDevice>)> {
        if let Some((range, dev)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                return Some((range.base, offset, dev));
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(&mut self, device: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        if self
            .devices
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(Error::Overlap);
        }

        if self
            .devices
            .insert(BusRange { base, len }, device)
            .is_some()
        {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.lock()
                .expect("Failed to acquire device lock")
                .read(base, offset, data);
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.lock()
                .expect("Failed to acquire device lock")
                .write(base, offset, data);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {}

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }
        }
    }

    #[test]
    fn bus_insert() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        assert!(result.is_err());
        assert_eq!(format!("{:?}", result), "Err(Overlap)");

        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0, 0x10).is_ok());
    }

    #[test]
    fn bus_read_write() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x16, &[0, 0, 0, 0]));
        assert!(!bus.read(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.read(0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x06, &mut [0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn busrange_cmp_and_clone() {
        let range = BusRange { base: 0x10, len: 2 };
        assert_eq!(range, BusRange { base: 0x10, len: 3 });
        assert_eq!(range, BusRange { base: 0x10, len: 2 });

        assert!(range < BusRange { base: 0x12, len: 1 });
        assert!(range < BusRange { base: 0x12, len: 3 });

        assert_eq!(range, range.clone());

        let mut bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        assert!(bus
            .insert(Arc::new(Mutex::new(DummyDevice)), 0x10, 0x10)
            .is_ok());
        assert!(bus.write(0x10, &mut data));
        let bus_clone = bus.clone();
        assert!(bus.read(0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
        assert!(bus_clone.read(0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
        };
        assert!(a.overlaps(0x1000, 0x400));
        assert!(a.overlaps(0xf00, 0x400));
        assert!(a.overlaps(0x1000, 0x01));
        assert!(a.overlaps(0xfff, 0x02));
        assert!(a.overlaps(0x1100, 0x100));
        assert!(a.overlaps(0x13ff, 0x100));
        assert!(!a.overlaps(0x1400, 0x100));
        assert!(!a.overlaps(0xf00, 0x100));
    }
}
