// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Handles routing to devices in an address space.

use std::cmp::Ordering;
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, RwLock, Weak};
use std::{convert, io, result};

use thiserror::Error;

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Reads at `offset` from this device
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

#[allow(unused_variables)]
pub trait BusDeviceSync: Send + Sync {
    /// Reads at `offset` from this device
    fn read(&self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

impl<B: BusDevice> BusDeviceSync for Mutex<B> {
    /// Reads at `offset` from this device
    fn read(&self, base: u64, offset: u64, data: &mut [u8]) {
        self.lock()
            .expect("Failed to acquire device lock")
            .read(base, offset, data);
    }
    /// Writes at `offset` into this device
    fn write(&self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.lock()
            .expect("Failed to acquire device lock")
            .write(base, offset, data)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// The insertion failed because the new device overlapped with an old device.
    #[error("The insertion failed because the new device overlapped with an old device")]
    Overlap,
    /// Failed to operate on zero sized range.
    #[error("Failed to operate on zero sized range")]
    ZeroSizedRange,
    /// Failed to find address range.
    #[error("Failed to find address range")]
    MissingAddressRange,
}

pub type Result<T> = result::Result<T, Error>;

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::other(e)
    }
}

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
        Some(self.cmp(other))
    }
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Default)]
pub struct Bus {
    devices: RwLock<BTreeMap<BusRange, Weak<dyn BusDeviceSync>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: RwLock::new(BTreeMap::new()),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, Arc<dyn BusDeviceSync>)> {
        let devices = self.devices.read().unwrap();
        let (range, dev) = devices
            .range(..=BusRange { base: addr, len: 1 })
            .next_back()?;
        dev.upgrade().map(|d| (*range, d.clone()))
    }

    #[allow(clippy::type_complexity)]
    fn resolve(&self, addr: u64, len: u64) -> Option<(u64, u64, Arc<dyn BusDeviceSync>)> {
        if let Some((range, dev)) = self.first_before(addr) {
            let offset = addr - range.base;
            // Reject when (offset, len) wraps u64 or spills past the device's
            // window into an adjacent device.
            let end_offset = offset.checked_add(len)?;
            if offset < range.len && end_offset <= range.len {
                return Some((range.base, offset, dev));
            }
        }
        None
    }

    /// Inserts a bus device into the bus.
    ///
    /// The bus will only hold a weak reference to the object.
    #[allow(clippy::needless_pass_by_value)]
    pub fn insert(&self, device: Arc<dyn BusDeviceSync>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::ZeroSizedRange);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        if self
            .devices
            .read()
            .unwrap()
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(Error::Overlap);
        }

        if self
            .devices
            .write()
            .unwrap()
            .insert(BusRange { base, len }, Arc::downgrade(&device))
            .is_some()
        {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Removes the device at the given address space range.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::ZeroSizedRange);
        }

        let bus_range = BusRange { base, len };

        if self.devices.write().unwrap().remove(&bus_range).is_none() {
            return Err(Error::MissingAddressRange);
        }

        Ok(())
    }

    /// Removes all entries referencing the given device.
    pub fn remove_by_device(&self, device: &dyn BusDeviceSync) -> Result<()> {
        let mut device_list = self.devices.write().unwrap();
        let mut remove_key_list = Vec::new();

        for (key, value) in device_list.iter() {
            let value = value.upgrade().unwrap();
            if core::ptr::eq(Arc::as_ptr(&value), device) {
                remove_key_list.push(*key);
            }
        }

        for key in remove_key_list.iter() {
            device_list.remove(key);
        }

        Ok(())
    }

    /// Updates the address range for an existing device.
    pub fn update_range(
        &self,
        old_base: u64,
        old_len: u64,
        new_base: u64,
        new_len: u64,
    ) -> Result<()> {
        // Retrieve the device corresponding to the range
        let device = if let Some((_, _, dev)) = self.resolve(old_base, 1) {
            dev.clone()
        } else {
            return Err(Error::MissingAddressRange);
        };

        // Remove the old address range
        self.remove(old_base, old_len)?;

        // Insert the new address range
        self.insert(device, new_base, new_len)
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns `Ok(())` on success, otherwise `data` is untouched and the device is not invoked.
    /// Accesses whose `(addr, data.len())` span extends past a single device's range are rejected
    /// with `Error::MissingAddressRange`, mirroring the behaviour for completely unmapped
    /// addresses.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        if let Some((base, offset, dev)) = self.resolve(addr, data.len() as u64) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.read(base, offset, data);
            Ok(())
        } else {
            Err(Error::MissingAddressRange)
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns `Ok(...)` on success, otherwise the device is not invoked.  Accesses whose `(addr,
    /// data.len())` span extends past a single device's range are rejected with
    /// `Error::MissingAddressRange`, mirroring the behaviour for completely unmapped addresses.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<Arc<Barrier>>> {
        if let Some((base, offset, dev)) = self.resolve(addr, data.len() as u64) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            Ok(dev.write(base, offset, data))
        } else {
            Err(Error::MissingAddressRange)
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    struct DummyDevice;
    impl BusDeviceSync for DummyDevice {}

    struct ConstantDevice;
    impl BusDeviceSync for ConstantDevice {
        fn read(&self, _base: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        fn write(&self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8));
            }

            None
        }
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);
        bus.insert(dummy.clone(), 0x10, 0).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        assert_eq!(format!("{result:?}"), "Err(Overlap)");

        bus.insert(dummy.clone(), 0x10, 0x10).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x01).unwrap_err();
        bus.insert(dummy.clone(), 0x0, 0x20).unwrap_err();
        bus.insert(dummy.clone(), 0x20, 0x05).unwrap();
        bus.insert(dummy.clone(), 0x25, 0x05).unwrap();
        bus.insert(dummy, 0x0, 0x10).unwrap();
    }

    #[test]
    fn bus_read_write() {
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();
        bus.read(0x10, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x10, &[0, 0, 0, 0]).unwrap();
        bus.read(0x11, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x11, &[0, 0, 0, 0]).unwrap();
        bus.read(0x16, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x16, &[0, 0, 0, 0]).unwrap();
        bus.read(0x20, &mut [0, 0, 0, 0]).unwrap_err();
        bus.write(0x20, &[0, 0, 0, 0]).unwrap_err();
        bus.read(0x06, &mut [0, 0, 0, 0]).unwrap_err();
        bus.write(0x06, &[0, 0, 0, 0]).unwrap_err();
    }

    #[test]
    fn bus_read_write_values() {
        let bus = Bus::new();
        let dummy = Arc::new(ConstantDevice);
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let mut values = [0, 1, 2, 3];
        bus.read(0x10, &mut values).unwrap();
        assert_eq!(values, [0, 1, 2, 3]);
        bus.write(0x10, &values).unwrap();
        bus.read(0x15, &mut values).unwrap();
        assert_eq!(values, [5, 6, 7, 8]);
        bus.write(0x15, &values).unwrap();
    }

    #[test]
    fn busrange_cmp() {
        let range = BusRange { base: 0x10, len: 2 };
        assert_eq!(range, BusRange { base: 0x10, len: 3 });
        assert_eq!(range, BusRange { base: 0x10, len: 2 });

        assert!(range < BusRange { base: 0x12, len: 1 });
        assert!(range < BusRange { base: 0x12, len: 3 });

        assert_eq!(range, range.clone());

        let bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        let device = Arc::new(DummyDevice);
        bus.insert(device.clone(), 0x10, 0x10).unwrap();
        bus.write(0x10, &data).unwrap();
        bus.read(0x10, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn bus_resolve_rejects_access_spanning_past_device() {
        // An MMIO/PIO access that begins inside a device's window but extends past the end of that
        // window must be rejected by the bus, not delivered to the device with a slice that
        // overflows the device's logical size.
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);
        // Device A occupies [0x10, 0x20); device B sits adjacent at [0x20, 0x30).
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();
        bus.insert(dummy.clone(), 0x20, 0x10).unwrap();

        let assert_rejected = |addr: u64, len: usize| {
            assert!(matches!(
                bus.read(addr, &mut vec![0u8; len]),
                Err(Error::MissingAddressRange)
            ));
            assert!(matches!(
                bus.write(addr, &vec![0u8; len]),
                Err(Error::MissingAddressRange)
            ));
        };

        // Accesses that fit entirely within device A, including ones that end
        // exactly at device A's last byte.
        bus.read(0x10, &mut [0u8; 4]).unwrap();
        bus.write(0x10, &[0u8; 4]).unwrap();
        bus.read(0x1C, &mut [0u8; 4]).unwrap();
        bus.write(0x1C, &[0u8; 4]).unwrap();
        bus.read(0x18, &mut [0u8; 8]).unwrap();
        bus.write(0x18, &[0u8; 8]).unwrap();
        bus.read(0x1F, &mut [0u8; 1]).unwrap();
        bus.write(0x1F, &[0u8; 1]).unwrap();

        // Accesses that begin in device A but spill into device B. Without
        // the fix these would be delivered to device A with a slice longer
        // than the device's window.
        assert_rejected(0x1D, 4);
        assert_rejected(0x1F, 2);
        assert_rejected(0x19, 8);
    }

    #[test]
    fn bus_resolve_does_not_invoke_device_on_rejected_access() {
        // ConstantDevice::read overwrites every byte of `data`. If an access
        // that spills past the device's end were still delivered, the buffer
        // would be overwritten. The fix must short-circuit before invoking
        // the device.
        let bus = Bus::new();
        let dev = Arc::new(ConstantDevice);
        // Keep the Arc alive — Bus stores only a Weak.
        bus.insert(dev.clone(), 0x10, 0x10).unwrap();
        // 9-byte access at 0x18 spills one byte past the device's end.
        let mut buf = [0xa5u8; 9];
        assert!(matches!(
            bus.read(0x18, &mut buf),
            Err(Error::MissingAddressRange)
        ));
        // Buffer is untouched because the device was never called.
        assert_eq!(buf, [0xa5u8; 9]);
    }

    #[test]
    fn bus_resolve_handles_address_overflow() {
        // A device placed near the top of the address space must not produce
        // a u64 overflow when computing offset + len for an access whose
        // length would push past u64::MAX. The checked_add guard returns None
        // and the access is rejected.
        let bus = Bus::new();
        let dummy = Arc::new(DummyDevice);
        // Device occupies [u64::MAX - 0x10 + 1, u64::MAX] inclusive — i.e. the
        // last 0x10 bytes of the address space. Keep an Arc alive — Bus stores
        // only a Weak.
        let base = u64::MAX - 0x10 + 1;
        bus.insert(dummy.clone(), base, 0x10).unwrap();
        // 4-byte access fitting in the device's last 4 bytes is OK.
        bus.read(u64::MAX - 3, &mut [0u8; 4]).unwrap();
        // 4-byte access starting at u64::MAX - 2 would need to read past
        // u64::MAX; reject.
        assert!(matches!(
            bus.read(u64::MAX - 2, &mut [0u8; 4]),
            Err(Error::MissingAddressRange)
        ));
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
