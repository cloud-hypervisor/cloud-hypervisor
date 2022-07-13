// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Firmware Configuration (fw_cfg) Device
//!
//! Derived from QEMU. Introduced it here to conceal grub boot when boot from firmware
//! and reuse fw_cfg device driver in edk2.
//! This hardware interface allows the guest to retrieve various data items (blobs) that
//! can influence how the firmware configures itself.
//! More info see https://github.com/qemu/qemu/blob/master/docs/specs/fw_cfg.rst
//!
use crate::{read_be_u16, read_be_u32, read_be_u64, write_be_u16, write_be_u32, write_be_u64};
use std::fmt;
use std::sync::Arc;
use std::sync::Barrier;
use std::{io, result};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_device::BusDevice;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable, VersionMapped,
};

const FW_CFG_VERSION: u32 = 0x01;
const FW_CFG_DMA_ENABLED: u32 = 0x02;
const FW_CFG_DMA_SIGNATURE: u64 = 0x51454d5520434647;

// Fw_cfg key used for identify the fw_cfg entry
pub const FW_CFG_SIGNATURE: u16 = 0x00;
pub const FW_CFG_ID: u16 = 0x01;
pub const FW_CFG_KERNEL_ADDR: u16 = 0x07;
pub const FW_CFG_KERNEL_SIZE: u16 = 0x08;
pub const FW_CFG_KERNEL_CMDLINE: u16 = 0x09;
pub const FW_CFG_KERNEL_ENTRY: u16 = 0x10;
pub const FW_CFG_KERNEL_DATA: u16 = 0x11;
pub const FW_CFG_CMDLINE_ADDR: u16 = 0x13;
pub const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
pub const FW_CFG_CMDLINE_DATA: u16 = 0x15;
const FW_CFG_LAST_KEY: u16 = 0x15;

// Fw_cfg dma control bits
const FW_CFG_DMA_CTL_ERROR: u32 = 0x01;
const FW_CFG_DMA_CTL_READ: u32 = 0x02;
const FW_CFG_DMA_CTL_SKIP: u32 = 0x04;
const FW_CFG_DMA_CTL_SELECT: u32 = 0x08;

// Fw_cfg register offset of its MMIO region
const FW_CFG_REG_CTL_OFFSET: u64 = 8;
const FW_CFG_REG_DATA_OFFSET: u64 = 0;
const FW_CFG_REG_DMA_OFFSET: u64 = 16;

#[derive(Debug)]
pub enum Error {
    FwCfgCtlSelectError(io::Error),
    FwCfgGetDmaUserAddrErr,
    FwCfgDmaReadErr(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::FwCfgCtlSelectError(e) => {
                write!(f, "Write fw_cfg select register: {}", e)
            }
            Error::FwCfgGetDmaUserAddrErr => {
                write!(f, "fw_cfg get dma user address error")
            }
            Error::FwCfgDmaReadErr(e) => {
                write!(f, "fw_cfg dma read error: {}", e)
            }
        }
    }
}

type Result<T> = result::Result<T, Error>;

// Convert u64 from big endianness to little endianness
fn be_to_le(data: u64, len: usize) -> u64 {
    let mut ret: u64 = 0;
    let mut d: u64 = data;

    for _ in 0..len {
        ret <<= 8;
        ret |= d & 0xff;
        d >>= 8;
    }

    ret
}

#[derive(Versionize, Clone)]
pub struct FWCfgEntry {
    pub len: u32,
    pub data: Option<Box<Vec<u8>>>,
}

impl FWCfgEntry {
    fn new() -> Self {
        Self { len: 0, data: None }
    }
}

#[derive(Versionize)]
pub struct FWCfgStateSnapShotData {
    id: String,
    entries: Option<Box<Vec<FWCfgEntry>>>,
    entry_order: i32,
    pub cur_entry: u16,
    cur_offset: u32,
    dma_addr: u64,
}

impl FWCfgStateSnapShotData {
    pub fn new(id: String) -> FWCfgStateSnapShotData {
        Self {
            id,
            entries: None,
            entry_order: 0,
            cur_entry: 0,
            cur_offset: 0,
            dma_addr: 0,
        }
    }

    fn state(&self) -> FWCfgStateSnapShotData {
        let e = self.entries.as_ref().unwrap().clone();
        let e = Some(e);
        FWCfgStateSnapShotData {
            id: self.id.clone(),
            entries: e,
            entry_order: self.entry_order,
            cur_entry: self.cur_entry,
            cur_offset: self.cur_offset,
            dma_addr: self.dma_addr,
        }
    }

    fn set_state(&mut self, state: &FWCfgStateSnapShotData) {
        let e = state.entries.as_ref().unwrap().clone();
        let e = Some(e);
        self.id = state.id.clone();
        self.entries = e;
        self.entry_order = state.entry_order;
        self.cur_entry = state.cur_entry;
        self.cur_offset = state.cur_offset;
        self.dma_addr = state.dma_addr;
    }
}

pub struct FWCfgState {
    core_data: FWCfgStateSnapShotData,
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
}

impl FWCfgState {
    pub fn new(id: String, mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>) -> Self {
        let core = FWCfgStateSnapShotData::new(id);
        Self {
            core_data: core,
            memory: mem,
        }
    }

    pub fn init(&mut self) {
        let vec: Vec<FWCfgEntry> = Vec::new();
        let b = Box::new(vec);
        self.core_data.entries = Some(b);

        for _ in 0..FW_CFG_LAST_KEY + 1 {
            let e = FWCfgEntry::new();
            self.core_data.entries.as_mut().unwrap().push(e);
        }
        let mut version: u32 = FW_CFG_VERSION;
        version |= FW_CFG_DMA_ENABLED;
        self.add_string(FW_CFG_SIGNATURE, "QEMU");
        self.add_i32(FW_CFG_ID, version as i32);
    }

    pub fn select(&mut self, key: u16) {
        self.core_data.cur_entry = key;
        self.core_data.cur_offset = 0;
    }

    pub fn add_bytes(&mut self, key: u16, data: Option<Box<Vec<u8>>>, len: u32) {
        if let Some(e) = &mut self.core_data.entries {
            e[key as usize].data = data;
            e[key as usize].len = len;
        }
    }

    pub fn add_string(&mut self, key: u16, value: &str) {
        let v: Vec<u8> = value.as_bytes().to_vec();
        let l = v.len();
        let b = Box::new(v);
        self.add_bytes(key, Some(b), l as u32);
    }

    pub fn add_i32(&mut self, key: u16, value: i32) {
        let mut v = Vec::new();
        let tmp = &mut v;
        let mut val = value;
        for _ in 0..4 {
            tmp.push(val as u8 & 0xff);
            val >>= 8;
        }
        let d = Box::new(v);
        self.add_bytes(key, Some(d), 4);
    }

    // Read buff from location specified by source_va(HVA) to location specified by dest_gpa(GPA)
    fn dma_read(
        &self,
        source_va: u64,
        dest_gpa: u64,
        size: usize,
    ) -> std::result::Result<(), io::Error> {
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(dest_gpa);
        let user_addr = if mem.check_range(guest_addr, size) {
            mem.get_host_address(guest_addr).unwrap() as u64
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "failed to convert guest address 0x{:x} into \
                        host user virtual address",
                    dest_gpa
                ),
            ));
        };

        // Copy memory region from source_va to dest_gpa
        unsafe {
            std::ptr::copy(source_va as *const u8, user_addr as *mut u8, size);
        }

        Ok(())
    }

    // Transfer data specified by self.cur_entry to buff specified by self.dam_addr(GPA)
    fn dma_transfer(&mut self) -> Result<()> {
        let mut control: u32;
        let mut length: u32;
        let mut address: u64;

        let mem = self.memory.memory();
        let guest_addr = GuestAddress(self.core_data.dma_addr);
        let user_addr = if mem.check_range(guest_addr, 16) {
            mem.get_host_address(guest_addr).unwrap() as u64
        } else {
            return Err(Error::FwCfgGetDmaUserAddrErr);
        };
        let pctl = user_addr as *mut u32;
        let mut ret = 0;

        // Get FWCfgDmaAccess feilds: control, length and address all of which are in big endianness mode.
        unsafe {
            let c = user_addr as *const u32;
            control = *c;
            control = be_to_le(control as u64, 4) as u32;

            let l = (user_addr + 4) as *const u32;
            length = *l;
            length = be_to_le(length as u64, 4) as u32;

            let a = (user_addr + 8) as *const u64;
            address = *a;
            address = be_to_le(address, 8);
        }

        // Let guest handle these error
        if self.core_data.dma_addr == 0 {
            ret |= FW_CFG_DMA_CTL_ERROR;
        }
        if ret & FW_CFG_DMA_CTL_ERROR != 0 || self.core_data.cur_entry > FW_CFG_LAST_KEY {
            unsafe {
                *pctl = ret;
            }

            return Ok(());
        }

        // FW_CFG_DMA_CTL_SELECT means the top 16bits of select register stores the selected entry key
        if control & FW_CFG_DMA_CTL_SELECT != 0 {
            self.select((control >> 16) as u16);
        }

        let len = self.core_data.entries.as_ref().unwrap()[self.core_data.cur_entry as usize].len;
        if length > len - self.core_data.cur_offset {
            length = len - self.core_data.cur_offset;
        }

        // Just handle dma read and skip
        if control & FW_CFG_DMA_CTL_READ != 0 {
            if let Some(e) = &self.core_data.entries {
                if let Some(d) = &e[self.core_data.cur_entry as usize].data {
                    let data_addr: u64 = d.as_ptr() as u64;
                    // Read data from region start specified by data_addr to buff specified by address
                    if let Err(e) = self.dma_read(
                        (data_addr + self.core_data.cur_offset as u64) as u64,
                        address,
                        length as usize,
                    ) {
                        // Before return error we need tell the guest what happend
                        unsafe {
                            *pctl = FW_CFG_DMA_CTL_ERROR;
                        }
                        return Err(Error::FwCfgDmaReadErr(e));
                    }
                    self.core_data.cur_offset += length;
                }
            }
        } else if control & FW_CFG_DMA_CTL_SKIP != 0 {
            self.core_data.cur_offset += length;
        } else {
            ret |= FW_CFG_DMA_CTL_ERROR;
        }

        unsafe {
            *pctl = ret;
        }

        Ok(())
    }

    fn data_read(&mut self, offset: u64, size: usize) -> Option<u64> {
        let mut value: u64 = 0;

        // Read dma register will return FW_CFG_DMA_SIGNATURE indicating dma is enabled
        if offset == FW_CFG_REG_DMA_OFFSET {
            value = FW_CFG_DMA_SIGNATURE;
            return Some(value);
        }

        // Control register is write only
        if offset != FW_CFG_REG_DATA_OFFSET
            || self.core_data.cur_entry > FW_CFG_LAST_KEY
            || size > 8
        {
            return Some(value);
        }

        // Read data from data register which the length of data specified by size.
        let mut sz = size;
        let len = self.core_data.entries.as_ref().unwrap()[self.core_data.cur_entry as usize].len;
        if let Some(e) = &self.core_data.entries {
            if let Some(d) = &e[self.core_data.cur_entry as usize].data {
                while sz > 0 && self.core_data.cur_offset < len {
                    value = value << 8 | d[self.core_data.cur_offset as usize] as u64;
                    self.core_data.cur_offset += 1;
                    sz -= 1;
                }

                if sz > 0 {
                    value = value << (8 * sz);
                }

                return Some(value);
            }
        }

        None
    }

    fn data_write(&mut self, offset: u64, value: u64, len: usize) -> Result<()> {
        match offset {
            // Data in Selector (Control) Register is big endianness for MMIO.
            // Selector (Control) Register is 2 bytes wide.
            // Data Register is read-only
            FW_CFG_REG_CTL_OFFSET => self.select(value as u16),
            // Dma write can be in one 8-bytes or two 4-bytes, after write is done, dma transfer will be fired off
            FW_CFG_REG_DMA_OFFSET => {
                if len == 8 {
                    self.core_data.dma_addr = value;
                    self.dma_transfer()?
                } else if len == 4 {
                    self.core_data.dma_addr = value << 32;
                }
            }
            20 => {
                if len == 4 {
                    self.core_data.dma_addr |= value;
                    self.dma_transfer()?
                }
            }
            _ => {}
        }

        Ok(())
    }
}

impl BusDevice for FWCfgState {
    // Data for MMIO is in big endianness format
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if let Some(d) = self.data_read(offset, data.len()) {
            match data.len() {
                1 => data[0] = d as u8,
                2 => write_be_u16(data, d as u16),
                4 => write_be_u32(data, d as u32),
                8 => write_be_u64(data, d),
                _ => {}
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let mut len = data.len();
        if len > 8 {
            len = 8
        }
        let value: u64 = match len {
            1 => data[0] as u64,
            2 => read_be_u16(data) as u64,
            4 => read_be_u32(data) as u64,
            8 => read_be_u64(data),
            _ => 0,
        };
        if let Err(e) = self.data_write(offset, value, len) {
            warn!("Fail to write data to fw_cfg register: {}", e);
        }

        None
    }
}

impl Snapshottable for FWCfgStateSnapShotData {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_versioned_state(&self.id, &self.state())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}

impl Pausable for FWCfgStateSnapShotData {}
impl Transportable for FWCfgStateSnapShotData {}
impl Migratable for FWCfgStateSnapShotData {}

impl VersionMapped for FWCfgStateSnapShotData {}

#[cfg(test)]
mod tests {
    #[test]
    fn test_be_to_le() {
        let input: u64 = 0x01;
        let output = be_to_le(input, 1);
        assert_eq!(0x01, output);

        let input: u64 = 0x0102;
        let output = be_to_le(input, 2);
        assert_eq!(0x0201, output);

        let input: u64 = 0x01020304;
        let output = be_to_le(input, 4);
        assert_eq!(0x04030201, output);

        let input: u64 = 0x0102030405060708;
        let output = be_to_le(input, 8);
        assert_eq!(0x0807060504030201, output);
    }

    #[test]
    fn test_fw_cfg_add_key() {
        let fw_cfg = FWCfgState::new("fw_cfg");
        fw_cfg.init();

        //test add_string
        let s = "console=hvc0 console=ttyAMA0 earlycon root=/dev/vda1 rw";
        let val: i32 = s.len();
        fw_cfg.add_string(FW_CFG_CMDLINE_DATA, s);
        fw_cfg.add_i32(FW_CFG_CMDLINE_SIZE, val);
        match fw_cfg.core_data.entries {
            Some(d) => {
                let data = d[FW_CFG_CMDLINE_DATA].data.unwrap();
                let size = d[FW_CFG_CMDLINE_SIZE].data.unwrap();
                let mut vec = Vec::new();
                let vc = &mut vec;
                for i in data {
                    vc.push(i);
                }
                let mut num = 0;
                let n = &mut num;
                for i in size {
                    n <<= 8;
                    n |= i;
                }
                let sv = String::from_utf8(vec).unwrap();
                let sr = &sv[0..sv.len()];
                assert_eq!(s, sr);
                assert_eq!(num, val);
            }
            None => error!("test fw_cfg add_key fail, no data found"),
        }
    }

    #[test]
    fn test_data_read_write() {
        let fw_cfg = FWCfgState::new("fw_cfg");
        fw_cfg.init();

        let mut data_input: Vec<u8> = Vec::with_capacity(2);
        let mut data_output: Vec<u8> = Vec::with_capacity(2);

        write_be_u16(data_input, FW_CFG_ID);
        fw_cfg.write(0, FW_CFG_REG_CTL_OFFSET, data_input);
        fw_cfg.read(0, FW_CFG_REG_DATA_OFFSET, data_output);

        assert_eq!(data_input, data_output);
    }
}
