// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

extern crate byteorder;
extern crate vm_memory;

use crate::{PciCapability, PciCapabilityID};
use byteorder::{ByteOrder, LittleEndian};
use vm_memory::ByteValued;

const MAX_MSIX_VECTORS_PER_DEVICE: u16 = 2048;
const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
const BITS_PER_PBA_ENTRY: usize = 64;

#[derive(Debug, Clone)]
pub struct MsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctl: u32,
}

impl Default for MsixTableEntry {
    fn default() -> Self {
        MsixTableEntry {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
            vector_ctl: 0,
        }
    }
}

pub struct MsixConfig {
    pub table_entries: Vec<MsixTableEntry>,
    pub pba_entries: Vec<u64>,
}

impl MsixConfig {
    pub fn new(msix_vectors: u16) -> Self {
        assert!(msix_vectors < MAX_MSIX_VECTORS_PER_DEVICE);

        let mut table_entries: Vec<MsixTableEntry> = Vec::new();
        table_entries.resize_with(msix_vectors as usize, Default::default);
        let mut pba_entries: Vec<u64> = Vec::new();
        let num_pba_entries: usize = ((msix_vectors as usize) / BITS_PER_PBA_ENTRY) + 1;
        pba_entries.resize_with(num_pba_entries, Default::default);

        MsixConfig {
            table_entries,
            pba_entries,
        }
    }

    pub fn read_table(&mut self, offset: u64, data: &mut [u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value = match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo,
                    0x4 => self.table_entries[index].msg_addr_hi,
                    0x8 => self.table_entries[index].msg_data,
                    0x10 => self.table_entries[index].vector_ctl,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R TABLE offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u32(data, value);
            }
            8 => {
                let value = match modulo_offset {
                    0x0 => {
                        (u64::from(self.table_entries[index].msg_addr_hi) << 32)
                            | u64::from(self.table_entries[index].msg_addr_lo)
                    }
                    0x8 => {
                        (u64::from(self.table_entries[index].vector_ctl) << 32)
                            | u64::from(self.table_entries[index].msg_data)
                    }
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R TABLE offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u64(data, value);
            }
            _ => {
                error!("invalid data length");
            }
        }
    }

    pub fn write_table(&mut self, offset: u64, data: &[u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value = LittleEndian::read_u32(data);
                match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo = value,
                    0x4 => self.table_entries[index].msg_addr_hi = value,
                    0x8 => self.table_entries[index].msg_data = value,
                    0x10 => self.table_entries[index].vector_ctl = value,
                    _ => error!("invalid offset"),
                };

                debug!("MSI_W TABLE offset 0x{:x} data 0x{:x}", offset, value);
            }
            8 => {
                let value = LittleEndian::read_u64(data);
                match modulo_offset {
                    0x0 => {
                        self.table_entries[index].msg_addr_lo = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].msg_addr_hi = (value >> 32) as u32;
                    }
                    0x8 => {
                        self.table_entries[index].msg_data = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].vector_ctl = (value >> 32) as u32;
                    }
                    _ => error!("invalid offset"),
                };

                debug!("MSI_W TABLE offset 0x{:x} data 0x{:x}", offset, value);
            }
            _ => error!("invalid data length"),
        };
    }

    pub fn read_pba(&mut self, offset: u64, data: &mut [u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / MSIX_PBA_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_PBA_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value: u32 = match modulo_offset {
                    0x0 => (self.pba_entries[index] & 0xffff_ffffu64) as u32,
                    0x4 => (self.pba_entries[index] >> 32) as u32,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R PBA offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u32(data, value);
            }
            8 => {
                let value: u64 = match modulo_offset {
                    0x0 => self.pba_entries[index],
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("MSI_R PBA offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u64(data, value);
            }
            _ => {
                error!("invalid data length");
            }
        }
    }

    pub fn write_pba(&mut self, _offset: u64, _data: &[u8]) {
        error!("Pending Bit Array is read only");
    }
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy, Default)]
pub struct MsixCap {
    // Message Control Register
    //   10-0:  MSI-X Table size
    //   13-11: Reserved
    //   14:    Mask. Mask all MSI-X when set.
    //   15:    Enable. Enable all MSI-X when set.
    msg_ctl: u16,
    // Table. Contains the offset and the BAR indicator (BIR)
    //   2-0:  Table BAR indicator (BIR). Can be 0 to 5.
    //   31-3: Table offset in the BAR pointed by the BIR.
    table: u32,
    // Pending Bit Array. Contains the offset and the BAR indicator (BIR)
    //   2-0:  PBA BAR indicator (BIR). Can be 0 to 5.
    //   31-3: PBA offset in the BAR pointed by the BIR.
    pba: u32,
}

// It is safe to implement ByteValued. All members are simple numbers and any value is valid.
unsafe impl ByteValued for MsixCap {}

impl PciCapability for MsixCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::MSIX
    }
}

impl MsixCap {
    pub fn new(pci_bar: u8, table_size: u16, table_off: u32, pba_off: u32) -> Self {
        assert!(table_size < MAX_MSIX_VECTORS_PER_DEVICE);

        // Set the table size and enable MSI-X.
        let msg_ctl: u16 = 0x8000u16 + table_size - 1;

        MsixCap {
            msg_ctl,
            table: (table_off & 0xffff_fff8u32) | u32::from(pci_bar & 0x7u8),
            pba: (pba_off & 0xffff_fff8u32) | u32::from(pci_bar & 0x7u8),
        }
    }
}
