// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// NOTE: This is not a full implementation of the qemu fw_cfg spec.
/// We implement the functionality necessary to use Oak's Stage0 Firmware
/// (This includes most of the functionality, besides adding additional
/// items to the fw_cfg device for the firmware).
use std::{
    fs::File,
    io::Result,
    mem::size_of_val,
    os::unix::fs::FileExt,
    sync::{Arc, Barrier},
};
use vm_device::BusDevice;
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{IntoBytes, FromBytes};

pub const PORT_FW_CFG_SELECTOR: u16 = 0x510;
pub const PORT_FW_CFG_DATA: u16 = 0x511;
pub const PORT_FW_CFG_DMA_HI: u16 = 0x514;
pub const PORT_FW_CFG_DMA_LO: u16 = 0x518;

pub const FW_CFG_SIGNATURE: u16 = 0x00;
pub const FW_CFG_ID: u16 = 0x01;
pub const FW_CFG_KERNEL_SIZE: u16 = 0x08;
pub const FW_CFG_INITRD_SIZE: u16 = 0x0b;
pub const FW_CFG_KERNEL_DATA: u16 = 0x11;
pub const FW_CFG_INITRD_DATA: u16 = 0x12;
pub const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
pub const FW_CFG_CMDLINE_DATA: u16 = 0x15;
pub const FW_CFG_SETUP_SIZE: u16 = 0x17;
pub const FW_CFG_SETUP_DATA: u16 = 0x18;
pub const FW_CFG_FILE_DIR: u16 = 0x19;
pub const FW_CFG_KNOWN_ITEMS: usize = 0x20;

pub const FW_CFG_FILE_FIRST: u16 = 0x20;
pub const FW_CFG_DMA_SIGNATURE: [u8; 8] = *b"QEMU CFG";
// bit 1 must always be enabled, bit 2 enables DMA
pub const FW_CFG_FEATURE: [u8; 4] = [0b11, 0, 0, 0];

#[derive(Debug)]
pub enum FwCfgContent {
    Bytes(Vec<u8>),
    Slice(&'static [u8]),
    File(u64, File),
    U32(u32),
}

impl Default for FwCfgContent {
    fn default() -> Self {
        FwCfgContent::Slice(&[])
    }
}

impl FwCfgContent {
    fn size(&self) -> Result<u32> {
        let ret = match self {
            FwCfgContent::Bytes(v) => v.len(),
            FwCfgContent::File(offset, f) => (f.metadata()?.len() - offset) as usize,
            FwCfgContent::Slice(s) => s.len(),
            FwCfgContent::U32(n) => size_of_val(n),
        };
        u32::try_from(ret).map_err(|_| std::io::ErrorKind::InvalidInput.into())
    }
}

#[derive(Debug, Default)]
pub struct FwCfgItem {
    pub name: String,
    pub content: FwCfgContent,
}

/// https://www.qemu.org/docs/master/specs/fw_cfg.html
pub struct FwCfg {
    selector: u16,
    data_offset: u32,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFilesHeader {
    count_be: u32,
}

pub const FILE_NAME_SIZE: usize = 56;

pub fn create_file_name(name: &str) -> [u8; FILE_NAME_SIZE] {
    let mut c_name = [0u8; FILE_NAME_SIZE];
    let c_len = std::cmp::min(FILE_NAME_SIZE - 1, name.len());
    c_name[0..c_len].copy_from_slice(&name.as_bytes()[0..c_len]);
    c_name
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, FromBytes, Clone, Copy)]
pub struct BootE820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFile {
    size_be: u32,
    select_be: u16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

impl FwCfg {
    pub fn new() -> FwCfg {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_DMA_SIGNATURE);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_mut_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        FwCfg {
            selector: 0,
            data_offset: 0,
            items: vec![],
            known_items,
        }
    }

    fn get_file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let mut header = FwCfgFilesHeader {
            count_be: (self.items.len() as u32).to_be(),
        };
        self.get_file_dir_mut()[0..4].copy_from_slice(header.as_mut_bytes());
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let index = self.items.len();
        let c_name = create_file_name(&item.name);
        let size = item.content.size()?;
        let mut cfg_file = FwCfgFile {
            size_be: size.to_be(),
            select_be: (FW_CFG_FILE_FIRST + index as u16).to_be(),
            _reserved: 0,
            name: c_name,
        };
        self.get_file_dir_mut()
            .extend_from_slice(cfg_file.as_mut_bytes());
        self.items.push(item);
        self.update_count();
        Ok(())
    }

    fn read_content(content: &FwCfgContent, offset: u32) -> Option<u8> {
        match content {
            FwCfgContent::Bytes(b) => b.get(offset as usize).copied(),
            FwCfgContent::Slice(s) => s.get(offset as usize).copied(),
            FwCfgContent::File(o, f) => {
                let mut buf = [0u8];
                match f.read_exact_at(&mut buf, o + offset as u64) {
                    Ok(_) => Some(buf[0]),
                    Err(e) => {
                        error!("fw_cfg: reading {f:?}: {e:?}");
                        None
                    }
                }
            }
            FwCfgContent::U32(n) => n.to_le_bytes().get(offset as usize).copied(),
        }
    }

    fn read_data(&mut self) -> u8 {
        let ret = if let Some(content) = self.known_items.get(self.selector as usize) {
            Self::read_content(content, self.data_offset)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            Self::read_content(&item.content, self.data_offset)
        } else {
            error!("fw_cfg: selector {:#x} does not exist.", self.selector);
            None
        };
        if let Some(val) = ret {
            self.data_offset += 1;
            val
        } else {
            0
        }
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let port = offset as u16 + PORT_FW_CFG_SELECTOR;
        let size = data.len();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, _) => {
                error!("fw_cfg: selector register is write-only.");
            }
            (PORT_FW_CFG_DATA, 1) => data[0] = self.read_data(),
            (PORT_FW_CFG_DMA_HI, 4) => {
                unimplemented!()
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                unimplemented!()
            }
            _ => {
                error!("fw_cfg: read unknown port {port:#x} with size {size}.");
            }
        };
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let port = offset as u16 + PORT_FW_CFG_SELECTOR;
        let size = data.size();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, 2) => {
                let mut buf = [0u8; 2];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u16::from_le_bytes(buf);
                self.selector = val;
                self.data_offset = 0;
            }
            (PORT_FW_CFG_DATA, 1) => error!("fw_cfg: data register is read-only."),
            (PORT_FW_CFG_DMA_HI, 4) => {
                unimplemented!()
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                unimplemented!()
            }
            _ => error!(
                "fw_cfg: write 0x{offset:0width$x} to unknown port {port:#x}.",
                width = 2 * size,
            ),
        };
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature() {
        let mut fw_cfg = FwCfg::new();

        let mut data = vec![0u8];

        let mut sig_iter = FW_CFG_DMA_SIGNATURE.into_iter();
        fw_cfg.write(0, 0, &[FW_CFG_SIGNATURE as u8, 0]);
        loop {
            if let Some(char) = sig_iter.next() {
                fw_cfg.read(0, 1, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }
}
