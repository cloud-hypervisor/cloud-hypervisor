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
/// (This includes most of the functinality, besides adding additional
/// items to the fw_cfg device for the firmware)
use bitfield::bitfield;
use std::sync::{Arc, Barrier};
use vm_device::BusDevice;
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::AsBytes;

pub const PORT_FW_CFG_SELECTOR: u16 = 0x510;
pub const PORT_FW_CFG_DATA: u16 = 0x511;
pub const PORT_FW_CFG_DMA_HI: u16 = 0x514;
pub const PORT_FW_CFG_DMA_LO: u16 = 0x518;

pub const FW_CFG_SIGNATURE: u16 = 0x00;
pub const FW_CFG_ID: u16 = 0x01;
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
}

impl Default for FwCfgContent {
    fn default() -> Self {
        FwCfgContent::Slice(&[])
    }
}

#[derive(Debug, Default)]
pub struct FwCfgItem {
    pub content: FwCfgContent,
}

/// https://www.qemu.org/docs/master/specs/fw_cfg.html
#[derive(Default)]
pub struct FwCfg {
    selector: u16,
    data_offset: u32,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
}

bitfield! {
    struct AccessControl(u32);
    impl Debug;
    error, set_error: 0;
    read, _: 1;
    skip, _: 2;
    select, _ : 3;
    write, _ :4;
    selector, _: 31, 16;
}

#[repr(C)]
#[derive(Debug, AsBytes)]
struct FwCfgFilesHeader {
    count_be: u32,
}

impl FwCfg {
    pub fn new() -> FwCfg {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_DMA_SIGNATURE);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        FwCfg {
            selector: 0,
            data_offset: 0,
            items: vec![],
            known_items,
        }
    }

    fn read_content(content: &FwCfgContent, offset: u32) -> Option<u8> {
        match content {
            FwCfgContent::Bytes(b) => b.get(offset as usize).copied(),
            FwCfgContent::Slice(s) => s.get(offset as usize).copied(),
        }
    }

    fn read_data(&mut self) -> u8 {
        let ret = if let Some(content) = self.known_items.get(self.selector as usize) {
            Self::read_content(content, self.data_offset)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            Self::read_content(&item.content, self.data_offset)
        } else {
            log::error!("fw_cfg: selector {:#x} does not exist.", self.selector);
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
                log::error!("fw_cfg: selector register is write-only.");
            }
            (PORT_FW_CFG_DATA, 1) => data[0] = self.read_data(),
            (PORT_FW_CFG_DMA_HI, 4) => {
                unimplemented!()
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                unimplemented!()
            }
            _ => {
                log::error!("fw_cfg: read unknown port {port:#x} with size {size}.");
            }
        };
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let port = offset as u16 + PORT_FW_CFG_SELECTOR;
        let size = data.size();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, 2) => {
                self.selector = data[0] as u16;
                self.data_offset = 0;
            }
            (PORT_FW_CFG_DATA, 1) => log::error!("fw_cfg: data register is read-only."),
            (PORT_FW_CFG_DMA_HI, 4) => {
                unimplemented!()
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                unimplemented!()
            }
            _ => log::error!(
                "fw_cfg: write 0x{offset:0width$x} to unknown port {port:#x}.",
                width = 2 * size,
            ),
        };
        None
    }
}
