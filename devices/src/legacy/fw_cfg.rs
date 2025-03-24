// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

/// NOTE: This is not a full implementation of the qemu fw_cfg spec.
/// We implement the functionality necessary to use Oak's Stage0 Firmware
/// (This includes most of the functionality, besides adding additional
/// items to the fw_cfg device for the firmware).
use std::{
    fs::File,
    io::Result,
    mem::{size_of, size_of_val},
    os::unix::fs::FileExt,
    sync::{Arc, Barrier},
};

#[cfg(target_arch = "x86_64")]
use linux_loader::bootparam::boot_params;
use vm_device::BusDevice;
use vm_memory::ByteValued;
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{FromBytes, IntoBytes};

// TODO: make arm64_image_header public in linux loader crate
// https://github.com/rust-vmm/linux-loader/blob/main/src/loader/pe/mod.rs#L78
#[cfg(target_arch = "aarch64")]
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct boot_params {
    code0: u32,
    code1: u32,
    text_offset: u64,
    image_size: u64,
    flags: u64,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: u32,
    res5: u32,
}
// SAFETY: boot_params is only data, reading it from data is a safe initialization.
#[cfg(target_arch = "aarch64")]
unsafe impl ByteValued for boot_params {}

#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_SELECTOR: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_DATA: u64 = 0x511;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_DMA_HI: u64 = 0x514;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_DMA_LO: u64 = 0x518;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_BASE: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0xc;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_SELECTOR: u64 = 0x9020008;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_DATA: u64 = 0x9020000;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_DMA_HI: u64 = 0x9020010;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_DMA_LO: u64 = 0x9020014;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_BASE: u64 = 0x9020000;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0x10;

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

    pub fn add_kernel_data(&mut self, file: &File) -> Result<()> {
        let mut buffer = vec![0u8; size_of::<boot_params>()];
        file.read_exact_at(&mut buffer, 0)?;
        let bp = boot_params::from_mut_slice(&mut buffer).unwrap();
        #[cfg(target_arch = "x86_64")]
        {
            if bp.hdr.setup_sects == 0 {
                bp.hdr.setup_sects = 4;
            }
            bp.hdr.type_of_loader = 0xff;
        }
        #[cfg(target_arch = "aarch64")]
        let kernel_start = bp.text_offset;
        #[cfg(target_arch = "x86_64")]
        let kernel_start = (bp.hdr.setup_sects as usize + 1) * 512;
        self.known_items[FW_CFG_SETUP_SIZE as usize] = FwCfgContent::U32(buffer.len() as u32);
        self.known_items[FW_CFG_SETUP_DATA as usize] = FwCfgContent::Bytes(buffer);
        self.known_items[FW_CFG_KERNEL_SIZE as usize] =
            FwCfgContent::U32(file.metadata()?.len() as u32 - kernel_start as u32);
        self.known_items[FW_CFG_KERNEL_DATA as usize] =
            FwCfgContent::File(kernel_start as u64, file.try_clone()?);
        Ok(())
    }

    pub fn add_kernel_cmdline(&mut self, s: std::ffi::CString) {
        let bytes = s.into_bytes_with_nul();
        self.known_items[FW_CFG_CMDLINE_SIZE as usize] = FwCfgContent::U32(bytes.len() as u32);
        self.known_items[FW_CFG_CMDLINE_DATA as usize] = FwCfgContent::Bytes(bytes);
    }

    pub fn add_initramfs_data(&mut self, file: &File) -> Result<()> {
        let initramfs_size = file.metadata()?.len();
        self.known_items[FW_CFG_INITRD_SIZE as usize] = FwCfgContent::U32(initramfs_size as _);
        self.known_items[FW_CFG_INITRD_DATA as usize] = FwCfgContent::File(0, file.try_clone()?);
        Ok(())
    }

    fn read_content(content: &FwCfgContent, offset: u32, data: &mut [u8], size: u32) -> Option<u8> {
        let start = offset as usize;
        let end = start + size as usize;
        match content {
            FwCfgContent::Bytes(b) => {
                if b.len() >= size as usize {
                    data.copy_from_slice(&b[start..end]);
                }
            }
            FwCfgContent::Slice(s) => {
                if s.len() >= size as usize {
                    data.copy_from_slice(&s[start..end]);
                }
            }
            FwCfgContent::File(o, f) => {
                f.read_exact_at(data, o + offset as u64).ok()?;
            }
            FwCfgContent::U32(n) => {
                let bytes = n.to_le_bytes();
                data.copy_from_slice(&bytes[start..end]);
            }
        };
        Some(size as u8)
    }

    fn read_data(&mut self, data: &mut [u8], size: u32) -> u8 {
        let ret = if let Some(content) = self.known_items.get(self.selector as usize) {
            Self::read_content(content, self.data_offset, data, size)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            Self::read_content(&item.content, self.data_offset, data, size)
        } else {
            error!("fw_cfg: selector {:#x} does not exist.", self.selector);
            None
        };
        if let Some(val) = ret {
            self.data_offset += size;
            val
        } else {
            0
        }
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let port = offset + PORT_FW_CFG_BASE;
        let size = data.len();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, _) => {
                error!("fw_cfg: selector register is write-only.");
            }
            (PORT_FW_CFG_DATA, _) => _ = self.read_data(data, size as u32),
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
        let port = offset + PORT_FW_CFG_BASE;
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
    use std::ffi::CString;
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[cfg(target_arch = "x86_64")]
    const SELECTOR_OFFSET: u64 = 0;
    #[cfg(target_arch = "aarch64")]
    const SELECTOR_OFFSET: u64 = 8;
    #[cfg(target_arch = "x86_64")]
    const DATA_OFFSET: u64 = 1;
    #[cfg(target_arch = "aarch64")]
    const DATA_OFFSET: u64 = 0;

    #[test]
    fn test_signature() {
        let mut fw_cfg = FwCfg::new();

        let mut data = vec![0u8];

        let mut sig_iter = FW_CFG_DMA_SIGNATURE.into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        loop {
            if let Some(char) = sig_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }
    #[test]
    fn test_kernel_cmdline() {
        let mut fw_cfg = FwCfg::new();

        let cmdline = *b"cmdline\0";

        fw_cfg.add_kernel_cmdline(CString::from_vec_with_nul(cmdline.to_vec()).unwrap());

        let mut data = vec![0u8];

        let mut cmdline_iter = cmdline.into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_CMDLINE_DATA as u8, 0]);
        loop {
            if let Some(char) = cmdline_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_initram_fs() {
        let mut fw_cfg = FwCfg::new();

        let temp = TempFile::new().unwrap();
        let mut temp_file = temp.as_file();

        let initram_content = b"this is the initramfs";
        let written = temp_file.write(initram_content);
        assert_eq!(written.unwrap(), 21);
        let _ = fw_cfg.add_initramfs_data(temp_file);

        let mut data = vec![0u8];

        let mut initram_iter = (*initram_content).into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_INITRD_DATA as u8, 0]);
        loop {
            if let Some(char) = initram_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }
}
