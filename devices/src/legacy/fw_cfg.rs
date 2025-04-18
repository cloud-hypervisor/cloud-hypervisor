// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

/// Cloud Hypervisor implementation of Qemu's fw_cfg spec
/// https://www.qemu.org/docs/master/specs/fw_cfg.html
/// Linux kernel fw_cfg driver header
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
/// Uploading files to the guest via fw_cfg is supported for all kernels 4.6+ w/ CONFIG_FW_CFG_SYSFS enabled
/// https://cateee.net/lkddb/web-lkddb/FW_CFG_SYSFS.html
/// No kernel requirement if above functionality is not required,
/// only firmware must implement mechanism to interact with this fw_cfg device
use std::{
    fs::File,
    io::Result,
    mem::{size_of, size_of_val},
    os::unix::fs::FileExt,
    sync::{Arc, Barrier},
};

#[cfg(target_arch = "aarch64")]
use arch::aarch64::layout::{
    MEM_32BIT_DEVICES_START, MEM_32BIT_RESERVED_START, RAM_64BIT_START, RAM_START as HIGH_RAM_START,
};
#[cfg(target_arch = "x86_64")]
use arch::layout::{
    EBDA_START, HIGH_RAM_START, MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START,
    MEM_32BIT_RESERVED_START, PCI_MMCONFIG_SIZE, PCI_MMCONFIG_START, RAM_64BIT_START,
};
use arch::RegionType;
#[cfg(target_arch = "x86_64")]
use linux_loader::bootparam::boot_params;
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::pe::arm64_image_header as boot_params;
use vm_device::BusDevice;
use vm_memory::ByteValued;
#[cfg(target_arch = "x86_64")]
use vm_memory::GuestAddress;
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{FromBytes, IntoBytes};

#[cfg(target_arch = "x86_64")]
// https://github.com/project-oak/oak/tree/main/stage0_bin#memory-layout
const STAGE0_START_ADDRESS: GuestAddress = GuestAddress(0xfffe_0000);
#[cfg(target_arch = "x86_64")]
const STAGE0_SIZE: usize = 0x2_0000;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_SELECTOR: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DATA: u64 = 0x511;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_HI: u64 = 0x514;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_LO: u64 = 0x518;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_BASE: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0xc;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_SELECTOR: u64 = 0x9030008;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DATA: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_HI: u64 = 0x9030010;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_LO: u64 = 0x9030014;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_BASE: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0x10;

const FW_CFG_SIGNATURE: u16 = 0x00;
const FW_CFG_ID: u16 = 0x01;
const FW_CFG_KERNEL_SIZE: u16 = 0x08;
const FW_CFG_INITRD_SIZE: u16 = 0x0b;
const FW_CFG_KERNEL_DATA: u16 = 0x11;
const FW_CFG_INITRD_DATA: u16 = 0x12;
const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
const FW_CFG_CMDLINE_DATA: u16 = 0x15;
const FW_CFG_SETUP_SIZE: u16 = 0x17;
const FW_CFG_SETUP_DATA: u16 = 0x18;
const FW_CFG_FILE_DIR: u16 = 0x19;
const FW_CFG_KNOWN_ITEMS: usize = 0x20;

pub const FW_CFG_FILE_FIRST: u16 = 0x20;
pub const FW_CFG_DMA_SIGNATURE: [u8; 8] = *b"QEMU CFG";
// Reserved (must be enabled)
const FW_CFG_F_RESERVED: u8 = 1 << 0;
// DMA Toggle Bit (enabled by default)
const FW_CFG_F_DMA: u8 = 1 << 1;
pub const FW_CFG_FEATURE: [u8; 4] = [FW_CFG_F_RESERVED | FW_CFG_F_DMA, 0, 0, 0];

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
#[derive(Debug, Default)]
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
struct BootE820Entry {
    addr: u64,
    size: u64,
    type_: u32,
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

    pub fn add_e820(&mut self, mem_size: usize) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        let mut mem_regions = vec![
            (GuestAddress(0), EBDA_START.0 as usize, RegionType::Ram),
            (
                MEM_32BIT_DEVICES_START,
                MEM_32BIT_DEVICES_SIZE as usize,
                RegionType::Reserved,
            ),
            (
                PCI_MMCONFIG_START,
                PCI_MMCONFIG_SIZE as usize,
                RegionType::Reserved,
            ),
            (STAGE0_START_ADDRESS, STAGE0_SIZE, RegionType::Reserved),
        ];
        #[cfg(target_arch = "aarch64")]
        let mut mem_regions = arch::aarch64::arch_memory_regions();
        if mem_size < MEM_32BIT_DEVICES_START.0 as usize {
            mem_regions.push((
                HIGH_RAM_START,
                mem_size - HIGH_RAM_START.0 as usize,
                RegionType::Ram,
            ));
        } else {
            mem_regions.push((
                HIGH_RAM_START,
                MEM_32BIT_RESERVED_START.0 as usize - HIGH_RAM_START.0 as usize,
                RegionType::Ram,
            ));
            mem_regions.push((
                RAM_64BIT_START,
                mem_size - (MEM_32BIT_DEVICES_START.0 as usize),
                RegionType::Ram,
            ));
        }
        let mut bytes = vec![];
        for (addr, size, region) in mem_regions.iter() {
            let type_ = match region {
                RegionType::Ram => E820_RAM,
                RegionType::Reserved => E820_RESERVED,
                RegionType::SubRegion => continue,
            };
            let mut entry = BootE820Entry {
                addr: addr.0,
                size: *size as u64,
                type_,
            };
            bytes.extend_from_slice(entry.as_mut_bytes());
        }
        let item = FwCfgItem {
            name: "etc/e820".to_owned(),
            content: FwCfgContent::Bytes(bytes),
        };
        self.add_item(item)
    }

    fn file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let mut header = FwCfgFilesHeader {
            count_be: (self.items.len() as u32).to_be(),
        };
        self.file_dir_mut()[0..4].copy_from_slice(header.as_mut_bytes());
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
        self.file_dir_mut()
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
            // must set to 4 for backwards compatibility
            // https://docs.kernel.org/arch/x86/boot.html#the-real-mode-kernel-header
            if bp.hdr.setup_sects == 0 {
                bp.hdr.setup_sects = 4;
            }
            // wildcard boot loader type
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
                debug!("fw_cfg: read from unknown port {port:#x}: {size:#x} bytes and offset {offset:#x}.");
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
                #[cfg(target_arch = "x86_64")]
                let val = u16::from_le_bytes(buf);
                #[cfg(target_arch = "aarch64")]
                let val = u16::from_be_bytes(buf);
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
            _ => debug!(
                "fw_cfg: write to unknown port {port:#x}: {size:#x} bytes and offset {offset:#x} ."
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
