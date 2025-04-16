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
use crate::acpi::{create_acpi_loader, AcpiTable};
use arch::{
    layout::{
        EBDA_START, HIGH_RAM_START, MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START,
        MEM_32BIT_RESERVED_START, PCI_MMCONFIG_SIZE, PCI_MMCONFIG_START, RAM_64BIT_START,
    },
    RegionType,
};
use bitfield::bitfield;
use linux_loader::bootparam::boot_params;
use std::{
    fs::File,
    io::{ErrorKind, Read, Result, Seek, SeekFrom},
    mem::{size_of, size_of_val},
    os::unix::fs::FileExt,
    sync::{Arc, Barrier},
};
use vm_device::BusDevice;
use vm_memory::{
    bitmap::AtomicBitmap, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryMmap,
};
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{FromBytes, Immutable, IntoBytes, FromZeros};

const STAGE0_START_ADDRESS: GuestAddress = GuestAddress(0xffe0_0000);
const STAGE0_SIZE: usize = 0x20_0000;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

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

struct FwCfgContentAccess<'a> {
    content: &'a FwCfgContent,
    offset: u32,
}

impl Read for FwCfgContentAccess<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.content {
            FwCfgContent::File(offset, f) => {
                Seek::seek(&mut (&*f), SeekFrom::Start(offset + self.offset as u64))?;
                Read::read(&mut (&*f), buf)
            }
            FwCfgContent::Bytes(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Slice(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::U32(n) => match n.to_le_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
        }
    }
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
    fn access(&self, offset: u32) -> FwCfgContentAccess {
        FwCfgContentAccess {
            content: self,
            offset,
        }
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
    dma_address: u64,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable)]
struct FwCfgDmaAccess {
    control_be: u32,
    length_be: u32,
    address_be: u64,
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
#[derive(Debug, IntoBytes, Immutable)]
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
#[derive(Debug, IntoBytes, FromBytes, Clone, Copy, Immutable)]
pub struct BootE820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
struct FwCfgFile {
    size_be: u32,
    select_be: u16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

impl FwCfg {
    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>) -> FwCfg {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_DMA_SIGNATURE);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        FwCfg {
            selector: 0,
            data_offset: 0,
            dma_address: 0,
            items: vec![],
            known_items,
            memory,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_e820(&mut self, mem_size: usize) -> Result<()> {
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
            let entry = BootE820Entry {
                addr: addr.0,
                size: *size as u64,
                type_,
            };
            bytes.extend_from_slice(entry.as_bytes());
        }
        let item = FwCfgItem {
            name: "etc/e820".to_owned(),
            content: FwCfgContent::Bytes(bytes),
        };
        self.add_item(item)
    }

    fn get_file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let header = FwCfgFilesHeader {
            count_be: (self.items.len() as u32).to_be(),
        };
        self.get_file_dir_mut()[0..4].copy_from_slice(header.as_bytes());
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let index = self.items.len();
        let c_name = create_file_name(&item.name);
        let size = item.content.size()?;
        let cfg_file = FwCfgFile {
            size_be: size.to_be(),
            select_be: (FW_CFG_FILE_FIRST + index as u16).to_be(),
            _reserved: 0,
            name: c_name,
        };
        self.get_file_dir_mut()
            .extend_from_slice(cfg_file.as_bytes());
        self.items.push(item);
        self.update_count();
        Ok(())
    }

    fn dma_read_content(
        &self,
        content: &FwCfgContent,
        offset: u32,
        len: u32,
        address: u64,
    ) -> Result<u32> {
        let content_size = content.size()?.saturating_sub(offset);
        let op_size = std::cmp::min(content_size, len);
        let mut access = content.access(offset);
        let mut buf = vec![0u8; op_size as usize];
        access.read_exact(buf.as_mut_bytes())?;
        let r = self
            .memory
            .memory()
            .write(buf.as_bytes(), GuestAddress(address));
        match r {
            Err(e) => {
                error!("fw_cfg: dma read error: {e:x?}");
                Err(ErrorKind::InvalidInput.into())
            }
            Ok(size) => Ok(size as u32),
        }
    }

    fn dma_read(&mut self, selector: u16, len: u32, address: u64) -> Result<()> {
        let op_size = if let Some(content) = self.known_items.get(selector as usize) {
            self.dma_read_content(content, self.data_offset, len, address)
        } else if let Some(item) = self.items.get((selector - FW_CFG_FILE_FIRST) as usize) {
            self.dma_read_content(&item.content, self.data_offset, len, address)
        } else {
            error!("fw_cfg: selector {selector:#x} does not exist.");
            Err(ErrorKind::NotFound.into())
        }?;
        self.data_offset += op_size;
        Ok(())
    }

    fn dma_write(&self, _selector: u16, _len: u32, _address: u64) -> Result<()> {
        unimplemented!()
    }

    fn do_dma(&mut self) {
        let dma_address = self.dma_address;
        let mut access = FwCfgDmaAccess::new_zeroed();
        let dma_access = match self
            .memory
            .memory()
            .read(access.as_mut_bytes(), GuestAddress(dma_address))
        {
            Ok(_) => access,
            Err(e) => {
                error!("fw_cfg: invalid address of dma access {dma_address:#x}: {e:?}");
                return;
            }
        };
        let control = AccessControl(u32::from_be(dma_access.control_be));
        if control.select() {
            self.selector = control.select() as u16;
        }
        let len = u32::from_be(dma_access.length_be);
        let addr = u64::from_be(dma_access.address_be);
        let ret = if control.read() {
            self.dma_read(self.selector, len, addr)
        } else if control.write() {
            self.dma_write(self.selector, len, addr)
        } else if control.skip() {
            self.data_offset += len;
            Ok(())
        } else {
            Err(ErrorKind::InvalidData.into())
        };
        let mut access_resp = AccessControl(0);
        if let Err(e) = ret {
            error!("fw_cfg: dma operation {dma_access:x?}: {e:x?}");
            access_resp.set_error(true);
        }
        if let Err(e) = self.memory.memory().write(
            &access_resp.0.to_be_bytes(),
            GuestAddress(dma_address + core::mem::offset_of!(FwCfgDmaAccess, control_be) as u64),
        ) {
            error!("fw_cfg: finishing dma: {e:?}")
        }
    }

    pub fn add_kernel_data(&mut self, file: &File) -> Result<()> {
        let mut buffer = vec![0u8; size_of::<boot_params>()];
        file.read_exact_at(&mut buffer, 0)?;
        let bp = boot_params::from_mut_slice(&mut buffer).unwrap();
        if bp.hdr.setup_sects == 0 {
            bp.hdr.setup_sects = 4;
        }
        bp.hdr.type_of_loader = 0xff;
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

    #[cfg(target_arch = "x86_64")]
    pub fn add_acpi(&mut self, acpi_table: AcpiTable) -> Result<()> {
        let [table_loader, acpi_rsdp, apci_tables] = create_acpi_loader(acpi_table);
        self.add_item(table_loader)?;
        self.add_item(acpi_rsdp)?;
        self.add_item(apci_tables)
    }

    pub fn add_initramfs_data(&mut self, file: &File) -> Result<()> {
        let initramfs_size = file.metadata()?.len();
        self.known_items[FW_CFG_INITRD_SIZE as usize] = FwCfgContent::U32(initramfs_size as _);
        self.known_items[FW_CFG_INITRD_DATA as usize] = FwCfgContent::File(0, file.try_clone()?);
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
                let addr = self.dma_address;
                let addr_hi = (addr >> 32) as u32;
                data.copy_from_slice(&addr_hi.to_be_bytes());
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                let addr = self.dma_address;
                let addr_lo = (addr & 0xffff_ffff) as u32;
                data.copy_from_slice(&addr_lo.to_be_bytes());
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
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                self.dma_address &= 0xffff_ffff;
                self.dma_address |= (val as u64) << 32;
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                self.dma_address &= !0xffff_ffff;
                self.dma_address |= val as u64;
                self.do_dma();
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

    #[test]
    fn test_signature() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

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
    #[test]
    fn test_kernel_cmdline() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let cmdline = *b"cmdline\0";

        fw_cfg.add_kernel_cmdline(CString::from_vec_with_nul(cmdline.to_vec()).unwrap());

        let mut data = vec![0u8];

        let mut cmdline_iter = cmdline.into_iter();
        fw_cfg.write(0, 0, &[FW_CFG_CMDLINE_DATA as u8, 0]);
        loop {
            if let Some(char) = cmdline_iter.next() {
                fw_cfg.read(0, 1, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_initram_fs() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let temp = TempFile::new().unwrap();
        let mut temp_file = temp.as_file();

        let initram_content = b"this is the initramfs";
        let written = temp_file.write(initram_content);
        assert_eq!(written.unwrap(), 21);
        let _ = fw_cfg.add_initramfs_data(temp_file);

        let mut data = vec![0u8];

        let mut initram_iter = (*initram_content).into_iter();
        fw_cfg.write(0, 0, &[FW_CFG_INITRD_DATA as u8, 0]);
        loop {
            if let Some(char) = initram_iter.next() {
                fw_cfg.read(0, 1, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_dma() {
        use bitfield::BitMut;
        let code = [
            0xba, 0xf8, 0x03, 0x00, 0xd8, 0x04, b'0', 0xee, 0xb0, b'\n', 0xee, 0xf4,
        ];

        let content = FwCfgContent::Bytes(code.to_vec());

        let mem_size = 0x1000;
        let load_addr = GuestAddress(0x1000);
        let mem: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&[(load_addr, mem_size)]).unwrap();

        // Note: In firmware we would just allocate FwCfgDmaAccess struct
        // and use address of struct (&) as dma address
        let mut access_control = AccessControl(0);
        // bit 1 = read access
        access_control.set_bit(1, true);
        // length of data to access
        let length_be = (code.len() as u32).to_be();
        // guest address for data
        let code_address = 0x1900_u64;
        let address_be = code_address.to_be();
        let mut access = FwCfgDmaAccess {
            control_be: access_control.0.to_be(), // bit(1) = read bit
            length_be,
            address_be,
        };
        // access address is where to put the code
        let access_address = GuestAddress(load_addr.0);
        let address_bytes = access_address.0.to_be_bytes();
        let dma_lo: [u8; 4] = address_bytes[0..4].try_into().unwrap();
        let dma_hi: [u8; 4] = address_bytes[4..8].try_into().unwrap();

        // writing the FwCfgDmaAccess to mem (this would just be self.dma_acess.as_ref() in guest)
        let _ = mem.write(access.as_bytes_mut(), access_address);
        let mem_m = GuestMemoryAtomic::new(mem.clone());
        let mut fw_cfg = FwCfg::new(mem_m);
        let cfg_item = FwCfgItem {
            name: "code".to_string(),
            content,
        };
        let _ = fw_cfg.add_item(cfg_item);

        let mut data = [0u8; 12];

        let _ = mem.read(&mut data, GuestAddress(code_address));
        assert_ne!(data, code);

        fw_cfg.write(0, 0, &[FW_CFG_FILE_FIRST as u8, 0]);
        fw_cfg.write(0, 4, &dma_lo);
        fw_cfg.write(0, 8, &dma_hi);
        let _ = mem.read(&mut data, GuestAddress(code_address));
        assert_eq!(data, code);
    }
}
