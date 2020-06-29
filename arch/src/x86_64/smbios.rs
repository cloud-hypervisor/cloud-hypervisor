// Copyright © 2020 Intel Corporation
//
// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use layout::SMBIOS_START;
use std::fmt::{self, Display};
use std::mem;
use std::result;
use std::slice;
use vm_memory::ByteValued;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

#[allow(unused_variables)]
#[derive(Debug)]
pub enum Error {
    /// There was too little guest memory to store the entire SMBIOS table.
    NotEnoughMemory,
    /// The SMBIOS table has too little address space to be stored.
    AddressOverflow,
    /// Failure while zeroing out the memory for the SMBIOS table.
    Clear,
    /// Failure to write SMBIOS entrypoint structure
    WriteSmbiosEp,
    /// Failure to write additional data to memory
    WriteData,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        let description = match self {
            NotEnoughMemory => "There was too little guest memory to store the SMBIOS table",
            AddressOverflow => "The SMBIOS table has too little address space to be stored",
            Clear => "Failure while zeroing out the memory for the SMBIOS table",
            WriteSmbiosEp => "Failure to write SMBIOS entrypoint structure",
            WriteData => "Failure to write additional data to memory",
        };

        write!(f, "SMBIOS error: {}", description)
    }
}

pub type Result<T> = result::Result<T, Error>;

// Constants sourced from SMBIOS Spec 3.2.0.
const SM3_MAGIC_IDENT: &[u8; 5usize] = b"_SM3_";
const BIOS_INFORMATION: u8 = 0;
const SYSTEM_INFORMATION: u8 = 1;
const PCI_SUPPORTED: u64 = 1 << 7;
const IS_VIRTUAL_MACHINE: u8 = 1 << 4;

fn compute_checksum<T: Copy>(v: &T) -> u8 {
    // Safe because we are only reading the bytes within the size of the `T` reference `v`.
    let v_slice = unsafe { slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    (!checksum).wrapping_add(1)
}

#[repr(packed)]
#[derive(Default, Copy)]
pub struct Smbios30Entrypoint {
    pub signature: [u8; 5usize],
    pub checksum: u8,
    pub length: u8,
    pub majorver: u8,
    pub minorver: u8,
    pub docrev: u8,
    pub revision: u8,
    pub reserved: u8,
    pub max_size: u32,
    pub physptr: u64,
}
unsafe impl ByteValued for Smbios30Entrypoint {}

impl Clone for Smbios30Entrypoint {
    fn clone(&self) -> Self {
        *self
    }
}

#[repr(packed)]
#[derive(Default, Copy)]
pub struct SmbiosBiosInfo {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
    pub vendor: u8,
    pub version: u8,
    pub start_addr: u16,
    pub release_date: u8,
    pub rom_size: u8,
    pub characteristics: u64,
    pub characteristics_ext1: u8,
    pub characteristics_ext2: u8,
}

impl Clone for SmbiosBiosInfo {
    fn clone(&self) -> Self {
        *self
    }
}

unsafe impl ByteValued for SmbiosBiosInfo {}

#[repr(packed)]
#[derive(Default, Copy)]
pub struct SmbiosSysInfo {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
    pub manufacturer: u8,
    pub product_name: u8,
    pub version: u8,
    pub serial_number: u8,
    pub uuid: [u8; 16usize],
    pub wake_up_type: u8,
    pub sku: u8,
    pub family: u8,
}

impl Clone for SmbiosSysInfo {
    fn clone(&self) -> Self {
        *self
    }
}

unsafe impl ByteValued for SmbiosSysInfo {}

fn write_and_incr<T: ByteValued>(
    mem: &GuestMemoryMmap,
    val: T,
    mut curptr: GuestAddress,
) -> Result<GuestAddress> {
    mem.write_obj(val, curptr).map_err(|_| Error::WriteData)?;
    curptr = curptr
        .checked_add(mem::size_of::<T>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    Ok(curptr)
}

fn write_string(
    mem: &GuestMemoryMmap,
    val: &str,
    mut curptr: GuestAddress,
) -> Result<GuestAddress> {
    for c in val.as_bytes().iter() {
        curptr = write_and_incr(mem, *c, curptr)?;
    }
    curptr = write_and_incr(mem, 0 as u8, curptr)?;
    Ok(curptr)
}

pub fn setup_smbios(mem: &GuestMemoryMmap) -> Result<()> {
    let physptr = GuestAddress(SMBIOS_START)
        .checked_add(mem::size_of::<Smbios30Entrypoint>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    let mut curptr = physptr;
    let mut handle = 0;

    {
        handle += 1;
        let mut smbios_biosinfo = SmbiosBiosInfo::default();
        smbios_biosinfo.typ = BIOS_INFORMATION;
        smbios_biosinfo.length = mem::size_of::<SmbiosBiosInfo>() as u8;
        smbios_biosinfo.handle = handle;
        smbios_biosinfo.vendor = 1; // First string written in this section
        smbios_biosinfo.version = 2; // Second string written in this section
        smbios_biosinfo.characteristics = PCI_SUPPORTED;
        smbios_biosinfo.characteristics_ext2 = IS_VIRTUAL_MACHINE;
        curptr = write_and_incr(mem, smbios_biosinfo, curptr)?;
        curptr = write_string(mem, "cloud-hypervisor", curptr)?;
        curptr = write_string(mem, "0", curptr)?;
        curptr = write_and_incr(mem, 0 as u8, curptr)?;
    }

    {
        handle += 1;
        let mut smbios_sysinfo = SmbiosSysInfo::default();
        smbios_sysinfo.typ = SYSTEM_INFORMATION;
        smbios_sysinfo.length = mem::size_of::<SmbiosSysInfo>() as u8;
        smbios_sysinfo.handle = handle;
        smbios_sysinfo.manufacturer = 1; // First string written in this section
        smbios_sysinfo.product_name = 2; // Second string written in this section
        curptr = write_and_incr(mem, smbios_sysinfo, curptr)?;
        curptr = write_string(mem, "Cloud Hypervisor", curptr)?;
        curptr = write_string(mem, "cloud-hypervisor", curptr)?;
        curptr = write_and_incr(mem, 0 as u8, curptr)?;
    }

    {
        let mut smbios_ep = Smbios30Entrypoint::default();
        smbios_ep.signature = *SM3_MAGIC_IDENT;
        smbios_ep.length = mem::size_of::<Smbios30Entrypoint>() as u8;
        // SMBIOS rev 3.2.0
        smbios_ep.majorver = 0x03;
        smbios_ep.minorver = 0x02;
        smbios_ep.docrev = 0x00;
        smbios_ep.revision = 0x01; // SMBIOS 3.0
        smbios_ep.max_size = curptr.unchecked_offset_from(physptr) as u32;
        smbios_ep.physptr = physptr.0;
        smbios_ep.checksum = compute_checksum(&smbios_ep);
        mem.write_obj(smbios_ep, GuestAddress(SMBIOS_START))
            .map_err(|_| Error::WriteSmbiosEp)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_size() {
        assert_eq!(
            mem::size_of::<Smbios30Entrypoint>(),
            0x18usize,
            concat!("Size of: ", stringify!(Smbios30Entrypoint))
        );
        assert_eq!(
            mem::size_of::<SmbiosBiosInfo>(),
            0x14usize,
            concat!("Size of: ", stringify!(SmbiosBiosInfo))
        );
        assert_eq!(
            mem::size_of::<SmbiosSysInfo>(),
            0x1busize,
            concat!("Size of: ", stringify!(SmbiosSysInfo))
        );
    }

    #[test]
    fn entrypoint_checksum() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(SMBIOS_START), 4096)]).unwrap();

        setup_smbios(&mem).unwrap();

        let smbios_ep: Smbios30Entrypoint = mem.read_obj(GuestAddress(SMBIOS_START)).unwrap();

        assert_eq!(compute_checksum(&smbios_ep), 0);
    }
}
