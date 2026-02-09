// Copyright © 2020 Intel Corporation
//
// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::{mem, result, slice};

use thiserror::Error;
use uuid::Uuid;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress};

use crate::GuestMemoryMmap;
use crate::layout::SMBIOS_START;

#[derive(Debug, Error)]
pub enum Error {
    /// There was too little guest memory to store the entire SMBIOS table.
    #[error("There was too little guest memory to store the SMBIOS table")]
    NotEnoughMemory,
    /// The SMBIOS table has too little address space to be stored.
    #[error("The SMBIOS table has too little address space to be stored")]
    AddressOverflow,
    /// Failure while zeroing out the memory for the SMBIOS table.
    #[error("Failure while zeroing out the memory for the SMBIOS table")]
    Clear,
    /// Failure to write SMBIOS entrypoint structure
    #[error("Failure to write SMBIOS entrypoint structure")]
    WriteSmbiosEp,
    /// Failure to write additional data to memory
    #[error("Failure to write additional data to memory")]
    WriteData,
    /// Failure to parse uuid, uuid format may be error
    #[error("Failure to parse uuid: {1}")]
    ParseUuid(#[source] uuid::Error, String),
    /// SMBIOS string index overflow (u8 limit reached).
    #[error("SMBIOS string index overflow (u8 limit reached: {})", u8::MAX)]
    TooManyStrings,
}

pub type Result<T> = result::Result<T, Error>;

// Constants sourced from SMBIOS Spec 3.9.0.
const SM3_MAGIC_IDENT: &[u8; 5usize] = b"_SM3_";
const BIOS_INFORMATION: u8 = 0;
const SYSTEM_INFORMATION: u8 = 1;
const OEM_STRINGS: u8 = 11;
const SYSTEM_ENCLOSURE: u8 = 3;
const END_OF_TABLE: u8 = 127;
const SYSTEM_WAKE_UP_TYPE_UNKNOWN: u8 = 0x02;
const CHASSIS_TYPE_UNKNOWN: u8 = 0x02;
const CHASSIS_STATE_UNKNOWN: u8 = 0x02;
const CHASSIS_SECURITY_STATUS_NONE: u8 = 0x03;
const PCI_SUPPORTED: u64 = 1 << 7;
const IS_VIRTUAL_MACHINE: u8 = 1 << 4;
pub const DEFAULT_SYSTEM_MANUFACTURER: &str = "Cloud Hypervisor";
pub const DEFAULT_SYSTEM_PRODUCT_NAME: &str = "cloud-hypervisor";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmbiosConfig {
    pub system: Option<SmbiosSystem>,
    pub chassis: Option<SmbiosChassisConfig>,
    pub oem_strings: Box<[String]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmbiosSystem {
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub version: Option<String>,
    pub serial_number: Option<String>,
    pub uuid: Option<String>,
    pub sku_number: Option<String>,
    pub family: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmbiosChassisConfig {
    pub asset_tag: Option<String>,
}

impl SmbiosConfig {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn compute_checksum<T: Copy>(v: &T) -> u8 {
    let v: *const T = v;
    // SAFETY: we are only reading the bytes within the size of the `T` reference `v`.
    let v_slice = unsafe { slice::from_raw_parts(v.cast(), mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    (!checksum).wrapping_add(1)
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct Smbios30Entrypoint {
    signature: [u8; 5usize],
    checksum: u8,
    length: u8,
    majorver: u8,
    minorver: u8,
    docrev: u8,
    revision: u8,
    reserved: u8,
    max_size: u32,
    physptr: u64,
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosBiosInfo {
    r#type: u8,
    length: u8,
    handle: u16,
    vendor: u8,
    version: u8,
    start_addr: u16,
    release_date: u8,
    rom_size: u8,
    characteristics: u64,
    characteristics_ext1: u8,
    characteristics_ext2: u8,
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosSysInfo {
    r#type: u8,
    length: u8,
    handle: u16,
    manufacturer: u8,
    product_name: u8,
    version: u8,
    serial_number: u8,
    uuid: [u8; 16usize],
    wake_up_type: u8,
    sku: u8,
    family: u8,
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosOemStrings {
    r#type: u8,
    length: u8,
    handle: u16,
    count: u8,
}

/// SMBIOS Chassis Table (Type 3) as defined in DMTF SMBIOS 3.9.0:
/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.9.0.pdf
/// Note: trailing fields are omitted, so this structure is not complete.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosChassis {
    r#type: u8,
    length: u8,
    handle: u16,
    manufacturer: u8,
    chassis_type: u8,
    version: u8,
    serial_number: u8,
    asset_tag: u8,
    bootup_state: u8,
    power_supply_state: u8,
    thermal_state: u8,
    security_status: u8,
    oem_defined: u32,
    height: u8,
    number_of_power_cords: u8,
    contained_element_count: u8,
    contained_element_record_length: u8,
    // followed by contained element records (optional, variable-length)
    // followed by sku_number: u8, rack_type: u8, rack_height: u8
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosEndOfTable {
    r#type: u8,
    length: u8,
    handle: u16,
}

// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for Smbios30Entrypoint {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for SmbiosBiosInfo {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for SmbiosSysInfo {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for SmbiosOemStrings {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for SmbiosChassis {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for SmbiosEndOfTable {}

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
    curptr = write_and_incr(mem, 0u8, curptr)?;
    Ok(curptr)
}

fn write_opt_string(
    mem: &GuestMemoryMmap,
    s: Option<&str>,
    cur: GuestAddress,
) -> Result<GuestAddress> {
    if let Some(v) = s {
        write_string(mem, v, cur)
    } else {
        Ok(cur)
    }
}

fn write_string_terminator(
    mem: &GuestMemoryMmap,
    cur: GuestAddress,
    has_strings: bool,
) -> Result<GuestAddress> {
    // SMBIOS DSP0134 §6.1.3: if all string-reference fields are 0, follow the
    // formatted section with two null bytes (empty string-set).
    if has_strings {
        write_and_incr(mem, 0u8, cur)
    } else {
        let cur = write_and_incr(mem, 0u8, cur)?;
        write_and_incr(mem, 0u8, cur)
    }
}

/// Allocate the next string index for an SMBIOS string-set.
///
/// Per SMBIOS DSP0134, index `0` means "no string", so valid indices run from
/// `1` to `255`. Returns `0` when `present` is `false`. Otherwise returns the
/// current value of `*next` and advances it by one. Fails with
/// [`Error::TooManyStrings`] once all 255 indices have been used: `next`
/// starts at `1`, so it can only be `0` here after wrapping past `255`.
fn alloc_index(next: &mut u8, present: bool) -> Result<u8> {
    if !present {
        return Ok(0);
    }

    let idx = *next;
    if idx == 0 {
        return Err(Error::TooManyStrings);
    }

    *next = next.wrapping_add(1);
    Ok(idx)
}

fn write_type1_system(
    mem: &GuestMemoryMmap,
    curptr: &mut GuestAddress,
    handle: &mut u16,
    system: Option<&SmbiosSystem>,
) -> Result<()> {
    *handle += 1;

    let manufacturer = system
        .and_then(|s| s.manufacturer.as_deref())
        .unwrap_or(DEFAULT_SYSTEM_MANUFACTURER);
    let product = system
        .and_then(|s| s.product_name.as_deref())
        .unwrap_or(DEFAULT_SYSTEM_PRODUCT_NAME);
    let version = system.and_then(|s| s.version.as_deref());
    let serial = system.and_then(|s| s.serial_number.as_deref());
    let uuid = system.and_then(|s| s.uuid.as_deref());
    let sku = system.and_then(|s| s.sku_number.as_deref());
    let family = system.and_then(|s| s.family.as_deref());

    let uuid_number = uuid
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|e| Error::ParseUuid(e, uuid.unwrap().to_string()))?
        .unwrap_or(Uuid::nil());

    let mut next = 1u8;
    let manufacturer_idx = alloc_index(&mut next, true)?;
    let product_idx = alloc_index(&mut next, true)?;
    let version_idx = alloc_index(&mut next, version.is_some())?;
    let serial_idx = alloc_index(&mut next, serial.is_some())?;
    let sku_idx = alloc_index(&mut next, sku.is_some())?;
    let family_idx = alloc_index(&mut next, family.is_some())?;

    let sys = SmbiosSysInfo {
        r#type: SYSTEM_INFORMATION,
        length: mem::size_of::<SmbiosSysInfo>() as u8,
        handle: *handle,
        manufacturer: manufacturer_idx,
        product_name: product_idx,
        version: version_idx,
        serial_number: serial_idx,
        uuid: uuid_number.to_bytes_le(),
        wake_up_type: SYSTEM_WAKE_UP_TYPE_UNKNOWN,
        sku: sku_idx,
        family: family_idx,
    };

    *curptr = write_and_incr(mem, sys, *curptr)?;
    *curptr = write_string(mem, manufacturer, *curptr)?;
    *curptr = write_string(mem, product, *curptr)?;
    *curptr = write_opt_string(mem, version, *curptr)?;
    *curptr = write_opt_string(mem, serial, *curptr)?;
    *curptr = write_opt_string(mem, sku, *curptr)?;
    *curptr = write_opt_string(mem, family, *curptr)?;
    *curptr = write_and_incr(mem, 0u8, *curptr)?;
    Ok(())
}

fn write_type3_chassis(
    mem: &GuestMemoryMmap,
    curptr: &mut GuestAddress,
    handle: &mut u16,
    chassis: &SmbiosChassisConfig,
) -> Result<()> {
    *handle += 1;

    let asset_tag = chassis.asset_tag.as_deref();
    let mut next = 1u8;
    let asset_idx = alloc_index(&mut next, asset_tag.is_some())?;

    let ch = SmbiosChassis {
        r#type: SYSTEM_ENCLOSURE,
        length: mem::size_of::<SmbiosChassis>() as u8,
        handle: *handle,
        manufacturer: 0,
        chassis_type: CHASSIS_TYPE_UNKNOWN,
        version: 0,
        serial_number: 0,
        asset_tag: asset_idx,
        bootup_state: CHASSIS_STATE_UNKNOWN,
        power_supply_state: CHASSIS_STATE_UNKNOWN,
        thermal_state: CHASSIS_STATE_UNKNOWN,
        security_status: CHASSIS_SECURITY_STATUS_NONE,
        contained_element_count: 0,
        contained_element_record_length: 0,
        ..Default::default()
    };

    *curptr = write_and_incr(mem, ch, *curptr)?;
    *curptr = write_opt_string(mem, asset_tag, *curptr)?;
    *curptr = write_string_terminator(mem, *curptr, asset_tag.is_some())?;
    Ok(())
}

pub fn setup_smbios(mem: &GuestMemoryMmap, smbios: Option<&SmbiosConfig>) -> Result<u64> {
    let system = smbios.and_then(|cfg| cfg.system.as_ref());
    let chassis = smbios.and_then(|cfg| cfg.chassis.as_ref());
    let oem_strings: &[String] = smbios.map_or(&[], |cfg| &cfg.oem_strings);
    let physptr = GuestAddress(SMBIOS_START)
        .checked_add(mem::size_of::<Smbios30Entrypoint>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    let mut curptr = physptr;
    let mut handle = 0;

    {
        handle += 1;
        let smbios_biosinfo = SmbiosBiosInfo {
            r#type: BIOS_INFORMATION,
            length: mem::size_of::<SmbiosBiosInfo>() as u8,
            handle,
            vendor: 1,  // First string written in this section
            version: 2, // Second string written in this section
            characteristics: PCI_SUPPORTED,
            characteristics_ext2: IS_VIRTUAL_MACHINE,
            ..Default::default()
        };
        curptr = write_and_incr(mem, smbios_biosinfo, curptr)?;
        curptr = write_string(mem, "cloud-hypervisor", curptr)?;
        curptr = write_string(mem, "0", curptr)?;
        curptr = write_and_incr(mem, 0u8, curptr)?;
    }

    write_type1_system(mem, &mut curptr, &mut handle, system)?;

    if let Some(chassis) = chassis {
        write_type3_chassis(mem, &mut curptr, &mut handle, chassis)?;
    }

    if !oem_strings.is_empty() {
        handle += 1;

        let smbios_oemstrings = SmbiosOemStrings {
            r#type: OEM_STRINGS,
            length: mem::size_of::<SmbiosOemStrings>() as u8,
            handle,
            count: oem_strings.len() as u8,
        };

        curptr = write_and_incr(mem, smbios_oemstrings, curptr)?;

        for s in oem_strings {
            curptr = write_string(mem, s, curptr)?;
        }

        curptr = write_string_terminator(mem, curptr, true)?;
    }

    {
        handle += 1;
        let smbios_end = SmbiosEndOfTable {
            r#type: END_OF_TABLE,
            length: mem::size_of::<SmbiosEndOfTable>() as u8,
            handle,
        };
        curptr = write_and_incr(mem, smbios_end, curptr)?;
        curptr = write_and_incr(mem, 0u8, curptr)?;
        curptr = write_and_incr(mem, 0u8, curptr)?;
    }

    {
        let mut smbios_ep = Smbios30Entrypoint {
            signature: *SM3_MAGIC_IDENT,
            length: mem::size_of::<Smbios30Entrypoint>() as u8,
            // SMBIOS rev 3.2.0
            majorver: 0x03,
            minorver: 0x02,
            docrev: 0x00,
            revision: 0x01, // SMBIOS 3.0
            max_size: curptr.unchecked_offset_from(physptr) as u32,
            physptr: physptr.0,
            ..Default::default()
        };
        smbios_ep.checksum = compute_checksum(&smbios_ep);
        mem.write_obj(smbios_ep, GuestAddress(SMBIOS_START))
            .map_err(|_| Error::WriteSmbiosEp)?;
    }

    Ok(curptr.unchecked_offset_from(physptr) + std::mem::size_of::<Smbios30Entrypoint>() as u64)
}

#[cfg(test)]
mod unit_tests {
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

        setup_smbios(&mem, None).unwrap();

        let smbios_ep: Smbios30Entrypoint = mem.read_obj(GuestAddress(SMBIOS_START)).unwrap();

        assert_eq!(compute_checksum(&smbios_ep), 0);
    }
}
