// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::result;

use libc::c_uchar;
use log::{info, warn};
use thiserror::Error;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryError};

use super::MAX_SUPPORTED_CPUS_LEGACY;
use crate::GuestMemoryMmap;
use crate::layout::{APIC_START, HIGH_RAM_START, IOAPIC_START};
use crate::x86_64::{get_x2apic_id, mpspec};

#[derive(Debug, Error)]
pub enum Error {
    /// There was too little guest memory to store the entire MP table.
    #[error("There was too little guest memory to store the entire MP table")]
    NotEnoughMemory,
    /// The MP table has too little address space to be stored.
    #[error("The MP table has too little address space to be stored")]
    AddressOverflow,
    /// Failure while zeroing out the memory for the MP table.
    #[error("Failure while zeroing out the memory for the MP table")]
    Clear(#[source] GuestMemoryError),
    /// Failure to write the MP floating pointer.
    #[error("Failure to write the MP floating pointer")]
    WriteMpfIntel(#[source] GuestMemoryError),
    /// Failure to write MP CPU entry.
    #[error("Failure to write MP CPU entry")]
    WriteMpcCpu(#[source] GuestMemoryError),
    /// Failure to write MP ioapic entry.
    #[error("Failure to write MP ioapic entry")]
    WriteMpcIoapic(#[source] GuestMemoryError),
    /// Failure to write MP bus entry.
    #[error("Failure to write MP bus entry")]
    WriteMpcBus(#[source] GuestMemoryError),
    /// Failure to write MP interrupt source entry.
    #[error("Failure to write MP interrupt source entry")]
    WriteMpcIntsrc(#[source] GuestMemoryError),
    /// Failure to write MP local interrupt source entry.
    #[error("Failure to write MP local interrupt source entry")]
    WriteMpcLintsrc(#[source] GuestMemoryError),
    /// Failure to write MP table header.
    #[error("Failure to write MP table header")]
    WriteMpcTable(#[source] GuestMemoryError),
}

pub(super) type Result<T> = result::Result<T, Error>;

// Most of these variables are sourced from the Intel MP Spec 1.4.
const SMP_MAGIC_IDENT: &[c_uchar; 4] = b"_MP_";
const MPC_SIGNATURE: &[c_uchar; 4] = b"PCMP";
const MPC_SPEC: u8 = 4;
const MPC_OEM: &[c_uchar; 8] = b"FC      ";
const MPC_PRODUCT_ID: &[c_uchar; 12] = &[b'0'; 12];
const BUS_TYPE_ISA: &[c_uchar; 6] = b"ISA   ";
const APIC_VERSION: u8 = 0x14;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;

fn compute_checksum<T: Copy + ByteValued>(v: &T) -> u8 {
    let mut checksum: u8 = 0;
    for i in v.as_slice().iter() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

fn compute_mp_size(num_cpus: u32) -> usize {
    size_of::<mpspec::mpf_intel>()
        + size_of::<mpspec::mpc_table>()
        + size_of::<mpspec::mpc_cpu>() * (num_cpus as usize)
        + size_of::<mpspec::mpc_ioapic>()
        + size_of::<mpspec::mpc_bus>()
        + size_of::<mpspec::mpc_intsrc>() * 16
        + size_of::<mpspec::mpc_lintsrc>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`.
pub(super) fn setup_mptable(
    offset: GuestAddress,
    mem: &GuestMemoryMmap,
    num_cpus: u32,
    topology: Option<(u16, u16, u16, u16)>,
) -> Result<()> {
    if num_cpus > 0 {
        let cpu_id_max = num_cpus - 1;
        let x2apic_id_max = get_x2apic_id(cpu_id_max, topology);
        if x2apic_id_max >= MAX_SUPPORTED_CPUS_LEGACY {
            info!("Skipping mptable creation due to too many CPUs");
            return Ok(());
        }
    }

    // Used to keep track of the next base pointer into the MP table.
    let mut base_mp = offset;

    let mp_size = compute_mp_size(num_cpus);

    if offset.unchecked_add(mp_size as u64) >= HIGH_RAM_START {
        warn!("Skipping mptable creation due to insufficient space");
        return Ok(());
    }

    let mut checksum: u8 = 0;
    let ioapicid: u8 = MAX_SUPPORTED_CPUS_LEGACY as u8 + 1;

    // The checked_add here ensures the all of the following base_mp.unchecked_add's will be without
    // overflow.
    if let Some(end_mp) = base_mp.checked_add((mp_size - 1) as u64) {
        if !mem.address_in_range(end_mp) {
            return Err(Error::NotEnoughMemory);
        }
    } else {
        return Err(Error::AddressOverflow);
    }

    mem.read_exact_volatile_from(base_mp, &mut vec![0; mp_size].as_slice(), mp_size)
        .map_err(Error::Clear)?;

    {
        let mut mpf_intel = mpspec::mpf_intel::default();
        let size = size_of::<mpspec::mpf_intel>() as u64;
        mpf_intel.signature = *SMP_MAGIC_IDENT;
        mpf_intel.length = 1;
        mpf_intel.specification = 4;
        mpf_intel.physptr = (base_mp.raw_value() + size) as u32;
        mpf_intel.checksum = mpf_intel_compute_checksum(&mpf_intel);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(Error::WriteMpfIntel)?;
        base_mp = base_mp.unchecked_add(size);
    }

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(size_of::<mpspec::mpc_table>() as u64);

    {
        let size = size_of::<mpspec::mpc_cpu>();
        for cpu_id in 0..num_cpus {
            let mpc_cpu = mpspec::mpc_cpu {
                type_: mpspec::MP_PROCESSOR as u8,
                apicid: get_x2apic_id(cpu_id, topology) as u8,
                apicver: APIC_VERSION,
                cpuflag: mpspec::CPU_ENABLED as u8
                    | if cpu_id == 0 {
                        mpspec::CPU_BOOTPROCESSOR as u8
                    } else {
                        0
                    },
                cpufeature: CPU_STEPPING,
                featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
                ..Default::default()
            };
            mem.write_obj(mpc_cpu, base_mp)
                .map_err(Error::WriteMpcCpu)?;
            base_mp = base_mp.unchecked_add(size as u64);
            checksum = checksum.wrapping_add(compute_checksum(&mpc_cpu));
        }
    }
    {
        let size = size_of::<mpspec::mpc_bus>();
        let mpc_bus = mpspec::mpc_bus {
            type_: mpspec::MP_BUS as u8,
            busid: 0,
            bustype: *BUS_TYPE_ISA,
        };
        mem.write_obj(mpc_bus, base_mp)
            .map_err(Error::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus));
    }
    {
        let size = size_of::<mpspec::mpc_ioapic>();
        let mpc_ioapic = mpspec::mpc_ioapic {
            type_: mpspec::MP_IOAPIC as u8,
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: mpspec::MPC_APIC_USABLE as u8,
            apicaddr: IOAPIC_START.0 as u32,
        };
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(Error::WriteMpcIoapic)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic));
    }
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..16 {
        let size = size_of::<mpspec::mpc_intsrc>();
        let mpc_intsrc = mpspec::mpc_intsrc {
            type_: mpspec::MP_INTSRC as u8,
            irqtype: mpspec::MP_IRQ_SOURCE_TYPES_MP_INT as u8,
            irqflag: mpspec::MP_IRQDIR_DEFAULT as u16,
            srcbus: 0,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc));
    }
    {
        let size = size_of::<mpspec::mpc_lintsrc>();
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC as u8,
            irqtype: mpspec::MP_IRQ_SOURCE_TYPES_MP_EXT_INT as u8,
            irqflag: mpspec::MP_IRQDIR_DEFAULT as u16,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
    }
    {
        let size = size_of::<mpspec::mpc_lintsrc>();
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC as u8,
            irqtype: mpspec::MP_IRQ_SOURCE_TYPES_MP_NMI as u8,
            irqflag: mpspec::MP_IRQDIR_DEFAULT as u16,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0xFF, /* to all local APICs */
            destapiclint: 1,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = mpspec::mpc_table {
            signature: *MPC_SIGNATURE,
            length: table_end.unchecked_offset_from(table_base) as u16,
            spec: MPC_SPEC,
            oem: *MPC_OEM,
            productid: *MPC_PRODUCT_ID,
            lapic: APIC_START.0 as u32,
            ..Default::default()
        };
        checksum = checksum.wrapping_add(compute_checksum(&mpc_table));
        mpc_table.checksum = (!checksum).wrapping_add(1);
        mem.write_obj(mpc_table, table_base)
            .map_err(Error::WriteMpcTable)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use vm_memory::bitmap::BitmapSlice;
    use vm_memory::{GuestUsize, VolatileMemoryError, VolatileSlice, WriteVolatile};

    use super::*;
    use crate::layout::MPTABLE_START;

    fn table_entry_size(type_: u8) -> usize {
        match type_ as u32 {
            mpspec::MP_PROCESSOR => size_of::<mpspec::mpc_cpu>(),
            mpspec::MP_BUS => size_of::<mpspec::mpc_bus>(),
            mpspec::MP_IOAPIC => size_of::<mpspec::mpc_ioapic>(),
            mpspec::MP_INTSRC => size_of::<mpspec::mpc_intsrc>(),
            mpspec::MP_LINTSRC => size_of::<mpspec::mpc_lintsrc>(),
            _ => panic!("unrecognized mpc table entry type: {type_}"),
        }
    }

    #[test]
    fn bounds_check() {
        let num_cpus = 4;
        let mem =
            GuestMemoryMmap::from_ranges(&[(MPTABLE_START, compute_mp_size(num_cpus))]).unwrap();

        setup_mptable(MPTABLE_START, &mem, num_cpus, None).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 4;
        let mem = GuestMemoryMmap::from_ranges(&[(MPTABLE_START, compute_mp_size(num_cpus) - 1)])
            .unwrap();

        setup_mptable(MPTABLE_START, &mem, num_cpus, None).unwrap_err();
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem =
            GuestMemoryMmap::from_ranges(&[(MPTABLE_START, compute_mp_size(num_cpus))]).unwrap();

        setup_mptable(MPTABLE_START, &mem, num_cpus, None).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(MPTABLE_START).unwrap();

        assert_eq!(mpf_intel_compute_checksum(&mpf_intel), mpf_intel.checksum);
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem =
            GuestMemoryMmap::from_ranges(&[(MPTABLE_START, compute_mp_size(num_cpus))]).unwrap();

        setup_mptable(MPTABLE_START, &mem, num_cpus, None).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(MPTABLE_START).unwrap();
        let mpc_offset = GuestAddress(mpf_intel.physptr as GuestUsize);
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();

        struct Sum(u8);
        impl WriteVolatile for Sum {
            fn write_volatile<B: BitmapSlice>(
                &mut self,
                buf: &VolatileSlice<B>,
            ) -> result::Result<usize, VolatileMemoryError> {
                let mut tmp = vec![0u8; buf.len()];
                tmp.write_all_volatile(buf)?;

                for v in tmp.iter() {
                    self.0 = self.0.wrapping_add(*v);
                }

                Ok(buf.len())
            }
        }

        let mut sum = Sum(0);
        mem.write_volatile_to(mpc_offset, &mut sum, mpc_table.length as usize)
            .unwrap();
        assert_eq!(sum.0, 0);
    }

    #[test]
    fn cpu_entry_count() {
        let mem = GuestMemoryMmap::from_ranges(&[(
            MPTABLE_START,
            compute_mp_size(MAX_SUPPORTED_CPUS_LEGACY),
        )])
        .unwrap();

        for i in 0..MAX_SUPPORTED_CPUS_LEGACY {
            setup_mptable(MPTABLE_START, &mem, i, None).unwrap();

            let mpf_intel: mpspec::mpf_intel = mem.read_obj(MPTABLE_START).unwrap();
            let mpc_offset = GuestAddress(mpf_intel.physptr as GuestUsize);
            let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();
            let mpc_end = mpc_offset
                .checked_add(mpc_table.length as GuestUsize)
                .unwrap();

            let mut entry_offset = mpc_offset
                .checked_add(size_of::<mpspec::mpc_table>() as GuestUsize)
                .unwrap();
            let mut cpu_count = 0;
            while entry_offset < mpc_end {
                let entry_type: u8 = mem.read_obj(entry_offset).unwrap();
                entry_offset = entry_offset
                    .checked_add(table_entry_size(entry_type) as GuestUsize)
                    .unwrap();
                assert!(entry_offset <= mpc_end);
                if entry_type as u32 == mpspec::MP_PROCESSOR {
                    cpu_count += 1;
                }
            }
            assert_eq!(cpu_count, i);
        }
    }

    #[test]
    fn cpu_entry_count_max() {
        let cpus = MAX_SUPPORTED_CPUS_LEGACY + 1;
        let mem = GuestMemoryMmap::from_ranges(&[(MPTABLE_START, compute_mp_size(cpus))]).unwrap();

        setup_mptable(MPTABLE_START, &mem, cpus, None).unwrap();
    }
}
