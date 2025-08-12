// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::{mem, result, slice};

use libc::c_uchar;
use thiserror::Error;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError};

use super::MAX_SUPPORTED_CPUS_LEGACY;
use crate::GuestMemoryMmap;
use crate::layout::{APIC_START, HIGH_RAM_START, IOAPIC_START};
use crate::x86_64::{get_x2apic_id, mpspec};

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `ByteValued`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct MpcBusWrapper(mpspec::mpc_bus);
#[derive(Copy, Clone, Default)]
struct MpcCpuWrapper(mpspec::mpc_cpu);
#[derive(Copy, Clone, Default)]
struct MpcIntsrcWrapper(mpspec::mpc_intsrc);
#[derive(Copy, Clone, Default)]
struct MpcIoapicWrapper(mpspec::mpc_ioapic);
#[derive(Copy, Clone, Default)]
struct MpcTableWrapper(mpspec::mpc_table);
#[derive(Copy, Clone, Default)]
struct MpcLintsrcWrapper(mpspec::mpc_lintsrc);
#[derive(Copy, Clone, Default)]
struct MpfIntelWrapper(mpspec::mpf_intel);

// SAFETY: These `mpspec` wrapper types are only data, reading them from data is a safe initialization.
unsafe impl ByteValued for MpcBusWrapper {}
// SAFETY: see above
unsafe impl ByteValued for MpcCpuWrapper {}
// SAFETY: see above
unsafe impl ByteValued for MpcIntsrcWrapper {}
// SAFETY: see above
unsafe impl ByteValued for MpcIoapicWrapper {}
// SAFETY: see above
unsafe impl ByteValued for MpcTableWrapper {}
// SAFETY: see above
unsafe impl ByteValued for MpcLintsrcWrapper {}
// SAFETY: see above
unsafe impl ByteValued for MpfIntelWrapper {}

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

pub type Result<T> = result::Result<T, Error>;

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
    // SAFETY: we are only reading the bytes within the size of the `T` reference `v`.
    let v_slice = unsafe { slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

fn compute_mp_size(num_cpus: u32) -> usize {
    mem::size_of::<MpfIntelWrapper>()
        + mem::size_of::<MpcTableWrapper>()
        + mem::size_of::<MpcCpuWrapper>() * (num_cpus as usize)
        + mem::size_of::<MpcIoapicWrapper>()
        + mem::size_of::<MpcBusWrapper>()
        + mem::size_of::<MpcIntsrcWrapper>() * 16
        + mem::size_of::<MpcLintsrcWrapper>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`.
pub fn setup_mptable(
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
        let mut mpf_intel = MpfIntelWrapper(mpspec::mpf_intel::default());
        let size = mem::size_of::<MpfIntelWrapper>() as u64;
        mpf_intel.0.signature = *SMP_MAGIC_IDENT;
        mpf_intel.0.length = 1;
        mpf_intel.0.specification = 4;
        mpf_intel.0.physptr = (base_mp.raw_value() + size) as u32;
        mpf_intel.0.checksum = mpf_intel_compute_checksum(&mpf_intel.0);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(Error::WriteMpfIntel)?;
        base_mp = base_mp.unchecked_add(size);
    }

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(mem::size_of::<MpcTableWrapper>() as u64);

    {
        let size = mem::size_of::<MpcCpuWrapper>();
        for cpu_id in 0..num_cpus {
            let mut mpc_cpu = MpcCpuWrapper(mpspec::mpc_cpu::default());
            mpc_cpu.0.type_ = mpspec::MP_PROCESSOR as u8;
            mpc_cpu.0.apicid = get_x2apic_id(cpu_id, topology) as u8;
            mpc_cpu.0.apicver = APIC_VERSION;
            mpc_cpu.0.cpuflag = mpspec::CPU_ENABLED as u8
                | if cpu_id == 0 {
                    mpspec::CPU_BOOTPROCESSOR as u8
                } else {
                    0
                };
            mpc_cpu.0.cpufeature = CPU_STEPPING;
            mpc_cpu.0.featureflag = CPU_FEATURE_APIC | CPU_FEATURE_FPU;
            mem.write_obj(mpc_cpu, base_mp)
                .map_err(Error::WriteMpcCpu)?;
            base_mp = base_mp.unchecked_add(size as u64);
            checksum = checksum.wrapping_add(compute_checksum(&mpc_cpu.0));
        }
    }
    {
        let size = mem::size_of::<MpcBusWrapper>();
        let mut mpc_bus = MpcBusWrapper(mpspec::mpc_bus::default());
        mpc_bus.0.type_ = mpspec::MP_BUS as u8;
        mpc_bus.0.busid = 0;
        mpc_bus.0.bustype = *BUS_TYPE_ISA;
        mem.write_obj(mpc_bus, base_mp)
            .map_err(Error::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus.0));
    }
    {
        let size = mem::size_of::<MpcIoapicWrapper>();
        let mut mpc_ioapic = MpcIoapicWrapper(mpspec::mpc_ioapic::default());
        mpc_ioapic.0.type_ = mpspec::MP_IOAPIC as u8;
        mpc_ioapic.0.apicid = ioapicid;
        mpc_ioapic.0.apicver = APIC_VERSION;
        mpc_ioapic.0.flags = mpspec::MPC_APIC_USABLE as u8;
        mpc_ioapic.0.apicaddr = IOAPIC_START.0 as u32;
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(Error::WriteMpcIoapic)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic.0));
    }
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..16 {
        let size = mem::size_of::<MpcIntsrcWrapper>();
        let mut mpc_intsrc = MpcIntsrcWrapper(mpspec::mpc_intsrc::default());
        mpc_intsrc.0.type_ = mpspec::MP_INTSRC as u8;
        mpc_intsrc.0.irqtype = mpspec::MP_IRQ_SOURCE_TYPES_MP_INT as u8;
        mpc_intsrc.0.irqflag = mpspec::MP_IRQDIR_DEFAULT as u16;
        mpc_intsrc.0.srcbus = 0;
        mpc_intsrc.0.srcbusirq = i;
        mpc_intsrc.0.dstapic = ioapicid;
        mpc_intsrc.0.dstirq = i;
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc.0));
    }
    {
        let size = mem::size_of::<MpcLintsrcWrapper>();
        let mut mpc_lintsrc = MpcLintsrcWrapper(mpspec::mpc_lintsrc::default());
        mpc_lintsrc.0.type_ = mpspec::MP_LINTSRC as u8;
        mpc_lintsrc.0.irqtype = mpspec::MP_IRQ_SOURCE_TYPES_MP_EXT_INT as u8;
        mpc_lintsrc.0.irqflag = mpspec::MP_IRQDIR_DEFAULT as u16;
        mpc_lintsrc.0.srcbusid = 0;
        mpc_lintsrc.0.srcbusirq = 0;
        mpc_lintsrc.0.destapic = 0;
        mpc_lintsrc.0.destapiclint = 0;
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc.0));
    }
    {
        let size = mem::size_of::<MpcLintsrcWrapper>();
        let mut mpc_lintsrc = MpcLintsrcWrapper(mpspec::mpc_lintsrc::default());
        mpc_lintsrc.0.type_ = mpspec::MP_LINTSRC as u8;
        mpc_lintsrc.0.irqtype = mpspec::MP_IRQ_SOURCE_TYPES_MP_NMI as u8;
        mpc_lintsrc.0.irqflag = mpspec::MP_IRQDIR_DEFAULT as u16;
        mpc_lintsrc.0.srcbusid = 0;
        mpc_lintsrc.0.srcbusirq = 0;
        mpc_lintsrc.0.destapic = 0xFF; /* to all local APICs */
        mpc_lintsrc.0.destapiclint = 1;
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc.0));
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = MpcTableWrapper(mpspec::mpc_table::default());
        mpc_table.0.signature = *MPC_SIGNATURE;
        mpc_table.0.length = table_end.unchecked_offset_from(table_base) as u16;
        mpc_table.0.spec = MPC_SPEC;
        mpc_table.0.oem = *MPC_OEM;
        mpc_table.0.productid = *MPC_PRODUCT_ID;
        mpc_table.0.lapic = APIC_START.0 as u32;
        checksum = checksum.wrapping_add(compute_checksum(&mpc_table.0));
        mpc_table.0.checksum = (!checksum).wrapping_add(1);
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
            mpspec::MP_PROCESSOR => mem::size_of::<MpcCpuWrapper>(),
            mpspec::MP_BUS => mem::size_of::<MpcBusWrapper>(),
            mpspec::MP_IOAPIC => mem::size_of::<MpcIoapicWrapper>(),
            mpspec::MP_INTSRC => mem::size_of::<MpcIntsrcWrapper>(),
            mpspec::MP_LINTSRC => mem::size_of::<MpcLintsrcWrapper>(),
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

        let mpf_intel: MpfIntelWrapper = mem.read_obj(MPTABLE_START).unwrap();

        assert_eq!(
            mpf_intel_compute_checksum(&mpf_intel.0),
            mpf_intel.0.checksum
        );
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem =
            GuestMemoryMmap::from_ranges(&[(MPTABLE_START, compute_mp_size(num_cpus))]).unwrap();

        setup_mptable(MPTABLE_START, &mem, num_cpus, None).unwrap();

        let mpf_intel: MpfIntelWrapper = mem.read_obj(MPTABLE_START).unwrap();
        let mpc_offset = GuestAddress(mpf_intel.0.physptr as GuestUsize);
        let mpc_table: MpcTableWrapper = mem.read_obj(mpc_offset).unwrap();

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
        mem.write_volatile_to(mpc_offset, &mut sum, mpc_table.0.length as usize)
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

            let mpf_intel: MpfIntelWrapper = mem.read_obj(MPTABLE_START).unwrap();
            let mpc_offset = GuestAddress(mpf_intel.0.physptr as GuestUsize);
            let mpc_table: MpcTableWrapper = mem.read_obj(mpc_offset).unwrap();
            let mpc_end = mpc_offset
                .checked_add(mpc_table.0.length as GuestUsize)
                .unwrap();

            let mut entry_offset = mpc_offset
                .checked_add(mem::size_of::<MpcTableWrapper>() as GuestUsize)
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
