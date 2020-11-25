// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
use std::sync::Arc;
use std::{mem, result};

use super::BootProtocol;
use hypervisor::arch::x86::gdt::{gdt_entry, segment_from_gdt};
use hypervisor::x86_64::{FpuState, SpecialRegisters, StandardRegisters};
use layout::{
    BOOT_GDT_START, BOOT_IDT_START, PDE_START, PDPTE_START, PML4_START, PML5_START, PVH_INFO_START,
};
use vm_memory::{Address, Bytes, GuestMemory, GuestMemoryError, GuestMemoryMmap};

#[derive(Debug)]
pub enum Error {
    /// Failed to get SREGs for this CPU.
    GetStatusRegisters(hypervisor::HypervisorCpuError),
    /// Failed to set base registers for this CPU.
    SetBaseRegisters(hypervisor::HypervisorCpuError),
    /// Failed to configure the FPU.
    SetFPURegisters(hypervisor::HypervisorCpuError),
    /// Setting up MSRs failed.
    SetModelSpecificRegisters(hypervisor::HypervisorCpuError),
    /// Failed to set SREGs for this CPU.
    SetStatusRegisters(hypervisor::HypervisorCpuError),
    /// Checking the GDT address failed.
    CheckGDTAddr,
    /// Writing the GDT to RAM failed.
    WriteGDT(GuestMemoryError),
    /// Writing the IDT to RAM failed.
    WriteIDT(GuestMemoryError),
    /// Writing PDPTE to RAM failed.
    WritePDPTEAddress(GuestMemoryError),
    /// Writing PDE to RAM failed.
    WritePDEAddress(GuestMemoryError),
    /// Writing PML4 to RAM failed.
    WritePML4Address(GuestMemoryError),
    /// Writing PML5 to RAM failed.
    WritePML5Address(GuestMemoryError),
}

pub type Result<T> = result::Result<T, Error>;

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_fpu(vcpu: &Arc<dyn hypervisor::Vcpu>) -> Result<()> {
    let fpu: FpuState = FpuState {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(Error::SetFPURegisters)
}

/// Configure Model Specific Registers (MSRs) for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_msrs(vcpu: &Arc<dyn hypervisor::Vcpu>) -> Result<()> {
    vcpu.set_msrs(&hypervisor::x86_64::boot_msr_entries())
        .map_err(Error::SetModelSpecificRegisters)?;

    Ok(())
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
/// * `boot_sp` - Starting stack pointer.
/// * `boot_si` - Must point to zero page address per Linux ABI.
pub fn setup_regs(
    vcpu: &Arc<dyn hypervisor::Vcpu>,
    boot_ip: u64,
    boot_sp: u64,
    boot_si: u64,
    boot_prot: BootProtocol,
) -> Result<()> {
    let regs: StandardRegisters = match boot_prot {
        // Configure regs as required by PVH boot protocol.
        BootProtocol::PvhBoot => StandardRegisters {
            rflags: 0x0000000000000002u64,
            rbx: PVH_INFO_START.raw_value(),
            rip: boot_ip,
            ..Default::default()
        },
        // Configure regs as required by Linux 64-bit boot protocol.
        BootProtocol::LinuxBoot => StandardRegisters {
            rflags: 0x0000000000000002u64,
            rip: boot_ip,
            rsp: boot_sp,
            rbp: boot_sp,
            rsi: boot_si,
            ..Default::default()
        },
    };
    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_sregs(
    mem: &GuestMemoryMmap,
    vcpu: &Arc<dyn hypervisor::Vcpu>,
    boot_prot: BootProtocol,
) -> Result<()> {
    let mut sregs: SpecialRegisters = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    configure_segments_and_sregs(mem, &mut sregs, boot_prot)?;

    if let BootProtocol::LinuxBoot = boot_prot {
        setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead?
    }

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x80000000;
const X86_CR4_PAE: u64 = 0x20;
const X86_CR4_LA57: u64 = 0x1000;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_gdt_addr = BOOT_GDT_START;
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::CheckGDTAddr)?;
        guest_mem.write_obj(*entry, addr).map_err(Error::WriteGDT)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_idt_addr = BOOT_IDT_START;
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(Error::WriteIDT)
}

pub fn configure_segments_and_sregs(
    mem: &GuestMemoryMmap,
    sregs: &mut SpecialRegisters,
    boot_prot: BootProtocol,
) -> Result<()> {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = match boot_prot {
        BootProtocol::PvhBoot => {
            // Configure GDT entries as specified by PVH boot protocol
            [
                gdt_entry(0, 0, 0),               // NULL
                gdt_entry(0xc09b, 0, 0xffffffff), // CODE
                gdt_entry(0xc093, 0, 0xffffffff), // DATA
                gdt_entry(0x008b, 0, 0x67),       // TSS
            ]
        }
        BootProtocol::LinuxBoot => {
            // Configure GDT entries as specified by Linux 64bit boot protocol
            [
                gdt_entry(0, 0, 0),            // NULL
                gdt_entry(0xa09b, 0, 0xfffff), // CODE
                gdt_entry(0xc093, 0, 0xfffff), // DATA
                gdt_entry(0x808b, 0, 0xfffff), // TSS
            ]
        }
    };

    let code_seg = segment_from_gdt(gdt_table[1], 1);
    let data_seg = segment_from_gdt(gdt_table[2], 2);
    let tss_seg = segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_START.raw_value();
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_START.raw_value();
    sregs.idt.limit = mem::size_of::<u64>() as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    match boot_prot {
        BootProtocol::PvhBoot => {
            sregs.cr0 = X86_CR0_PE;
            sregs.cr4 = 0;
        }
        BootProtocol::LinuxBoot => {
            /* 64-bit protected mode */
            sregs.cr0 |= X86_CR0_PE;
            sregs.efer |= EFER_LME | EFER_LMA;
        }
    }

    Ok(())
}

pub fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut SpecialRegisters) -> Result<()> {
    // Puts PML5 or PML4 right after zero page but aligned to 4k.
    if unsafe { std::arch::x86_64::__cpuid(7).ecx } & (1 << 16) != 0 {
        // Entry covering VA [0..256TB)
        mem.write_obj(PML4_START.raw_value() | 0x03, PML5_START)
            .map_err(Error::WritePML5Address)?;

        sregs.cr3 = PML5_START.raw_value();
        sregs.cr4 |= X86_CR4_LA57;
    } else {
        sregs.cr3 = PML4_START.raw_value();
    }

    // Entry covering VA [0..512GB)
    mem.write_obj(PDPTE_START.raw_value() | 0x03, PML4_START)
        .map_err(Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj(PDE_START.raw_value() | 0x03, PDPTE_START)
        .map_err(Error::WritePDPTEAddress)?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, PDE_START.unchecked_add(i * 8))
            .map_err(Error::WritePDEAddress)?;
    }

    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate vm_memory;

    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: GuestAddress) -> u64 {
        gm.read_obj(offset).unwrap()
    }

    #[test]
    fn segments_and_sregs() {
        let mut sregs: SpecialRegisters = Default::default();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut sregs, BootProtocol::LinuxBoot).unwrap();

        assert_eq!(0x0, read_u64(&gm, BOOT_GDT_START));
        assert_eq!(
            0xaf9b000000ffff,
            read_u64(&gm, BOOT_GDT_START.unchecked_add(8))
        );
        assert_eq!(
            0xcf93000000ffff,
            read_u64(&gm, BOOT_GDT_START.unchecked_add(16))
        );
        assert_eq!(
            0x8f8b000000ffff,
            read_u64(&gm, BOOT_GDT_START.unchecked_add(24))
        );
        assert_eq!(0x0, read_u64(&gm, BOOT_IDT_START));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xffffffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xffffffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert_eq!(X86_CR0_PE, sregs.cr0);
        assert_eq!(EFER_LME | EFER_LMA, sregs.efer);

        configure_segments_and_sregs(&gm, &mut sregs, BootProtocol::PvhBoot).unwrap();
        assert_eq!(0x0, read_u64(&gm, BOOT_GDT_START));
        assert_eq!(
            0xcf9b000000ffff,
            read_u64(&gm, BOOT_GDT_START.unchecked_add(8))
        );
        assert_eq!(
            0xcf93000000ffff,
            read_u64(&gm, BOOT_GDT_START.unchecked_add(16))
        );
        assert_eq!(
            0x8b0000000067,
            read_u64(&gm, BOOT_GDT_START.unchecked_add(24))
        );
        assert_eq!(0x0, read_u64(&gm, BOOT_IDT_START));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xffffffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0, sregs.tr.g);
        assert_eq!(0x67, sregs.tr.limit);
        assert_eq!(0xb, sregs.tr.type_);
        assert_eq!(0, sregs.tr.avl);
        assert_eq!(X86_CR0_PE, sregs.cr0);
        assert_eq!(0, sregs.cr4);
    }

    #[test]
    fn page_tables() {
        let mut sregs: SpecialRegisters = Default::default();
        let gm = create_guest_mem();
        setup_page_tables(&gm, &mut sregs).unwrap();

        if unsafe { std::arch::x86_64::__cpuid(7).ecx } & (1 << 16) != 0 {
            assert_eq!(0xa003, read_u64(&gm, PML5_START));
        }
        assert_eq!(0xb003, read_u64(&gm, PML4_START));
        assert_eq!(0xc003, read_u64(&gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!(
                (i << 21) + 0x83u64,
                read_u64(&gm, PDE_START.unchecked_add(i * 8))
            );
        }

        if unsafe { std::arch::x86_64::__cpuid(7).ecx } & (1 << 16) != 0 {
            assert_eq!(PML5_START.raw_value(), sregs.cr3);
        } else {
            assert_eq!(PML4_START.raw_value(), sregs.cr3);
        }
        assert_eq!(X86_CR4_PAE, sregs.cr4);
        assert_eq!(X86_CR0_PG, sregs.cr0);
    }
}
