// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::{mem, result};

use super::gdt::{gdt_entry, kvm_segment_from_gdt};
use super::BootProtocol;
use arch_gen::x86::msr_index;
use kvm_bindings::{kvm_fpu, kvm_msr_entry, kvm_regs, kvm_sregs, Msrs};
use kvm_ioctls::VcpuFd;
use layout::{BOOT_GDT_START, BOOT_IDT_START, PDE_START, PDPTE_START, PML4_START, PVH_INFO_START};
use vm_memory::{Address, Bytes, GuestMemory, GuestMemoryError, GuestMemoryMmap};

// MTRR constants
const MTRR_ENABLE: u64 = 0x800; // IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
const MTRR_MEM_TYPE_WB: u64 = 0x6;

#[derive(Debug)]
pub enum Error {
    /// Failed to get SREGs for this CPU.
    GetStatusRegisters(kvm_ioctls::Error),
    /// Failed to set base registers for this CPU.
    SetBaseRegisters(kvm_ioctls::Error),
    /// Failed to configure the FPU.
    SetFPURegisters(kvm_ioctls::Error),
    /// Setting up MSRs failed.
    SetModelSpecificRegisters(kvm_ioctls::Error),
    /// Failed to set SREGs for this CPU.
    SetStatusRegisters(kvm_ioctls::Error),
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
}

pub type Result<T> = result::Result<T, Error>;

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<()> {
    let fpu: kvm_fpu = kvm_fpu {
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
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<()> {
    vcpu.set_msrs(&create_msr_entries())
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
    vcpu: &VcpuFd,
    boot_ip: u64,
    boot_sp: u64,
    boot_si: u64,
    boot_prot: BootProtocol,
) -> Result<()> {
    let regs: kvm_regs = match boot_prot {
        // Configure regs as required by PVH boot protocol.
        BootProtocol::PvhBoot => kvm_regs {
            rflags: 0x0000000000000002u64,
            rbx: PVH_INFO_START.raw_value(),
            rip: boot_ip,
            ..Default::default()
        },
        // Configure regs as required by Linux 64-bit boot protocol.
        BootProtocol::LinuxBoot => kvm_regs {
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
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &VcpuFd, boot_prot: BootProtocol) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

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

fn configure_segments_and_sregs(
    mem: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
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

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

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

fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    // Puts PML4 right after zero page but aligned to 4k.

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

    sregs.cr3 = PML4_START.raw_value();
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

macro_rules! KVM_MSR {
    ($msr:expr) => {
        kvm_msr_entry {
            index: $msr,
            data: 0x0,
            ..Default::default()
        }
    };
}

macro_rules! KVM_MSR_DATA {
    ($msr:expr, $data:expr) => {
        kvm_msr_entry {
            index: $msr,
            data: $data,
            ..Default::default()
        }
    };
}

fn create_msr_entries() -> Msrs {
    Msrs::from_entries(&[
        KVM_MSR!(msr_index::MSR_IA32_SYSENTER_CS),
        KVM_MSR!(msr_index::MSR_IA32_SYSENTER_ESP),
        KVM_MSR!(msr_index::MSR_IA32_SYSENTER_EIP),
        KVM_MSR!(msr_index::MSR_STAR),
        KVM_MSR!(msr_index::MSR_CSTAR),
        KVM_MSR!(msr_index::MSR_LSTAR),
        KVM_MSR!(msr_index::MSR_KERNEL_GS_BASE),
        KVM_MSR!(msr_index::MSR_SYSCALL_MASK),
        KVM_MSR!(msr_index::MSR_IA32_TSC),
        KVM_MSR_DATA!(
            msr_index::MSR_IA32_MISC_ENABLE,
            msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
        ),
        KVM_MSR_DATA!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
    ])
}

#[cfg(test)]
mod tests {
    extern crate kvm_ioctls;
    extern crate vm_memory;

    use super::*;
    use kvm_ioctls::Kvm;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&vec![(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: GuestAddress) -> u64 {
        gm.read_obj(offset).unwrap()
    }

    #[test]
    fn segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
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
        let mut sregs: kvm_sregs = Default::default();
        let gm = create_guest_mem();
        setup_page_tables(&gm, &mut sregs).unwrap();

        assert_eq!(0xa003, read_u64(&gm, PML4_START));
        assert_eq!(0xb003, read_u64(&gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!(
                (i << 21) + 0x83u64,
                read_u64(&gm, PDE_START.unchecked_add(i * 8))
            );
        }

        assert_eq!(PML4_START.raw_value(), sregs.cr3);
        assert_eq!(X86_CR4_PAE, sregs.cr4);
        assert_eq!(X86_CR0_PG, sregs.cr0);
    }

    #[test]
    fn test_setup_fpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
        // TODO: auto-generate kvm related structures with PartialEq on.
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
        // Setting the mxcsr register from kvm_fpu inside setup_fpu does not influence anything.
        // See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        // The mxcsr will stay 0 and the assert below fails. Decide whether or not we should
        // remove it at all.
        // assert!(expected_fpu.mxcsr == actual_fpu.mxcsr);
    }

    #[test]
    fn test_setup_msrs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries for details.
        let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: msr_index::MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }]);

        // get_msrs returns the number of msrs that it succeed in reading. We only want to read 1
        // in this test case scenario.
        let read_msrs = vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(read_msrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index msr_index::MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = create_msr_entries();
        assert_eq!(entry_vec.as_slice()[9], msrs.as_slice()[0]);
    }

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: kvm_regs = kvm_regs {
            rflags: 0x0000000000000002u64,
            rip: 1,
            rsp: 2,
            rbp: 2,
            rsi: 3,
            ..Default::default()
        };

        setup_regs(
            &vcpu,
            expected_regs.rip,
            expected_regs.rsp,
            expected_regs.rsi,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut expected_sregs: kvm_sregs = vcpu.get_sregs().unwrap();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut expected_sregs, BootProtocol::LinuxBoot).unwrap();
        setup_page_tables(&gm, &mut expected_sregs).unwrap();

        setup_sregs(&gm, &vcpu, BootProtocol::LinuxBoot).unwrap();
        let actual_sregs: kvm_sregs = vcpu.get_sregs().unwrap();
        assert_eq!(expected_sregs, actual_sregs);
    }
}
