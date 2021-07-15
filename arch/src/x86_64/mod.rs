// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
use std::sync::Arc;
pub mod interrupts;
pub mod layout;
mod mpspec;
mod mptable;
pub mod regs;
use crate::GuestMemoryMmap;
use crate::InitramfsConfig;
use crate::RegionType;
use hypervisor::{CpuId, CpuIdEntry, HypervisorError, CPUID_FLAG_VALID_INDEX};
use linux_loader::loader::bootparam::boot_params;
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};
use std::collections::BTreeMap;
use std::mem;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryRegion, GuestUsize,
};
mod smbios;
use std::arch::x86_64;
#[cfg(feature = "tdx")]
pub mod tdx;

// CPUID feature bits
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.
const MTRR_EDX_BIT: u8 = 12; // Hypervisor ecx bit.

// KVM feature bits
const KVM_FEATURE_ASYNC_PF_INT_BIT: u8 = 14;
#[cfg(feature = "tdx")]
const KVM_FEATURE_CLOCKSOURCE_BIT: u8 = 0;
#[cfg(feature = "tdx")]
const KVM_FEATURE_CLOCKSOURCE2_BIT: u8 = 3;
#[cfg(feature = "tdx")]
const KVM_FEATURE_CLOCKSOURCE_STABLE_BIT: u8 = 24;
#[cfg(feature = "tdx")]
const KVM_FEATURE_ASYNC_PF_BIT: u8 = 4;
#[cfg(feature = "tdx")]
const KVM_FEATURE_ASYNC_PF_VMEXIT_BIT: u8 = 10;
#[cfg(feature = "tdx")]
const KVM_FEATURE_STEAL_TIME_BIT: u8 = 5;

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code, as well as which of the supported boot protocols
/// is to be used to configure the guest initial state.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
}

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

#[derive(Clone)]
pub struct SgxEpcSection {
    start: GuestAddress,
    size: GuestUsize,
}

impl SgxEpcSection {
    pub fn new(start: GuestAddress, size: GuestUsize) -> Self {
        SgxEpcSection { start, size }
    }
    pub fn start(&self) -> GuestAddress {
        self.start
    }
    pub fn size(&self) -> GuestUsize {
        self.size
    }
}

#[derive(Clone)]
pub struct SgxEpcRegion {
    start: GuestAddress,
    size: GuestUsize,
    epc_sections: BTreeMap<String, SgxEpcSection>,
}

impl SgxEpcRegion {
    pub fn new(start: GuestAddress, size: GuestUsize) -> Self {
        SgxEpcRegion {
            start,
            size,
            epc_sections: BTreeMap::new(),
        }
    }
    pub fn start(&self) -> GuestAddress {
        self.start
    }
    pub fn size(&self) -> GuestUsize {
        self.size
    }
    pub fn epc_sections(&self) -> &BTreeMap<String, SgxEpcSection> {
        &self.epc_sections
    }
    pub fn insert(&mut self, id: String, epc_section: SgxEpcSection) {
        self.epc_sections.insert(id, epc_section);
    }
}

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `DataInit`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct StartInfoWrapper(hvm_start_info);

// It is safe to initialize StartInfoWrapper which is a wrapper over `hvm_start_info` (a series of ints).
unsafe impl ByteValued for StartInfoWrapper {}

#[derive(Copy, Clone, Default)]
struct MemmapTableEntryWrapper(hvm_memmap_table_entry);

unsafe impl ByteValued for MemmapTableEntryWrapper {}

#[derive(Copy, Clone, Default)]
struct ModlistEntryWrapper(hvm_modlist_entry);

unsafe impl ByteValued for ModlistEntryWrapper {}

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `DataInit`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl ByteValued for BootParamsWrapper {}

#[derive(Debug)]
pub enum Error {
    /// Error writing MP table to memory.
    MpTableSetup(mptable::Error),

    /// Error configuring the general purpose registers
    RegsConfiguration(regs::Error),

    /// Error configuring the special registers
    SregsConfiguration(regs::Error),

    /// Error configuring the floating point related registers
    FpuConfiguration(regs::Error),

    /// Error configuring the MSR registers
    MsrsConfiguration(regs::Error),

    /// Failed to set supported CPUs.
    SetSupportedCpusFailed(anyhow::Error),

    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(anyhow::Error),

    /// Error setting up SMBIOS table
    SmbiosSetup(smbios::Error),

    /// Could not find any SGX EPC section
    NoSgxEpcSection,

    /// Missing SGX CPU feature
    MissingSgxFeature,

    /// Missing SGX_LC CPU feature
    MissingSgxLaunchControlFeature,

    /// Error getting supported CPUID through the hypervisor (kvm/mshv) API
    CpuidGetSupported(HypervisorError),

    /// Error populating CPUID with KVM HyperV emulation details
    CpuidKvmHyperV(vmm_sys_util::fam::Error),

    /// Error populating CPUID with CPU identification
    CpuidIdentification(vmm_sys_util::fam::Error),
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::X86_64Setup(e)
    }
}

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Copy, Clone)]
pub enum CpuidReg {
    EAX,
    EBX,
    ECX,
    EDX,
}

pub struct CpuidPatch {
    pub function: u32,
    pub index: u32,
    pub flags_bit: Option<u8>,
    pub eax_bit: Option<u8>,
    pub ebx_bit: Option<u8>,
    pub ecx_bit: Option<u8>,
    pub edx_bit: Option<u8>,
}

impl CpuidPatch {
    pub fn set_cpuid_reg(
        cpuid: &mut CpuId,
        function: u32,
        index: Option<u32>,
        reg: CpuidReg,
        value: u32,
    ) {
        let entries = cpuid.as_mut_slice();

        let mut entry_found = false;
        for entry in entries.iter_mut() {
            if entry.function == function && (index == None || index.unwrap() == entry.index) {
                entry_found = true;
                match reg {
                    CpuidReg::EAX => {
                        entry.eax = value;
                    }
                    CpuidReg::EBX => {
                        entry.ebx = value;
                    }
                    CpuidReg::ECX => {
                        entry.ecx = value;
                    }
                    CpuidReg::EDX => {
                        entry.edx = value;
                    }
                }
            }
        }

        if entry_found {
            return;
        }

        // Entry not found, so let's add it.
        if let Some(index) = index {
            let mut entry = CpuIdEntry {
                function,
                index,
                flags: CPUID_FLAG_VALID_INDEX,
                ..Default::default()
            };
            match reg {
                CpuidReg::EAX => {
                    entry.eax = value;
                }
                CpuidReg::EBX => {
                    entry.ebx = value;
                }
                CpuidReg::ECX => {
                    entry.ecx = value;
                }
                CpuidReg::EDX => {
                    entry.edx = value;
                }
            }

            if let Err(e) = cpuid.push(entry) {
                error!("Failed adding new CPUID entry: {:?}", e);
            }
        }
    }

    pub fn patch_cpuid(cpuid: &mut CpuId, patches: Vec<CpuidPatch>) {
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            for patch in patches.iter() {
                if entry.function == patch.function && entry.index == patch.index {
                    if let Some(flags_bit) = patch.flags_bit {
                        entry.flags |= 1 << flags_bit;
                    }
                    if let Some(eax_bit) = patch.eax_bit {
                        entry.eax |= 1 << eax_bit;
                    }
                    if let Some(ebx_bit) = patch.ebx_bit {
                        entry.ebx |= 1 << ebx_bit;
                    }
                    if let Some(ecx_bit) = patch.ecx_bit {
                        entry.ecx |= 1 << ecx_bit;
                    }
                    if let Some(edx_bit) = patch.edx_bit {
                        entry.edx |= 1 << edx_bit;
                    }
                }
            }
        }
    }

    pub fn is_feature_enabled(
        cpuid: &CpuId,
        function: u32,
        index: u32,
        reg: CpuidReg,
        feature_bit: usize,
    ) -> bool {
        let entries = cpuid.as_slice();
        let mask = 1 << feature_bit;

        for entry in entries.iter() {
            if entry.function == function && entry.index == index {
                let reg_val: u32;
                match reg {
                    CpuidReg::EAX => {
                        reg_val = entry.eax;
                    }
                    CpuidReg::EBX => {
                        reg_val = entry.ebx;
                    }
                    CpuidReg::ECX => {
                        reg_val = entry.ecx;
                    }
                    CpuidReg::EDX => {
                        reg_val = entry.edx;
                    }
                }

                return (reg_val & mask) == mask;
            }
        }

        false
    }
}

pub fn generate_common_cpuid(
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    topology: Option<(u8, u8, u8)>,
    sgx_epc_sections: Option<Vec<SgxEpcSection>>,
    phys_bits: u8,
    kvm_hyperv: bool,
    #[cfg(feature = "tdx")] tdx_enabled: bool,
) -> super::Result<CpuId> {
    let cpuid_patches = vec![
        // Patch tsc deadline timer bit
        CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: Some(TSC_DEADLINE_TIMER_ECX_BIT),
            edx_bit: None,
        },
        // Patch hypervisor bit
        CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: Some(HYPERVISOR_ECX_BIT),
            edx_bit: None,
        },
        // Enable MTRR feature
        CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: None,
            edx_bit: Some(MTRR_EDX_BIT),
        },
    ];

    // Supported CPUID
    let mut cpuid = hypervisor.get_cpuid().map_err(Error::CpuidGetSupported)?;

    CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

    if let Some(t) = topology {
        update_cpuid_topology(&mut cpuid, t.0, t.1, t.2);
    }

    if let Some(sgx_epc_sections) = sgx_epc_sections {
        update_cpuid_sgx(&mut cpuid, sgx_epc_sections)?;
    }

    // Update some existing CPUID
    for entry in cpuid.as_mut_slice().iter_mut() {
        match entry.function {
            // Set CPU physical bits
            0x8000_0008 => {
                entry.eax = (entry.eax & 0xffff_ff00) | (phys_bits as u32 & 0xff);
            }
            // Disable KVM_FEATURE_ASYNC_PF_INT
            // This is required until we find out why the asynchronous page
            // fault is generating unexpected behavior when using interrupt
            // mechanism.
            // TODO: Re-enable KVM_FEATURE_ASYNC_PF_INT (#2277)
            0x4000_0001 => {
                entry.eax &= !(1 << KVM_FEATURE_ASYNC_PF_INT_BIT);

                // These features are not supported by TDX
                #[cfg(feature = "tdx")]
                if tdx_enabled {
                    entry.eax &= !(1 << KVM_FEATURE_CLOCKSOURCE_BIT
                        | 1 << KVM_FEATURE_CLOCKSOURCE2_BIT
                        | 1 << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT
                        | 1 << KVM_FEATURE_ASYNC_PF_BIT
                        | 1 << KVM_FEATURE_ASYNC_PF_VMEXIT_BIT
                        | 1 << KVM_FEATURE_STEAL_TIME_BIT)
                }
            }
            _ => {}
        }
    }

    // Copy CPU identification string
    for i in 0x8000_0002..=0x8000_0004 {
        cpuid.retain(|c| c.function != i);
        let leaf = unsafe { std::arch::x86_64::__cpuid(i) };
        cpuid
            .push(CpuIdEntry {
                function: i,
                eax: leaf.eax,
                ebx: leaf.ebx,
                ecx: leaf.ecx,
                edx: leaf.edx,
                ..Default::default()
            })
            .map_err(Error::CpuidIdentification)?;
    }

    if kvm_hyperv {
        // Remove conflicting entries
        cpuid.retain(|c| c.function != 0x4000_0000);
        cpuid.retain(|c| c.function != 0x4000_0001);
        // See "Hypervisor Top Level Functional Specification" for details
        // Compliance with "Hv#1" requires leaves up to 0x4000_000a
        cpuid
            .push(CpuIdEntry {
                function: 0x40000000,
                eax: 0x4000000a, // Maximum cpuid leaf
                ebx: 0x756e694c, // "Linu"
                ecx: 0x564b2078, // "x KV"
                edx: 0x7648204d, // "M Hv"
                ..Default::default()
            })
            .map_err(Error::CpuidKvmHyperV)?;
        cpuid
            .push(CpuIdEntry {
                function: 0x40000001,
                eax: 0x31237648, // "Hv#1"
                ..Default::default()
            })
            .map_err(Error::CpuidKvmHyperV)?;
        cpuid
            .push(CpuIdEntry {
                function: 0x40000002,
                eax: 0x3839,  // "Build number"
                ebx: 0xa0000, // "Version"
                ..Default::default()
            })
            .map_err(Error::CpuidKvmHyperV)?;
        cpuid
            .push(CpuIdEntry {
                function: 0x4000_0003,
                eax: 1 << 1 // AccessPartitionReferenceCounter
                   | 1 << 2 // AccessSynicRegs
                   | 1 << 3 // AccessSyntheticTimerRegs
                   | 1 << 9, // AccessPartitionReferenceTsc
                edx: 1 << 3, // CPU dynamic partitioning
                ..Default::default()
            })
            .map_err(Error::CpuidKvmHyperV)?;
        cpuid
            .push(CpuIdEntry {
                function: 0x4000_0004,
                eax: 1 << 5, // Recommend relaxed timing
                ..Default::default()
            })
            .map_err(Error::CpuidKvmHyperV)?;
        for i in 0x4000_0005..=0x4000_000a {
            cpuid
                .push(CpuIdEntry {
                    function: i,
                    ..Default::default()
                })
                .map_err(Error::CpuidKvmHyperV)?;
        }
    }

    Ok(cpuid)
}

pub fn configure_vcpu(
    fd: &Arc<dyn hypervisor::Vcpu>,
    id: u8,
    kernel_entry_point: Option<EntryPoint>,
    vm_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
    cpuid: CpuId,
    kvm_hyperv: bool,
) -> super::Result<()> {
    // Per vCPU CPUID changes; common are handled via generate_common_cpuid()
    let mut cpuid = cpuid;
    CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, u32::from(id));
    CpuidPatch::set_cpuid_reg(&mut cpuid, 0x1f, None, CpuidReg::EDX, u32::from(id));

    fd.set_cpuid2(&cpuid)
        .map_err(|e| Error::SetSupportedCpusFailed(e.into()))?;

    if kvm_hyperv {
        fd.enable_hyperv_synic().unwrap();
    }

    regs::setup_msrs(fd).map_err(Error::MsrsConfiguration)?;
    if let Some(kernel_entry_point) = kernel_entry_point {
        // Safe to unwrap because this method is called after the VM is configured
        regs::setup_regs(fd, kernel_entry_point.entry_addr.raw_value())
            .map_err(Error::RegsConfiguration)?;
        regs::setup_fpu(fd).map_err(Error::FpuConfiguration)?;
        regs::setup_sregs(&vm_memory.memory(), fd).map_err(Error::SregsConfiguration)?;
    }
    interrupts::set_lint(fd).map_err(|e| Error::LocalIntConfiguration(e.into()))?;
    Ok(())
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    let reserved_memory_gap_start = layout::MEM_32BIT_RESERVED_START
        .checked_add(layout::MEM_32BIT_DEVICES_SIZE)
        .expect("32-bit reserved region is too large");

    let requested_memory_size = GuestAddress(size as u64);
    let mut regions = Vec::new();

    // case1: guest memory fits before the gap
    if size as u64 <= layout::MEM_32BIT_RESERVED_START.raw_value() {
        regions.push((GuestAddress(0), size as usize, RegionType::Ram));
    // case2: guest memory extends beyond the gap
    } else {
        // push memory before the gap
        regions.push((
            GuestAddress(0),
            layout::MEM_32BIT_RESERVED_START.raw_value() as usize,
            RegionType::Ram,
        ));
        regions.push((
            layout::RAM_64BIT_START,
            requested_memory_size.unchecked_offset_from(layout::MEM_32BIT_RESERVED_START) as usize,
            RegionType::Ram,
        ));
    }

    // Add the 32-bit device memory hole as a sub region.
    regions.push((
        layout::MEM_32BIT_RESERVED_START,
        layout::MEM_32BIT_DEVICES_SIZE as usize,
        RegionType::SubRegion,
    ));

    // Add the 32-bit reserved memory hole as a sub region.
    regions.push((
        reserved_memory_gap_start,
        (layout::MEM_32BIT_RESERVED_SIZE - layout::MEM_32BIT_DEVICES_SIZE) as usize,
        RegionType::Reserved,
    ));

    regions
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
#[allow(clippy::too_many_arguments)]
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    initramfs: &Option<InitramfsConfig>,
    _num_cpus: u8,
    rsdp_addr: Option<GuestAddress>,
    sgx_epc_region: Option<SgxEpcRegion>,
) -> super::Result<()> {
    let size = smbios::setup_smbios(guest_mem).map_err(Error::SmbiosSetup)?;

    // Place the MP table after the SMIOS table aligned to 16 bytes
    let offset = GuestAddress(layout::SMBIOS_START).unchecked_add(size);
    let offset = GuestAddress((offset.0 + 16) & !0xf);
    mptable::setup_mptable(offset, guest_mem, _num_cpus).map_err(Error::MpTableSetup)?;

    // Check that the RAM is not smaller than the RSDP start address
    if let Some(rsdp_addr) = rsdp_addr {
        if rsdp_addr.0 > guest_mem.last_addr().0 {
            return Err(super::Error::RsdpPastRamEnd);
        }
    }

    configure_pvh(
        guest_mem,
        cmdline_addr,
        initramfs,
        rsdp_addr,
        sgx_epc_region,
    )
}

fn configure_pvh(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    initramfs: &Option<InitramfsConfig>,
    rsdp_addr: Option<GuestAddress>,
    sgx_epc_region: Option<SgxEpcRegion>,
) -> super::Result<()> {
    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;

    let mut start_info: StartInfoWrapper = StartInfoWrapper(hvm_start_info::default());

    start_info.0.magic = XEN_HVM_START_MAGIC_VALUE;
    start_info.0.version = 1; // pvh has version 1
    start_info.0.nr_modules = 0;
    start_info.0.cmdline_paddr = cmdline_addr.raw_value() as u64;
    start_info.0.memmap_paddr = layout::MEMMAP_START.raw_value();

    if let Some(rsdp_addr) = rsdp_addr {
        start_info.0.rsdp_paddr = rsdp_addr.0;
    }

    if let Some(initramfs_config) = initramfs {
        // The initramfs has been written to guest memory already, here we just need to
        // create the module structure that describes it.
        let ramdisk_mod: ModlistEntryWrapper = ModlistEntryWrapper(hvm_modlist_entry {
            paddr: initramfs_config.address.raw_value(),
            size: initramfs_config.size as u64,
            ..Default::default()
        });

        start_info.0.nr_modules += 1;
        start_info.0.modlist_paddr = layout::MODLIST_START.raw_value();

        // Write the modlist struct to guest memory.
        guest_mem
            .write_obj(ramdisk_mod, layout::MODLIST_START)
            .map_err(super::Error::ModlistSetup)?;
    }

    // Vector to hold the memory maps which needs to be written to guest memory
    // at MEMMAP_START after all of the mappings are recorded.
    let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

    // Create the memory map entries.
    add_memmap_entry(&mut memmap, 0, layout::EBDA_START.raw_value(), E820_RAM);

    let mem_end = guest_mem.last_addr();

    if mem_end < layout::MEM_32BIT_RESERVED_START {
        add_memmap_entry(
            &mut memmap,
            layout::HIGH_RAM_START.raw_value(),
            mem_end.unchecked_offset_from(layout::HIGH_RAM_START) + 1,
            E820_RAM,
        );
    } else {
        add_memmap_entry(
            &mut memmap,
            layout::HIGH_RAM_START.raw_value(),
            layout::MEM_32BIT_RESERVED_START.unchecked_offset_from(layout::HIGH_RAM_START),
            E820_RAM,
        );
        if mem_end > layout::RAM_64BIT_START {
            add_memmap_entry(
                &mut memmap,
                layout::RAM_64BIT_START.raw_value(),
                mem_end.unchecked_offset_from(layout::RAM_64BIT_START) + 1,
                E820_RAM,
            );
        }
    }

    add_memmap_entry(
        &mut memmap,
        layout::PCI_MMCONFIG_START.0,
        layout::PCI_MMCONFIG_SIZE,
        E820_RESERVED,
    );

    if let Some(sgx_epc_region) = sgx_epc_region {
        add_memmap_entry(
            &mut memmap,
            sgx_epc_region.start().raw_value(),
            sgx_epc_region.size() as u64,
            E820_RESERVED,
        );
    }

    start_info.0.memmap_entries = memmap.len() as u32;

    // Copy the vector with the memmap table to the MEMMAP_START address
    // which is already saved in the memmap_paddr field of hvm_start_info struct.
    let mut memmap_start_addr = layout::MEMMAP_START;

    guest_mem
        .checked_offset(
            memmap_start_addr,
            mem::size_of::<hvm_memmap_table_entry>() * start_info.0.memmap_entries as usize,
        )
        .ok_or(super::Error::MemmapTablePastRamEnd)?;

    // For every entry in the memmap vector, create a MemmapTableEntryWrapper
    // and write it to guest memory.
    for memmap_entry in memmap {
        let map_entry_wrapper: MemmapTableEntryWrapper = MemmapTableEntryWrapper(memmap_entry);

        guest_mem
            .write_obj(map_entry_wrapper, memmap_start_addr)
            .map_err(|_| super::Error::MemmapTableSetup)?;
        memmap_start_addr =
            memmap_start_addr.unchecked_add(mem::size_of::<hvm_memmap_table_entry>() as u64);
    }

    // The hvm_start_info struct itself must be stored at PVH_START_INFO
    // address, and %rbx will be initialized to contain PVH_INFO_START prior to
    // starting the guest, as required by the PVH ABI.
    let start_info_addr = layout::PVH_INFO_START;

    guest_mem
        .checked_offset(start_info_addr, mem::size_of::<hvm_start_info>())
        .ok_or(super::Error::StartInfoPastRamEnd)?;

    // Write the start_info struct to guest memory.
    guest_mem
        .write_obj(start_info, start_info_addr)
        .map_err(|_| super::Error::StartInfoSetup)?;

    Ok(())
}

fn add_memmap_entry(memmap: &mut Vec<hvm_memmap_table_entry>, addr: u64, size: u64, mem_type: u32) {
    // Add the table entry to the vector
    memmap.push(hvm_memmap_table_entry {
        addr,
        size,
        type_: mem_type,
        reserved: 0,
    });
}

/// Returns the memory address where the initramfs could be loaded.
pub fn initramfs_load_addr(
    guest_mem: &GuestMemoryMmap,
    initramfs_size: usize,
) -> super::Result<u64> {
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(super::Error::InitramfsAddress)?;
    // It's safe to cast to usize because the size of a region can't be greater than usize.
    let lowmem_size = first_region.len() as usize;

    if lowmem_size < initramfs_size {
        return Err(super::Error::InitramfsAddress);
    }

    let aligned_addr: u64 = ((lowmem_size - initramfs_size) & !(crate::pagesize() - 1)) as u64;
    Ok(aligned_addr)
}

pub fn get_host_cpu_phys_bits() -> u8 {
    unsafe {
        let leaf = x86_64::__cpuid(0x8000_0000);

        // Detect and handle AMD SME (Secure Memory Encryption) properly.
        // Some physical address bits may become reserved when the feature is enabled.
        // See AMD64 Architecture Programmer's Manual Volume 2, Section 7.10.1
        let reduced = if leaf.eax >= 0x8000_001f
            && leaf.ebx == 0x6874_7541    // Vendor ID: AuthenticAMD
            && leaf.ecx == 0x444d_4163
            && leaf.edx == 0x6974_6e65
            && x86_64::__cpuid(0x8000_001f).eax & 0x1 != 0
        {
            (x86_64::__cpuid(0x8000_001f).ebx >> 6) & 0x3f
        } else {
            0
        };

        if leaf.eax >= 0x8000_0008 {
            let leaf = x86_64::__cpuid(0x8000_0008);
            ((leaf.eax & 0xff) - reduced) as u8
        } else {
            36
        }
    }
}

fn update_cpuid_topology(
    cpuid: &mut CpuId,
    threads_per_core: u8,
    cores_per_die: u8,
    dies_per_package: u8,
) {
    let thread_width = 8 - (threads_per_core - 1).leading_zeros();
    let core_width = (8 - (cores_per_die - 1).leading_zeros()) + thread_width;
    let die_width = (8 - (dies_per_package - 1).leading_zeros()) + core_width;

    // CPU Topology leaf 0xb
    CpuidPatch::set_cpuid_reg(cpuid, 0xb, Some(0), CpuidReg::EAX, thread_width);
    CpuidPatch::set_cpuid_reg(
        cpuid,
        0xb,
        Some(0),
        CpuidReg::EBX,
        u32::from(threads_per_core),
    );
    CpuidPatch::set_cpuid_reg(cpuid, 0xb, Some(0), CpuidReg::ECX, 1 << 8);

    CpuidPatch::set_cpuid_reg(cpuid, 0xb, Some(1), CpuidReg::EAX, die_width);
    CpuidPatch::set_cpuid_reg(
        cpuid,
        0xb,
        Some(1),
        CpuidReg::EBX,
        u32::from(dies_per_package * cores_per_die * threads_per_core),
    );
    CpuidPatch::set_cpuid_reg(cpuid, 0xb, Some(1), CpuidReg::ECX, 2 << 8);

    // CPU Topology leaf 0x1f
    CpuidPatch::set_cpuid_reg(cpuid, 0x1f, Some(0), CpuidReg::EAX, thread_width);
    CpuidPatch::set_cpuid_reg(
        cpuid,
        0x1f,
        Some(0),
        CpuidReg::EBX,
        u32::from(threads_per_core),
    );
    CpuidPatch::set_cpuid_reg(cpuid, 0x1f, Some(0), CpuidReg::ECX, 1 << 8);

    CpuidPatch::set_cpuid_reg(cpuid, 0x1f, Some(1), CpuidReg::EAX, core_width);
    CpuidPatch::set_cpuid_reg(
        cpuid,
        0x1f,
        Some(1),
        CpuidReg::EBX,
        u32::from(cores_per_die * threads_per_core),
    );
    CpuidPatch::set_cpuid_reg(cpuid, 0x1f, Some(1), CpuidReg::ECX, 2 << 8);

    CpuidPatch::set_cpuid_reg(cpuid, 0x1f, Some(2), CpuidReg::EAX, die_width);
    CpuidPatch::set_cpuid_reg(
        cpuid,
        0x1f,
        Some(2),
        CpuidReg::EBX,
        u32::from(dies_per_package * cores_per_die * threads_per_core),
    );
    CpuidPatch::set_cpuid_reg(cpuid, 0x1f, Some(2), CpuidReg::ECX, 5 << 8);
}

// The goal is to update the CPUID sub-leaves to reflect the number of EPC
// sections exposed to the guest.
fn update_cpuid_sgx(cpuid: &mut CpuId, epc_sections: Vec<SgxEpcSection>) -> Result<(), Error> {
    // Something's wrong if there's no EPC section.
    if epc_sections.is_empty() {
        return Err(Error::NoSgxEpcSection);
    }
    // We can't go further if the hypervisor does not support SGX feature.
    if !CpuidPatch::is_feature_enabled(cpuid, 0x7, 0, CpuidReg::EBX, 2) {
        return Err(Error::MissingSgxFeature);
    }
    // We can't go further if the hypervisor does not support SGX_LC feature.
    if !CpuidPatch::is_feature_enabled(cpuid, 0x7, 0, CpuidReg::ECX, 30) {
        return Err(Error::MissingSgxLaunchControlFeature);
    }

    // Get host CPUID for leaf 0x12, subleaf 0x2. This is to retrieve EPC
    // properties such as confidentiality and integrity.
    let leaf = unsafe { std::arch::x86_64::__cpuid_count(0x12, 0x2) };

    for (i, epc_section) in epc_sections.iter().enumerate() {
        let subleaf_idx = i + 2;
        let start = epc_section.start().raw_value();
        let size = epc_section.size() as u64;
        let eax = (start & 0xffff_f000) as u32 | 0x1;
        let ebx = (start >> 32) as u32;
        let ecx = (size & 0xffff_f000) as u32 | (leaf.ecx & 0xf);
        let edx = (size >> 32) as u32;
        // CPU Topology leaf 0x12
        CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::EAX, eax);
        CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::EBX, ebx);
        CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::ECX, ecx);
        CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::EDX, edx);
    }

    // Add one NULL entry to terminate the dynamic list
    let subleaf_idx = epc_sections.len() + 2;
    // CPU Topology leaf 0x12
    CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::EAX, 0);
    CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::EBX, 0);
    CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::ECX, 0);
    CpuidPatch::set_cpuid_reg(cpuid, 0x12, Some(subleaf_idx as u32), CpuidReg::EDX, 0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1 << 29);
        assert_eq!(3, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let regions = arch_memory_regions((1 << 32) + 0x8000);
        assert_eq!(4, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1 << 32), regions[1].0);
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let config_err = configure_system(
            &gm,
            GuestAddress(0),
            &None,
            1,
            Some(layout::RSDP_POINTER),
            None,
        );
        assert!(config_err.is_err());

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();

        configure_system(&gm, GuestAddress(0), &None, no_vcpus, None, None).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();
        configure_system(&gm, GuestAddress(0), &None, no_vcpus, None, None).unwrap();

        configure_system(&gm, GuestAddress(0), &None, no_vcpus, None, None).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();
        configure_system(&gm, GuestAddress(0), &None, no_vcpus, None, None).unwrap();

        configure_system(&gm, GuestAddress(0), &None, no_vcpus, None, None).unwrap();
    }

    #[test]
    fn test_add_memmap_entry() {
        let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

        let expected_memmap = vec![
            hvm_memmap_table_entry {
                addr: 0x0,
                size: 0x1000,
                type_: E820_RAM,
                ..Default::default()
            },
            hvm_memmap_table_entry {
                addr: 0x10000,
                size: 0xa000,
                type_: E820_RESERVED,
                ..Default::default()
            },
        ];

        add_memmap_entry(&mut memmap, 0, 0x1000, E820_RAM);
        add_memmap_entry(&mut memmap, 0x10000, 0xa000, E820_RESERVED);

        assert_eq!(format!("{:?}", memmap), format!("{:?}", expected_memmap));
    }
}
