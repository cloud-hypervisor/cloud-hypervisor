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
use std::mem;

use hypervisor::arch::x86::{CpuIdEntry, CPUID_FLAG_VALID_INDEX};
use hypervisor::{CpuVendor, HypervisorCpuError, HypervisorError};
use linux_loader::loader::bootparam::{boot_params, setup_header};
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};
use thiserror::Error;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryRegion,
};

use crate::{GuestMemoryMmap, InitramfsConfig, RegionType};
mod smbios;
use std::arch::x86_64;
#[cfg(feature = "tdx")]
pub mod tdx;

// While modern architectures support more than 255 CPUs via x2APIC,
// legacy devices such as mptable support at most 254 CPUs.
pub(crate) const MAX_SUPPORTED_CPUS_LEGACY: u32 = 254;

// CPUID feature bits
#[cfg(feature = "kvm")]
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.
const MTRR_EDX_BIT: u8 = 12; // Hypervisor ecx bit.
const INVARIANT_TSC_EDX_BIT: u8 = 8; // Invariant TSC bit on 0x8000_0007 EDX
const AMX_BF16: u8 = 22; // AMX tile computation on bfloat16 numbers
const AMX_TILE: u8 = 24; // AMX tile load/store instructions
const AMX_INT8: u8 = 25; // AMX tile computation on 8-bit integers

// KVM feature bits
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

const KVM_FEATURE_MSI_EXT_DEST_ID: u8 = 15;

pub const _NSIG: i32 = 65;

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code, as well as which of the supported boot protocols
/// is to be used to configure the guest initial state.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
    /// This field is used for bzImage to fill the zero page
    pub setup_header: Option<setup_header>,
}

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

pub struct CpuidConfig {
    pub phys_bits: u8,
    pub kvm_hyperv: bool,
    #[cfg(feature = "tdx")]
    pub tdx: bool,
    pub amx: bool,
}

#[derive(Debug, Error)]
pub enum Error {
    /// Error writing MP table to memory.
    #[error("Error writing MP table to memory")]
    MpTableSetup(#[source] mptable::Error),

    /// Error configuring the general purpose registers
    #[error("Error configuring the general purpose registers")]
    RegsConfiguration(#[source] regs::Error),

    /// Error configuring the special registers
    #[error("Error configuring the special registers")]
    SregsConfiguration(#[source] regs::Error),

    /// Error configuring the floating point related registers
    #[error("Error configuring the floating point related registers")]
    FpuConfiguration(#[source] regs::Error),

    /// Error configuring the MSR registers
    #[error("Error configuring the MSR registers")]
    MsrsConfiguration(#[source] regs::Error),

    /// Failed to set supported CPUs.
    #[error("Failed to set supported CPUs")]
    SetSupportedCpusFailed(#[source] anyhow::Error),

    /// Cannot set the local interruption due to bad configuration.
    #[error("Cannot set the local interruption due to bad configuration")]
    LocalIntConfiguration(#[source] anyhow::Error),

    /// Error setting up SMBIOS table
    #[error("Error setting up SMBIOS table")]
    SmbiosSetup(#[source] smbios::Error),

    /// Error getting supported CPUID through the hypervisor (kvm/mshv) API
    #[error("Error getting supported CPUID through the hypervisor API")]
    CpuidGetSupported(#[source] HypervisorError),

    /// Error populating CPUID with KVM HyperV emulation details
    #[error("Error populating CPUID with KVM HyperV emulation details")]
    CpuidKvmHyperV(#[source] vmm_sys_util::fam::Error),

    /// Error populating CPUID with CPU identification
    #[error("Error populating CPUID with CPU identification")]
    CpuidIdentification(#[source] vmm_sys_util::fam::Error),

    /// Error checking CPUID compatibility
    #[error("Error checking CPUID compatibility")]
    CpuidCheckCompatibility,

    // Error writing EBDA address
    #[error("Error writing EBDA address")]
    EbdaSetup(#[source] vm_memory::GuestMemoryError),

    // Error getting CPU TSC frequency
    #[error("Error getting CPU TSC frequency")]
    GetTscFrequency(#[source] HypervisorCpuError),

    /// Error retrieving TDX capabilities through the hypervisor (kvm/mshv) API
    #[cfg(feature = "tdx")]
    #[error("Error retrieving TDX capabilities through the hypervisor API")]
    TdxCapabilities(#[source] HypervisorError),

    /// Failed to configure E820 map for bzImage
    #[error("Failed to configure E820 map for bzImage")]
    E820Configuration,
}

pub fn get_x2apic_id(cpu_id: u32, topology: Option<(u16, u16, u16, u16)>) -> u32 {
    if let Some(t) = topology {
        let thread_mask_width = u16::BITS - (t.0 - 1).leading_zeros();
        let core_mask_width = u16::BITS - (t.1 - 1).leading_zeros();
        let die_mask_width = u16::BITS - (t.2 - 1).leading_zeros();

        let thread_id = cpu_id % (t.0 as u32);
        let core_id = cpu_id / (t.0 as u32) % (t.1 as u32);
        let die_id = cpu_id / ((t.0 * t.1) as u32) % (t.2 as u32);
        let socket_id = cpu_id / ((t.0 * t.1 * t.2) as u32);

        return thread_id
            | (core_id << thread_mask_width)
            | (die_id << (thread_mask_width + core_mask_width))
            | (socket_id << (thread_mask_width + core_mask_width + die_mask_width));
    }

    cpu_id
}

pub fn get_max_x2apic_id(topology: (u16, u16, u16, u16)) -> u32 {
    get_x2apic_id(
        (topology.0 as u32 * topology.1 as u32 * topology.2 as u32 * topology.3 as u32) - 1,
        Some(topology),
    )
}

#[derive(Copy, Clone, Debug)]
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
    pub fn get_cpuid_reg(
        cpuid: &[CpuIdEntry],
        function: u32,
        index: Option<u32>,
        reg: CpuidReg,
    ) -> Option<u32> {
        for entry in cpuid.iter() {
            if entry.function == function && (index.is_none() || index.unwrap() == entry.index) {
                return match reg {
                    CpuidReg::EAX => Some(entry.eax),
                    CpuidReg::EBX => Some(entry.ebx),
                    CpuidReg::ECX => Some(entry.ecx),
                    CpuidReg::EDX => Some(entry.edx),
                };
            }
        }

        None
    }

    pub fn set_cpuid_reg(
        cpuid: &mut Vec<CpuIdEntry>,
        function: u32,
        index: Option<u32>,
        reg: CpuidReg,
        value: u32,
    ) {
        let mut entry_found = false;
        for entry in cpuid.iter_mut() {
            if entry.function == function && (index.is_none() || index.unwrap() == entry.index) {
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

            cpuid.push(entry);
        }
    }

    pub fn patch_cpuid(cpuid: &mut [CpuIdEntry], patches: Vec<CpuidPatch>) {
        for entry in cpuid {
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
        cpuid: &[CpuIdEntry],
        function: u32,
        index: u32,
        reg: CpuidReg,
        feature_bit: usize,
    ) -> bool {
        let mask = 1 << feature_bit;

        for entry in cpuid {
            if entry.function == function && entry.index == index {
                let reg_val = match reg {
                    CpuidReg::EAX => entry.eax,
                    CpuidReg::EBX => entry.ebx,
                    CpuidReg::ECX => entry.ecx,
                    CpuidReg::EDX => entry.edx,
                };

                return (reg_val & mask) == mask;
            }
        }

        false
    }
}

#[derive(Debug)]
enum CpuidCompatibleCheck {
    BitwiseSubset, // bitwise subset
    Equal,         // equal in value
    NumNotGreater, // smaller or equal as a number
}

pub struct CpuidFeatureEntry {
    function: u32,
    index: u32,
    feature_reg: CpuidReg,
    compatible_check: CpuidCompatibleCheck,
}

impl CpuidFeatureEntry {
    fn checked_feature_entry_list() -> Vec<CpuidFeatureEntry> {
        vec![
            // The following list includes all hardware features bits from
            // the CPUID Wiki Page: https://en.wikipedia.org/wiki/CPUID
            // Leaf 0x1, ECX/EDX, feature bits
            CpuidFeatureEntry {
                function: 1,
                index: 0,
                feature_reg: CpuidReg::ECX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 1,
                index: 0,
                feature_reg: CpuidReg::EDX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            // Leaf 0x7, EAX/EBX/ECX/EDX, extended features
            CpuidFeatureEntry {
                function: 7,
                index: 0,
                feature_reg: CpuidReg::EAX,
                compatible_check: CpuidCompatibleCheck::NumNotGreater,
            },
            CpuidFeatureEntry {
                function: 7,
                index: 0,
                feature_reg: CpuidReg::EBX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 7,
                index: 0,
                feature_reg: CpuidReg::ECX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 7,
                index: 0,
                feature_reg: CpuidReg::EDX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            // Leaf 0x7 subleaf 0x1, EAX, extended features
            CpuidFeatureEntry {
                function: 7,
                index: 1,
                feature_reg: CpuidReg::EAX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            // Leaf 0x8000_0001, ECX/EDX, CPUID features bits
            CpuidFeatureEntry {
                function: 0x8000_0001,
                index: 0,
                feature_reg: CpuidReg::ECX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 0x8000_0001,
                index: 0,
                feature_reg: CpuidReg::EDX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            // KVM CPUID bits: https://www.kernel.org/doc/html/latest/virt/kvm/x86/cpuid.html
            // Leaf 0x4000_0000, EAX/EBX/ECX/EDX, KVM CPUID SIGNATURE
            CpuidFeatureEntry {
                function: 0x4000_0000,
                index: 0,
                feature_reg: CpuidReg::EAX,
                compatible_check: CpuidCompatibleCheck::NumNotGreater,
            },
            CpuidFeatureEntry {
                function: 0x4000_0000,
                index: 0,
                feature_reg: CpuidReg::EBX,
                compatible_check: CpuidCompatibleCheck::Equal,
            },
            CpuidFeatureEntry {
                function: 0x4000_0000,
                index: 0,
                feature_reg: CpuidReg::ECX,
                compatible_check: CpuidCompatibleCheck::Equal,
            },
            CpuidFeatureEntry {
                function: 0x4000_0000,
                index: 0,
                feature_reg: CpuidReg::EDX,
                compatible_check: CpuidCompatibleCheck::Equal,
            },
            // Leaf 0x4000_0001, EAX/EBX/ECX/EDX, KVM CPUID features
            CpuidFeatureEntry {
                function: 0x4000_0001,
                index: 0,
                feature_reg: CpuidReg::EAX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 0x4000_0001,
                index: 0,
                feature_reg: CpuidReg::EBX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 0x4000_0001,
                index: 0,
                feature_reg: CpuidReg::ECX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
            CpuidFeatureEntry {
                function: 0x4000_0001,
                index: 0,
                feature_reg: CpuidReg::EDX,
                compatible_check: CpuidCompatibleCheck::BitwiseSubset,
            },
        ]
    }

    fn get_features_from_cpuid(
        cpuid: &[CpuIdEntry],
        feature_entry_list: &[CpuidFeatureEntry],
    ) -> Vec<u32> {
        let mut features = vec![0; feature_entry_list.len()];
        for (i, feature_entry) in feature_entry_list.iter().enumerate() {
            for cpuid_entry in cpuid {
                if cpuid_entry.function == feature_entry.function
                    && cpuid_entry.index == feature_entry.index
                {
                    match feature_entry.feature_reg {
                        CpuidReg::EAX => {
                            features[i] = cpuid_entry.eax;
                        }
                        CpuidReg::EBX => {
                            features[i] = cpuid_entry.ebx;
                        }
                        CpuidReg::ECX => {
                            features[i] = cpuid_entry.ecx;
                        }
                        CpuidReg::EDX => {
                            features[i] = cpuid_entry.edx;
                        }
                    }

                    break;
                }
            }
        }

        features
    }

    // The function returns `Error` (a.k.a. "incompatible"), when the CPUID features from `src_vm_cpuid`
    // is not a subset of those of the `dest_vm_cpuid`.
    pub fn check_cpuid_compatibility(
        src_vm_cpuid: &[CpuIdEntry],
        dest_vm_cpuid: &[CpuIdEntry],
    ) -> Result<(), Error> {
        let feature_entry_list = &Self::checked_feature_entry_list();
        let src_vm_features = Self::get_features_from_cpuid(src_vm_cpuid, feature_entry_list);
        let dest_vm_features = Self::get_features_from_cpuid(dest_vm_cpuid, feature_entry_list);

        // Loop on feature bit and check if the 'source vm' feature is a subset
        // of those of the 'destination vm' feature
        let mut compatible = true;
        for (i, (src_vm_feature, dest_vm_feature)) in src_vm_features
            .iter()
            .zip(dest_vm_features.iter())
            .enumerate()
        {
            let entry = &feature_entry_list[i];
            let entry_compatible = match entry.compatible_check {
                CpuidCompatibleCheck::BitwiseSubset => {
                    let different_feature_bits = src_vm_feature ^ dest_vm_feature;
                    let src_vm_feature_bits_only = different_feature_bits & src_vm_feature;
                    src_vm_feature_bits_only == 0
                }
                CpuidCompatibleCheck::Equal => src_vm_feature == dest_vm_feature,
                CpuidCompatibleCheck::NumNotGreater => src_vm_feature <= dest_vm_feature,
            };
            if !entry_compatible {
                error!(
                    "Detected incompatible CPUID entry: leaf={:#02x} (subleaf={:#02x}), register='{:?}', \
                    compatible_check='{:?}', source VM feature='{:#04x}', destination VM feature'{:#04x}'.",
                    entry.function, entry.index, entry.feature_reg,
                    entry.compatible_check, src_vm_feature, dest_vm_feature
                    );

                compatible = false;
            }
        }

        if compatible {
            info!("No CPU incompatibility detected.");
            Ok(())
        } else {
            Err(Error::CpuidCheckCompatibility)
        }
    }
}

pub fn generate_common_cpuid(
    hypervisor: &Arc<dyn hypervisor::Hypervisor>,
    config: &CpuidConfig,
) -> super::Result<Vec<CpuIdEntry>> {
    // SAFETY: cpuid called with valid leaves
    if unsafe { x86_64::__cpuid(1) }.ecx & (1 << HYPERVISOR_ECX_BIT) == 1 << HYPERVISOR_ECX_BIT {
        // SAFETY: cpuid called with valid leaves
        let hypervisor_cpuid = unsafe { x86_64::__cpuid(0x4000_0000) };

        let mut identifier: [u8; 12] = [0; 12];
        identifier[0..4].copy_from_slice(&hypervisor_cpuid.ebx.to_le_bytes()[..]);
        identifier[4..8].copy_from_slice(&hypervisor_cpuid.ecx.to_le_bytes()[..]);
        identifier[8..12].copy_from_slice(&hypervisor_cpuid.edx.to_le_bytes()[..]);

        info!(
            "Running under nested virtualisation. Hypervisor string: {}",
            String::from_utf8_lossy(&identifier)
        );
    }

    info!(
        "Generating guest CPUID for with physical address size: {}",
        config.phys_bits
    );
    #[allow(unused_mut)]
    let mut cpuid_patches = vec![
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

    #[cfg(feature = "kvm")]
    if matches!(
        hypervisor.hypervisor_type(),
        hypervisor::HypervisorType::Kvm
    ) {
        // Patch tsc deadline timer bit
        cpuid_patches.push(CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: Some(TSC_DEADLINE_TIMER_ECX_BIT),
            edx_bit: None,
        });
    }

    // Supported CPUID
    let mut cpuid = hypervisor
        .get_supported_cpuid()
        .map_err(Error::CpuidGetSupported)?;

    CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

    #[cfg(feature = "tdx")]
    let tdx_capabilities = if config.tdx {
        let caps = hypervisor
            .tdx_capabilities()
            .map_err(Error::TdxCapabilities)?;
        info!("TDX capabilities {:#?}", caps);
        Some(caps)
    } else {
        None
    };

    // Update some existing CPUID
    for entry in cpuid.as_mut_slice().iter_mut() {
        match entry.function {
            // Clear AMX related bits if the AMX feature is not enabled
            0x7 => {
                if !config.amx && entry.index == 0 {
                    entry.edx &= !((1 << AMX_BF16) | (1 << AMX_TILE) | (1 << AMX_INT8))
                }
            }
            0xd =>
            {
                #[cfg(feature = "tdx")]
                if let Some(caps) = &tdx_capabilities {
                    let xcr0_mask: u64 = 0x82ff;
                    let xss_mask: u64 = !xcr0_mask;
                    if entry.index == 0 {
                        entry.eax &= (caps.xfam_fixed0 as u32) & (xcr0_mask as u32);
                        entry.eax |= (caps.xfam_fixed1 as u32) & (xcr0_mask as u32);
                        entry.edx &= ((caps.xfam_fixed0 & xcr0_mask) >> 32) as u32;
                        entry.edx |= ((caps.xfam_fixed1 & xcr0_mask) >> 32) as u32;
                    } else if entry.index == 1 {
                        entry.ecx &= (caps.xfam_fixed0 as u32) & (xss_mask as u32);
                        entry.ecx |= (caps.xfam_fixed1 as u32) & (xss_mask as u32);
                        entry.edx &= ((caps.xfam_fixed0 & xss_mask) >> 32) as u32;
                        entry.edx |= ((caps.xfam_fixed1 & xss_mask) >> 32) as u32;
                    }
                }
            }
            // Copy host L1 cache details if not populated by KVM
            0x8000_0005 => {
                if entry.eax == 0 && entry.ebx == 0 && entry.ecx == 0 && entry.edx == 0 {
                    // SAFETY: cpuid called with valid leaves
                    if unsafe { std::arch::x86_64::__cpuid(0x8000_0000).eax } >= 0x8000_0005 {
                        // SAFETY: cpuid called with valid leaves
                        let leaf = unsafe { std::arch::x86_64::__cpuid(0x8000_0005) };
                        entry.eax = leaf.eax;
                        entry.ebx = leaf.ebx;
                        entry.ecx = leaf.ecx;
                        entry.edx = leaf.edx;
                    }
                }
            }
            // Copy host L2 cache details if not populated by KVM
            0x8000_0006 => {
                if entry.eax == 0 && entry.ebx == 0 && entry.ecx == 0 && entry.edx == 0 {
                    // SAFETY: cpuid called with valid leaves
                    if unsafe { std::arch::x86_64::__cpuid(0x8000_0000).eax } >= 0x8000_0006 {
                        // SAFETY: cpuid called with valid leaves
                        let leaf = unsafe { std::arch::x86_64::__cpuid(0x8000_0006) };
                        entry.eax = leaf.eax;
                        entry.ebx = leaf.ebx;
                        entry.ecx = leaf.ecx;
                        entry.edx = leaf.edx;
                    }
                }
            }
            // Set CPU physical bits
            0x8000_0008 => {
                entry.eax = (entry.eax & 0xffff_ff00) | (config.phys_bits as u32 & 0xff);
            }
            0x4000_0001 => {
                // Enable KVM_FEATURE_MSI_EXT_DEST_ID. This allows the guest to target
                // device interrupts to cpus with APIC IDs > 254 without interrupt remapping.
                entry.eax |= 1 << KVM_FEATURE_MSI_EXT_DEST_ID;

                // These features are not supported by TDX
                #[cfg(feature = "tdx")]
                if config.tdx {
                    entry.eax &= !((1 << KVM_FEATURE_CLOCKSOURCE_BIT)
                        | (1 << KVM_FEATURE_CLOCKSOURCE2_BIT)
                        | (1 << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT)
                        | (1 << KVM_FEATURE_ASYNC_PF_BIT)
                        | (1 << KVM_FEATURE_ASYNC_PF_VMEXIT_BIT)
                        | (1 << KVM_FEATURE_STEAL_TIME_BIT))
                }
            }
            _ => {}
        }
    }

    // Copy CPU identification string
    for i in 0x8000_0002..=0x8000_0004 {
        cpuid.retain(|c| c.function != i);
        // SAFETY: call cpuid with valid leaves
        let leaf = unsafe { std::arch::x86_64::__cpuid(i) };
        cpuid.push(CpuIdEntry {
            function: i,
            eax: leaf.eax,
            ebx: leaf.ebx,
            ecx: leaf.ecx,
            edx: leaf.edx,
            ..Default::default()
        });
    }

    if config.kvm_hyperv {
        // Remove conflicting entries
        cpuid.retain(|c| c.function != 0x4000_0000);
        cpuid.retain(|c| c.function != 0x4000_0001);
        // See "Hypervisor Top Level Functional Specification" for details
        // Compliance with "Hv#1" requires leaves up to 0x4000_000a
        cpuid.push(CpuIdEntry {
            function: 0x40000000,
            eax: 0x4000000a, // Maximum cpuid leaf
            ebx: 0x756e694c, // "Linu"
            ecx: 0x564b2078, // "x KV"
            edx: 0x7648204d, // "M Hv"
            ..Default::default()
        });
        cpuid.push(CpuIdEntry {
            function: 0x40000001,
            eax: 0x31237648, // "Hv#1"
            ..Default::default()
        });
        cpuid.push(CpuIdEntry {
            function: 0x40000002,
            eax: 0x3839,  // "Build number"
            ebx: 0xa0000, // "Version"
            ..Default::default()
        });
        cpuid.push(CpuIdEntry {
            function: 0x4000_0003,
            eax: (1 << 1) // AccessPartitionReferenceCounter
                   | (1 << 2) // AccessSynicRegs
                   | (1 << 3) // AccessSyntheticTimerRegs
                   | (1 << 9), // AccessPartitionReferenceTsc
            edx: 1 << 3, // CPU dynamic partitioning
            ..Default::default()
        });
        cpuid.push(CpuIdEntry {
            function: 0x4000_0004,
            eax: 1 << 5, // Recommend relaxed timing
            ..Default::default()
        });
        for i in 0x4000_0005..=0x4000_000a {
            cpuid.push(CpuIdEntry {
                function: i,
                ..Default::default()
            });
        }
    }

    Ok(cpuid)
}

pub fn configure_vcpu(
    vcpu: &Arc<dyn hypervisor::Vcpu>,
    id: u32,
    boot_setup: Option<(EntryPoint, &GuestMemoryAtomic<GuestMemoryMmap>)>,
    cpuid: Vec<CpuIdEntry>,
    kvm_hyperv: bool,
    cpu_vendor: CpuVendor,
    topology: (u16, u16, u16, u16),
) -> super::Result<()> {
    let x2apic_id = get_x2apic_id(id, Some(topology));

    // Per vCPU CPUID changes; common are handled via generate_common_cpuid()
    let mut cpuid = cpuid;
    CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, x2apic_id);
    CpuidPatch::set_cpuid_reg(&mut cpuid, 0x1f, None, CpuidReg::EDX, x2apic_id);
    if matches!(cpu_vendor, CpuVendor::AMD) {
        CpuidPatch::set_cpuid_reg(&mut cpuid, 0x8000_001e, Some(0), CpuidReg::EAX, x2apic_id);
    }

    // Set ApicId in cpuid for each vcpu - found in cpuid ebx when eax = 1
    let mut apic_id_patched = false;
    for entry in &mut cpuid {
        if entry.function == 1 {
            entry.ebx &= 0xffffff;
            entry.ebx |= x2apic_id << 24;
            apic_id_patched = true;
            break;
        }
    }
    assert!(apic_id_patched);

    update_cpuid_topology(
        &mut cpuid, topology.0, topology.1, topology.2, topology.3, cpu_vendor, id,
    );

    // The TSC frequency CPUID leaf should not be included when running with HyperV emulation
    if !kvm_hyperv {
        if let Some(tsc_khz) = vcpu.tsc_khz().map_err(Error::GetTscFrequency)? {
            // Need to check that the TSC doesn't vary with dynamic frequency
            // SAFETY: cpuid called with valid leaves
            if unsafe { std::arch::x86_64::__cpuid(0x8000_0007) }.edx
                & (1u32 << INVARIANT_TSC_EDX_BIT)
                > 0
            {
                CpuidPatch::set_cpuid_reg(
                    &mut cpuid,
                    0x4000_0000,
                    None,
                    CpuidReg::EAX,
                    0x4000_0010,
                );
                cpuid.retain(|c| c.function != 0x4000_0010);
                cpuid.push(CpuIdEntry {
                    function: 0x4000_0010,
                    eax: tsc_khz,
                    ebx: 1000000, /* LAPIC resolution of 1ns (freq: 1GHz) is hardcoded in KVM's
                                   * APIC_BUS_CYCLE_NS */
                    ..Default::default()
                });
            };
        }
    }

    for c in &cpuid {
        debug!("{}", c);
    }

    vcpu.set_cpuid2(&cpuid)
        .map_err(|e| Error::SetSupportedCpusFailed(e.into()))?;

    if kvm_hyperv {
        vcpu.enable_hyperv_synic().unwrap();
    }

    regs::setup_msrs(vcpu).map_err(Error::MsrsConfiguration)?;
    if let Some((kernel_entry_point, guest_memory)) = boot_setup {
        regs::setup_regs(vcpu, kernel_entry_point).map_err(Error::RegsConfiguration)?;
        regs::setup_fpu(vcpu).map_err(Error::FpuConfiguration)?;

        // CPUs are required (by Intel sdm spec) to boot in x2apic mode if any
        // of the apic IDs is larger than 255. Experimentally, the Linux kernel
        // does not recognize the last vCPU if x2apic is not enabled when
        // there are 256 vCPUs in a flat hierarchy (i.e. max x2apic ID is 255),
        // so we need to enable x2apic in this case as well.
        let enable_x2_apic_mode = get_max_x2apic_id(topology) > MAX_SUPPORTED_CPUS_LEGACY;
        regs::setup_sregs(&guest_memory.memory(), vcpu, enable_x2_apic_mode)
            .map_err(Error::SregsConfiguration)?;
    }
    interrupts::set_lint(vcpu).map_err(|e| Error::LocalIntConfiguration(e.into()))?;
    Ok(())
}

/// Returns a Vec of the valid memory addresses.
///
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions() -> Vec<(GuestAddress, usize, RegionType)> {
    vec![
        // 0 GiB ~ 3GiB: memory before the gap
        (
            GuestAddress(0),
            layout::MEM_32BIT_RESERVED_START.raw_value() as usize,
            RegionType::Ram,
        ),
        // 4 GiB ~ inf: memory after the gap
        (layout::RAM_64BIT_START, usize::MAX, RegionType::Ram),
        // 3 GiB ~ 3712 MiB: 32-bit device memory hole
        (
            layout::MEM_32BIT_RESERVED_START,
            layout::MEM_32BIT_DEVICES_SIZE as usize,
            RegionType::SubRegion,
        ),
        // 3712 MiB ~ 3968 MiB: 32-bit reserved memory hole
        (
            layout::MEM_32BIT_RESERVED_START.unchecked_add(layout::MEM_32BIT_DEVICES_SIZE),
            (layout::MEM_32BIT_RESERVED_SIZE - layout::MEM_32BIT_DEVICES_SIZE) as usize,
            RegionType::Reserved,
        ),
    ]
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
    cmdline_size: usize,
    initramfs: &Option<InitramfsConfig>,
    _num_cpus: u32,
    setup_header: Option<setup_header>,
    rsdp_addr: Option<GuestAddress>,
    serial_number: Option<&str>,
    uuid: Option<&str>,
    oem_strings: Option<&[&str]>,
    topology: Option<(u16, u16, u16, u16)>,
) -> super::Result<()> {
    // Write EBDA address to location where ACPICA expects to find it
    guest_mem
        .write_obj((layout::EBDA_START.0 >> 4) as u16, layout::EBDA_POINTER)
        .map_err(Error::EbdaSetup)?;

    let size = smbios::setup_smbios(guest_mem, serial_number, uuid, oem_strings)
        .map_err(Error::SmbiosSetup)?;

    // Place the MP table after the SMIOS table aligned to 16 bytes
    let offset = GuestAddress(layout::SMBIOS_START).unchecked_add(size);
    let offset = GuestAddress((offset.0 + 16) & !0xf);
    mptable::setup_mptable(offset, guest_mem, _num_cpus, topology).map_err(Error::MpTableSetup)?;

    // Check that the RAM is not smaller than the RSDP start address
    if let Some(rsdp_addr) = rsdp_addr {
        if rsdp_addr.0 > guest_mem.last_addr().0 {
            return Err(super::Error::RsdpPastRamEnd);
        }
    }

    match setup_header {
        Some(hdr) => configure_32bit_entry(
            guest_mem,
            cmdline_addr,
            cmdline_size,
            initramfs,
            hdr,
            rsdp_addr,
        ),
        None => configure_pvh(guest_mem, cmdline_addr, initramfs, rsdp_addr),
    }
}

type RamRange = (u64, u64);

/// Returns usable physical memory ranges for the guest
/// These should be used to create e820_RAM memory maps
pub fn generate_ram_ranges(guest_mem: &GuestMemoryMmap) -> super::Result<Vec<RamRange>> {
    // Merge continuous memory regions into one region.
    // Note: memory regions from "GuestMemory" are sorted and non-zero sized.
    let ram_regions = {
        let mut ram_regions = Vec::new();
        let mut current_start = guest_mem
            .iter()
            .next()
            .map(GuestMemoryRegion::start_addr)
            .expect("GuestMemory must have one memory region at least")
            .raw_value();
        let mut current_end = current_start;

        for (start, size) in guest_mem
            .iter()
            .map(|m| (m.start_addr().raw_value(), m.len()))
        {
            if current_end == start {
                // This zone is continuous with the previous one.
                current_end += size;
            } else {
                ram_regions.push((current_start, current_end));

                current_start = start;
                current_end = start + size;
            }
        }

        ram_regions.push((current_start, current_end));

        ram_regions
    };

    // Create the memory map entry for memory region before the gap
    let mut ram_ranges = vec![];

    // Generate the first usable physical memory range before the gap. The e820 map
    // should only report memory above 1MiB.
    let first_ram_range = {
        let (first_region_start, first_region_end) =
            ram_regions.first().ok_or(super::Error::MemmapTableSetup)?;
        let high_ram_start = layout::HIGH_RAM_START.raw_value();
        let mem_32bit_reserved_start = layout::MEM_32BIT_RESERVED_START.raw_value();

        if !((first_region_start <= &high_ram_start)
            && (first_region_end > &high_ram_start)
            && (first_region_end <= &mem_32bit_reserved_start))
        {
            error!(
                "Unexpected first memory region layout: (start: 0x{:08x}, end: 0x{:08x}).
                high_ram_start: 0x{:08x}, mem_32bit_reserved_start: 0x{:08x}",
                first_region_start, first_region_end, high_ram_start, mem_32bit_reserved_start
            );

            return Err(super::Error::MemmapTableSetup);
        }

        info!(
            "first usable physical memory range, start: 0x{:08x}, end: 0x{:08x}",
            high_ram_start, first_region_end
        );

        (high_ram_start, *first_region_end)
    };
    ram_ranges.push(first_ram_range);

    // Generate additional usable physical memory range after the gap if any.
    for ram_region in ram_regions.iter().skip(1) {
        info!(
            "found usable physical memory range, start: 0x{:08x}, end: 0x{:08x}",
            ram_region.0, ram_region.1
        );

        ram_ranges.push(*ram_region);
    }

    Ok(ram_ranges)
}

fn configure_pvh(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    initramfs: &Option<InitramfsConfig>,
    rsdp_addr: Option<GuestAddress>,
) -> super::Result<()> {
    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;

    let mut start_info = hvm_start_info {
        magic: XEN_HVM_START_MAGIC_VALUE,
        version: 1, // pvh has version 1
        nr_modules: 0,
        cmdline_paddr: cmdline_addr.raw_value(),
        memmap_paddr: layout::MEMMAP_START.raw_value(),
        ..Default::default()
    };

    if let Some(rsdp_addr) = rsdp_addr {
        start_info.rsdp_paddr = rsdp_addr.0;
    }

    if let Some(initramfs_config) = initramfs {
        // The initramfs has been written to guest memory already, here we just need to
        // create the module structure that describes it.
        let ramdisk_mod = hvm_modlist_entry {
            paddr: initramfs_config.address.raw_value(),
            size: initramfs_config.size as u64,
            ..Default::default()
        };

        start_info.nr_modules += 1;
        start_info.modlist_paddr = layout::MODLIST_START.raw_value();

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

    // Get usable physical memory ranges
    let ram_ranges = generate_ram_ranges(guest_mem)?;

    // Create e820 memory map entries
    for ram_range in ram_ranges {
        info!(
            "create_memmap_entry, start: 0x{:08x}, end: 0x{:08x}",
            ram_range.0, ram_range.1
        );
        add_memmap_entry(
            &mut memmap,
            ram_range.0,
            ram_range.1 - ram_range.0,
            E820_RAM,
        );
    }

    add_memmap_entry(
        &mut memmap,
        layout::PCI_MMCONFIG_START.0,
        layout::PCI_MMCONFIG_SIZE,
        E820_RESERVED,
    );

    start_info.memmap_entries = memmap.len() as u32;

    // Copy the vector with the memmap table to the MEMMAP_START address
    // which is already saved in the memmap_paddr field of hvm_start_info struct.
    let mut memmap_start_addr = layout::MEMMAP_START;

    guest_mem
        .checked_offset(
            memmap_start_addr,
            mem::size_of::<hvm_memmap_table_entry>() * start_info.memmap_entries as usize,
        )
        .ok_or(super::Error::MemmapTablePastRamEnd)?;

    // For every entry in the memmap vector, write it to guest memory.
    for memmap_entry in memmap {
        guest_mem
            .write_obj(memmap_entry, memmap_start_addr)
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

fn configure_32bit_entry(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initramfs: &Option<InitramfsConfig>,
    setup_hdr: setup_header,
    rsdp_addr: Option<GuestAddress>,
) -> super::Result<()> {
    const KERNEL_LOADER_OTHER: u8 = 0xff;

    // Use the provided setup header
    let mut params = boot_params {
        hdr: setup_hdr,
        ..Default::default()
    };

    // Common bootparams settings
    if params.hdr.type_of_loader == 0 {
        params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    }
    params.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;

    if let Some(initramfs_config) = initramfs {
        params.hdr.ramdisk_image = initramfs_config.address.raw_value() as u32;
        params.hdr.ramdisk_size = initramfs_config.size as u32;
    }

    add_e820_entry(&mut params, 0, layout::EBDA_START.raw_value(), E820_RAM)?;

    let mem_end = guest_mem.last_addr();
    if mem_end < layout::MEM_32BIT_RESERVED_START {
        add_e820_entry(
            &mut params,
            layout::HIGH_RAM_START.raw_value(),
            mem_end.unchecked_offset_from(layout::HIGH_RAM_START) + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            layout::HIGH_RAM_START.raw_value(),
            layout::MEM_32BIT_RESERVED_START.unchecked_offset_from(layout::HIGH_RAM_START),
            E820_RAM,
        )?;
        if mem_end > layout::RAM_64BIT_START {
            add_e820_entry(
                &mut params,
                layout::RAM_64BIT_START.raw_value(),
                mem_end.unchecked_offset_from(layout::RAM_64BIT_START) + 1,
                E820_RAM,
            )?;
        }
    }

    add_e820_entry(
        &mut params,
        layout::PCI_MMCONFIG_START.0,
        layout::PCI_MMCONFIG_SIZE,
        E820_RESERVED,
    )?;

    if let Some(rsdp_addr) = rsdp_addr {
        params.acpi_rsdp_addr = rsdp_addr.0;
    }

    let zero_page_addr = layout::ZERO_PAGE_START;
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(super::Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(super::Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), Error> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

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

pub fn get_host_cpu_phys_bits(hypervisor: &Arc<dyn hypervisor::Hypervisor>) -> u8 {
    // SAFETY: call cpuid with valid leaves
    unsafe {
        let leaf = x86_64::__cpuid(0x8000_0000);

        // Detect and handle AMD SME (Secure Memory Encryption) properly.
        // Some physical address bits may become reserved when the feature is enabled.
        // See AMD64 Architecture Programmer's Manual Volume 2, Section 7.10.1
        let reduced = if leaf.eax >= 0x8000_001f
            && matches!(hypervisor.get_cpu_vendor(), CpuVendor::AMD)
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
    cpuid: &mut Vec<CpuIdEntry>,
    threads_per_core: u16,
    cores_per_die: u16,
    dies_per_package: u16,
    packages: u16,
    cpu_vendor: CpuVendor,
    id: u32,
) {
    let x2apic_id = get_x2apic_id(
        id,
        Some((threads_per_core, cores_per_die, dies_per_package, packages)),
    );

    // Note: the topology defined here is per "package" (~NUMA node).
    let thread_width = u16::BITS - (threads_per_core - 1).leading_zeros();
    let core_width = u16::BITS - (cores_per_die - 1).leading_zeros() + thread_width;
    let die_width = u16::BITS - (dies_per_package - 1).leading_zeros() + core_width;

    // The very old way: a flat number of logical CPUs per package: CPUID.1H:EBX[23:16] bits.
    let mut cpu_ebx = CpuidPatch::get_cpuid_reg(cpuid, 0x1, None, CpuidReg::EBX).unwrap_or(0);
    cpu_ebx |= ((dies_per_package as u32) * (cores_per_die as u32) * (threads_per_core as u32))
        & (0xff << 16);
    CpuidPatch::set_cpuid_reg(cpuid, 0x1, None, CpuidReg::EBX, cpu_ebx);

    let mut cpu_edx = CpuidPatch::get_cpuid_reg(cpuid, 0x1, None, CpuidReg::EDX).unwrap_or(0);
    cpu_edx |= 1 << 28;
    CpuidPatch::set_cpuid_reg(cpuid, 0x1, None, CpuidReg::EDX, cpu_edx);

    // The legacy way: threads+cores per package.
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
    CpuidPatch::set_cpuid_reg(cpuid, 0xb, Some(1), CpuidReg::EDX, x2apic_id);

    // The modern way: many-level hierarchy (but we here only support four levels).
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

    if matches!(cpu_vendor, CpuVendor::AMD) {
        CpuidPatch::set_cpuid_reg(
            cpuid,
            0x8000_001e,
            Some(0),
            CpuidReg::EBX,
            ((threads_per_core as u32 - 1) << 8) | (x2apic_id & 0xff),
        );
        CpuidPatch::set_cpuid_reg(
            cpuid,
            0x8000_001e,
            Some(0),
            CpuidReg::ECX,
            ((dies_per_package as u32 - 1) << 8) | (thread_width + die_width) & 0xff,
        );
        CpuidPatch::set_cpuid_reg(cpuid, 0x8000_001e, Some(0), CpuidReg::EDX, 0);
        if cores_per_die * threads_per_core > 1 {
            let ecx =
                CpuidPatch::get_cpuid_reg(cpuid, 0x8000_0001, Some(0), CpuidReg::ECX).unwrap_or(0);
            CpuidPatch::set_cpuid_reg(
                cpuid,
                0x8000_0001,
                Some(0),
                CpuidReg::ECX,
                ecx | (1u32 << 1) | (1u32 << 22),
            );
            CpuidPatch::set_cpuid_reg(
                cpuid,
                0x0000_0001,
                Some(0),
                CpuidReg::EBX,
                (x2apic_id << 24) | (8 << 8) | (((cores_per_die * threads_per_core) as u32) << 16),
            );
            let cpuid_patches = vec![
                // Patch tsc deadline timer bit
                CpuidPatch {
                    function: 1,
                    index: 0,
                    flags_bit: None,
                    eax_bit: None,
                    ebx_bit: None,
                    ecx_bit: None,
                    edx_bit: Some(28),
                },
            ];
            CpuidPatch::patch_cpuid(cpuid, cpuid_patches);
            CpuidPatch::set_cpuid_reg(
                cpuid,
                0x8000_0008,
                Some(0),
                CpuidReg::ECX,
                ((thread_width + core_width + die_width) << 12)
                    | ((cores_per_die * threads_per_core) - 1) as u32,
            );
        } else {
            CpuidPatch::set_cpuid_reg(cpuid, 0x8000_0008, Some(0), CpuidReg::ECX, 0u32);
        }
    }
}
#[cfg(test)]
mod tests {
    use linux_loader::loader::bootparam::boot_e820_entry;

    use super::*;

    #[test]
    fn regions_base_addr() {
        let regions = arch_memory_regions();
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
            0,
            &None,
            1,
            None,
            Some(layout::RSDP_POINTER),
            None,
            None,
            None,
            None,
        );
        config_err.unwrap_err();

        // Now assigning some memory that falls before the 32bit memory hole.
        let arch_mem_regions = arch_memory_regions();
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram && r.1 != usize::MAX)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let arch_mem_regions = arch_memory_regions();
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| {
                if r.1 == usize::MAX {
                    (r.0, 128 << 20)
                } else {
                    (r.0, r.1)
                }
            })
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_table = [(boot_e820_entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_table,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_table[0].addr,
            e820_table[0].size,
            e820_table[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_table[0]),
            format!("{:?}", expected_params.e820_table[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_table.len() as u8 + 1;
        add_e820_entry(
            &mut params,
            e820_table[0].addr,
            e820_table[0].size,
            e820_table[0].type_,
        )
        .unwrap_err();
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

        assert_eq!(format!("{memmap:?}"), format!("{expected_memmap:?}"));
    }

    #[test]
    fn test_get_x2apic_id() {
        let x2apic_id = get_x2apic_id(0, Some((2, 3, 1, 1)));
        assert_eq!(x2apic_id, 0);

        let x2apic_id = get_x2apic_id(1, Some((2, 3, 1, 1)));
        assert_eq!(x2apic_id, 1);

        let x2apic_id = get_x2apic_id(2, Some((2, 3, 1, 1)));
        assert_eq!(x2apic_id, 2);

        let x2apic_id = get_x2apic_id(6, Some((2, 3, 1, 1)));
        assert_eq!(x2apic_id, 8);

        let x2apic_id = get_x2apic_id(7, Some((2, 3, 1, 1)));
        assert_eq!(x2apic_id, 9);

        let x2apic_id = get_x2apic_id(8, Some((2, 3, 1, 1)));
        assert_eq!(x2apic_id, 10);

        let x2apic_id = get_x2apic_id(257, Some((1, 312, 1, 1)));
        assert_eq!(x2apic_id, 257);

        assert_eq!(255, get_max_x2apic_id((1, 256, 1, 1)));
    }
}
