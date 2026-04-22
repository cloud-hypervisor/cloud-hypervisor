// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2023, Microsoft Corporation
//
use std::collections::HashMap;
use std::ffi::CString;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use hypervisor::HypervisorType;
use igvm::snp_defs::SevVmsa;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader};
#[cfg(feature = "sev_snp")]
use igvm_defs::{IGVM_VHS_MEMORY_MAP_ENTRY, MemoryMapEntryType};
use igvm_defs::{
    IGVM_VHS_PARAMETER, IGVM_VHS_PARAMETER_INSERT, IgvmPageDataType, IgvmPlatformType,
};
use log::debug;
#[cfg(all(feature = "kvm", feature = "sev_snp"))]
use log::error;
#[cfg(feature = "sev_snp")]
use log::info;
#[cfg(feature = "mshv")]
use mshv_bindings::*;
use thiserror::Error;
#[cfg(all(feature = "kvm", feature = "sev_snp"))]
use vm_memory::Bytes;
#[cfg(feature = "sev_snp")]
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemory};
#[cfg(all(feature = "kvm", feature = "sev_snp"))]
use vm_migration::Snapshottable;
use zerocopy::IntoBytes;
#[cfg(all(feature = "kvm", feature = "sev_snp"))]
use zerocopy::{FromBytes, FromZeros};

#[cfg(feature = "sev_snp")]
use crate::GuestMemoryMmap;
use crate::cpu::CpuManager;
use crate::igvm::loader::Loader;
use crate::igvm::{BootPageAcceptance, HV_PAGE_SIZE, IgvmLoadedInfo, StartupMemoryType};
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
#[cfg(all(
    feature = "kvm",
    feature = "sev_snp",
    feature = "fw_cfg",
    target_arch = "x86_64"
))]
use crate::sev::{MeasuredBootInfo, SEV_HASH_BLOCK_ADDRESS, SEV_HASH_BLOCK_SIZE};

#[cfg(feature = "sev_snp")]
const ISOLATED_PAGE_SHIFT: u32 = 12;
#[cfg(all(feature = "kvm", feature = "sev_snp"))]
const SNP_CPUID_LIMIT: u32 = 64;
// see section 7.1
// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
#[cfg(all(feature = "kvm", feature = "sev_snp"))]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, IntoBytes, FromBytes)]
pub struct SnpCpuidFunc {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub xcr0_in: u64,
    pub xss_in: u64,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub reserved: u64,
}

#[cfg(all(feature = "kvm", feature = "sev_snp"))]
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes)]
pub struct SnpCpuidInfo {
    pub count: u32,
    pub _reserved1: u32,
    pub _reserved2: u64,
    pub entries: [SnpCpuidFunc; SNP_CPUID_LIMIT as usize],
}
#[derive(Debug, Error)]
pub enum Error {
    #[error("command line is not a valid C string")]
    InvalidCommandLine(#[source] std::ffi::NulError),
    #[error("failed to read igvm file")]
    Igvm(#[source] std::io::Error),
    #[error("invalid igvm file")]
    InvalidIgvmFile(#[source] igvm::Error),
    #[error("invalid guest memory map")]
    InvalidGuestMemmap(#[source] arch::Error),
    #[error("loader error")]
    Loader(#[source] crate::igvm::loader::Error),
    #[error("parameter too large for parameter area")]
    ParameterTooLarge,
    #[error("Error importing isolated pages")]
    ImportIsolatedPages(#[source] hypervisor::HypervisorVmError),
    #[error("Error completing importing isolated pages")]
    CompleteIsolatedImport(#[source] hypervisor::HypervisorVmError),
    #[error("Error decoding host data")]
    FailedToDecodeHostData(#[source] hex::FromHexError),
    #[error("Error allocating address space")]
    MemoryManager(MemoryManagerError),
    #[error("IGVM file not provided")]
    MissingIgvm,
    #[error("Error applying VMSA to vCPU registers: {0}")]
    SetVmsa(#[source] crate::cpu::Error),
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    #[error("Error building SEV-SNP measured boot hash block")]
    MeasuredBoot(#[source] vmm_sys_util::errno::Error),
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    #[error(
        "igvmfile inserts unmeasured parameter area [0x{region_start:x}, 0x{region_end:x}) over SEV-SNP kernel hashes region [0x{hash_start:x}, 0x{hash_end:x})"
    )]
    MeasuredBootHashOverlap {
        region_start: u64,
        region_end: u64,
        hash_start: u64,
        hash_end: u64,
    },
}

// KVM SNP page types — linux/arch/x86/include/uapi/asm/sev-guest.h
#[cfg(feature = "kvm")]
const KVM_SNP_PAGE_TYPE_NORMAL: u32 = 1;
#[cfg(feature = "kvm")]
const KVM_SNP_PAGE_TYPE_VMSA: u32 = 2;
#[cfg(feature = "kvm")]
const KVM_SNP_PAGE_TYPE_UNMEASURED: u32 = 4;
#[cfg(feature = "kvm")]
const KVM_SNP_PAGE_TYPE_SECRETS: u32 = 5;
#[cfg(feature = "kvm")]
const KVM_SNP_PAGE_TYPE_CPUID: u32 = 6;

// Consolidated page type/size configuration per hypervisor.
struct PageTypeConfig {
    isolated_page_size_4kb: u32,
    normal: u32,
    unmeasured: u32,
    cpuid: u32,
    secrets: u32,
    vmsa: u32,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
struct GpaPages {
    pub gpa: u64,
    pub page_type: u32,
    pub page_size: u32,
}

#[derive(Debug)]
enum ParameterAreaState {
    /// Parameter area has been declared via a ParameterArea header.
    Allocated { data: Vec<u8>, max_size: u64 },
    /// Parameter area inserted and invalid to use.
    Inserted,
}

#[cfg(feature = "sev_snp")]
fn igvm_memmap_from_ram_range(ram_range: (u64, u64)) -> IGVM_VHS_MEMORY_MAP_ENTRY {
    assert!(ram_range.0.is_multiple_of(HV_PAGE_SIZE));
    assert!((ram_range.1 - ram_range.0).is_multiple_of(HV_PAGE_SIZE));

    IGVM_VHS_MEMORY_MAP_ENTRY {
        starting_gpa_page_number: ram_range.0 / HV_PAGE_SIZE,
        number_of_pages: (ram_range.1 - ram_range.0) / HV_PAGE_SIZE,
        entry_type: MemoryMapEntryType::MEMORY,
        flags: 0,
        reserved: 0,
    }
}

#[cfg(feature = "sev_snp")]
fn generate_memory_map(
    guest_mem: &GuestMemoryMmap,
) -> Result<Vec<IGVM_VHS_MEMORY_MAP_ENTRY>, Error> {
    let mut memory_map = Vec::new();

    // Get usable physical memory ranges
    let ram_ranges = arch::generate_ram_ranges(guest_mem).map_err(Error::InvalidGuestMemmap)?;

    for ram_range in ram_ranges {
        memory_map.push(igvm_memmap_from_ram_range(ram_range));
    }

    Ok(memory_map)
}

// Import a parameter to the given parameter area.
fn import_parameter(
    parameter_areas: &mut HashMap<u32, ParameterAreaState>,
    info: &IGVM_VHS_PARAMETER,
    parameter: &[u8],
) -> Result<(), Error> {
    let (parameter_area, max_size) = match parameter_areas
        .get_mut(&info.parameter_area_index)
        .expect("parameter area should be present")
    {
        ParameterAreaState::Allocated { data, max_size } => (data, max_size),
        ParameterAreaState::Inserted => panic!("igvmfile is not valid"),
    };
    let offset = info.byte_offset as usize;
    let end_of_parameter = offset + parameter.len();

    if end_of_parameter > *max_size as usize {
        // TODO: tracing for which parameter was too big?
        return Err(Error::ParameterTooLarge);
    }

    if parameter_area.len() < end_of_parameter {
        parameter_area.resize(end_of_parameter, 0);
    }

    parameter_area[offset..end_of_parameter].copy_from_slice(parameter);
    Ok(())
}

///
/// Extract sev_features from the boot CPU (vp_index 0) VMSA.
///
#[cfg(feature = "sev_snp")]
pub fn extract_sev_features(igvm_file: &IgvmFile) -> u64 {
    for header in igvm_file.directives() {
        if let IgvmDirectiveHeader::SnpVpContext { vp_index, vmsa, .. } = header
            && *vp_index == 0
        {
            return vmsa.sev_features.into();
        }
    }
    0
}

///
/// Load the given IGVM file to guest memory.
/// Right now it only supports SNP based isolation.
/// We can boot legacy VM with an igvm file without
/// any isolation.
///
/// NOTE: KVM and MSHV have different page type values and CPUID/VMSA handling.
/// Hypervisor-specific code paths are gated by runtime type checks. A future
/// refactor could split these into separate KVM/MSHV loader implementations.
#[allow(clippy::needless_pass_by_value)]
pub fn load_igvm(
    igvm_file: IgvmFile,
    memory_manager: Arc<Mutex<MemoryManager>>,
    cpu_manager: Arc<Mutex<CpuManager>>,
    cmdline: &str,
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    measured_boot: Option<MeasuredBootInfo>,
    #[cfg(feature = "sev_snp")] host_data: &Option<String>,
) -> Result<Box<IgvmLoadedInfo>, Error> {
    let hypervisor_type = cpu_manager.lock().unwrap().hypervisor_type();
    let page_types = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => PageTypeConfig {
            isolated_page_size_4kb: mshv_bindings::hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
            normal: mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
            unmeasured: mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_UNMEASURED,
            cpuid: mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_CPUID,
            secrets: mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_SECRETS,
            vmsa: mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_VMSA,
        },
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => PageTypeConfig {
            isolated_page_size_4kb: HV_PAGE_SIZE as u32,
            normal: KVM_SNP_PAGE_TYPE_NORMAL,
            unmeasured: KVM_SNP_PAGE_TYPE_UNMEASURED,
            cpuid: KVM_SNP_PAGE_TYPE_CPUID,
            secrets: KVM_SNP_PAGE_TYPE_SECRETS,
            vmsa: KVM_SNP_PAGE_TYPE_VMSA,
        },
    };

    let mut loaded_info: Box<IgvmLoadedInfo> = Box::default();
    let command_line = CString::new(cmdline).map_err(Error::InvalidCommandLine)?;
    let memory = memory_manager.lock().as_ref().unwrap().guest_memory();
    let mut gpas: Vec<GpaPages> = Vec::new();
    let proc_count = cpu_manager.lock().unwrap().vcpus().len() as u32;

    #[cfg(feature = "sev_snp")]
    let mut host_data_contents = [0; 32];
    #[cfg(feature = "sev_snp")]
    if let Some(host_data_str) = host_data {
        hex::decode_to_slice(host_data_str, &mut host_data_contents as &mut [u8])
            .map_err(Error::FailedToDecodeHostData)?;
    }

    #[cfg(feature = "sev_snp")]
    let sev_snp_enabled = cpu_manager.lock().unwrap().sev_snp_enabled();
    let mask = match &igvm_file.platforms()[0] {
        IgvmPlatformHeader::SupportedPlatform(info) => {
            debug_assert!(info.platform_type == IgvmPlatformType::SEV_SNP);
            info.compatibility_mask
        }
    };

    let mut loader = Loader::new(memory);

    let mut parameter_areas: HashMap<u32, ParameterAreaState> = HashMap::new();
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    let measured_boot_hash_block = if hypervisor_type == HypervisorType::Kvm {
        measured_boot
            .as_ref()
            .map(|measured_boot| {
                measured_boot
                    .build_hash_block()
                    .map_err(Error::MeasuredBoot)
            })
            .transpose()?
    } else {
        None
    };
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    let measured_boot_hash_page_base = SEV_HASH_BLOCK_ADDRESS / HV_PAGE_SIZE;
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    let measured_boot_hash_offset = (SEV_HASH_BLOCK_ADDRESS % HV_PAGE_SIZE) as usize;
    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    let mut measured_boot_hash_block_inserted = measured_boot_hash_block.is_none();

    for header in igvm_file.directives() {
        debug_assert!(header.compatibility_mask().unwrap_or(mask) & mask == mask);

        match header {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: _,
                flags,
                data_type,
                data,
            } => {
                debug_assert!((data.len() as u64).is_multiple_of(HV_PAGE_SIZE));

                // TODO: only 4k or empty page data supported right now
                assert!(data.len() as u64 == HV_PAGE_SIZE || data.is_empty());

                let acceptance = match *data_type {
                    IgvmPageDataType::NORMAL => {
                        if flags.unmeasured() {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: page_types.unmeasured,
                                page_size: page_types.isolated_page_size_4kb,
                            });
                            BootPageAcceptance::ExclusiveUnmeasured
                        } else {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: page_types.normal,
                                page_size: page_types.isolated_page_size_4kb,
                            });
                            BootPageAcceptance::Exclusive
                        }
                    }
                    IgvmPageDataType::SECRETS => {
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: page_types.secrets,
                            page_size: page_types.isolated_page_size_4kb,
                        });
                        BootPageAcceptance::SecretsPage
                    }
                    IgvmPageDataType::CPUID_DATA => {
                        #[cfg(feature = "mshv")]
                        if hypervisor_type == HypervisorType::Mshv {
                            // SAFETY: CPUID is readonly
                            unsafe {
                                let cpuid_page_p: *mut hv_psp_cpuid_page =
                                    data.as_ptr() as *mut hv_psp_cpuid_page; // as *mut hv_psp_cpuid_page;
                                let cpuid_page: &mut hv_psp_cpuid_page = &mut *cpuid_page_p;
                                for i in 0..cpuid_page.count {
                                    let leaf = cpuid_page.cpuid_leaf_info[i as usize];
                                    let mut in_leaf = cpu_manager
                                        .lock()
                                        .unwrap()
                                        .get_cpuid_leaf(
                                            0,
                                            leaf.eax_in,
                                            leaf.ecx_in,
                                            leaf.xfem_in,
                                            leaf.xss_in,
                                        )
                                        .unwrap();
                                    if leaf.eax_in == 1 {
                                        in_leaf[2] &= 0x7FFFFFFF;
                                    }
                                    cpuid_page.cpuid_leaf_info[i as usize].eax_out = in_leaf[0];
                                    cpuid_page.cpuid_leaf_info[i as usize].ebx_out = in_leaf[1];
                                    cpuid_page.cpuid_leaf_info[i as usize].ecx_out = in_leaf[2];
                                    cpuid_page.cpuid_leaf_info[i as usize].edx_out = in_leaf[3];
                                }
                            }
                        }
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: page_types.cpuid,
                            page_size: page_types.isolated_page_size_4kb,
                        });
                        BootPageAcceptance::CpuidPage
                    }
                    // TODO: other data types SNP / TDX only, unsupported
                    _ => todo!("unsupported IgvmPageDataType"),
                };

                #[allow(unused_mut)]
                let mut imported_page = false;
                #[cfg(all(feature = "kvm", feature = "sev_snp"))]
                if hypervisor_type == HypervisorType::Kvm
                    && *data_type == IgvmPageDataType::CPUID_DATA
                {
                    let mut new_cp = SnpCpuidInfo::new_zeroed();

                    let entries = cpu_manager.lock().unwrap().common_cpuid();
                    let cp_count = std::cmp::min(SNP_CPUID_LIMIT as usize, entries.len());
                    // TODO: Filter cpuid rather than truncate
                    for (i, entry) in entries.iter().enumerate().take(cp_count) {
                        new_cp.entries[i].eax_in = entry.function;
                        new_cp.entries[i].ecx_in = entry.index;
                        new_cp.entries[i].eax = entry.eax;
                        new_cp.entries[i].ebx = entry.ebx;
                        new_cp.entries[i].ecx = entry.ecx;
                        new_cp.entries[i].edx = entry.edx;
                        /*
                         * Guest kernels will calculate EBX themselves using the 0xD
                         * subfunctions corresponding to the individual XSAVE areas, so only
                         * encode the base XSAVE size in the initial leaves, corresponding
                         * to the initial XCR0=1 state. (https://tinyurl.com/qemu-cpuid)
                         */
                        if new_cp.entries[i].eax_in == 0xd
                            && (new_cp.entries[i].ecx_in == 0x0 || new_cp.entries[i].ecx_in == 0x1)
                        {
                            new_cp.entries[i].ebx = 0x240;
                            new_cp.entries[i].xcr0_in = 1;
                            new_cp.entries[i].xss_in = 0;
                        }

                        // KVM SNP launch may reject a CPUID page with bits it intends
                        // to sanitize internally. Pre-clearing the known unsafe bits keeps
                        // the CPUID page stable across launch updates.
                        match (new_cp.entries[i].eax_in, new_cp.entries[i].ecx_in) {
                            (0x1, 0x0) => {
                                new_cp.entries[i].ecx &= !(1 << 24);
                            }
                            (0x7, 0x0) => {
                                new_cp.entries[i].ebx &= !0x2;
                                new_cp.entries[i].edx = 0;
                            }
                            (0x80000008, 0x0) => {
                                new_cp.entries[i].ebx &= !0x0200_0000;
                            }
                            (0x80000021, 0x0) => {
                                new_cp.entries[i].ecx = 0;
                            }
                            _ => {}
                        }
                    }
                    new_cp.count = cp_count as u32;
                    loader
                        .import_pages(gpa / HV_PAGE_SIZE, 1, acceptance, new_cp.as_mut_bytes())
                        .map_err(Error::Loader)?;
                    imported_page = true;
                }
                #[cfg(all(
                    feature = "kvm",
                    feature = "sev_snp",
                    feature = "fw_cfg",
                    target_arch = "x86_64"
                ))]
                if let Some(hash_block) = measured_boot_hash_block.as_ref().filter(|_| {
                    !imported_page && gpa / HV_PAGE_SIZE == measured_boot_hash_page_base
                }) {
                    let mut page = if data.is_empty() {
                        vec![0; HV_PAGE_SIZE as usize]
                    } else {
                        let mut page = data.clone();
                        page.resize(HV_PAGE_SIZE as usize, 0);
                        page
                    };
                    // If a data page from the bootloader contains this range,
                    // we need to ensure that the measured boot table is injected
                    // prior to importing the pages
                    page[measured_boot_hash_offset
                        ..measured_boot_hash_offset + SEV_HASH_BLOCK_SIZE]
                        .copy_from_slice(&hash_block[..SEV_HASH_BLOCK_SIZE]);
                    loader
                        .import_pages(gpa / HV_PAGE_SIZE, 1, acceptance, &page)
                        .map_err(Error::Loader)?;
                    measured_boot_hash_block_inserted = true;
                    imported_page = true;
                }
                if !imported_page {
                    loader
                        .import_pages(gpa / HV_PAGE_SIZE, 1, acceptance, data)
                        .map_err(Error::Loader)?;
                }
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data,
            } => {
                debug_assert!(number_of_bytes % HV_PAGE_SIZE == 0);
                debug_assert!(
                    initial_data.is_empty() || initial_data.len() as u64 == *number_of_bytes
                );

                // Allocate a new parameter area. It must not be already used.
                if parameter_areas
                    .insert(
                        *parameter_area_index,
                        ParameterAreaState::Allocated {
                            data: initial_data.clone(),
                            max_size: *number_of_bytes,
                        },
                    )
                    .is_some()
                {
                    panic!("IgvmFile is not valid, invalid invariant");
                }
            }
            IgvmDirectiveHeader::VpCount(info) => {
                import_parameter(&mut parameter_areas, info, proc_count.as_bytes())?;
            }
            IgvmDirectiveHeader::MmioRanges(_info) => {
                todo!("unsupported IgvmPageDataType");
            }
            IgvmDirectiveHeader::MemoryMap(_info) =>
            {
                #[cfg(feature = "sev_snp")]
                if sev_snp_enabled {
                    let guest_mem = memory_manager.lock().unwrap().boot_guest_memory();
                    let memory_map = generate_memory_map(&guest_mem)?;
                    import_parameter(&mut parameter_areas, _info, memory_map.as_bytes())?;
                } else {
                    todo!("Not implemented");
                }
            }
            IgvmDirectiveHeader::CommandLine(info) => {
                import_parameter(&mut parameter_areas, info, command_line.as_bytes_with_nul())?;
            }
            IgvmDirectiveHeader::RequiredMemory {
                gpa,
                compatibility_mask: _,
                number_of_bytes,
                vtl2_protectable: _,
            } => {
                let memory_type = StartupMemoryType::Ram;
                loaded_info.gpas.push(*gpa);
                loader
                    .verify_startup_memory_available(
                        gpa / HV_PAGE_SIZE,
                        *number_of_bytes as u64 / HV_PAGE_SIZE,
                        memory_type,
                    )
                    .map_err(Error::Loader)?;
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                compatibility_mask: _,
                vp_index,
                vmsa,
            } => {
                assert_eq!(gpa % HV_PAGE_SIZE, 0);
                let mut data: [u8; HV_PAGE_SIZE as usize] = [0; HV_PAGE_SIZE as usize];
                let len = size_of::<SevVmsa>();
                loaded_info.vmsa_gpa = *gpa;
                loaded_info.vmsa = **vmsa;
                // Only supported for index zero
                if *vp_index == 0 {
                    data[..len].copy_from_slice(vmsa.as_bytes());
                    loader
                        .import_pages(gpa / HV_PAGE_SIZE, 1, BootPageAcceptance::VpContext, &data)
                        .map_err(Error::Loader)?;
                }

                // Set vCPU initial register state from VMSA before SNP_LAUNCH_FINISH
                #[cfg(all(feature = "kvm", feature = "sev_snp"))]
                if hypervisor_type == HypervisorType::Kvm {
                    let vcpus = cpu_manager.lock().unwrap().vcpus();
                    for vcpu in vcpus {
                        let vcpu_locked = vcpu.lock().unwrap();
                        let vcpu_id: u16 = vcpu_locked.id().parse().unwrap();
                        if vcpu_id == *vp_index {
                            vcpu_locked
                                .setup_sev_snp_regs(loaded_info.vmsa)
                                .map_err(Error::SetVmsa)?;
                            vcpu_locked
                                .set_sev_control_register(0)
                                .map_err(Error::SetVmsa)?;
                        }
                    }
                }

                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: page_types.vmsa,
                    page_size: page_types.isolated_page_size_4kb,
                });
            }
            IgvmDirectiveHeader::SnpIdBlock {
                compatibility_mask,
                author_key_enabled,
                reserved,
                ld,
                family_id,
                image_id,
                version,
                guest_svn,
                id_key_algorithm,
                author_key_algorithm,
                id_key_signature,
                id_public_key,
                author_key_signature,
                author_public_key,
            } => {
                loaded_info.snp_id_block.compatibility_mask = *compatibility_mask;
                loaded_info.snp_id_block.author_key_enabled = *author_key_enabled;
                loaded_info.snp_id_block.reserved = *reserved;
                loaded_info.snp_id_block.ld = *ld;
                loaded_info.snp_id_block.family_id = *family_id;
                loaded_info.snp_id_block.image_id = *image_id;
                loaded_info.snp_id_block.version = *version;
                loaded_info.snp_id_block.guest_svn = *guest_svn;
                loaded_info.snp_id_block.id_key_algorithm = *id_key_algorithm;
                loaded_info.snp_id_block.author_key_algorithm = *author_key_algorithm;
                loaded_info.snp_id_block.id_key_signature = **id_key_signature;
                loaded_info.snp_id_block.id_public_key = **id_public_key;
                loaded_info.snp_id_block.author_key_signature = **author_key_signature;
                loaded_info.snp_id_block.author_public_key = **author_public_key;
            }
            IgvmDirectiveHeader::X64VbsVpContext {
                vtl: _,
                registers: _,
                compatibility_mask: _,
            } => {
                todo!("VbsVpContext not supported");
            }
            IgvmDirectiveHeader::VbsMeasurement { .. } => {
                todo!("VbsMeasurement not supported")
            }
            IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
                gpa,
                compatibility_mask: _,
                parameter_area_index,
            }) => {
                debug_assert!(gpa % HV_PAGE_SIZE == 0);

                let area = parameter_areas
                    .get_mut(parameter_area_index)
                    .expect("igvmfile should be valid");
                match area {
                    ParameterAreaState::Allocated { data, max_size } => {
                        #[cfg(all(
                            feature = "kvm",
                            feature = "sev_snp",
                            feature = "fw_cfg",
                            target_arch = "x86_64"
                        ))]
                        if measured_boot_hash_block.is_some() {
                            let region_end = *gpa + *max_size;
                            let hash_end = SEV_HASH_BLOCK_ADDRESS + SEV_HASH_BLOCK_SIZE as u64;
                            if *gpa <= SEV_HASH_BLOCK_ADDRESS && hash_end <= region_end {
                                // In the case of parameter being inserted where the kernel hashes table lies,
                                // we should reject the igvmfile since it would interfere with the launch digest
                                return Err(Error::MeasuredBootHashOverlap {
                                    region_start: *gpa,
                                    region_end,
                                    hash_start: SEV_HASH_BLOCK_ADDRESS,
                                    hash_end,
                                });
                            }
                        }

                        loader
                            .import_pages(
                                gpa / HV_PAGE_SIZE,
                                *max_size / HV_PAGE_SIZE,
                                BootPageAcceptance::ExclusiveUnmeasured,
                                data,
                            )
                            .map_err(Error::Loader)?;
                    }
                    ParameterAreaState::Inserted => panic!("igvmfile is invalid, multiple insert"),
                }
                *area = ParameterAreaState::Inserted;
                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: page_types.unmeasured,
                    page_size: page_types.isolated_page_size_4kb,
                });
            }
            IgvmDirectiveHeader::ErrorRange { .. } => {
                todo!("Error Range not supported")
            }
            _ => {
                todo!("Header not supported!!")
            }
        }
    }

    #[cfg(all(
        feature = "kvm",
        feature = "sev_snp",
        feature = "fw_cfg",
        target_arch = "x86_64"
    ))]
    if let Some(hash_block) = measured_boot_hash_block.as_ref()
        && !measured_boot_hash_block_inserted
    {
        // Fallback to adding kernel hashes after importing if the page data wasn't found previously
        let mut page = vec![0u8; HV_PAGE_SIZE as usize];
        page[measured_boot_hash_offset..measured_boot_hash_offset + SEV_HASH_BLOCK_SIZE]
            .copy_from_slice(&hash_block[..SEV_HASH_BLOCK_SIZE]);
        loader
            .import_pages(
                measured_boot_hash_page_base,
                1,
                BootPageAcceptance::Exclusive,
                &page,
            )
            .map_err(Error::Loader)?;
        gpas.push(GpaPages {
            gpa: measured_boot_hash_page_base * HV_PAGE_SIZE,
            page_type: page_types.normal,
            page_size: page_types.isolated_page_size_4kb,
        });
    }

    #[cfg(feature = "sev_snp")]
    if sev_snp_enabled {
        memory_manager
            .lock()
            .unwrap()
            .allocate_address_space()
            .map_err(Error::MemoryManager)?;
        use std::time::Instant;

        let mut now = Instant::now();

        // Sort the gpas to group them by the page type
        gpas.sort_by_key(|a| a.gpa);

        let gpas_grouped = gpas
            .iter()
            .fold(Vec::<Vec<GpaPages>>::new(), |mut acc, gpa| {
                if let Some(last_vec) = acc.last_mut()
                    && last_vec[0].page_type == gpa.page_type
                {
                    last_vec.push(*gpa);
                    return acc;
                }
                acc.push(vec![*gpa]);
                acc
            });

        // Import the pages as a group(by page type) of PFNs to reduce the
        // hypercall.
        for group in gpas_grouped.iter() {
            info!(
                "Importing {} page{}",
                group.len(),
                if group.len() > 1 { "s" } else { "" }
            );
            // Convert the gpa into PFN as MSHV hypercall takes an array
            // of PFN for importing the isolated pages
            let pfns: Vec<u64> = group
                .iter()
                .map(|gpa| gpa.gpa >> ISOLATED_PAGE_SHIFT)
                .collect();
            let guest_memory = memory_manager.lock().unwrap().guest_memory().memory();
            let uaddrs: Vec<_> = group
                .iter()
                .map(|gpa| {
                    let guest_region_mmap = guest_memory.to_region_addr(GuestAddress(gpa.gpa));
                    let uaddr_base = guest_region_mmap.unwrap().0.as_ptr() as u64;
                    let uaddr_offset: u64 = guest_region_mmap.unwrap().1.0;
                    uaddr_base + uaddr_offset
                })
                .collect();
            #[cfg(feature = "kvm")]
            let page_type = group[0].page_type;
            #[cfg(feature = "kvm")]
            let mut new_cp = SnpCpuidInfo::new_zeroed();
            #[cfg(feature = "kvm")]
            if hypervisor_type == HypervisorType::Kvm {
                let _ = guest_memory.read(new_cp.as_mut_bytes(), GuestAddress(group[0].gpa));
            }
            let import_result = memory_manager
                .lock()
                .unwrap()
                .vm
                .import_isolated_pages(
                    group[0].page_type,
                    page_types.isolated_page_size_4kb,
                    &pfns,
                    &uaddrs,
                )
                .map_err(Error::ImportIsolatedPages);
            #[cfg(feature = "kvm")]
            if hypervisor_type == HypervisorType::Kvm
                && import_result.is_err()
                && page_type == page_types.cpuid
            {
                // When we import the CPUID page, the firmware will change any cpuid fns that
                // could lead to an insecure guest, we must then make sure to import the updated cpuid
                // https://elixir.bootlin.com/linux/v6.11/source/arch/x86/kvm/svm/sev.c#L2322
                let mut updated_cp = SnpCpuidInfo::new_zeroed();
                let _ = guest_memory.read(updated_cp.as_mut_bytes(), GuestAddress(group[0].gpa));
                for (set, got) in std::iter::zip(new_cp.entries.iter(), updated_cp.entries.iter()) {
                    if set != got {
                        error!("Set cpuid fn: {set:#x?}, but firmware expects: {got:#x?}");
                    }
                }
                memory_manager
                    .lock()
                    .unwrap()
                    .vm
                    .import_isolated_pages(
                        group[0].page_type,
                        page_types.isolated_page_size_4kb,
                        &pfns,
                        &uaddrs,
                    )
                    .map_err(Error::ImportIsolatedPages)?;
                continue;
            }
            import_result?;
        }

        info!(
            "Time it took to for hashing pages {:.2?} and page_count {:?}",
            now.elapsed(),
            gpas.len()
        );

        let id_block_enabled = if hypervisor_type == HypervisorType::Mshv {
            1
        } else {
            0
        };

        now = Instant::now();
        // Call Complete Isolated Import since we are done importing isolated pages
        memory_manager
            .lock()
            .unwrap()
            .vm
            .complete_isolated_import(
                loaded_info.snp_id_block,
                host_data_contents,
                id_block_enabled,
            )
            .map_err(Error::CompleteIsolatedImport)?;

        info!(
            "Time it took to for launch complete command  {:.2?}",
            now.elapsed()
        );
    }

    debug!("Dumping the contents of VMSA page: {:x?}", loaded_info.vmsa);
    Ok(loaded_info)
}
