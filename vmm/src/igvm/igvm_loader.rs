// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2023, Microsoft Corporation
//
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use hypervisor::HypervisorType;
use igvm::snp_defs::SevVmsa;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IsolationType};
use igvm_defs::{IgvmPageDataType, IGVM_VHS_PARAMETER, IGVM_VHS_PARAMETER_INSERT};
#[cfg(feature = "sev_snp")]
use igvm_defs::{MemoryMapEntryType, IGVM_VHS_MEMORY_MAP_ENTRY};
#[cfg(feature = "mshv")]
use mshv_bindings::*;
use thiserror::Error;
#[cfg(feature = "sev_snp")]
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemory};
#[cfg(feature = "kvm")]
use vm_migration::Snapshottable;
use zerocopy::IntoBytes;
#[cfg(feature = "sev_snp")]
use zerocopy::{FromBytes, FromZeros};

use crate::cpu::CpuManager;
use crate::igvm::loader::Loader;
use crate::igvm::{BootPageAcceptance, IgvmLoadedInfo, StartupMemoryType, HV_PAGE_SIZE};
use crate::memory_manager::MemoryManager;
#[cfg(feature = "sev_snp")]
use crate::GuestMemoryMmap;

const ISOLATED_PAGE_SHIFT: u32 = 12;
#[cfg(feature = "sev_snp")]
const SNP_CPUID_LIMIT: u32 = 64;
// see section 7.1
// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
#[cfg(feature = "sev_snp")]
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

#[cfg(feature = "sev_snp")]
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
    #[error("Error importing isolated pages: {0}")]
    ImportIsolatedPages(#[source] hypervisor::HypervisorVmError),
    #[error("Error completing importing isolated pages: {0}")]
    CompleteIsolatedImport(#[source] hypervisor::HypervisorVmError),
    #[error("Error decoding host data: {0}")]
    FailedToDecodeHostData(#[source] hex::FromHexError),
    #[error("Error applying VMSA to vCPU registers: {0}")]
    SetVmsa(#[source] crate::cpu::Error),
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
    assert!(ram_range.0 % HV_PAGE_SIZE == 0);
    assert!((ram_range.1 - ram_range.0) % HV_PAGE_SIZE == 0);

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
/// Load the given IGVM file to guest memory.
/// Right now it only supports SNP based isolation.
/// We can boot legacy VM with an igvm file without
/// any isolation.
///
pub fn load_igvm(
    mut file: &std::fs::File,
    memory_manager: Arc<Mutex<MemoryManager>>,
    cpu_manager: Arc<Mutex<CpuManager>>,
    cmdline: &str,
    #[cfg(feature = "sev_snp")] host_data: &Option<String>,
) -> Result<Box<IgvmLoadedInfo>, Error> {
    let hypervisor_type = cpu_manager.lock().unwrap().hypervisor_type();
    let isolated_page_size_4kb: u32 = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => mshv_bindings::hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => 0x1000,
    };
    let normal_page_type: u32 = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => 1,
    };
    let unmeasured_page_type: u32 = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => {
            mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_UNMEASURED
        }
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => 4,
    };
    let cpuid_page_type: u32 = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => 6,
    };
    let secrets_page_type: u32 = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => {
            mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_UNMEASURED
        }
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => 5,
    };
    let vmsa_page_type: u32 = match hypervisor_type {
        #[cfg(feature = "mshv")]
        HypervisorType::Mshv => mshv_bindings::hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_VMSA,
        #[cfg(feature = "kvm")]
        HypervisorType::Kvm => 2,
    };

    let mut loaded_info: Box<IgvmLoadedInfo> = Box::default();
    let command_line = CString::new(cmdline).map_err(Error::InvalidCommandLine)?;
    let mut file_contents = Vec::new();
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

    file.seek(SeekFrom::Start(0)).map_err(Error::Igvm)?;
    file.read_to_end(&mut file_contents).map_err(Error::Igvm)?;

    let igvm_file = IgvmFile::new_from_binary(&file_contents, Some(IsolationType::Snp))
        .map_err(Error::InvalidIgvmFile)?;

    let sev_snp_enabled = cpu_manager.lock().unwrap().sev_snp_enabled();
    let mask = match &igvm_file.platforms()[0] {
        IgvmPlatformHeader::SupportedPlatform(info) => info.compatibility_mask,
    };

    let mut loader = Loader::new(memory);

    let mut parameter_areas: HashMap<u32, ParameterAreaState> = HashMap::new();

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
                debug_assert!(data.len() as u64 % HV_PAGE_SIZE == 0);

                // TODO: only 4k or empty page data supported right now
                assert!(data.len() as u64 == HV_PAGE_SIZE || data.is_empty());

                let acceptance = match *data_type {
                    IgvmPageDataType::NORMAL => {
                        if flags.unmeasured() {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: unmeasured_page_type,
                                page_size: isolated_page_size_4kb,
                            });
                            BootPageAcceptance::ExclusiveUnmeasured
                        } else {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: normal_page_type,
                                page_size: isolated_page_size_4kb,
                            });
                            BootPageAcceptance::Exclusive
                        }
                    }
                    IgvmPageDataType::SECRETS => {
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: secrets_page_type,
                            page_size: isolated_page_size_4kb,
                        });
                        BootPageAcceptance::SecretsPage
                    }
                    IgvmPageDataType::CPUID_DATA => {
                        // SAFETY: CPUID is readonly
                        #[cfg(feature = "mshv")]
                        if hypervisor_type == HypervisorType::Mshv {
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
                            page_type: cpuid_page_type,
                            page_size: isolated_page_size_4kb,
                        });
                        BootPageAcceptance::CpuidPage
                    }
                    // TODO: other data types SNP / TDX only, unsupported
                    _ => todo!("unsupported IgvmPageDataType"),
                };

                #[allow(unused_mut)]
                let mut imported_page = false;
                #[cfg(feature = "kvm")]
                if hypervisor_type == HypervisorType::Kvm
                    && *data_type == IgvmPageDataType::CPUID_DATA
                {
                    let mut new_cp = SnpCpuidInfo::new_zeroed();

                    let entries = cpu_manager.lock().unwrap().common_cpuid();
                    // TODO: Filter cpuid rather than truncate
                    for i in 0..std::cmp::min(SNP_CPUID_LIMIT as usize, entries.len()) {
                        new_cp.entries[i].eax_in = entries[i].function;
                        new_cp.entries[i].ecx_in = entries[i].index;
                        new_cp.entries[i].eax = entries[i].eax;
                        new_cp.entries[i].ebx = entries[i].ebx;
                        new_cp.entries[i].ecx = entries[i].ecx;
                        new_cp.entries[i].edx = entries[i].edx;
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
                    }
                    new_cp.count = new_cp.entries.len() as u32;
                    info!("gpa: {:#x}", *gpa);
                    loader
                        .import_pages(gpa / HV_PAGE_SIZE, 1, acceptance, new_cp.as_mut_bytes())
                        .map_err(Error::Loader)?;
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
                let mut data: [u8; 4096] = [0; 4096];
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

                // Set vCPU initial states before calling SNP_LAUNCH_FINISH
                #[cfg(feature = "kvm")]
                if hypervisor_type == HypervisorType::Kvm {
                    let vcpus = cpu_manager.lock().unwrap().vcpus();
                    for vcpu in vcpus {
                        let vcpu_locked = vcpu.lock().unwrap();
                        let vcpu_id: u16 = vcpu_locked.id().parse().unwrap();
                        if vcpu_id == *vp_index {
                            vcpu_locked
                                .set_sev_control_register(0, loaded_info.vmsa)
                                .map_err(Error::SetVmsa)?;
                        }
                    }
                }

                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: vmsa_page_type,
                    page_size: isolated_page_size_4kb,
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
                    ParameterAreaState::Allocated { data, max_size } => loader
                        .import_pages(
                            gpa / HV_PAGE_SIZE,
                            *max_size / HV_PAGE_SIZE,
                            BootPageAcceptance::ExclusiveUnmeasured,
                            data,
                        )
                        .map_err(Error::Loader)?,
                    ParameterAreaState::Inserted => panic!("igvmfile is invalid, multiple insert"),
                }
                *area = ParameterAreaState::Inserted;
                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: normal_page_type,
                    page_size: isolated_page_size_4kb,
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

    #[cfg(feature = "sev_snp")]
    if sev_snp_enabled {
        use std::time::Instant;

        let mut now = Instant::now();

        // Sort the gpas to group them by the page type
        gpas.sort_by(|a, b| a.gpa.cmp(&b.gpa));

        let gpas_grouped = gpas
            .iter()
            .fold(Vec::<Vec<GpaPages>>::new(), |mut acc, gpa| {
                if let Some(last_vec) = acc.last_mut() {
                    if last_vec[0].page_type == gpa.page_type {
                        last_vec.push(*gpa);
                        return acc;
                    }
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
                    let uaddr_offset: u64 = guest_region_mmap.unwrap().1 .0;
                    let uaddr = uaddr_base + uaddr_offset;
                    uaddr
                })
                .collect();
            #[cfg(feature = "kvm")]
            let page_type = group[0].page_type;
            let mut new_cp = SnpCpuidInfo::new_zeroed();
            let _ = guest_memory.read(new_cp.as_mut_bytes(), GuestAddress(group[0].gpa));
            let _import = memory_manager
                .lock()
                .unwrap()
                .vm
                .import_isolated_pages(group[0].page_type, isolated_page_size_4kb, &pfns, &uaddrs)
                .map_err(Error::ImportIsolatedPages);
            #[cfg(feature = "kvm")]
            if hypervisor_type == HypervisorType::Kvm
                && _import.is_err()
                && page_type == cpuid_page_type
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
                        isolated_page_size_4kb,
                        &pfns,
                        &uaddrs,
                    )
                    .map_err(Error::ImportIsolatedPages)?
            }
        }

        info!(
            "Time it took to for hashing pages {:.2?} and page_count {:?}",
            now.elapsed(),
            gpas.len()
        );

        now = Instant::now();
        // Call Complete Isolated Import since we are done importing isolated pages
        memory_manager
            .lock()
            .unwrap()
            .vm
            .complete_isolated_import(loaded_info.snp_id_block, host_data_contents, 1)
            .map_err(Error::CompleteIsolatedImport)?;

        info!(
            "Time it took to for launch complete command  {:.2?}",
            now.elapsed()
        );
    }

    debug!("Dumping the contents of VMSA page: {:x?}", loaded_info.vmsa);
    Ok(loaded_info)
}
