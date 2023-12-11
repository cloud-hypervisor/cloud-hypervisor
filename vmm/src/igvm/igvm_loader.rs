// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2023, Microsoft Corporation
//
use crate::cpu::CpuManager;
use zerocopy::AsBytes;

use crate::igvm::loader::Loader;
use crate::igvm::IgvmLoadedInfo;
use crate::igvm::{BootPageAcceptance, StartupMemoryType, HV_PAGE_SIZE};
use crate::memory_manager::MemoryManager;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
use igvm_parser::IgvmDirectiveHeader;
use igvm_parser::IgvmFile;
use igvm_parser::IgvmPlatformHeader;
use igvm_parser::IsolationType;

use igvm_defs::IGVM_VHS_PARAMETER;
use igvm_defs::IGVM_VHS_PARAMETER_INSERT;

use igvm_parser::snp_defs::SevVmsa;
pub use mshv_bindings::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("command line is not a valid C string")]
    InvalidCommandLine(#[source] std::ffi::NulError),
    #[error("failed to read igvm file")]
    Igvm(#[source] std::io::Error),
    #[error("invalid igvm file")]
    InvalidIgvmFile(#[source] igvm_parser::Error),
    #[error("loader error")]
    Loader(#[source] crate::igvm::loader::Error),
    #[error("parameter too large for parameter area")]
    ParameterTooLarge,
    #[error("Error importing isolated pages: {0}")]
    ImportIsolatedPages(#[source] hypervisor::HypervisorVmError),
    #[error("Error completing importing isolated pages: {0}")]
    CompleteIsolatedImport(#[source] hypervisor::HypervisorVmError),
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
) -> Result<Box<IgvmLoadedInfo>, Error> {
    let mut loaded_info: Box<IgvmLoadedInfo> = Box::default();
    let command_line = CString::new(cmdline).map_err(Error::InvalidCommandLine)?;
    let mut file_contents = Vec::new();
    let memory = memory_manager.lock().as_ref().unwrap().guest_memory();
    let mut gpas: Vec<GpaPages> = Vec::new();
    let proc_count = cpu_manager.lock().unwrap().vcpus().len() as u32;

    file.seek(SeekFrom::Start(0)).map_err(Error::Igvm)?;
    file.read_to_end(&mut file_contents).map_err(Error::Igvm)?;

    let igvm_file = IgvmFile::new_from_binary(&file_contents, Some(IsolationType::Snp))
        .map_err(Error::InvalidIgvmFile)?;

    let mask = match &igvm_file.platforms()[0] {
        IgvmPlatformHeader::SupportedPlatform(info) => {
            debug_assert!(info.platform_type == IgvmPlatformType::SEV_SNP);
            info.compatibility_mask
        }
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
                                page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_UNMEASURED,
                                page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
                            });
                            BootPageAcceptance::ExclusiveUnmeasured
                        } else {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
                                page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
                            });
                            BootPageAcceptance::Exclusive
                        }
                    }
                    IgvmPageDataType::SECRETS => {
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_SECRETS,
                            page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
                        });
                        BootPageAcceptance::SecretsPage
                    }
                    IgvmPageDataType::CPUID_DATA => {
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
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_CPUID,
                            page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
                        });
                        BootPageAcceptance::CpuidPage
                    }
                    // TODO: other data types SNP / TDX only, unsupported
                    _ => todo!("unsupported IgvmPageDataType"),
                };

                loader
                    .import_pages(gpa / HV_PAGE_SIZE, 1, acceptance, data)
                    .map_err(Error::Loader)?;
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
            IgvmDirectiveHeader::MemoryMap(_info) => {
                todo!("Not implemented");
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

                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_VMSA,
                    page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
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
                    page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_UNMEASURED,
                    page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB,
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

    debug!("Dumping the contents of VMSA page: {:x?}", loaded_info.vmsa);
    Ok(loaded_info)
}
