// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use arch::RegionType;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use vm_allocator::SystemAllocator;
use vm_memory::guest_memory::FileOffset;
use vm_memory::{
    Address, Error as MmapError, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    GuestUsize,
};

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::*;

pub struct MemoryManager {
    guest_memory: Arc<RwLock<GuestMemoryMmap>>,
    ram_regions: u32,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
}

#[derive(Debug)]
pub enum Error {
    /// Failed to create shared file.
    SharedFileCreate(io::Error),

    /// Failed to set shared file length.
    SharedFileSetLen(io::Error),

    /// Mmap backed guest memory error
    GuestMemory(MmapError),

    /// Failed to allocate a memory range.
    MemoryRangeAllocation,
}

pub fn get_host_cpu_phys_bits() -> u8 {
    use core::arch::x86_64;
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

impl MemoryManager {
    pub fn new(
        allocator: Arc<Mutex<SystemAllocator>>,
        fd: Arc<VmFd>,
        boot_ram: u64,
        backing_file: &Option<PathBuf>,
        mergeable: bool,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(boot_ram);

        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();

        let guest_memory = match backing_file {
            Some(ref file) => {
                let mut mem_regions = Vec::<(GuestAddress, usize, Option<FileOffset>)>::new();
                for region in ram_regions.iter() {
                    if file.is_file() {
                        let file = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(file)
                            .map_err(Error::SharedFileCreate)?;

                        file.set_len(region.1 as u64)
                            .map_err(Error::SharedFileSetLen)?;

                        mem_regions.push((region.0, region.1, Some(FileOffset::new(file, 0))));
                    } else if file.is_dir() {
                        let fs_str = format!("{}{}", file.display(), "/tmpfile_XXXXXX");
                        let fs = std::ffi::CString::new(fs_str).unwrap();
                        let mut path = fs.as_bytes_with_nul().to_owned();
                        let path_ptr = path.as_mut_ptr() as *mut _;
                        let fd = unsafe { libc::mkstemp(path_ptr) };
                        unsafe { libc::unlink(path_ptr) };

                        let f = unsafe { File::from_raw_fd(fd) };
                        f.set_len(region.1 as u64)
                            .map_err(Error::SharedFileSetLen)?;

                        mem_regions.push((region.0, region.1, Some(FileOffset::new(f, 0))));
                    }
                }

                GuestMemoryMmap::with_files(&mem_regions).map_err(Error::GuestMemory)?
            }
            None => GuestMemoryMmap::new(&ram_regions).map_err(Error::GuestMemory)?,
        };

        guest_memory
            .with_regions(|index, region| {
                let mem_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len() as u64,
                    userspace_addr: region.as_ptr() as u64,
                    flags: 0,
                };

                // Safe because the guest regions are guaranteed not to overlap.
                unsafe {
                    fd.set_user_memory_region(mem_region)
                        .map_err(|e| io::Error::from_raw_os_error(e.errno()))
                }?;

                // Mark the pages as mergeable if explicitly asked for.
                if mergeable {
                    // Safe because the address and size are valid since the
                    // mmap succeeded.
                    let ret = unsafe {
                        libc::madvise(
                            region.as_ptr() as *mut libc::c_void,
                            region.len() as libc::size_t,
                            libc::MADV_MERGEABLE,
                        )
                    };
                    if ret != 0 {
                        let err = io::Error::last_os_error();
                        // Safe to unwrap because the error is constructed with
                        // last_os_error(), which ensures the output will be Some().
                        let errno = err.raw_os_error().unwrap();
                        if errno == libc::EINVAL {
                            warn!("kernel not configured with CONFIG_KSM");
                        } else {
                            warn!("madvise error: {}", err);
                        }
                        warn!("failed to mark pages as mergeable");
                    }
                }

                Ok(())
            })
            .map_err(|_: io::Error| Error::GuestMemory(MmapError::NoMemoryRegion))?;

        // Allocate RAM and Reserved address ranges.
        for region in arch_mem_regions.iter() {
            allocator
                .lock()
                .unwrap()
                .allocate_mmio_addresses(Some(region.0), region.1 as GuestUsize, None)
                .ok_or(Error::MemoryRangeAllocation)?;
        }

        let end_of_device_area = GuestAddress((1 << get_host_cpu_phys_bits()) - 1);
        let mem_end = guest_memory.end_addr();
        let start_of_device_area = if mem_end < arch::layout::MEM_32BIT_RESERVED_START {
            arch::layout::RAM_64BIT_START
        } else {
            mem_end.unchecked_add(1)
        };

        // Convert the guest memory into an Arc. The point being able to use it
        // anywhere in the code, no matter which thread might use it.
        // Add the RwLock aspect to guest memory as we might want to perform
        // additions to the memory during runtime.
        let guest_memory = Arc::new(RwLock::new(guest_memory));

        Ok(Arc::new(Mutex::new(MemoryManager {
            guest_memory,
            ram_regions: ram_regions.len() as u32,
            start_of_device_area,
            end_of_device_area,
        })))
    }

    pub fn guest_memory(&self) -> Arc<RwLock<GuestMemoryMmap>> {
        self.guest_memory.clone()
    }

    pub fn ram_regions(&self) -> u32 {
        self.ram_regions
    }

    pub fn start_of_device_area(&self) -> GuestAddress {
        self.start_of_device_area
    }

    pub fn end_of_device_area(&self) -> GuestAddress {
        self.end_of_device_area
    }
}
