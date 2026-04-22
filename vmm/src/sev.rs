// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//

use core::mem::size_of;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;

use linux_loader::bootparam::boot_params;
use sha2::{Digest, Sha256};
use uuid::{Uuid, uuid};
use vm_memory::ByteValued;
use vmm_sys_util::errno;
use zerocopy::{Immutable, IntoBytes};

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

// https://github.com/tianocore/edk2/blob/f98662c5e35b6ab60f46ee4350fa0e6eab0497cf/OvmfPkg/Include/Fdf/MemFd.fdf.inc#L89-L93
pub const SEV_HASH_BLOCK_ADDRESS: u64 = 0x10c00;
pub const SEV_HASH_BLOCK_SIZE: usize = 0x400;
const SHA256_HASH_SIZE: usize = 32;

// Measured hashes table definitions. These match the definitions found in
// QEMU's implementation: https://gitlab.com/qemu-project/qemu/-/blob/master/target/i386/sev.c#L68
#[repr(C, packed)]
#[derive(IntoBytes, Immutable)]
struct SevHashTableEntry {
    pub guid: [u8; 16],
    pub len: u16,
    pub hash: [u8; SHA256_HASH_SIZE],
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable)]
struct SevHashTable {
    pub guid: [u8; 16],
    pub len: u16,
    pub cmdline: SevHashTableEntry,
    pub initrd: SevHashTableEntry,
    pub kernel: SevHashTableEntry,
}

const SEV_HASH_TABLE_PADDING: usize =
    size_of::<SevHashTable>().next_multiple_of(16) - size_of::<SevHashTable>();

#[derive(IntoBytes, Immutable)]
pub struct PaddedSevHashTable {
    #[allow(dead_code)]
    hash_table: SevHashTable,
    #[allow(dead_code)]
    padding: [u8; SEV_HASH_TABLE_PADDING],
}

// These GUIDs are defined in both EDK2 and QEMU:
// https://github.com/tianocore/edk2/blob/master/OvmfPkg/AmdSev/BlobVerifierLibSevHashes/BlobVerifierSevHashes.c#L36-L43
// https://gitlab.com/qemu-project/qemu/-/blob/master/target/i386/sev.c#L2344-2360
const SEV_HASH_TABLE_GUID: Uuid = uuid!("9438d606-4f22-4cc9-b479-a793d411fd21");
const SEV_KERNEL_HASH_GUID: Uuid = uuid!("4de79437-abd2-427f-b835-d5b172d2045b");
const SEV_INITRD_HASH_GUID: Uuid = uuid!("44baf731-3a2f-4bd7-9af1-41e29169781d");
const SEV_CMDLINE_HASH_GUID: Uuid = uuid!("97d02dd8-bd20-4c94-aa78-e7714d36ab2a");

pub struct MeasuredBootInfo {
    pub kernel: File,
    // QEMU also makes initrd optional in the hash table
    pub initramfs: Option<File>,
    pub cmdline: CString,
}

impl MeasuredBootInfo {
    fn measured_boot_io(err: &io::Error) -> errno::Error {
        errno::Error::new(err.raw_os_error().unwrap_or(libc::EINVAL))
    }

    fn sha256_reader<R: Read>(mut reader: R) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        let mut chunk = [0u8; 8192];
        loop {
            let bytes_read = reader
                .read(&mut chunk)
                .map_err(|e| Self::measured_boot_io(&e))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&chunk[..bytes_read]);
        }

        Ok(hasher.finalize().into())
    }

    pub fn build_hash_block(&self) -> Result<[u8; SEV_HASH_BLOCK_SIZE]> {
        // Current tooling appends a NUL byte at the end of cmdlines:
        // https://github.com/virtee/sev-snp-measure/blob/main/sevsnpmeasure/sev_hashes.py#L71-L74
        let cmdline_digest: [u8; 32] = Sha256::digest(self.cmdline.as_bytes_with_nul()).into();

        // If no initrd is provided, we will simply hash over an empty buffer, mimicking
        // QEMU's behavior: https://gitlab.com/qemu-project/qemu/-/blob/master/target/i386/sev.c#L2387
        let initrd_digest: [u8; 32] = if let Some(initramfs) = &self.initramfs {
            let mut initramfs = initramfs
                .try_clone()
                .map_err(|e| Self::measured_boot_io(&e))?;
            initramfs
                .seek(SeekFrom::Start(0))
                .map_err(|e| Self::measured_boot_io(&e))?;
            Self::sha256_reader(initramfs)?
        } else {
            Self::sha256_reader(Cursor::new([]))?
        };

        // The kernel components are split up into a setup section and the actual kernel data,
        // so split them up to avoid double counting, assuming this is a bzImage Linux kernel
        let mut setup_header = vec![0u8; size_of::<boot_params>()];
        self.kernel
            .read_exact_at(&mut setup_header, 0)
            .map_err(|e| Self::measured_boot_io(&e))?;

        let kernel_start = {
            // Matches QEMU's way of finding the kernel start/setup start
            // https://gitlab.com/qemu-project/qemu/-/blob/master/hw/i386/x86-common.c#L903
            let bp = boot_params::from_mut_slice(&mut setup_header).unwrap();
            let setup_sects = if bp.hdr.setup_sects == 0 {
                4
            } else {
                bp.hdr.setup_sects
            };
            (u64::from(setup_sects) + 1) * 512
        };
        let setup_len = kernel_start as usize;
        let mut setup_data = vec![0u8; setup_len];
        if setup_len <= setup_header.len() {
            setup_data.copy_from_slice(&setup_header[..setup_len]);
        } else {
            setup_data[..setup_header.len()].copy_from_slice(&setup_header);
            self.kernel
                .read_exact_at(
                    &mut setup_data[setup_header.len()..],
                    setup_header.len() as u64,
                )
                .map_err(|e| Self::measured_boot_io(&e))?;
        }

        let mut kernel = self
            .kernel
            .try_clone()
            .map_err(|e| Self::measured_boot_io(&e))?;
        kernel
            .seek(SeekFrom::Start(kernel_start))
            .map_err(|e| Self::measured_boot_io(&e))?;
        let kernel_digest = Self::sha256_reader(Cursor::new(setup_data).chain(kernel))?;

        let table = PaddedSevHashTable {
            hash_table: SevHashTable {
                guid: SEV_HASH_TABLE_GUID.to_bytes_le(),
                len: size_of::<SevHashTable>() as u16,
                cmdline: SevHashTableEntry {
                    guid: SEV_CMDLINE_HASH_GUID.to_bytes_le(),
                    len: size_of::<SevHashTableEntry>() as u16,
                    hash: cmdline_digest,
                },
                initrd: SevHashTableEntry {
                    guid: SEV_INITRD_HASH_GUID.to_bytes_le(),
                    len: size_of::<SevHashTableEntry>() as u16,
                    hash: initrd_digest,
                },
                kernel: SevHashTableEntry {
                    guid: SEV_KERNEL_HASH_GUID.to_bytes_le(),
                    len: size_of::<SevHashTableEntry>() as u16,
                    hash: kernel_digest,
                },
            },
            padding: [0; SEV_HASH_TABLE_PADDING],
        };

        let mut hash_block = [0u8; SEV_HASH_BLOCK_SIZE];
        // The remainder of the page is zeroed to ensure measurements are reliably calculated
        hash_block[..size_of::<PaddedSevHashTable>()].copy_from_slice(table.as_bytes());
        Ok(hash_block)
    }
}
