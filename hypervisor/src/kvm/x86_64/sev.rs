// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

use core::mem::size_of;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

use igvm_defs::SnpPolicy;
use kvm_bindings::kvm_sev_cmd;
use kvm_ioctls::VmFd;
use linux_loader::bootparam::boot_params;
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use uuid::{Uuid, uuid};
use vm_memory::ByteValued;
use vmm_sys_util::errno;
use zerocopy::{Immutable, IntoBytes};

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

// KVM SEV command IDs — linux/include/uapi/linux/kvm.h
const KVM_SEV_INIT2: u32 = 22;
const KVM_SEV_SNP_LAUNCH_START: u32 = 100;
const KVM_SEV_SNP_LAUNCH_UPDATE: u32 = 101;
const KVM_SEV_SNP_LAUNCH_FINISH: u32 = 102;
// SNP_LAUNCH_UPDATE page types — linux/arch/x86/include/uapi/asm/sev-guest.h
pub const SNP_PAGE_TYPE_VMSA: u32 = 2;

// See AMD Spec Section 8.17 — SNP_LAUNCH_UPDATE
// The last 12 bits are metadata about the guest context
// https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
pub const GPA_METADATA_SHIFT_OFFSET: u32 = 12;

// SNP in VMSA - linux/arch/x86/include/asm/svm.h
const SVM_SEV_FEAT_SNP_ACTIVE: u64 = 1 << 0;

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
    fn measured_boot_io(err: io::Error) -> errno::Error {
        errno::Error::new(err.raw_os_error().unwrap_or(libc::EINVAL))
    }

    fn sha256_reader<R: Read>(mut reader: R) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        let mut chunk = [0u8; 8192];
        loop {
            let bytes_read = reader.read(&mut chunk).map_err(Self::measured_boot_io)?;
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

        // If no initrd is provided, we will simply hash over an empty buffer, mimicing
        // QEMU's behavior: https://gitlab.com/qemu-project/qemu/-/blob/master/target/i386/sev.c#L2387
        let initrd_digest: [u8; 32] = if let Some(initramfs) = &self.initramfs {
            let mut initramfs = initramfs.try_clone().map_err(Self::measured_boot_io)?;
            initramfs
                .seek(SeekFrom::Start(0))
                .map_err(Self::measured_boot_io)?;
            Self::sha256_reader(initramfs)?
        } else {
            Self::sha256_reader(Cursor::new([]))?
        };

        // The kernel components are split up into a setup section and the actual kernel data,
        // so split them up to avoid double counting, assuming this is a bzImage Linux kernel
        let mut setup_header = vec![0u8; size_of::<boot_params>()];
        self.kernel
            .read_exact_at(&mut setup_header, 0)
            .map_err(Self::measured_boot_io)?;

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
            self.kernel
                .read_exact_at(&mut setup_data, 0)
                .map_err(Self::measured_boot_io)?;
            setup_data[..setup_header.len()].copy_from_slice(&setup_header);
        }

        let mut kernel = self.kernel.try_clone().map_err(Self::measured_boot_io)?;
        kernel
            .seek(SeekFrom::Start(kernel_start))
            .map_err(Self::measured_boot_io)?;
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

fn sev_op(vm: &VmFd, sev_cmd: &mut kvm_sev_cmd, name: &str) -> Result<()> {
    let ret = vm.encrypt_op_sev(sev_cmd);
    if ret.is_err() {
        error!("{name} op failed. error code: 0x{:x}", sev_cmd.error);
    }
    ret
}

#[derive(Debug)]
pub struct SevFd {
    pub fd: OwnedFd,
}

// These ioctl structs must match the kernel layout exactly.
// Layouts from linux/arch/x86/include/uapi/asm/kvm.h

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevInit {
    pub vmsa_features: u64,
    pub flags: u32,
    pub ghcb_version: u16,
    pub pad1: u16,
    pub pad2: [u32; 8],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchStart {
    pub policy: u64,
    pub gosvw: [u8; 16],
    pub flags: u16,
    pub pad0: [u8; 6],
    pub pad1: [u64; 4],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchUpdate {
    pub gfn_start: u64,
    pub uaddr: u64,
    pub len: u64,
    pub type_: u8,
    pub pad0: u8,
    pub flags: u16,
    pub pad1: u32,
    pub pad2: [u64; 4],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchFinish {
    pub id_block_uaddr: u64,
    pub id_auth_uaddr: u64,
    pub id_block_en: u8,
    pub auth_key_en: u8,
    pub vcek_disabled: u8,
    pub host_data: [u8; 32],
    pub pad0: [u8; 3],
    // must be zero https://elixir.bootlin.com/linux/v6.11/source/arch/x86/kvm/svm/sev.c#L2506
    pub flags: u16,
    pub pad1: [u64; 4],
}

impl SevFd {
    pub(crate) fn new(sev_path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(sev_path.as_ref())
            .map_err(|e| errno::Error::new(e.raw_os_error().unwrap_or(libc::EINVAL)))?;
        Ok(SevFd {
            fd: OwnedFd::from(file),
        })
    }

    pub(crate) fn init2(&self, vm: &VmFd, vmsa_features: u64) -> Result<()> {
        // Clear the SNP bit, KVM sets it directly
        let vmsa_features = vmsa_features & !SVM_SEV_FEAT_SNP_ACTIVE;

        // TODO: Query KVM for supported VMSA features before calling init2
        if vmsa_features != 0 {
            info!("SEV-SNP: requesting vmsa_features: {vmsa_features:#x}");
        }

        let mut init = KvmSevInit {
            vmsa_features,
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_INIT2,
            data: &mut init as *mut KvmSevInit as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        sev_op(vm, &mut sev_cmd, "KVM_SEV_INIT2")
    }

    pub(crate) fn launch_start(&self, vm: &VmFd, guest_policy: SnpPolicy) -> Result<()> {
        // See AMD Spec Section 4.3 - Guest Policy
        // Bit 17 is reserved and has to be one.
        // https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
        let mut start: KvmSevSnpLaunchStart = KvmSevSnpLaunchStart {
            policy: guest_policy.into_bits(),
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_START,
            data: &mut start as *mut KvmSevSnpLaunchStart as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        sev_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_START")
    }

    pub(crate) fn launch_update(
        &self,
        vm: &VmFd,
        // host virtual address
        hva: u64,
        size: u64,
        // guest frame number
        gfn_start: u64,
        page_type: u32,
    ) -> Result<()> {
        let mut update = KvmSevSnpLaunchUpdate {
            gfn_start,
            uaddr: hva,
            len: size,
            type_: page_type as u8,
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_UPDATE,
            data: &mut update as *mut KvmSevSnpLaunchUpdate as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        sev_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_UPDATE")
    }

    pub(crate) fn launch_finish(
        &self,
        vm: &VmFd,
        host_data: [u8; 32],
        id_block_en: u8,
        auth_key_en: u8,
    ) -> Result<()> {
        let mut finish = KvmSevSnpLaunchFinish {
            host_data,
            id_block_en,
            auth_key_en,
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_FINISH,
            data: &mut finish as *mut KvmSevSnpLaunchFinish as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        let flags = finish.flags;
        debug!("Calling KVM_SEV_SNP_LAUNCH_FINISH, flags: {flags}");
        sev_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_FINISH")
    }
}
