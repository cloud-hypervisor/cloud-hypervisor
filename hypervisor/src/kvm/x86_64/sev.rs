// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use igvm_defs::SnpPolicy;
use kvm_bindings::kvm_sev_cmd;
use kvm_ioctls::VmFd;
use log::debug;
use vmm_sys_util::errno;

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

// KVM SEV command IDs — linux/include/uapi/linux/kvm.h
const KVM_SEV_INIT2: u32 = 22;
const KVM_SEV_SNP_LAUNCH_START: u32 = 100;
const KVM_SEV_SNP_LAUNCH_UPDATE: u32 = 101;
const KVM_SEV_SNP_LAUNCH_FINISH: u32 = 102;
// SNP_LAUNCH_UPDATE page types — linux/arch/x86/include/uapi/asm/sev-guest.h
pub const SNP_PAGE_TYPE_NORMAL: u32 = 1;
pub const SNP_PAGE_TYPE_VMSA: u32 = 2;
pub const SNP_PAGE_TYPE_UNMEASURED: u32 = 4;
pub const SNP_PAGE_TYPE_SECRETS: u32 = 5;
pub const SNP_PAGE_TYPE_CPUID: u32 = 6;

// See AMD Spec Section 8.17 — SNP_LAUNCH_UPDATE
// The last 12 bits are metadata about the guest context
// https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
pub const GPA_METADATA_PADDING: u32 = 12;

#[derive(Debug)]
pub struct SevFd {
    pub fd: OwnedFd,
}

// These ioctl structs must match the kernel layout exactly.
// Layouts from linux/arch/x86/include/uapi/asm/sev-guest.h

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
    fn run_encrypt_op(&self, vm: &VmFd, sev_cmd: &mut kvm_sev_cmd, op_name: &str) -> Result<()> {
        vm.encrypt_op_sev(sev_cmd).inspect_err(|e| {
            debug!(
                "{op_name} failed: host errno={:?}, firmware error={:#x}",
                e, sev_cmd.error
            );
        })
    }

    pub(crate) fn new(sev_path: impl AsRef<Path>) -> Result<Self> {
        // give sev device rw and close on exec
        let file_r = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(sev_path.as_ref());
        if let Ok(file) = file_r {
            Ok(SevFd {
                fd: OwnedFd::from(file),
            })
        } else {
            Err(errno::Error::last())
        }
    }

    pub(crate) fn init2(&self, vm: &VmFd) -> Result<()> {
        let mut init = KvmSevInit::default();
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_INIT2,
            data: &mut init as *mut KvmSevInit as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        self.run_encrypt_op(vm, &mut sev_cmd, "KVM_SEV_INIT2")
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
        self.run_encrypt_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_START")
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
        self.run_encrypt_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_UPDATE")
    }
    pub(crate) fn launch_finish(
        &self,
        vm: &VmFd,
        host_data: [u8; 32],
        id_block_en: u8,
        auth_key_en: u8,
    ) -> Result<()> {
        let id_block_en = if id_block_en != 0 {
            debug!(
                "KVM_SEV_SNP_LAUNCH_FINISH currently does not provide id_block_uaddr/id_auth_uaddr; forcing id_block_en=0"
            );
            0
        } else {
            id_block_en
        };
        let auth_key_en = if auth_key_en != 0 {
            debug!(
                "KVM_SEV_SNP_LAUNCH_FINISH currently does not provide id_block_uaddr/id_auth_uaddr; forcing auth_key_en=0"
            );
            0
        } else {
            auth_key_en
        };

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
        debug!("calling KVM_SEV_SNP_LAUNCH_FINISH, flags: {}", flags);
        self.run_encrypt_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_FINISH")
    }
}
