// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

use igvm_defs::SnpPolicy;
use kvm_bindings::kvm_sev_cmd;
use kvm_ioctls::VmFd;
use vmm_sys_util::errno;

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

const KVM_SEV_INIT2: u32 = 22;
const KVM_SEV_SNP_LAUNCH_START: u32 = 100;
const KVM_SEV_SNP_LAUNCH_UPDATE: u32 = 101;
// See AMD Spec Section 8.17 - SNP_LAUNCH_UPDATE
// The last 12 bits are metadata about the guest context
// https://tinyurl.com/sev-guest-policy
pub const GPA_METADATA_PADDING: u32 = 12;
pub const SEV_VMSA_PAGE_TYPE: u32 = 2;

#[derive(Debug)]
pub struct SevFd {
    pub fd: OwnedFd,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevInit {
    pub vmsa_features: u64,
    pub flags: u32,
    pub ghcb_version: u16,
    pub pad1: u16,
    pub pad2: [u32; 8],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KvmSevSnpLaunchStart {
    pub policy: u64,
    pub gosvw: [u8; 16],
    pub flags: u16,
    pub pad0: [u8; 6],
    pub pad1: [u64; 4],
}

#[repr(C)]
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

impl SevFd {
    pub(crate) fn new(sev_path: &String) -> Result<Self> {
        // give sev device rw and close on exec
        let file_r = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(sev_path);
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
        vm.encrypt_op_sev(&mut sev_cmd)
    }

    pub(crate) fn launch_start(&self, vm: &VmFd, guest_policy: SnpPolicy) -> Result<()> {
        // See AMD Spec Section 4.3 - Guest Policy
        // Bit 17 is reserved and has to be one.
        // https://tinyurl.com/sev-guest-policy
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
        vm.encrypt_op_sev(&mut sev_cmd)
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
        vm.encrypt_op_sev(&mut sev_cmd)
    }
}