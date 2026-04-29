// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use igvm_defs::{IGVM_VHS_SNP_ID_BLOCK, SnpPolicy};
use kvm_bindings::kvm_sev_cmd;
use kvm_ioctls::VmFd;
use log::{debug, error, info};
use vmm_sys_util::errno;
use zerocopy::{FromZeros, Immutable, IntoBytes};

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

// See AMD Spec Section 8.18 — Structure of the ID Block
// https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
#[repr(C)]
#[derive(Debug, Copy, Clone, IntoBytes, Immutable)]
pub(crate) struct KvmSevSnpIdBlock {
    pub ld: [u8; 48],
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
}

// See AMD Spec Section 8.18 — Layout of the ID Authentication Information Structure
// https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
#[repr(C)]
#[derive(Clone, FromZeros, IntoBytes, Immutable)]
pub(crate) struct KvmSevSnpIdAuth {
    pub id_key_alg: u32,
    pub auth_key_algo: u32,
    pub reserved: [u8; 56],
    pub id_block_sig: [u8; 512],
    pub id_key: [u8; 1028],
    pub reserved2: [u8; 60],
    pub id_key_sig: [u8; 512],
    pub author_key: [u8; 1028],
    pub reserved3: [u8; 892],
}

// Must be 1
// AMD SEV-SNP Firmware ABI, Section 8.18 — Structure of the ID Block
// https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
const IGVM_SEV_ID_BLOCK_VERSION: u32 = 1;

fn build_id_block(snp_id_block: &IGVM_VHS_SNP_ID_BLOCK, guest_policy: u64) -> KvmSevSnpIdBlock {
    KvmSevSnpIdBlock {
        ld: snp_id_block.ld,
        family_id: snp_id_block.family_id,
        image_id: snp_id_block.image_id,
        version: IGVM_SEV_ID_BLOCK_VERSION,
        guest_svn: snp_id_block.guest_svn,
        policy: guest_policy,
    }
}

// SEV-SNP Firmware ABI Spec Chapter 10: Format for an ECDSA P-384 Public Key
// https://docs.amd.com/v/u/en-US/56860_PUB_1.58_SEV_SNP
fn serialize_public_key(curve: u32, qx: &[u8; 72], qy: &[u8; 72]) -> [u8; 1028] {
    let mut key = [0u8; 0x404];
    key[..0x004].copy_from_slice(&curve.to_le_bytes());
    key[0x004..0x04C].copy_from_slice(qx);
    key[0x04C..0x094].copy_from_slice(qy);
    key
}

fn build_id_auth(snp_id_block: &IGVM_VHS_SNP_ID_BLOCK) -> KvmSevSnpIdAuth {
    let mut id_auth = KvmSevSnpIdAuth::new_zeroed();

    id_auth.id_key_alg = snp_id_block.id_key_algorithm;
    id_auth.auth_key_algo = snp_id_block.author_key_algorithm;

    let sig = snp_id_block.id_key_signature.as_bytes();
    id_auth.id_block_sig[..sig.len()].copy_from_slice(sig);

    id_auth.id_key = serialize_public_key(
        snp_id_block.id_public_key.curve,
        &snp_id_block.id_public_key.qx,
        &snp_id_block.id_public_key.qy,
    );

    let sig = snp_id_block.author_key_signature.as_bytes();
    id_auth.id_key_sig[..sig.len()].copy_from_slice(sig);

    id_auth.author_key = serialize_public_key(
        snp_id_block.author_public_key.curve,
        &snp_id_block.author_public_key.qx,
        &snp_id_block.author_public_key.qy,
    );

    id_auth
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
            data: &raw mut init as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        sev_op(vm, &mut sev_cmd, "KVM_SEV_INIT2")
    }

    pub(crate) fn launch_start(&self, vm: &VmFd, guest_policy: SnpPolicy) -> Result<()> {
        let mut start: KvmSevSnpLaunchStart = KvmSevSnpLaunchStart {
            policy: guest_policy.into_bits(),
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_START,
            data: &raw mut start as u64,
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
            data: &raw mut update as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        sev_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_UPDATE")
    }

    pub(crate) fn launch_finish(
        &self,
        vm: &VmFd,
        snp_id_block: &IGVM_VHS_SNP_ID_BLOCK,
        host_data: [u8; 32],
        id_block_en: u8,
        auth_key_en: u8,
        guest_policy: u64,
    ) -> Result<()> {
        let id_block = build_id_block(snp_id_block, guest_policy);
        let id_auth = build_id_auth(snp_id_block);

        let mut finish = KvmSevSnpLaunchFinish {
            id_block_uaddr: id_block.as_bytes().as_ptr() as u64,
            id_auth_uaddr: id_auth.as_bytes().as_ptr() as u64,
            id_block_en,
            auth_key_en,
            host_data,
            ..Default::default()
        };
        let mut sev_cmd = kvm_sev_cmd {
            id: KVM_SEV_SNP_LAUNCH_FINISH,
            data: &raw mut finish as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };
        let flags = finish.flags;
        debug!(
            "KVM_SEV_SNP_LAUNCH_FINISH: id_block_en={id_block_en}, auth_key_en={auth_key_en}, policy={guest_policy:#x}, flags={flags}"
        );
        sev_op(vm, &mut sev_cmd, "KVM_SEV_SNP_LAUNCH_FINISH")
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    fn make_test_igvm_id_block() -> IGVM_VHS_SNP_ID_BLOCK {
        let mut block = IGVM_VHS_SNP_ID_BLOCK::new_zeroed();
        block.ld[0] = 0xAA;
        block.ld[47] = 0xBB;
        block.family_id[0] = 0x01;
        block.image_id[0] = 0x02;
        block.version = 42;
        block.guest_svn = 7;
        block.id_key_algorithm = 1;
        block.author_key_algorithm = 1;
        block.id_key_signature.r_comp[0] = 0x10;
        block.id_key_signature.s_comp[0] = 0x20;
        block.id_public_key.curve = 2;
        block.id_public_key.qx[0] = 0x30;
        block.id_public_key.qy[0] = 0x40;
        block.author_key_signature.r_comp[0] = 0x50;
        block.author_key_signature.s_comp[0] = 0x60;
        block.author_public_key.curve = 2;
        block.author_public_key.qx[0] = 0x70;
        block.author_public_key.qy[0] = 0x80;
        block
    }

    #[test]
    fn id_block_struct_sizes() {
        assert_eq!(size_of::<KvmSevSnpIdBlock>(), 96);
        assert_eq!(size_of::<KvmSevSnpIdAuth>(), 4096);
    }

    #[test]
    fn build_id_block_maps_fields_correctly() {
        let igvm = make_test_igvm_id_block();
        let policy = 0x30000u64;
        let id_block = build_id_block(&igvm, policy);

        assert_eq!(id_block.ld, igvm.ld);
        assert_eq!(id_block.family_id, igvm.family_id);
        assert_eq!(id_block.image_id, igvm.image_id);
        assert_eq!(id_block.version, IGVM_SEV_ID_BLOCK_VERSION);
        assert_eq!(id_block.guest_svn, igvm.guest_svn);
        assert_eq!(id_block.policy, policy);
    }

    #[test]
    fn build_id_block_policy_at_offset_88() {
        let igvm = IGVM_VHS_SNP_ID_BLOCK::new_zeroed();
        let policy = 0xDEAD_BEEF_CAFE_BABEu64;
        let id_block = build_id_block(&igvm, policy);
        let bytes = id_block.as_bytes();
        assert_eq!(&bytes[88..96], &policy.to_le_bytes());
    }

    #[test]
    fn build_id_auth_maps_signatures_correctly() {
        let igvm = make_test_igvm_id_block();
        let id_auth = build_id_auth(&igvm);

        assert_eq!(id_auth.id_key_alg, igvm.id_key_algorithm);
        assert_eq!(id_auth.auth_key_algo, igvm.author_key_algorithm);

        assert_eq!(id_auth.id_block_sig[0], 0x10);
        assert_eq!(id_auth.id_block_sig[72], 0x20);
        assert!(id_auth.id_block_sig[144..].iter().all(|&b| b == 0));

        assert_eq!(id_auth.id_key_sig[0], 0x50);
        assert_eq!(id_auth.id_key_sig[72], 0x60);
        assert!(id_auth.id_key_sig[144..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_id_auth_serializes_public_keys() {
        let igvm = make_test_igvm_id_block();
        let id_auth = build_id_auth(&igvm);

        assert_eq!(&id_auth.id_key[..4], &2u32.to_le_bytes());
        assert_eq!(id_auth.id_key[4], 0x30);
        assert_eq!(id_auth.id_key[76], 0x40);
        assert!(id_auth.id_key[148..].iter().all(|&b| b == 0));

        assert_eq!(&id_auth.author_key[..4], &2u32.to_le_bytes());
        assert_eq!(id_auth.author_key[4], 0x70);
        assert_eq!(id_auth.author_key[76], 0x80);
        assert!(id_auth.author_key[148..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_id_auth_zeroed_input() {
        let igvm = IGVM_VHS_SNP_ID_BLOCK::new_zeroed();
        let id_auth = build_id_auth(&igvm);
        assert!(id_auth.as_bytes().iter().all(|&b| b == 0));
    }
}
