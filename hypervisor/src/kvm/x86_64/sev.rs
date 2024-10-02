use igvm_defs::SnpPolicy;
use kvm_bindings::kvm_sev_cmd;
use kvm_ioctls::VmFd;
use vmm_sys_util::errno;

use std::fs::OpenOptions;
use std::os::fd::{OwnedFd, AsRawFd};
use std::os::unix::fs::OpenOptionsExt;

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

const KVM_SEV_SNP_LAUNCH_START: u32 = 100;

#[derive(Debug)]
pub struct SevFd {
    pub fd: OwnedFd,
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

impl SevFd {
    pub(crate) fn new(sev_path: &String) -> Result<Self> {
        // give sev device rw and close on exec
        let file_r = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(sev_path);
        if let Ok(file) = file_r {
            Ok(SevFd { fd: OwnedFd::from(file) })
        } else {
            Err(errno::Error::last())
        }
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
}
