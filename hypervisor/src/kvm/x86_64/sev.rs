use vmm_sys_util::errno;

use std::fs::OpenOptions;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;

pub(crate) type Result<T> = std::result::Result<T, errno::Error>;

#[derive(Debug)]
pub struct SevFd {
    pub fd: OwnedFd,
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
}
