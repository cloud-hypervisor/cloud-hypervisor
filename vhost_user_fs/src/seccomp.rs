// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use seccomp::{allow_syscall, BpfProgram, SeccompAction, SeccompFilter};
use std::convert::TryInto;
use std::{convert, fmt};

#[derive(Debug)]
pub enum Error {
    /// Cannot create seccomp filter
    CreateSeccompFilter(seccomp::SeccompError),

    /// Cannot apply seccomp filter
    ApplySeccompFilter(seccomp::Error),
}

impl convert::From<seccomp::Error> for Error {
    fn from(e: seccomp::Error) -> Self {
        Error::ApplySeccompFilter(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost_user_fs_seccomp_error: {:?}", self)
    }
}

fn vuf_filter(action: SeccompAction) -> Result<SeccompFilter, Error> {
    Ok(SeccompFilter::new(
        vec![
            allow_syscall(libc::SYS_accept4),
            allow_syscall(libc::SYS_brk),
            allow_syscall(libc::SYS_capget), // For CAP_FSETID
            allow_syscall(libc::SYS_capset),
            allow_syscall(libc::SYS_clock_gettime),
            allow_syscall(libc::SYS_clone),
            allow_syscall(libc::SYS_close),
            allow_syscall(libc::SYS_copy_file_range),
            allow_syscall(libc::SYS_dup),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_epoll_create),
            allow_syscall(libc::SYS_epoll_create1),
            allow_syscall(libc::SYS_epoll_ctl),
            allow_syscall(libc::SYS_epoll_pwait),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_epoll_wait),
            allow_syscall(libc::SYS_eventfd2),
            allow_syscall(libc::SYS_exit),
            allow_syscall(libc::SYS_exit_group),
            allow_syscall(libc::SYS_fallocate),
            allow_syscall(libc::SYS_fchdir),
            allow_syscall(libc::SYS_fchmodat),
            allow_syscall(libc::SYS_fchownat),
            allow_syscall(libc::SYS_fcntl),
            allow_syscall(libc::SYS_fdatasync),
            allow_syscall(libc::SYS_fgetxattr),
            allow_syscall(libc::SYS_flistxattr),
            allow_syscall(libc::SYS_flock),
            allow_syscall(libc::SYS_fremovexattr),
            allow_syscall(libc::SYS_fsetxattr),
            allow_syscall(libc::SYS_fstat),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_fstatfs),
            allow_syscall(libc::SYS_fsync),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_ftruncate),
            allow_syscall(libc::SYS_futex),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_getdents),
            allow_syscall(libc::SYS_getdents64),
            allow_syscall(libc::SYS_getegid),
            allow_syscall(libc::SYS_geteuid),
            allow_syscall(libc::SYS_getpid),
            allow_syscall(libc::SYS_gettid),
            allow_syscall(libc::SYS_gettimeofday),
            allow_syscall(libc::SYS_getxattr),
            allow_syscall(libc::SYS_linkat),
            allow_syscall(libc::SYS_listxattr),
            allow_syscall(libc::SYS_lseek),
            allow_syscall(libc::SYS_madvise),
            allow_syscall(libc::SYS_mkdirat),
            allow_syscall(libc::SYS_mknodat),
            allow_syscall(libc::SYS_mmap),
            allow_syscall(libc::SYS_mprotect),
            allow_syscall(libc::SYS_mremap),
            allow_syscall(libc::SYS_munmap),
            allow_syscall(libc::SYS_newfstatat),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_open),
            allow_syscall(libc::SYS_openat),
            allow_syscall(libc::SYS_prctl), // TODO restrict to just PR_SET_NAME?
            allow_syscall(libc::SYS_preadv),
            allow_syscall(libc::SYS_pread64),
            allow_syscall(libc::SYS_pwritev),
            allow_syscall(libc::SYS_pwrite64),
            allow_syscall(libc::SYS_read),
            allow_syscall(libc::SYS_readlinkat),
            allow_syscall(libc::SYS_recvmsg),
            allow_syscall(libc::SYS_renameat),
            allow_syscall(libc::SYS_renameat2),
            allow_syscall(libc::SYS_removexattr),
            allow_syscall(libc::SYS_rt_sigaction),
            allow_syscall(libc::SYS_rt_sigprocmask),
            allow_syscall(libc::SYS_rt_sigreturn),
            allow_syscall(libc::SYS_sched_getaffinity), // used by thread_pool
            allow_syscall(libc::SYS_sendmsg),
            allow_syscall(libc::SYS_setresgid),
            allow_syscall(libc::SYS_setresuid),
            //allow_syscall(libc::SYS_setresgid32),  Needed on some platforms,
            //allow_syscall(libc::SYS_setresuid32),  Needed on some platforms
            allow_syscall(libc::SYS_set_robust_list),
            allow_syscall(libc::SYS_setxattr),
            allow_syscall(libc::SYS_sigaltstack),
            allow_syscall(libc::SYS_statx),
            allow_syscall(libc::SYS_symlinkat),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_time), // Rarely needed, except on static builds
            allow_syscall(libc::SYS_tgkill),
            allow_syscall(libc::SYS_umask),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_unlink),
            allow_syscall(libc::SYS_unlinkat),
            allow_syscall(libc::SYS_unshare),
            allow_syscall(libc::SYS_utimensat),
            allow_syscall(libc::SYS_write),
            allow_syscall(libc::SYS_writev),
        ]
        .into_iter()
        .collect(),
        action,
    )?)
}

pub fn enable_seccomp(action: SeccompAction) -> Result<(), Error> {
    let scfilter = vuf_filter(action)?;
    let bpfprog: BpfProgram = scfilter.try_into()?;
    SeccompFilter::apply(bpfprog.try_into().unwrap()).unwrap();
    Ok(())
}
