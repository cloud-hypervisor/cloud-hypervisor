// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use seccomp::{
    allow_syscall, allow_syscall_if, BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen,
    SeccompCmpOp::Eq, SeccompCondition as Cond, SeccompError, SeccompFilter, SeccompRule,
    SyscallRuleSet,
};
use std::convert::TryInto;

pub enum Thread {
    VirtioBalloon,
    VirtioBlk,
    VirtioBlkIoUring,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioVhostBlk,
    VirtioVhostFs,
    VirtioVhostNet,
    VirtioVhostNetCtl,
    VirtioVsock,
    VirtioWatchdog,
}

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
///
/// [`Allow`]: enum.SeccompAction.html
/// [`SeccompCondition`]: struct.SeccompCondition.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! and {
    ($($x:expr,)*) => (SeccompRule::new(vec![$($x),*], SeccompAction::Allow));
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*], SeccompAction::Allow))
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilter`.
///
/// [`SeccompFilter`]: struct.SeccompFilter.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

// Define io_uring syscalls as they are not yet part of libc.
const SYS_IO_URING_ENTER: i64 = 426;

// See include/uapi/asm-generic/ioctls.h in the kernel code.
const FIONBIO: u64 = 0x5421;

fn virtio_balloon_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

// The filter containing the allowed syscall rules required by the
// virtio_blk thread to function.
fn virtio_blk_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_fallocate),
        allow_syscall(libc::SYS_fdatasync),
        allow_syscall(libc::SYS_fsync),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_ftruncate),
        #[cfg(target_arch = "aarch64")]
        // The definition of libc::SYS_ftruncate is missing on AArch64.
        // Use a hard-code number instead.
        allow_syscall(46),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_lseek),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_openat),
        allow_syscall(libc::SYS_prctl),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sched_getaffinity),
        allow_syscall(libc::SYS_set_robust_list),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_blk_io_uring_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_fsync),
        allow_syscall(libc::SYS_futex),
        allow_syscall(SYS_IO_URING_ENTER),
        allow_syscall(libc::SYS_lseek),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_console_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_prctl),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sched_getaffinity),
        allow_syscall(libc::SYS_set_robust_list),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_iommu_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_mem_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_fallocate),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_net_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_openat),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_net_ctl_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_pmem_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_fsync),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_rng_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_prctl),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sched_getaffinity),
        allow_syscall(libc::SYS_set_robust_list),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_vhost_blk_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_vhost_fs_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_recvmsg),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sendmsg),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_vhost_net_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_write),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_munmap),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_madvise),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_exit),
    ])
}

fn virtio_vhost_net_ctl_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_read),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_sigaltstack),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_munmap),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_madvise),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_exit),
    ])
}

fn create_vsock_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![and![Cond::new(1, ArgLen::DWORD, Eq, FIONBIO,)?],])
}

fn virtio_vsock_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_accept4),
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall_if(libc::SYS_ioctl, create_vsock_ioctl_seccomp_rule()?),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_recvfrom),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_watchdog_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_prctl),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sched_getaffinity),
        allow_syscall(libc::SYS_set_robust_list),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_timerfd_settime),
        allow_syscall(libc::SYS_write),
    ])
}

fn get_seccomp_filter_trap(thread_type: Thread) -> Result<SeccompFilter, Error> {
    let rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules()?,
        Thread::VirtioBlk => virtio_blk_thread_rules()?,
        Thread::VirtioBlkIoUring => virtio_blk_io_uring_thread_rules()?,
        Thread::VirtioConsole => virtio_console_thread_rules()?,
        Thread::VirtioIommu => virtio_iommu_thread_rules()?,
        Thread::VirtioMem => virtio_mem_thread_rules()?,
        Thread::VirtioNet => virtio_net_thread_rules()?,
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules()?,
        Thread::VirtioPmem => virtio_pmem_thread_rules()?,
        Thread::VirtioRng => virtio_rng_thread_rules()?,
        Thread::VirtioVhostBlk => virtio_vhost_blk_thread_rules()?,
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules()?,
        Thread::VirtioVhostNet => virtio_vhost_net_thread_rules()?,
        Thread::VirtioVhostNetCtl => virtio_vhost_net_ctl_thread_rules()?,
        Thread::VirtioVsock => virtio_vsock_thread_rules()?,
        Thread::VirtioWatchdog => virtio_watchdog_thread_rules()?,
    };

    Ok(SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Trap,
    )?)
}

fn get_seccomp_filter_log(thread_type: Thread) -> Result<SeccompFilter, Error> {
    let rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules()?,
        Thread::VirtioBlk => virtio_blk_thread_rules()?,
        Thread::VirtioBlkIoUring => virtio_blk_io_uring_thread_rules()?,
        Thread::VirtioConsole => virtio_console_thread_rules()?,
        Thread::VirtioIommu => virtio_iommu_thread_rules()?,
        Thread::VirtioMem => virtio_mem_thread_rules()?,
        Thread::VirtioNet => virtio_net_thread_rules()?,
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules()?,
        Thread::VirtioPmem => virtio_pmem_thread_rules()?,
        Thread::VirtioRng => virtio_rng_thread_rules()?,
        Thread::VirtioVhostBlk => virtio_vhost_blk_thread_rules()?,
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules()?,
        Thread::VirtioVhostNet => virtio_vhost_net_thread_rules()?,
        Thread::VirtioVhostNetCtl => virtio_vhost_net_ctl_thread_rules()?,
        Thread::VirtioVsock => virtio_vsock_thread_rules()?,
        Thread::VirtioWatchdog => virtio_watchdog_thread_rules()?,
    };

    Ok(SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Log,
    )?)
}

/// Generate a BPF program based on the seccomp_action value
pub fn get_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<BpfProgram, SeccompError> {
    match seccomp_action {
        SeccompAction::Allow => Ok(vec![]),
        SeccompAction::Log => get_seccomp_filter_log(thread_type)
            .and_then(|filter| filter.try_into())
            .map_err(SeccompError::SeccompFilter),
        _ => get_seccomp_filter_trap(thread_type)
            .and_then(|filter| filter.try_into())
            .map_err(SeccompError::SeccompFilter),
    }
}
