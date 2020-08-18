// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use seccomp::{
    allow_syscall, BpfProgram, Error, SeccompAction, SeccompError, SeccompFilter, SyscallRuleSet,
};
use std::convert::TryInto;

pub enum Thread {
    VirtioBalloon,
    VirtioBlk,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioVhostFs,
}

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
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_mem_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_fallocate),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_write),
    ])
}

fn virtio_net_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_dup),
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

fn get_seccomp_filter_trap(thread_type: Thread) -> Result<SeccompFilter, Error> {
    let rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules()?,
        Thread::VirtioBlk => virtio_blk_thread_rules()?,
        Thread::VirtioConsole => virtio_console_thread_rules()?,
        Thread::VirtioIommu => virtio_iommu_thread_rules()?,
        Thread::VirtioMem => virtio_mem_thread_rules()?,
        Thread::VirtioNet => virtio_net_thread_rules()?,
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules()?,
        Thread::VirtioPmem => virtio_pmem_thread_rules()?,
        Thread::VirtioRng => virtio_rng_thread_rules()?,
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules()?,
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
        Thread::VirtioConsole => virtio_console_thread_rules()?,
        Thread::VirtioIommu => virtio_iommu_thread_rules()?,
        Thread::VirtioMem => virtio_mem_thread_rules()?,
        Thread::VirtioNet => virtio_net_thread_rules()?,
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules()?,
        Thread::VirtioPmem => virtio_pmem_thread_rules()?,
        Thread::VirtioRng => virtio_rng_thread_rules()?,
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules()?,
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
