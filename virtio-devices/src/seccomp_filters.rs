// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use libc::{FIONBIO, TIOCGWINSZ, TUNSETOFFLOAD};
use seccompiler::SeccompCmpOp::Eq;
use seccompiler::{
    BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCondition as Cond,
    SeccompFilter, SeccompRule,
};

#[derive(Clone, Copy)]
pub enum Thread {
    VirtioBalloon,
    VirtioBlock,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioVhostBlock,
    VirtioVhostFs,
    VirtioVhostNet,
    VirtioVhostNetCtl,
    VirtioVsock,
    VirtioWatchdog,
}

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
///
/// [`SeccompCondition`]: struct.SeccompCondition.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! and {
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*]).unwrap())
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilter`.
///
/// [`SeccompFilter`]: struct.SeccompFilter.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

// See include/uapi/linux/vfio.h in the kernel code.
const VFIO_IOMMU_MAP_DMA: u64 = 0x3b71;
const VFIO_IOMMU_UNMAP_DMA: u64 = 0x3b72;

#[cfg(feature = "sev_snp")]
fn mshv_sev_snp_ioctl_seccomp_rule() -> SeccompRule {
    and![
        Cond::new(
            1,
            ArgLen::Dword,
            Eq,
            mshv_ioctls::MSHV_MODIFY_GPA_HOST_ACCESS()
        )
        .unwrap()
    ]
}

#[cfg(feature = "sev_snp")]
fn create_mshv_sev_snp_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![mshv_sev_snp_ioctl_seccomp_rule()]
}

fn create_virtio_console_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, TIOCGWINSZ as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn create_virtio_iommu_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
    ]
}

fn create_virtio_mem_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
    ]
}

fn virtio_balloon_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fallocate, vec![])]
}

fn virtio_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_fdatasync, vec![]),
        (libc::SYS_fsync, vec![]),
        (libc::SYS_ftruncate, vec![]),
        (libc::SYS_getrandom, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
        (libc::SYS_io_destroy, vec![]),
        (libc::SYS_io_getevents, vec![]),
        (libc::SYS_io_submit, vec![]),
        (libc::SYS_io_uring_enter, vec![]),
        (libc::SYS_lseek, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_preadv, vec![]),
        (libc::SYS_pwritev, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_sched_setaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn virtio_console_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_ioctl, create_virtio_console_ioctl_seccomp_rule()),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
    ]
}

fn virtio_iommu_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_iommu_ioctl_seccomp_rule())]
}

fn virtio_mem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_ioctl, create_virtio_mem_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendmsg, vec![]),
    ]
}

fn virtio_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_readv, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        (libc::SYS_writev, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
    ]
}

fn create_virtio_net_ctl_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, TUNSETOFFLOAD as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_net_ctl_ioctl_seccomp_rule())]
}

fn virtio_pmem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fsync, vec![])]
}

fn virtio_rng_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
    ]
}

fn virtio_vhost_fs_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
    ]
}

fn virtio_vhost_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![]
}

fn virtio_vhost_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_bind, vec![]),
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_getcwd, vec![]),
        (libc::SYS_listen, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_unlink, vec![]),
        #[cfg(target_arch = "aarch64")]
        (libc::SYS_unlinkat, vec![]),
    ]
}

fn virtio_vhost_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_socket, vec![]),
    ]
}

fn create_vsock_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, FIONBIO as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_vsock_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_ioctl, create_vsock_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
        // If debug_assertions is enabled, closing a file first checks
        // whether the FD is valid with fcntl.
        #[cfg(debug_assertions)]
        (libc::SYS_fcntl, vec![]),
    ]
}

fn virtio_watchdog_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn get_seccomp_rules(thread_type: Thread) -> Vec<(i64, Vec<SeccompRule>)> {
    let mut rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules(),
        Thread::VirtioBlock => virtio_block_thread_rules(),
        Thread::VirtioConsole => virtio_console_thread_rules(),
        Thread::VirtioIommu => virtio_iommu_thread_rules(),
        Thread::VirtioMem => virtio_mem_thread_rules(),
        Thread::VirtioNet => virtio_net_thread_rules(),
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules(),
        Thread::VirtioPmem => virtio_pmem_thread_rules(),
        Thread::VirtioRng => virtio_rng_thread_rules(),
        Thread::VirtioVhostBlock => virtio_vhost_block_thread_rules(),
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules(),
        Thread::VirtioVhostNet => virtio_vhost_net_thread_rules(),
        Thread::VirtioVhostNetCtl => virtio_vhost_net_ctl_thread_rules(),
        Thread::VirtioVsock => virtio_vsock_thread_rules(),
        Thread::VirtioWatchdog => virtio_watchdog_thread_rules(),
    };
    rules.append(&mut virtio_thread_common());
    rules
}

fn virtio_thread_common() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_brk, vec![]),
        (libc::SYS_clock_gettime, vec![]),
        (libc::SYS_close, vec![]),
        (libc::SYS_dup, vec![]),
        (libc::SYS_epoll_create1, vec![]),
        (libc::SYS_epoll_ctl, vec![]),
        (libc::SYS_epoll_pwait, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_epoll_wait, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_gettid, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_mremap, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_openat, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_write, vec![]),
        #[cfg(debug_assertions)]
        (libc::SYS_fcntl, vec![]),
    ]
}

/// Generate a BPF program based on the seccomp_action value
pub fn get_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<BpfProgram, Error> {
    match seccomp_action {
        SeccompAction::Allow => Ok(vec![]),
        SeccompAction::Log => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Log,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
        _ => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
    }
}
