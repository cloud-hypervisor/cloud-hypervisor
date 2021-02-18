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
    Api,
    SignalHandler,
    Vcpu,
    Vmm,
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
const SYS_IO_URING_SETUP: i64 = 425;
const SYS_IO_URING_ENTER: i64 = 426;
const SYS_IO_URING_REGISTER: i64 = 427;

// See include/uapi/asm-generic/ioctls.h in the kernel code.
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGTPEER: u64 = 0x5441;
const FIOCLEX: u64 = 0x5451;
const FIONBIO: u64 = 0x5421;

// See include/uapi/linux/if_tun.h in the kernel code.
const TUNGETIFF: u64 = 0x8004_54d2;
const TUNSETIFF: u64 = 0x4004_54ca;
const TUNSETOFFLOAD: u64 = 0x4004_54d0;
const TUNSETVNETHDRSZ: u64 = 0x4004_54d8;
const TUNGETFEATURES: u64 = 0x8004_54cf;

// See include/uapi/linux/sockios.h in the kernel code.
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFHWADDR: u64 = 0x8924;
const SIOCSIFNETMASK: u64 = 0x891c;

// See include/uapi/linux/vfio.h in the kernel code.
const VFIO_GET_API_VERSION: u64 = 0x3b64;
const VFIO_CHECK_EXTENSION: u64 = 0x3b65;
const VFIO_SET_IOMMU: u64 = 0x3b66;
const VFIO_GROUP_GET_STATUS: u64 = 0x3b67;
const VFIO_GROUP_SET_CONTAINER: u64 = 0x3b68;
const VFIO_GROUP_UNSET_CONTAINER: u64 = 0x3b69;
const VFIO_GROUP_GET_DEVICE_FD: u64 = 0x3b6a;
const VFIO_DEVICE_GET_INFO: u64 = 0x3b6b;
const VFIO_DEVICE_GET_REGION_INFO: u64 = 0x3b6c;
const VFIO_DEVICE_GET_IRQ_INFO: u64 = 0x3b6d;
const VFIO_DEVICE_SET_IRQS: u64 = 0x3b6e;
const VFIO_DEVICE_RESET: u64 = 0x3b6f;
const VFIO_IOMMU_MAP_DMA: u64 = 0x3b71;
const VFIO_IOMMU_UNMAP_DMA: u64 = 0x3b72;
const VFIO_DEVICE_IOEVENTFD: u64 = 0x3b74;

// See include/uapi/linux/kvm.h in the kernel code.
const KVM_GET_API_VERSION: u64 = 0xae00;
const KVM_CREATE_VM: u64 = 0xae01;
const KVM_CHECK_EXTENSION: u64 = 0xae03;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_CREATE_IRQCHIP: u64 = 0xae60;
const KVM_RUN: u64 = 0xae80;
const KVM_SET_MP_STATE: u64 = 0x4004_ae99;
const KVM_SET_GSI_ROUTING: u64 = 0x4008_ae6a;
const KVM_SET_DEVICE_ATTR: u64 = 0x4018_aee1;
const KVM_SET_ONE_REG: u64 = 0x4010_aeac;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020_ae46;
const KVM_IRQFD: u64 = 0x4020_ae76;
const KVM_IOEVENTFD: u64 = 0x4040_ae79;
const KVM_SET_VCPU_EVENTS: u64 = 0x4040_aea0;
const KVM_ENABLE_CAP: u64 = 0x4068_aea3;
const KVM_SET_REGS: u64 = 0x4090_ae82;
const KVM_GET_MP_STATE: u64 = 0x8004_ae98;
const KVM_GET_DEVICE_ATTR: u64 = 0x4018_aee2;
const KVM_GET_DIRTY_LOG: u64 = 0x4010_ae42;
const KVM_GET_VCPU_EVENTS: u64 = 0x8040_ae9f;
const KVM_GET_ONE_REG: u64 = 0x4010_aeab;
const KVM_GET_REGS: u64 = 0x8090_ae81;
const KVM_GET_SUPPORTED_CPUID: u64 = 0xc008_ae05;
const KVM_CREATE_DEVICE: u64 = 0xc00c_aee0;
const KVM_GET_REG_LIST: u64 = 0xc008_aeb0;

// The definition of libc::SYS_ftruncate on AArch64 is different from that on x86_64.
#[cfg(target_arch = "aarch64")]
pub const SYS_FTRUNCATE: libc::c_long = 46;
#[cfg(target_arch = "x86_64")]
pub const SYS_FTRUNCATE: libc::c_long = 77;

fn create_vmm_ioctl_seccomp_rule_common() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![
        and![Cond::new(1, ArgLen::DWORD, Eq, FIOCLEX)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, FIONBIO)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CHECK_EXTENSION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_DEVICE,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_IRQCHIP,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_VCPU)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_VM)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_ENABLE_CAP)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_API_VERSION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_DEVICE_ATTR,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_DIRTY_LOG)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_MP_STATE)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_ONE_REG)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_REGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_REG_LIST)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_SUPPORTED_CPUID,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_VCPU_EVENTS,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_VCPU_MMAP_SIZE,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_IOEVENTFD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_IRQFD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_RUN)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_DEVICE_ATTR,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_GSI_ROUTING)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_MP_STATE)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_ONE_REG)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_REGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_USER_MEMORY_REGION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_VCPU_EVENTS,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, SIOCGIFFLAGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, SIOCGIFHWADDR)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, SIOCSIFADDR)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, SIOCSIFFLAGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, SIOCSIFHWADDR)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, SIOCSIFNETMASK)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TCSETS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TCGETS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TIOCGWINSZ)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TIOCSPTLCK)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TIOCGTPEER)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNGETFEATURES)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNGETIFF)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNSETIFF)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNSETOFFLOAD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNSETVNETHDRSZ)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_GET_API_VERSION)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_CHECK_EXTENSION)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_SET_IOMMU)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_GROUP_GET_STATUS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_GROUP_SET_CONTAINER)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_GROUP_UNSET_CONTAINER)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_GROUP_GET_DEVICE_FD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_DEVICE_GET_INFO)?],
        and![Cond::new(
            1,
            ArgLen::DWORD,
            Eq,
            VFIO_DEVICE_GET_REGION_INFO
        )?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_DEVICE_GET_IRQ_INFO)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_DEVICE_SET_IRQS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_DEVICE_RESET)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_IOMMU_MAP_DMA)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_IOMMU_UNMAP_DMA)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_DEVICE_IOEVENTFD)?],
    ])
}

#[cfg(target_arch = "x86_64")]
fn create_vmm_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    const KVM_CREATE_PIT2: u64 = 0x4040_ae77;
    const KVM_GET_CLOCK: u64 = 0x8030_ae7c;
    const KVM_GET_CPUID2: u64 = 0xc008_ae91;
    const KVM_GET_FPU: u64 = 0x81a0_ae8c;
    const KVM_GET_LAPIC: u64 = 0x8400_ae8e;
    const KVM_GET_MSR_INDEX_LIST: u64 = 0xc004_ae02;
    const KVM_GET_MSRS: u64 = 0xc008_ae88;
    const KVM_GET_SREGS: u64 = 0x8138_ae83;
    const KVM_GET_XCRS: u64 = 0x8188_aea6;
    const KVM_GET_XSAVE: u64 = 0x9000_aea4;
    const KVM_KVMCLOCK_CTRL: u64 = 0xaead;
    const KVM_SET_CLOCK: u64 = 0x4030_ae7b;
    const KVM_SET_CPUID2: u64 = 0x4008_ae90;
    const KVM_SET_FPU: u64 = 0x41a0_ae8d;
    const KVM_SET_LAPIC: u64 = 0x4400_ae8f;
    const KVM_SET_MSRS: u64 = 0x4008_ae89;
    const KVM_SET_SREGS: u64 = 0x4138_ae84;
    const KVM_SET_TSS_ADDR: u64 = 0xae47;
    const KVM_SET_XCRS: u64 = 0x4188_aea7;
    const KVM_SET_XSAVE: u64 = 0x5000_aea5;

    let common_rules = create_vmm_ioctl_seccomp_rule_common()?;
    let mut arch_rules = or![
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_PIT2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_CLOCK,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_CPUID2,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_FPU)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_LAPIC)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_MSR_INDEX_LIST)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_MSRS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_SREGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_XCRS,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_XSAVE,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_KVMCLOCK_CTRL)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_CLOCK)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_CPUID2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_FPU)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_LAPIC)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_SREGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_TSS_ADDR,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_MSRS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_XCRS,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_XSAVE,)?],
    ];
    arch_rules.extend(common_rules);

    Ok(arch_rules)
}

#[cfg(target_arch = "aarch64")]
fn create_vmm_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    const KVM_ARM_PREFERRED_TARGET: u64 = 0x8020_aeaf;
    const KVM_ARM_VCPU_INIT: u64 = 0x4020_aeae;

    let common_rules = create_vmm_ioctl_seccomp_rule_common()?;
    let mut arch_rules = or![
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_ARM_PREFERRED_TARGET,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_ARM_VCPU_INIT,)?],
    ];
    arch_rules.extend(common_rules);

    Ok(arch_rules)
}

fn create_api_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![and![Cond::new(1, ArgLen::DWORD, Eq, FIONBIO)?],])
}

fn create_signal_handler_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![
        and![Cond::new(1, ArgLen::DWORD, Eq, TCGETS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TCSETS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TIOCGWINSZ)?],
    ])
}

fn signal_handler_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_exit_group),
        allow_syscall(libc::SYS_futex),
        allow_syscall_if(libc::SYS_ioctl, create_signal_handler_ioctl_seccomp_rule()?),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_recvfrom),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sendto),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_write),
    ])
}

// The filter containing the white listed syscall rules required by the VMM to
// function.
fn vmm_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_accept4),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_access),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_arch_prctl),
        allow_syscall(libc::SYS_bind),
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_clock_gettime),
        allow_syscall(libc::SYS_clock_nanosleep),
        allow_syscall(libc::SYS_clone),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_connect),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_epoll_create1),
        allow_syscall(libc::SYS_epoll_ctl),
        allow_syscall(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_epoll_wait),
        allow_syscall(libc::SYS_eventfd2),
        allow_syscall(libc::SYS_execve),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_exit_group),
        allow_syscall(libc::SYS_fallocate),
        allow_syscall(libc::SYS_fcntl),
        allow_syscall(libc::SYS_fdatasync),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_fork),
        allow_syscall(libc::SYS_fstat),
        allow_syscall(libc::SYS_fsync),
        allow_syscall(SYS_FTRUNCATE),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_faccessat),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_newfstatat),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_getpid),
        allow_syscall(libc::SYS_getrandom),
        allow_syscall(libc::SYS_gettid),
        allow_syscall(libc::SYS_gettimeofday),
        allow_syscall(libc::SYS_getuid),
        allow_syscall_if(libc::SYS_ioctl, create_vmm_ioctl_seccomp_rule()?),
        allow_syscall(SYS_IO_URING_ENTER),
        allow_syscall(SYS_IO_URING_SETUP),
        allow_syscall(SYS_IO_URING_REGISTER),
        allow_syscall(libc::SYS_kill),
        allow_syscall(libc::SYS_listen),
        allow_syscall(libc::SYS_lseek),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mbind),
        allow_syscall(libc::SYS_memfd_create),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_mremap),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_nanosleep),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_open),
        allow_syscall(libc::SYS_openat),
        allow_syscall(libc::SYS_pipe2),
        allow_syscall(libc::SYS_prctl),
        allow_syscall(libc::SYS_pread64),
        allow_syscall(libc::SYS_preadv),
        allow_syscall(libc::SYS_prlimit64),
        allow_syscall(libc::SYS_pwrite64),
        allow_syscall(libc::SYS_pwritev),
        allow_syscall(libc::SYS_read),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_readlink),
        allow_syscall(libc::SYS_recvfrom),
        allow_syscall(libc::SYS_recvmsg),
        allow_syscall(libc::SYS_restart_syscall),
        allow_syscall(libc::SYS_rt_sigaction),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_rt_sigreturn),
        allow_syscall(libc::SYS_sched_getaffinity),
        allow_syscall(libc::SYS_sendmsg),
        allow_syscall(libc::SYS_sendto),
        allow_syscall(libc::SYS_set_robust_list),
        allow_syscall(libc::SYS_set_tid_address),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall_if(
            libc::SYS_socket,
            or![
                and![Cond::new(0, ArgLen::DWORD, Eq, libc::AF_UNIX as u64)?],
                and![Cond::new(0, ArgLen::DWORD, Eq, libc::AF_INET as u64)?],
            ],
        ),
        allow_syscall(libc::SYS_socketpair),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_stat),
        allow_syscall(libc::SYS_statx),
        allow_syscall(libc::SYS_tgkill),
        allow_syscall(libc::SYS_timerfd_create),
        allow_syscall(libc::SYS_timerfd_settime),
        allow_syscall(libc::SYS_tkill),
        allow_syscall_if(
            libc::SYS_umask,
            or![and![Cond::new(0, ArgLen::DWORD, Eq, 0o077)?]],
        ),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_unlink),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_unlinkat),
        allow_syscall(libc::SYS_wait4),
        allow_syscall(libc::SYS_write),
    ])
}

fn create_vcpu_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CHECK_EXTENSION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_IOEVENTFD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_IRQFD,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_DEVICE_ATTR,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_GSI_ROUTING,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_USER_MEMORY_REGION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_RUN,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_DEVICE_SET_IRQS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_GROUP_UNSET_CONTAINER)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, VFIO_IOMMU_UNMAP_DMA)?],
    ])
}

fn vcpu_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_clock_gettime),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_dup),
        allow_syscall(libc::SYS_exit),
        allow_syscall(libc::SYS_fstat),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_getrandom),
        allow_syscall(libc::SYS_getpid),
        allow_syscall_if(libc::SYS_ioctl, create_vcpu_ioctl_seccomp_rule()?),
        allow_syscall(libc::SYS_lseek),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_nanosleep),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_open),
        allow_syscall(libc::SYS_openat),
        allow_syscall(libc::SYS_pread64),
        allow_syscall(libc::SYS_pwrite64),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_recvmsg),
        allow_syscall(libc::SYS_rt_sigaction),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_rt_sigreturn),
        allow_syscall(libc::SYS_sendmsg),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_tgkill),
        allow_syscall(libc::SYS_tkill),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_unlink),
        #[cfg(target_arch = "aarch64")]
        allow_syscall(libc::SYS_unlinkat),
        allow_syscall(libc::SYS_write),
    ])
}

// The filter containing the white listed syscall rules required by the API to
// function.
fn api_thread_rules() -> Result<Vec<SyscallRuleSet>, Error> {
    Ok(vec![
        allow_syscall(libc::SYS_accept4),
        allow_syscall(libc::SYS_bind),
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
        allow_syscall(libc::SYS_getrandom),
        allow_syscall_if(libc::SYS_ioctl, create_api_ioctl_seccomp_rule()?),
        allow_syscall(libc::SYS_listen),
        allow_syscall(libc::SYS_madvise),
        allow_syscall(libc::SYS_mprotect),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_recvfrom),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_socket),
        allow_syscall(libc::SYS_write),
    ])
}

fn get_seccomp_filter_trap(thread_type: Thread) -> Result<SeccompFilter, Error> {
    let rules = match thread_type {
        Thread::Api => api_thread_rules()?,
        Thread::SignalHandler => signal_handler_thread_rules()?,
        Thread::Vcpu => vcpu_thread_rules()?,
        Thread::Vmm => vmm_thread_rules()?,
    };

    Ok(SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Trap,
    )?)
}

fn get_seccomp_filter_log(thread_type: Thread) -> Result<SeccompFilter, Error> {
    let rules = match thread_type {
        Thread::Api => api_thread_rules()?,
        Thread::SignalHandler => signal_handler_thread_rules()?,
        Thread::Vcpu => vcpu_thread_rules()?,
        Thread::Vmm => vmm_thread_rules()?,
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
