// Copyright 2021 Alyssa Ross <hi@alyssa.is>
// SPDX-License-Identifier: Apache-2.0

use libc::{c_long, size_t, syscall, SYS_clone3};

pub(crate) const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;

#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
pub(crate) struct clone_args {
    pub(crate) flags: u64,
    pub(crate) pidfd: u64,
    pub(crate) child_tid: u64,
    pub(crate) parent_tid: u64,
    pub(crate) exit_signal: u64,
    pub(crate) stack: u64,
    pub(crate) stack_size: u64,
    pub(crate) tls: u64,
    pub(crate) set_tid: u64,
    pub(crate) set_tid_size: u64,
    pub(crate) cgroup: u64,
}

pub(crate) unsafe fn clone3(args: &mut clone_args, size: size_t) -> c_long {
    syscall(SYS_clone3, args, size)
}
