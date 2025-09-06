// Copyright 2021 Alyssa Ross <hi@alyssa.is>
// SPDX-License-Identifier: Apache-2.0

use libc::{SYS_clone3, c_long, size_t, syscall};

pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;

#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct clone_args {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// # Safety
/// `size` must have the proper size to match `args`.
/// Further, the caller needs to check the return value.
///
/// # Return
/// - On success:
///   - Parent: child PID (`c_long`)
///   - Child: `0`
/// - On error: `-1` and `errno` is set
#[must_use]
pub unsafe fn clone3(args: &mut clone_args, size: size_t) -> c_long {
    // SAFETY: parameters are assumed to be valid
    unsafe { syscall(SYS_clone3, args, size) }
}
