#![allow(dead_code)]
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Macros and wrapper functions for dealing with ioctls.
use libc;
use std::os::raw::{c_int, c_uint, c_ulong, c_void};
use std::os::unix::io::AsRawFd;

/// Raw macro to declare a function that returns an ioctl number.
#[macro_export]
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        #[allow(non_snake_case)]
        pub fn $name() -> ::std::os::raw::c_ulong {
            u64::from(
                ($dir << $crate::sys_ioctl::_IOC_DIRSHIFT)
                    | ($ty << $crate::sys_ioctl::_IOC_TYPESHIFT)
                    | ($nr << $crate::sys_ioctl::_IOC_NRSHIFT)
                    | ($size << $crate::sys_ioctl::_IOC_SIZESHIFT),
            )
        }
    };
}

/// Declare an ioctl that transfers no data.
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        ioctl_ioc_nr!($name, $crate::sys_ioctl::_IOC_NONE, $ty, $nr, 0);
    };
}

/// Declare an ioctl that reads data.
#[macro_export]
macro_rules! ioctl_ior_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        ioctl_ioc_nr!(
            $name,
            $crate::sys_ioctl::_IOC_READ,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
}

/// Declare an ioctl that writes data.
#[macro_export]
macro_rules! ioctl_iow_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        ioctl_ioc_nr!(
            $name,
            $crate::sys_ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
}

/// Declare an ioctl that reads and writes data.
#[macro_export]
macro_rules! ioctl_iowr_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        ioctl_ioc_nr!(
            $name,
            $crate::sys_ioctl::_IOC_READ | $crate::sys_ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
}

pub const _IOC_NRBITS: c_uint = 8;
pub const _IOC_TYPEBITS: c_uint = 8;
pub const _IOC_SIZEBITS: c_uint = 14;
pub const _IOC_DIRBITS: c_uint = 2;
pub const _IOC_NRMASK: c_uint = 255;
pub const _IOC_TYPEMASK: c_uint = 255;
pub const _IOC_SIZEMASK: c_uint = 16383;
pub const _IOC_DIRMASK: c_uint = 3;
pub const _IOC_NRSHIFT: c_uint = 0;
pub const _IOC_TYPESHIFT: c_uint = 8;
pub const _IOC_SIZESHIFT: c_uint = 16;
pub const _IOC_DIRSHIFT: c_uint = 30;
pub const _IOC_NONE: c_uint = 0;
pub const _IOC_WRITE: c_uint = 1;
pub const _IOC_READ: c_uint = 2;
pub const IOC_IN: c_uint = 1_073_741_824;
pub const IOC_OUT: c_uint = 2_147_483_648;
pub const IOC_INOUT: c_uint = 3_221_225_472;
pub const IOCSIZE_MASK: c_uint = 1_073_676_288;
pub const IOCSIZE_SHIFT: c_uint = 16;

// The type of the `req` parameter is different for the `musl` library. This will enable
// successful build for other non-musl libraries.
#[cfg(target_env = "musl")]
type IoctlRequest = c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = c_ulong;

/// Run an ioctl with no arguments.
pub unsafe fn ioctl<F: AsRawFd>(fd: &F, req: c_ulong) -> c_int {
    libc::ioctl(fd.as_raw_fd(), req as IoctlRequest, 0)
}

/// Run an ioctl with a single value argument.
pub unsafe fn ioctl_with_val<F: AsRawFd>(fd: &F, req: c_ulong, arg: c_ulong) -> c_int {
    libc::ioctl(fd.as_raw_fd(), req as IoctlRequest, arg)
}

/// Run an ioctl with an immutable reference.
pub unsafe fn ioctl_with_ref<F: AsRawFd, T>(fd: &F, req: c_ulong, arg: &T) -> c_int {
    libc::ioctl(
        fd.as_raw_fd(),
        req as IoctlRequest,
        arg as *const T as *const c_void,
    )
}

/// Run an ioctl with a mutable reference.
pub unsafe fn ioctl_with_mut_ref<F: AsRawFd, T>(fd: &F, req: c_ulong, arg: &mut T) -> c_int {
    libc::ioctl(
        fd.as_raw_fd(),
        req as IoctlRequest,
        arg as *mut T as *mut c_void,
    )
}

/// Run an ioctl with a raw pointer.
pub unsafe fn ioctl_with_ptr<F: AsRawFd, T>(fd: &F, req: c_ulong, arg: *const T) -> c_int {
    libc::ioctl(fd.as_raw_fd(), req as IoctlRequest, arg as *const c_void)
}

/// Run an ioctl with a mutable raw pointer.
pub unsafe fn ioctl_with_mut_ptr<F: AsRawFd, T>(fd: &F, req: c_ulong, arg: *mut T) -> c_int {
    libc::ioctl(fd.as_raw_fd(), req as IoctlRequest, arg as *mut c_void)
}

#[cfg(test)]
mod tests {
    const TUNTAP: ::std::os::raw::c_uint = 0x54;
    const KVMIO: ::std::os::raw::c_uint = 0xAE;

    ioctl_io_nr!(KVM_CREATE_VM, KVMIO, 0x01);
    ioctl_ior_nr!(TUNGETFEATURES, TUNTAP, 0xcf, ::std::os::raw::c_uint);
    ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 0xd9, ::std::os::raw::c_int);
    ioctl_iowr_nr!(KVM_GET_MSR_INDEX_LIST, KVMIO, 0x2, ::std::os::raw::c_int);

    #[test]
    fn ioctl_macros() {
        assert_eq!(0x0000AE01, KVM_CREATE_VM());
        assert_eq!(0x800454CF, TUNGETFEATURES());
        assert_eq!(0x400454D9, TUNSETQUEUE());
        assert_eq!(0xC004AE02, KVM_GET_MSR_INDEX_LIST());
    }
}
