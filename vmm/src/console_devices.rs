// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use crate::sigwinch_listener::listen_for_sigwinch_on_tty;
use crate::vm_config::ConsoleOutputMode;
use crate::Vmm;
use libc::cfmakeraw;
use libc::isatty;
use libc::tcgetattr;
use libc::tcsetattr;
use libc::termios;
use libc::TCSANOW;
use std::fs::read_link;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
#[cfg(target_arch = "x86_64")]
use std::io::stdout;
use std::mem::zeroed;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::os::fd::RawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::result;
use std::sync::Arc;
use std::sync::Mutex;
use thiserror::Error;

const TIOCSPTLCK: libc::c_int = 0x4004_5431;
const TIOCGTPEER: libc::c_int = 0x5441;

/// Errors associated with console devices
#[derive(Debug, Error)]
pub enum ConsoleDeviceError {
    /// Error creating console device
    #[error("Error creating console device: {0}")]
    CreateConsoleDevice(#[source] io::Error),

    /// Error setting pty raw mode
    #[error("Error setting pty raw mode: {0}")]
    SetPtyRaw(#[source] vmm_sys_util::errno::Error),

    /// Cannot duplicate file descriptor
    #[error("Cannot duplicate file descriptor: {0}")]
    DupFd(#[source] vmm_sys_util::errno::Error),

    /// Error starting sigwinch listener
    #[error("Error starting sigwinch listener: {0}")]
    StartSigwinchListener(#[source] std::io::Error),
}

type ConsoleDeviceResult<T> = result::Result<T, ConsoleDeviceError>;

#[derive(Default, Clone)]
pub struct ConsoleInfo {
    // For each of File, Pty, Tty and Socket modes, below fields  hold the FD
    // of console, serial and debug devices.
    pub console_main_fd: Option<RawFd>,
    pub serial_main_fd: Option<RawFd>,
    #[cfg(target_arch = "x86_64")]
    pub debug_main_fd: Option<RawFd>,
}

fn modify_mode<F: FnOnce(&mut termios)>(
    fd: RawFd,
    f: F,
    original_termios_opt: Arc<Mutex<Option<termios>>>,
) -> vmm_sys_util::errno::Result<()> {
    // SAFETY: safe because we check the return value of isatty.
    if unsafe { isatty(fd) } != 1 {
        return Ok(());
    }

    // SAFETY: The following pair are safe because termios gets totally overwritten by tcgetattr
    // and we check the return result.
    let mut termios: termios = unsafe { zeroed() };
    // SAFETY: see above
    let ret = unsafe { tcgetattr(fd, &mut termios as *mut _) };
    if ret < 0 {
        return vmm_sys_util::errno::errno_result();
    }
    let mut original_termios_opt = original_termios_opt.lock().unwrap();
    if original_termios_opt.is_none() {
        original_termios_opt.replace(termios);
    }

    f(&mut termios);
    // SAFETY: Safe because the syscall will only read the extent of termios and we check
    // the return result.
    let ret = unsafe { tcsetattr(fd, TCSANOW, &termios as *const _) };
    if ret < 0 {
        return vmm_sys_util::errno::errno_result();
    }

    Ok(())
}

pub fn set_raw_mode(
    f: &dyn AsRawFd,
    original_termios_opt: Arc<Mutex<Option<termios>>>,
) -> ConsoleDeviceResult<()> {
    modify_mode(
        f.as_raw_fd(),
        // SAFETY: FFI call. Variable t is guaranteed to be a valid termios from modify_mode.
        |t| unsafe { cfmakeraw(t) },
        original_termios_opt,
    )
    .map_err(ConsoleDeviceError::SetPtyRaw)
}

pub fn create_pty() -> io::Result<(File, File, PathBuf)> {
    // Try to use /dev/pts/ptmx first then fall back to /dev/ptmx
    // This is done to try and use the devpts filesystem that
    // could be available for use in the process's namespace first.
    // Ideally these are all the same file though but different
    // kernels could have things setup differently.
    // See https://www.kernel.org/doc/Documentation/filesystems/devpts.txt
    // for further details.

    let custom_flags = libc::O_NONBLOCK;
    let main = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(custom_flags)
        .open("/dev/pts/ptmx")
    {
        Ok(f) => f,
        _ => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(custom_flags)
            .open("/dev/ptmx")?,
    };
    let mut unlock: libc::c_ulong = 0;
    // SAFETY: FFI call into libc, trivially safe
    unsafe { libc::ioctl(main.as_raw_fd(), TIOCSPTLCK as _, &mut unlock) };

    // SAFETY: FFI call into libc, trivially safe
    let sub_fd = unsafe {
        libc::ioctl(
            main.as_raw_fd(),
            TIOCGTPEER as _,
            libc::O_NOCTTY | libc::O_RDWR,
        )
    };
    if sub_fd == -1 {
        return vmm_sys_util::errno::errno_result().map_err(|e| e.into());
    }

    let proc_path = PathBuf::from(format!("/proc/self/fd/{sub_fd}"));
    let path = read_link(proc_path)?;

    // SAFETY: sub_fd is checked to be valid before being wrapped in File
    Ok((main, unsafe { File::from_raw_fd(sub_fd) }, path))
}

pub(crate) fn pre_create_console_devices(vmm: &mut Vmm) -> ConsoleDeviceResult<ConsoleInfo> {
    let vm_config = vmm.vm_config.as_mut().unwrap().clone();
    let mut vmconfig = vm_config.lock().unwrap();
    let mut console_info = ConsoleInfo::default();

    match vmconfig.console.mode {
        ConsoleOutputMode::File => {
            let file = File::create(vmconfig.console.file.as_ref().unwrap())
                .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.console_main_fd = Some(file.into_raw_fd());
        }
        ConsoleOutputMode::Pty => {
            let (main_fd, sub_fd, path) =
                create_pty().map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.console_main_fd = Some(main_fd.into_raw_fd());
            set_raw_mode(&sub_fd.as_raw_fd(), vmm.original_termios_opt.clone())?;
            vmconfig.console.file = Some(path.clone());
            vmm.console_resize_pipe = Some(
                listen_for_sigwinch_on_tty(
                    sub_fd,
                    &vmm.seccomp_action,
                    vmm.hypervisor.hypervisor_type(),
                )
                .map_err(ConsoleDeviceError::StartSigwinchListener)?,
            );
        }
        ConsoleOutputMode::Tty => {
            // Duplicating the file descriptors like this is needed as otherwise
            // they will be closed on a reboot and the numbers reused

            // SAFETY: FFI call to dup. Trivially safe.
            let stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
            if stdout == -1 {
                return vmm_sys_util::errno::errno_result().map_err(ConsoleDeviceError::DupFd);
            }
            // SAFETY: stdout is valid and owned solely by us.
            let stdout = unsafe { File::from_raw_fd(stdout) };

            // SAFETY: FFI call. Trivially safe.
            if unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1 {
                vmm.console_resize_pipe = Some(
                    listen_for_sigwinch_on_tty(
                        stdout.try_clone().unwrap(),
                        &vmm.seccomp_action,
                        vmm.hypervisor.hypervisor_type(),
                    )
                    .map_err(ConsoleDeviceError::StartSigwinchListener)?,
                );
            }

            // Make sure stdout is in raw mode, if it's a terminal.
            set_raw_mode(&stdout, vmm.original_termios_opt.clone())?;
            console_info.console_main_fd = Some(stdout.into_raw_fd());
        }
        ConsoleOutputMode::Null | ConsoleOutputMode::Socket | ConsoleOutputMode::Off => {}
    }

    match vmconfig.serial.mode {
        ConsoleOutputMode::File => {
            let file = File::create(vmconfig.serial.file.as_ref().unwrap())
                .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.serial_main_fd = Some(file.into_raw_fd());
        }
        ConsoleOutputMode::Pty => {
            let (main_fd, sub_fd, path) =
                create_pty().map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.serial_main_fd = Some(main_fd.into_raw_fd());
            set_raw_mode(&sub_fd.as_raw_fd(), vmm.original_termios_opt.clone())?;
            vmconfig.serial.file = Some(path.clone());
        }
        ConsoleOutputMode::Tty => {
            let out = stdout();
            console_info.serial_main_fd = Some(out.as_raw_fd());
            set_raw_mode(&out, vmm.original_termios_opt.clone())?;
        }
        ConsoleOutputMode::Socket => {
            let listener = UnixListener::bind(vmconfig.serial.socket.as_ref().unwrap())
                .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.serial_main_fd = Some(listener.into_raw_fd());
        }
        ConsoleOutputMode::Null | ConsoleOutputMode::Off => {}
    }

    #[cfg(target_arch = "x86_64")]
    match vmconfig.debug_console.mode {
        ConsoleOutputMode::File => {
            let file = File::create(vmconfig.debug_console.file.as_ref().unwrap())
                .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.debug_main_fd = Some(file.into_raw_fd());
        }
        ConsoleOutputMode::Pty => {
            let (main_fd, sub_fd, path) =
                create_pty().map_err(ConsoleDeviceError::CreateConsoleDevice)?;
            console_info.debug_main_fd = Some(main_fd.into_raw_fd());
            set_raw_mode(&sub_fd.as_raw_fd(), vmm.original_termios_opt.clone())?;
            vmconfig.debug_console.file = Some(path.clone());
        }
        ConsoleOutputMode::Tty => {
            let out = stdout();
            console_info.debug_main_fd = Some(out.as_raw_fd());
            set_raw_mode(&out, vmm.original_termios_opt.clone())?;
        }
        ConsoleOutputMode::Null | ConsoleOutputMode::Socket | ConsoleOutputMode::Off => {}
    }

    Ok(console_info)
}
