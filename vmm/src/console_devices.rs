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

use std::fs::{read_link, File, OpenOptions};
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::{io, result};

use libc::{cfmakeraw, isatty, tcgetattr, tcsetattr, termios, TCSANOW};
use thiserror::Error;

use crate::sigwinch_listener::listen_for_sigwinch_on_tty;
use crate::vm_config::ConsoleOutputMode;
use crate::Vmm;

const TIOCSPTLCK: libc::c_int = 0x4004_5431;
const TIOCGPTPEER: libc::c_int = 0x5441;

/// Errors associated with console devices
#[derive(Debug, Error)]
pub enum ConsoleDeviceError {
    /// Error creating console device
    #[error("Error creating console device: {0}")]
    CreateConsoleDevice(#[source] io::Error),

    /// No socket option support for console device
    #[error("No socket option support for console device")]
    NoSocketOptionSupportForConsoleDevice,

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

#[derive(Clone)]
pub enum ConsoleOutput {
    File(Arc<File>),
    Pty(Arc<File>),
    Tty(Arc<File>),
    Null,
    Socket(Arc<UnixListener>),
    Off,
}

#[derive(Clone)]
pub struct ConsoleInfo {
    pub console_main_fd: ConsoleOutput,
    pub serial_main_fd: ConsoleOutput,
    #[cfg(target_arch = "x86_64")]
    pub debug_main_fd: ConsoleOutput,
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

fn set_raw_mode(
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

fn create_pty() -> io::Result<(File, File, PathBuf)> {
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
            TIOCGPTPEER as _,
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

fn dup_stdout() -> vmm_sys_util::errno::Result<File> {
    // SAFETY: FFI call to dup. Trivially safe.
    let stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
    if stdout == -1 {
        return vmm_sys_util::errno::errno_result();
    }
    // SAFETY: stdout is valid and owned solely by us.
    Ok(unsafe { File::from_raw_fd(stdout) })
}

pub(crate) fn pre_create_console_devices(vmm: &mut Vmm) -> ConsoleDeviceResult<ConsoleInfo> {
    let vm_config = vmm.vm_config.as_mut().unwrap().clone();
    let mut vmconfig = vm_config.lock().unwrap();

    let console_info = ConsoleInfo {
        console_main_fd: match vmconfig.console.mode {
            ConsoleOutputMode::File => {
                let file = File::create(vmconfig.console.file.as_ref().unwrap())
                    .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                ConsoleOutput::File(Arc::new(file))
            }
            ConsoleOutputMode::Pty => {
                let (main_fd, sub_fd, path) =
                    create_pty().map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                set_raw_mode(&sub_fd.as_raw_fd(), vmm.original_termios_opt.clone())?;
                vmconfig.console.file = Some(path.clone());
                vmm.console_resize_pipe = Some(Arc::new(
                    listen_for_sigwinch_on_tty(
                        sub_fd,
                        &vmm.seccomp_action,
                        vmm.hypervisor.hypervisor_type(),
                    )
                    .map_err(ConsoleDeviceError::StartSigwinchListener)?,
                ));
                ConsoleOutput::Pty(Arc::new(main_fd))
            }
            ConsoleOutputMode::Tty => {
                // Duplicating the file descriptors like this is needed as otherwise
                // they will be closed on a reboot and the numbers reused

                let stdout = dup_stdout().map_err(ConsoleDeviceError::DupFd)?;

                // SAFETY: FFI call. Trivially safe.
                if unsafe { libc::isatty(stdout.as_raw_fd()) } == 1 {
                    vmm.console_resize_pipe = Some(Arc::new(
                        listen_for_sigwinch_on_tty(
                            stdout.try_clone().unwrap(),
                            &vmm.seccomp_action,
                            vmm.hypervisor.hypervisor_type(),
                        )
                        .map_err(ConsoleDeviceError::StartSigwinchListener)?,
                    ));
                }

                // Make sure stdout is in raw mode, if it's a terminal.
                set_raw_mode(&stdout, vmm.original_termios_opt.clone())?;
                ConsoleOutput::Tty(Arc::new(stdout))
            }
            ConsoleOutputMode::Socket => {
                return Err(ConsoleDeviceError::NoSocketOptionSupportForConsoleDevice)
            }
            ConsoleOutputMode::Null => ConsoleOutput::Null,
            ConsoleOutputMode::Off => ConsoleOutput::Off,
        },
        serial_main_fd: match vmconfig.serial.mode {
            ConsoleOutputMode::File => {
                let file = File::create(vmconfig.serial.file.as_ref().unwrap())
                    .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                ConsoleOutput::File(Arc::new(file))
            }
            ConsoleOutputMode::Pty => {
                let (main_fd, sub_fd, path) =
                    create_pty().map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                set_raw_mode(&sub_fd.as_raw_fd(), vmm.original_termios_opt.clone())?;
                vmconfig.serial.file = Some(path.clone());
                ConsoleOutput::Pty(Arc::new(main_fd))
            }
            ConsoleOutputMode::Tty => {
                // During vm_shutdown, when serial device is closed, FD#2(STDOUT)
                // will be closed and FD#2 could be reused in a future boot of the
                // guest by a different file.
                //
                // To ensure FD#2 always points to STANDARD OUT, a `dup` of STDOUT
                // is passed to serial device. Doing so, even if the serial device
                // were to be closed, FD#2 will continue to point to STANDARD OUT.

                let stdout = dup_stdout().map_err(ConsoleDeviceError::DupFd)?;

                // Make sure stdout is in raw mode, if it's a terminal.
                set_raw_mode(&stdout, vmm.original_termios_opt.clone())?;

                ConsoleOutput::Tty(Arc::new(stdout))
            }
            ConsoleOutputMode::Socket => {
                let listener = UnixListener::bind(vmconfig.serial.socket.as_ref().unwrap())
                    .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                ConsoleOutput::Socket(Arc::new(listener))
            }
            ConsoleOutputMode::Null => ConsoleOutput::Null,
            ConsoleOutputMode::Off => ConsoleOutput::Off,
        },
        #[cfg(target_arch = "x86_64")]
        debug_main_fd: match vmconfig.debug_console.mode {
            ConsoleOutputMode::File => {
                let file = File::create(vmconfig.debug_console.file.as_ref().unwrap())
                    .map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                ConsoleOutput::File(Arc::new(file))
            }
            ConsoleOutputMode::Pty => {
                let (main_fd, sub_fd, path) =
                    create_pty().map_err(ConsoleDeviceError::CreateConsoleDevice)?;
                set_raw_mode(&sub_fd.as_raw_fd(), vmm.original_termios_opt.clone())?;
                vmconfig.debug_console.file = Some(path.clone());
                ConsoleOutput::Pty(Arc::new(main_fd))
            }
            ConsoleOutputMode::Tty => {
                let out =
                    dup_stdout().map_err(|e| ConsoleDeviceError::CreateConsoleDevice(e.into()))?;
                set_raw_mode(&out, vmm.original_termios_opt.clone())?;
                ConsoleOutput::Tty(Arc::new(out))
            }
            ConsoleOutputMode::Socket => {
                return Err(ConsoleDeviceError::NoSocketOptionSupportForConsoleDevice)
            }
            ConsoleOutputMode::Null => ConsoleOutput::Null,
            ConsoleOutputMode::Off => ConsoleOutput::Off,
        },
    };

    Ok(console_info)
}
