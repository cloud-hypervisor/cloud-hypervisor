// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![no_main]

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::{ffi, io};

use libfuzzer_sys::fuzz_target;
use linux_loader::loader::KernelLoader;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::GuestAddress;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEM_SIZE: usize = 256 * 1024 * 1024;
// From 'arch::x86_64::layout::HIGH_RAM_START'
const HIGH_RAM_START: GuestAddress = GuestAddress(0x100000);

fuzz_target!(|bytes| {
    let shm = memfd_create(&ffi::CString::new("fuzz_load_kernel").unwrap(), 0).unwrap();
    let mut kernel_file: File = unsafe { File::from_raw_fd(shm) };
    kernel_file.write_all(&bytes).unwrap();
    kernel_file.seek(SeekFrom::Start(0)).unwrap();

    let guest_memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    linux_loader::loader::elf::Elf::load(
        &guest_memory,
        None,
        &mut kernel_file,
        Some(HIGH_RAM_START),
    )
    .ok();
});

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}
