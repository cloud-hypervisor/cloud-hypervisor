// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]
use std::ffi;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use block::async_io::GuestMemoryTarget;
use block::disk_file::AsyncDiskFile;
use block::formats::vhdx::VhdxDisk;
use libfuzzer_sys::{fuzz_target, Corpus};
use vm_memory::{GuestAddress, GuestMemoryMmap};

// Populate the corpus directory with a test file:
// truncate -s 16M /tmp/source
// qemu-img convert -O vhdx /tmp/source fuzz/corpus/vhdx/test.vhdx
// Run with:
// cargo fuzz run vhdx -j 32 -- -max_len=16777216
fuzz_target!(|bytes: &[u8]| -> Corpus {
    let shm = memfd_create(&ffi::CString::new("fuzz").unwrap(), 0).unwrap();
    let mut disk_file: File = unsafe { File::from_raw_fd(shm) };
    disk_file.write_all(bytes).unwrap();

    let Ok(disk) = VhdxDisk::new(disk_file, false) else {
        return Corpus::Reject;
    };
    let Ok(mut async_io) = disk.create_async_io(1) else {
        return Corpus::Keep;
    };

    let len = 8192usize;
    let Ok(mem) = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), len)]) else {
        return Corpus::Keep;
    };
    let mem = Arc::new(mem);
    let range = [(GuestAddress(0), len as u32)];

    let mut offset: libc::off_t = 0;
    while (offset as usize) < bytes.len() {
        if let Ok(target) = GuestMemoryTarget::new(Arc::clone(&mem), &range) {
            let _ = async_io.read_to_memory(offset, target, 0);
            while async_io.next_completed_request().is_some() {}
        }
        offset += len as libc::off_t;
    }

    offset = 0;
    while (offset as usize) < bytes.len() {
        if let Ok(target) = GuestMemoryTarget::new(Arc::clone(&mem), &range) {
            let _ = async_io.write_from_memory(offset, target, 1);
            while async_io.next_completed_request().is_some() {}
        }
        offset += len as libc::off_t;
    }

    let _ = async_io.fsync(Some(2));
    while async_io.next_completed_request().is_some() {}

    Corpus::Keep
});

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}
