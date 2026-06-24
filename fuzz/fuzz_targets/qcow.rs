// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![no_main]
use std::ffi;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use block::async_io::GuestMemoryTarget;
use block::disk_file::AsyncDiskFile;
use block::formats::qcow::QcowDisk;
use libfuzzer_sys::{fuzz_target, Corpus};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

// Take the first 64 bits of data as an address and the next 64 bits as data to
// store there. The rest of the data is used as a qcow image.
fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < 16 {
        // Need an address and data, each are 8 bytes.
        return Corpus::Reject;
    }
    let mut disk_image = Cursor::new(bytes);
    let addr = read_u64(&mut disk_image);
    let value = read_u64(&mut disk_image);
    let shm = memfd_create(&ffi::CString::new("fuzz").unwrap(), 0).unwrap();
    let mut disk_file: File = unsafe { File::from_raw_fd(shm) };
    disk_file.write_all(&bytes[16..]).unwrap();
    disk_file.seek(SeekFrom::Start(0)).unwrap();

    let Ok(disk) = QcowDisk::new(disk_file, false, false, true, false) else {
        return Corpus::Keep;
    };
    let Ok(mut async_io) = disk.create_async_io(1) else {
        return Corpus::Keep;
    };

    let len = size_of::<u64>();
    let Ok(mem) = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), len)]) else {
        return Corpus::Keep;
    };
    let mem = Arc::new(mem);
    let _ = mem.write_slice(&value.to_le_bytes(), GuestAddress(0));
    let range = [(GuestAddress(0), len as u32)];
    let off = addr as libc::off_t;

    if let Ok(target) = GuestMemoryTarget::new(Arc::clone(&mem), &range) {
        let _ = async_io.write_from_memory(off, target, 0);
        while async_io.next_completed_request().is_some() {}
    }
    if let Ok(target) = GuestMemoryTarget::new(Arc::clone(&mem), &range) {
        let _ = async_io.read_to_memory(off, target, 1);
        while async_io.next_completed_request().is_some() {}
    }
    let _ = async_io.write_zeroes(addr, len as u64, 2);
    while async_io.next_completed_request().is_some() {}
    let _ = async_io.punch_hole(addr, len as u64, 3);
    while async_io.next_completed_request().is_some() {}
    let _ = async_io.fsync(Some(4));
    while async_io.next_completed_request().is_some() {}

    Corpus::Keep
});

fn read_u64<T: Read>(readable: &mut T) -> u64 {
    let mut buf = [0u8; size_of::<u64>()];
    readable.read_exact(&mut buf[..]).unwrap();
    u64::from_le_bytes(buf)
}

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}
