// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![no_main]

use block_util::{async_io::DiskFile, raw_sync::RawFileDiskSync};
use libfuzzer_sys::fuzz_target;
use seccompiler::SeccompAction;
use std::ffi;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use virtio_devices::{Block, VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::{bitmap::AtomicBitmap, Bytes, GuestAddress, GuestMemoryAtomic};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEM_SIZE: u64 = 256 * 1024 * 1024;
const QUEUE_SIZE: u16 = 16; // Max entries in the queue.

fuzz_target!(|bytes| {
    if bytes.len() as u64 > MEM_SIZE {
        return;
    }

    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap();
    if mem.write_slice(bytes, GuestAddress(0 as u64)).is_err() {
        return;
    }

    let guest_memory = GuestMemoryAtomic::new(mem);

    let mut q = Queue::new(QUEUE_SIZE).unwrap();
    q.set_ready(true);
    q.set_size(QUEUE_SIZE / 2);

    let evt = EventFd::new(0).unwrap();
    let queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };

    let shm = memfd_create(&ffi::CString::new("fuzz").unwrap(), 0).unwrap();
    let disk_file: File = unsafe { File::from_raw_fd(shm) };
    let qcow_disk = Box::new(RawFileDiskSync::new(disk_file)) as Box<dyn DiskFile>;

    let mut block = Block::new(
        "tmp".to_owned(),
        qcow_disk,
        PathBuf::from(""),
        false,
        false,
        2,
        256,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
    )
    .unwrap();

    // Kick the 'queue' event before activate the block device
    queue_evt.write(1).unwrap();

    block
        .activate(
            guest_memory,
            Arc::new(NoopVirtioInterrupt {}),
            vec![(0, q, evt)],
        )
        .ok();

    // Wait for the events to finish and block device worker thread to return
    block.reset();
});

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

pub struct NoopVirtioInterrupt {}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}
