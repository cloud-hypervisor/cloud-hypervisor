// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use block_util::{async_io::DiskFile, raw_sync::RawFileDiskSync};
use libfuzzer_sys::fuzz_target;
use seccompiler::SeccompAction;
use std::ffi;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use virtio_devices::{Block, VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};
use vm_virtio::Queue;
use vmm_sys_util::eventfd::EventFd;

const MEM_SIZE: u64 = 256 * 1024 * 1024;
const DESC_SIZE: u64 = 16; // Bytes in one virtio descriptor.
const QUEUE_SIZE: u16 = 16; // Max entries in the queue.
const CMD_SIZE: usize = 16; // Bytes in the command.

fuzz_target!(|bytes| {
    let size_u64 = size_of::<u64>();
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap();

    // The fuzz data is interpreted as:
    // starting index 8 bytes
    // command location 8 bytes
    // command 16 bytes
    // descriptors circular buffer 16 bytes * 3
    if bytes.len() < 4 * size_u64 {
        // Need an index to start.
        return;
    }

    let mut data_image = Cursor::new(bytes);

    let first_index = read_u64(&mut data_image);
    if first_index > MEM_SIZE / DESC_SIZE {
        return;
    }
    let first_offset = first_index * DESC_SIZE;
    if first_offset as usize + size_u64 > bytes.len() {
        return;
    }

    let command_addr = read_u64(&mut data_image);
    if command_addr > MEM_SIZE - CMD_SIZE as u64 {
        return;
    }
    if mem
        .write_slice(
            &bytes[2 * size_u64..(2 * size_u64) + CMD_SIZE],
            GuestAddress(command_addr as u64),
        )
        .is_err()
    {
        return;
    }

    data_image.seek(SeekFrom::Start(first_offset)).unwrap();
    let desc_table = read_u64(&mut data_image);

    if mem
        .write_slice(&bytes[32..], GuestAddress(desc_table as u64))
        .is_err()
    {
        return;
    }

    let mut q = Queue::new(QUEUE_SIZE);
    q.ready = true;
    q.size = QUEUE_SIZE / 2;
    q.max_size = QUEUE_SIZE;

    let queue_evts: Vec<EventFd> = vec![EventFd::new(0).unwrap()];
    let queue_fd = queue_evts[0].as_raw_fd();
    let queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(queue_fd)) };

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
    )
    .unwrap();

    block
        .activate(
            GuestMemoryAtomic::new(mem),
            Arc::new(NoopVirtioInterrupt {}),
            vec![q],
            queue_evts,
        )
        .ok();

    queue_evt.write(77).unwrap(); // Rings the doorbell, any byte will do.
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

pub struct NoopVirtioInterrupt {}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(
        &self,
        _int_type: &VirtioInterruptType,
        _queue: Option<&Queue>,
    ) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}
