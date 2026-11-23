// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for block unit tests.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use virtio_bindings::virtio_blk::{VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN};
use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
use virtio_queue::QueueT;
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_virtio::queue::testing::VirtQueue;
use vmm_sys_util::tempfile::TempFile;

use crate::aligned_buffer::AlignedBuffer;
use crate::async_io::{AsyncIo, AsyncIoCompletion};
use crate::{Request, SECTOR_SIZE};

#[path = "../../cloud-hypervisor/tests/common/mod.rs"]
pub mod shared;

fn wait_for_completion(io: &mut dyn AsyncIo) -> AsyncIoCompletion {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(completion) = io.next_completed_request() {
            return completion;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for block completion"
        );
        thread::yield_now();
    }
}

pub(crate) fn execute_virtio_blk_request(
    io: &mut dyn AsyncIo,
    mem: &Arc<GuestMemoryMmap<()>>,
    request_type: u32,
    offset: u64,
    (data_address, len): (GuestAddress, usize),
    disk_size: u64,
    user_data: u64,
) {
    assert!(offset.is_multiple_of(SECTOR_SIZE));
    mem.write_obj(request_type.to_le(), GuestAddress(0x8000))
        .unwrap();
    mem.write_obj((offset / SECTOR_SIZE).to_le(), GuestAddress(0x8008))
        .unwrap();
    let guest_queue = VirtQueue::new(GuestAddress(0x1000), mem.as_ref(), 4);
    guest_queue.dtable[0].set(
        0x8000,
        16,
        VRING_DESC_F_NEXT as u16,
        if request_type == VIRTIO_BLK_T_FLUSH {
            2
        } else {
            1
        },
    );
    let data_flags = if request_type == VIRTIO_BLK_T_IN {
        VRING_DESC_F_NEXT | VRING_DESC_F_WRITE
    } else {
        VRING_DESC_F_NEXT
    };
    guest_queue.dtable[1].set(
        data_address.0,
        len.try_into().unwrap(),
        data_flags as u16,
        2,
    );
    guest_queue.dtable[2].set(0x9000, 1, VRING_DESC_F_WRITE as u16, 0);
    guest_queue.avail.ring[0].set(0);
    guest_queue.avail.idx.set(1);

    let mem_atomic = GuestMemoryAtomic::new(mem.as_ref().clone());
    let mut queue = guest_queue.create_queue();
    let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
    let (request, status_addr) = Request::parse(&mut chain, None);
    assert_eq!(status_addr, Some(GuestAddress(0x9000)));
    let mut request = request.unwrap();
    let result = request
        .execute_async(Arc::clone(mem), disk_size / SECTOR_SIZE, io, &[], user_data)
        .unwrap();
    assert!(result.async_complete);
    if let Some(operation) = result.batch_request {
        io.submit_batch_requests(vec![operation]).unwrap();
    }
    let mut completion = wait_for_completion(io);
    assert_eq!(completion.user_data, user_data);
    assert_eq!(completion.result, len as i32);
    request
        .complete_async(mem.as_ref(), &mut completion)
        .unwrap();
}

pub(crate) fn read_disk_data(
    io: &mut dyn AsyncIo,
    mem: &Arc<GuestMemoryMmap<()>>,
    data_address: GuestAddress,
    len: usize,
) -> Vec<u8> {
    let mut data = vec![0x5a; len];
    mem.write_slice(&data, data_address).unwrap();
    execute_virtio_blk_request(
        io,
        mem,
        VIRTIO_BLK_T_IN,
        0,
        (data_address, len),
        len as u64,
        1,
    );
    mem.read_slice(&mut data, data_address).unwrap();
    data
}

/// Returns whether the filesystem supports O_DIRECT reads.
pub(crate) fn direct_io_supported() -> bool {
    let Ok(tmp) = TempFile::new() else {
        return false;
    };
    if tmp.as_file().set_len(1 << 20).is_err() {
        return false;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(tmp.as_path())
    else {
        return false;
    };
    let Ok(mut buf) = AlignedBuffer::new(0, 4096, 4096) else {
        return false;
    };
    buf.read_from(&file).is_ok()
}

/// Skips the current test when the filesystem does not support O_DIRECT.
macro_rules! require_direct_io {
    () => {
        if !$crate::test_util::direct_io_supported() {
            eprintln!("skipping: O_DIRECT not supported on this filesystem");
            return;
        }
    };
}

pub(crate) use require_direct_io;
