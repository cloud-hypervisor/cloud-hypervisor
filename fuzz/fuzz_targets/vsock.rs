// Copyright © 2025 Microsoft
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::vsock::tests::TestBackend;
use virtio_devices::{VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
use vmm_sys_util::tempdir::TempDir;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

const QUEUE_DATA_SIZE: usize = 4;
const MEM_SIZE: usize = 1 * 1024 * 1024;

// Max entries in the queue.
const QUEUE_SIZE: u16 = 256;
// Descriptor table alignment
const DESC_TABLE_ALIGN_SIZE: u64 = 16;
// Available ring alignment
const AVAIL_RING_ALIGN_SIZE: u64 = 2;
// Used ring alignment
const USED_RING_ALIGN_SIZE: u64 = 4;
// Descriptor table size
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
// Available ring size
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
// Used ring size
const USED_RING_SIZE: u64 = 6_u64 + 8 * QUEUE_SIZE as u64;

// Guest memory gap
const GUEST_MEM_GAP: u64 = 1 * 1024 * 1024;
// Guest physical address for descriptor table.
const DESC_TABLE_ADDR: u64 = align!(MEM_SIZE as u64 + GUEST_MEM_GAP, DESC_TABLE_ALIGN_SIZE);
// Guest physical address for available ring
const AVAIL_RING_ADDR: u64 = align!(DESC_TABLE_ADDR + DESC_TABLE_SIZE, AVAIL_RING_ALIGN_SIZE);
// Guest physical address for used ring
const USED_RING_ADDR: u64 = align!(AVAIL_RING_ADDR + AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE);
// Virtio-queue size in bytes
const QUEUE_BYTES_SIZE: usize = (USED_RING_ADDR + USED_RING_SIZE - DESC_TABLE_ADDR) as usize;

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < (QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE)
        || bytes.len() > (QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE + MEM_SIZE)
    {
        return Corpus::Reject;
    }

    let queue_data = &bytes[..QUEUE_DATA_SIZE];
    let queue_bytes = &bytes[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE];
    let mem_bytes = &bytes[QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE..];

    let q = setup_virt_queue(queue_data.try_into().unwrap());

    let tmp_dir = TempDir::new_with_prefix("/tmp/fuzz_virtio_vsock").unwrap();
    let vsock_path = tmp_dir.as_path().join("vsock.sock");

    let backend = TestBackend::new();

    // Setup the guest memory with the input bytes
    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(DESC_TABLE_ADDR), QUEUE_BYTES_SIZE),
    ])
    .unwrap();
    if mem
        .write_slice(queue_bytes, GuestAddress(DESC_TABLE_ADDR))
        .is_err()
    {
        return Corpus::Reject;
    }
    if mem.write_slice(mem_bytes, GuestAddress(0 as u64)).is_err() {
        return Corpus::Reject;
    }
    let guest_memory = GuestMemoryAtomic::new(mem);

    let evt = EventFd::new(0).unwrap();
    let queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };

    // Kick the 'queue' event before activate the rng device
    queue_evt.write(1).unwrap();

    let mut vsock = virtio_devices::Vsock::new(
        "fuzzer_vsock".to_owned(),
        0,
        vsock_path,
        backend,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    )
    .unwrap();

    vsock
        .activate(
            guest_memory,
            Arc::new(NoopVirtioInterrupt {}),
            vec![(0, q, evt)],
        )
        .ok();

    // Wait for the events to finish and vsock device worker thread to return
    vsock.wait_for_epoll_threads();

    Corpus::Keep
});

pub struct NoopVirtioInterrupt {}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

fn setup_virt_queue(bytes: &[u8; QUEUE_DATA_SIZE]) -> Queue {
    let mut q = Queue::new(QUEUE_SIZE).unwrap();
    q.set_next_avail(bytes[0] as u16); // 'u8' is enough given the 'QUEUE_SIZE' is small
    q.set_next_used(bytes[1] as u16);
    q.set_event_idx(bytes[2] % 2 != 0);
    q.set_size(bytes[3] as u16 % QUEUE_SIZE);

    q.try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .unwrap();
    q.try_set_used_ring_address(GuestAddress(USED_RING_ADDR))
        .unwrap();
    q.set_ready(true);

    q
}
