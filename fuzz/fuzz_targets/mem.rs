// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use seccompiler::SeccompAction;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};
use virtio_devices::{BlocksState, Mem, VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::{bitmap::AtomicBitmap, Bytes, GuestAddress, GuestMemoryAtomic};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const VIRTIO_MEM_DATA_SIZE: usize = 6;
const QUEUE_DATA_SIZE: usize = 4;
const MEM_SIZE: usize = 256 * 1024 * 1024;
const MEM_ZONE_SIZE: usize = 128 * 1024 * 1024;
// Max entries in the queue.
const QUEUE_SIZE: u16 = 64;
// Guest physical address for descriptor table.
const DESC_TABLE_ADDR: u64 = 0;
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
// Guest physical address for available ring
const AVAIL_RING_ADDR: u64 = DESC_TABLE_ADDR + DESC_TABLE_SIZE;
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
// Guest physical address for used ring (requires to 4-bytes aligned)
const USED_RING_ADDR: u64 = (AVAIL_RING_ADDR + AVAIL_RING_SIZE + 3) & !3_u64;
// The same as what's defined from virtio-devices/mem.rs
const VIRTIO_MEM_DEFAULT_BLOCK_SIZE: u64 = 2 << 20;

fuzz_target!(|bytes| {
    if bytes.len() < VIRTIO_MEM_DATA_SIZE + QUEUE_DATA_SIZE
        || bytes.len() > (VIRTIO_MEM_DATA_SIZE + QUEUE_DATA_SIZE + MEM_SIZE)
    {
        return;
    }

    let virtio_mem_data = &bytes[..VIRTIO_MEM_DATA_SIZE];
    let queue_data = &bytes[VIRTIO_MEM_DATA_SIZE..VIRTIO_MEM_DATA_SIZE + QUEUE_DATA_SIZE];
    let mem_bytes = &bytes[VIRTIO_MEM_DATA_SIZE + QUEUE_DATA_SIZE..];

    // Create a virtio-mem device based on the input bytes;
    let mut virtio_mem = create_dummy_virtio_mem(virtio_mem_data.try_into().unwrap());

    // Setup the virt queue with the input bytes
    let q = setup_virt_queue(queue_data.try_into().unwrap());

    // Setup the guest memory with the input bytes
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    if mem.write_slice(mem_bytes, GuestAddress(0 as u64)).is_err() {
        return;
    }
    let guest_memory = GuestMemoryAtomic::new(mem);

    let evt = EventFd::new(0).unwrap();
    let queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };

    // Kick the 'queue' event before activate the virtio-mem device
    queue_evt.write(1).unwrap();

    virtio_mem
        .activate(
            guest_memory,
            Arc::new(NoopVirtioInterrupt {}),
            vec![(0, q, evt)],
        )
        .ok();

    // Wait for the events to finish and virtio-mem device worker thread to return
    virtio_mem.wait_for_epoll_threads();
});

pub struct NoopVirtioInterrupt {}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

// Create a dummy virtio-mem device for fuzzing purpose only
fn create_dummy_virtio_mem(bytes: &[u8; VIRTIO_MEM_DATA_SIZE]) -> Mem {
    let start_addr =
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()) % (MEM_SIZE - MEM_ZONE_SIZE) as u32;
    let aligned_start_addr =
        start_addr as u64 / VIRTIO_MEM_DEFAULT_BLOCK_SIZE * VIRTIO_MEM_DEFAULT_BLOCK_SIZE;
    let hugepages = bytes[4] % 2 != 0;
    let numa_id = if bytes[5] % 2 != 0 { Some(0) } else { None };

    let region = vmm::memory_manager::MemoryManager::create_ram_region(
        &None,
        0,
        GuestAddress(aligned_start_addr),
        MEM_ZONE_SIZE,
        false,
        false,
        hugepages,
        None,
        numa_id,
        None,
    )
    .unwrap();

    let blocks_state = Arc::new(Mutex::new(BlocksState::new(MEM_ZONE_SIZE as u64)));

    Mem::new(
        "fuzzer_mem".to_owned(),
        &region,
        SeccompAction::Allow,
        numa_id.map(|i| i as u16),
        0,
        hugepages,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        blocks_state.clone(),
    )
    .unwrap()
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
