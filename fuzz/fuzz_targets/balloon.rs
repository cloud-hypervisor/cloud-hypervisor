// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryAtomic};
use vm_migration::{Pausable, Snapshottable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const QUEUE_DATA_SIZE: usize = 4;
const CONTROL_SIZE: usize = 30;
const MEM_SIZE: usize = 512 * 1024;
const BALLOON_SIZE: u64 = 512 * 1024;
// Number of queues
const QUEUE_NUM: usize = 3;
// Max entries in the queue.
const QUEUE_SIZE: u16 = 64;
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
const VIRTIO_BALLOON_MAX_PFN_BYTES: u32 = 256 * 4;
const VIRTIO_BALLOON_F_STATS: u64 = 1;
const VIRTIO_BALLOON_F_REPORTING: u64 = 5;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const QUEUE_REGION_GAP: u64 = 1024 * 1024;
const QUEUE_REGION_BASE: u64 =
    (MEM_SIZE as u64 + QUEUE_REGION_GAP).div_ceil(DESC_TABLE_ALIGN_SIZE) * DESC_TABLE_ALIGN_SIZE;
const REPORTING_TAIL_SIZE: usize = 8 * 1024;
const QUEUE_REGION_SIZE: usize = 64 * 1024;

const INFLATE_DATA_ADDR: u64 = 0x1_000;
const DEFLATE_DATA_ADDR: u64 = 0x2_000;
const REPORTING_DATA_ADDR: u64 = MEM_SIZE as u64 - 0x400;
const INVALID_DATA_ADDR: u64 = QUEUE_REGION_BASE + QUEUE_REGION_SIZE as u64 + 0x1_000;
const FUZZ_HOST_4K_PAGE_SIZE: u64 = 4 * 1024;
const FUZZ_HOST_64K_PAGE_SIZE: u64 = 64 * 1024;

struct FuzzPageSizeGuard;

impl FuzzPageSizeGuard {
    fn new(page_size: u64) -> Self {
        vm_allocator::page_size::set_fuzz_page_size(Some(page_size));
        Self
    }
}

impl Drop for FuzzPageSizeGuard {
    fn drop(&mut self) {
        vm_allocator::page_size::set_fuzz_page_size(None);
    }
}

#[derive(Clone, Copy)]
struct QueueLayout {
    desc_table_addr: u64,
    avail_ring_addr: u64,
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < CONTROL_SIZE || bytes.len() > (CONTROL_SIZE + MEM_SIZE) {
        return Corpus::Reject;
    }

    let page_size = if bytes[23] & 0x2 == 0 {
        FUZZ_HOST_4K_PAGE_SIZE
    } else {
        FUZZ_HOST_64K_PAGE_SIZE
    };
    let _page_size_guard = FuzzPageSizeGuard::new(page_size);

    let mut balloon = virtio_devices::Balloon::new(
        "fuzzer_balloon".to_owned(),
        BALLOON_SIZE,
        true,
        true,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    )
    .unwrap();
    balloon.set_access_platform(Arc::new(IdentityAccessPlatform {}));
    let _ = balloon.access_platform();
    balloon.pause().ok();
    balloon.resume().ok();
    balloon.ack_features(1u64 << VIRTIO_BALLOON_F_REPORTING);
    exercise_balloon_api(&mut balloon, bytes);
    if let Ok(snapshot) = balloon.snapshot() {
        if let Ok(state) = snapshot.to_state::<virtio_devices::balloon::BalloonState>() {
            let _ = virtio_devices::Balloon::new(
                "fuzzer_balloon_restore".to_owned(),
                BALLOON_SIZE,
                true,
                true,
                false,
                SeccompAction::Allow,
                EventFd::new(EFD_NONBLOCK).unwrap(),
                Some(state),
            );
        }
    }

    let queue_data = &bytes[..QUEUE_DATA_SIZE * QUEUE_NUM];
    let mem_bytes = &bytes[CONTROL_SIZE..];

    // Setup the guest memory with the input bytes and dedicated queue region.
    let shared_memory = bytes[23] & 0x1 == 0;
    let mem = match create_guest_memory(shared_memory) {
        Some(mem) => mem,
        None => return Corpus::Reject,
    };
    if mem.write_slice(mem_bytes, GuestAddress(0)).is_err() {
        return Corpus::Reject;
    }

    // Setup the virt queues with the input bytes
    let (mut queues, queue_layouts) = setup_virt_queues(
        &[
            &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
            &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                .try_into()
                .unwrap(),
            &queue_data[QUEUE_DATA_SIZE * 2..QUEUE_DATA_SIZE * 3]
                .try_into()
                .unwrap(),
        ],
        QUEUE_REGION_BASE,
    );
    if !populate_queue_memory(&mem, &queue_layouts, bytes) {
        return Corpus::Reject;
    }
    let guest_memory = GuestMemoryAtomic::new(mem);

    let inflate_q = queues.remove(0);
    let inflate_evt = EventFd::new(0).unwrap();
    let inflate_kick_evt = inflate_evt.try_clone().unwrap();
    let deflate_q = queues.remove(0);
    let deflate_evt = EventFd::new(0).unwrap();
    let deflate_kick_evt = deflate_evt.try_clone().unwrap();
    let reporting_q = queues.remove(0);
    let reporting_evt = EventFd::new(0).unwrap();
    let reporting_kick_evt = reporting_evt.try_clone().unwrap();

    // Kick the 'queue' events before activating the device: under cfg(fuzzing)
    // the epoll loop returns as soon as no event is pending.
    inflate_kick_evt.write(1).ok();
    deflate_kick_evt.write(1).ok();
    reporting_kick_evt.write(1).ok();

    balloon
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            queues: vec![
                (0, inflate_q, inflate_evt),
                (1, deflate_q, deflate_evt),
                (2, reporting_q, reporting_evt),
            ],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();
    balloon.resize(BALLOON_SIZE / 4).ok();

    // Wait for the events to finish and balloon device worker thread to return
    balloon.wait_for_epoll_threads();
    balloon.snapshot().ok();
    balloon.id();
    balloon.reset();

    // Activate with two empty queues to exercise non-reporting paths.
    if let Some(guest_memory) = create_guest_memory(true).map(GuestMemoryAtomic::new) {
        let mut balloon_no_reporting = virtio_devices::Balloon::new(
            "fuzzer_balloon_no_reporting".to_owned(),
            BALLOON_SIZE,
            false,
            false,
            true,
            SeccompAction::Allow,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            None,
        )
        .unwrap();
        balloon_no_reporting.set_access_platform(Arc::new(IdentityAccessPlatform {}));

        let (mut no_reporting_queues, _) = setup_virt_queues(
            &[
                &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
                &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                    .try_into()
                    .unwrap(),
            ],
            QUEUE_REGION_BASE,
        );

        let inflate_q = no_reporting_queues.remove(0);
        let inflate_evt = EventFd::new(0).unwrap();
        let inflate_kick_evt = inflate_evt.try_clone().unwrap();
        let deflate_q = no_reporting_queues.remove(0);
        let deflate_evt = EventFd::new(0).unwrap();
        let deflate_kick_evt = deflate_evt.try_clone().unwrap();

        inflate_kick_evt.write(1).ok();
        deflate_kick_evt.write(1).ok();

        balloon_no_reporting
            .activate(virtio_devices::ActivationContext {
                mem: guest_memory,
                interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
                queues: vec![(0, inflate_q, inflate_evt), (1, deflate_q, deflate_evt)],
                device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            })
            .ok();
        balloon_no_reporting.wait_for_epoll_threads();
        balloon_no_reporting.reset();
    }

    // Activate with an empty reporting queue to exercise its empty path.
    if let Some(guest_memory) = create_guest_memory(true).map(GuestMemoryAtomic::new) {
        let mut balloon_reporting_empty = virtio_devices::Balloon::new(
            "fuzzer_balloon_reporting_empty".to_owned(),
            BALLOON_SIZE,
            true,
            true,
            false,
            SeccompAction::Allow,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            None,
        )
        .unwrap();
        balloon_reporting_empty.ack_features(1u64 << VIRTIO_BALLOON_F_REPORTING);

        let (mut reporting_empty_queues, _) = setup_virt_queues(
            &[
                &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
                &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                    .try_into()
                    .unwrap(),
                &queue_data[QUEUE_DATA_SIZE * 2..QUEUE_DATA_SIZE * 3]
                    .try_into()
                    .unwrap(),
            ],
            QUEUE_REGION_BASE,
        );

        let inflate_q = reporting_empty_queues.remove(0);
        let inflate_evt = EventFd::new(0).unwrap();
        let inflate_kick_evt = inflate_evt.try_clone().unwrap();
        let deflate_q = reporting_empty_queues.remove(0);
        let deflate_evt = EventFd::new(0).unwrap();
        let deflate_kick_evt = deflate_evt.try_clone().unwrap();
        let reporting_q = reporting_empty_queues.remove(0);
        let reporting_evt = EventFd::new(0).unwrap();
        let reporting_kick_evt = reporting_evt.try_clone().unwrap();

        inflate_kick_evt.write(1).ok();
        deflate_kick_evt.write(1).ok();
        reporting_kick_evt.write(1).ok();

        balloon_reporting_empty
            .activate(virtio_devices::ActivationContext {
                mem: guest_memory,
                interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
                queues: vec![
                    (0, inflate_q, inflate_evt),
                    (1, deflate_q, deflate_evt),
                    (2, reporting_q, reporting_evt),
                ],
                device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            })
            .ok();
        balloon_reporting_empty.wait_for_epoll_threads();
        balloon_reporting_empty.reset();
    }

    match bytes[0] % 3 {
        0 => run_failing_interrupt_case(bytes, queue_data, true, false, false),
        1 => run_failing_interrupt_case(bytes, queue_data, false, true, false),
        _ => run_failing_interrupt_case(bytes, queue_data, false, false, true),
    }

    exercise_activation_edges(bytes, queue_data);
    exercise_stats_queue(bytes, queue_data);

    Corpus::Keep
});

pub struct NoopVirtioInterrupt {}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }

    fn set_notifier(
        &self,
        _interrupt: u32,
        _eventfd: Option<EventFd>,
        _vm: &dyn hypervisor::Vm,
    ) -> std::io::Result<()> {
        unimplemented!()
    }
}

pub struct FailingVirtioInterrupt {}

impl VirtioInterrupt for FailingVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        Err(std::io::Error::other("failing interrupt"))
    }

    fn set_notifier(
        &self,
        _interrupt: u32,
        _eventfd: Option<EventFd>,
        _vm: &dyn hypervisor::Vm,
    ) -> std::io::Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
struct IdentityAccessPlatform {}

impl AccessPlatform for IdentityAccessPlatform {
    fn translate_gva(&self, base: u64, _size: u64) -> std::io::Result<u64> {
        Ok(base)
    }

    fn translate_gpa(&self, base: u64, _size: u64) -> std::io::Result<u64> {
        Ok(base)
    }
}

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

fn setup_virt_queues(
    bytes: &[&[u8; QUEUE_DATA_SIZE]],
    base_addr: u64,
) -> (Vec<Queue>, Vec<QueueLayout>) {
    let mut queues = Vec::new();
    let mut queue_layouts = Vec::new();
    let mut base_addr = base_addr;
    for (i, b) in bytes.iter().enumerate() {
        let mut q = Queue::new(QUEUE_SIZE).unwrap();

        let desc_table_addr = align!(base_addr, DESC_TABLE_ALIGN_SIZE);
        let avail_ring_addr = align!(desc_table_addr + DESC_TABLE_SIZE, AVAIL_RING_ALIGN_SIZE);
        let used_ring_addr = align!(avail_ring_addr + AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE);
        q.try_set_desc_table_address(GuestAddress(desc_table_addr))
            .unwrap();
        q.try_set_avail_ring_address(GuestAddress(avail_ring_addr))
            .unwrap();
        q.try_set_used_ring_address(GuestAddress(used_ring_addr))
            .unwrap();

        let max_size = if i + 1 == QUEUE_NUM {
            QUEUE_SIZE / 2
        } else {
            QUEUE_SIZE
        };
        let min_size = if i == 0 { 8 } else { 4 };
        q.set_size(min_size + u16::from(b[3]) % (max_size - min_size + 1));
        q.set_next_avail(u16::from(b[0] & 0x1));
        q.set_next_used(u16::from(b[1]) % q.size());
        q.set_event_idx(b[2] % 2 != 0);

        q.set_ready(true);
        queues.push(q);
        queue_layouts.push(QueueLayout {
            desc_table_addr,
            avail_ring_addr,
        });

        base_addr = used_ring_addr + USED_RING_SIZE;
    }

    (queues, queue_layouts)
}

fn exercise_balloon_api(balloon: &mut virtio_devices::Balloon, bytes: &[u8]) {
    let _ = balloon.device_type();
    let _ = balloon.queue_max_sizes();
    let _ = balloon.features();
    let _ = balloon.get_actual();

    let mut config = [0u8; 8];
    balloon.read_config(0, &mut config);
    balloon.read_config(2, &mut config[..4]);
    balloon.write_config(0, &bytes[12..16]);
    balloon.write_config(4, &bytes[16..18]);
    balloon.write_config(4, &bytes[18..22]);

    let resized = BALLOON_SIZE.saturating_sub((u64::from(bytes[22] & 0x3f)) << 12);
    balloon.resize(resized).ok();
}

fn exercise_stats_queue(bytes: &[u8], queue_data: &[u8]) {
    let Some(mem) = create_guest_memory(true) else {
        return;
    };
    let (mut queues, layouts) = setup_virt_queues(
        &[
            &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
            &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                .try_into()
                .unwrap(),
            &queue_data[QUEUE_DATA_SIZE * 2..QUEUE_DATA_SIZE * 3]
                .try_into()
                .unwrap(),
        ],
        QUEUE_REGION_BASE,
    );
    let stats = layouts[2];
    let stats_addr = INFLATE_DATA_ADDR;
    let stats_data = [4_u64.to_le_bytes(), u64::from(bytes[0]).to_le_bytes()].concat();
    if mem
        .write_slice(&stats_data, GuestAddress(stats_addr))
        .is_err()
        || !write_descriptor(&mem, stats.desc_table_addr, 0, stats_addr, 16, 0, 0)
        || !write_avail_ring(&mem, stats.avail_ring_addr, &[0])
    {
        return;
    }

    let mut balloon = match virtio_devices::Balloon::new(
        "fuzzer_balloon_stats".to_owned(),
        BALLOON_SIZE,
        true,
        false,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    ) {
        Ok(balloon) => balloon,
        Err(_) => return,
    };
    balloon.ack_features(1_u64 << VIRTIO_BALLOON_F_STATS);
    let inflate_q = queues.remove(0);
    let inflate_evt = EventFd::new(0).unwrap();
    let inflate_kick_evt = inflate_evt.try_clone().unwrap();
    let deflate_q = queues.remove(0);
    let deflate_evt = EventFd::new(0).unwrap();
    let deflate_kick_evt = deflate_evt.try_clone().unwrap();
    let stats_q = queues.remove(0);
    let stats_evt = EventFd::new(0).unwrap();
    let stats_kick_evt = stats_evt.try_clone().unwrap();
    inflate_kick_evt.write(1).ok();
    deflate_kick_evt.write(1).ok();
    stats_kick_evt.write(1).ok();
    balloon
        .activate(virtio_devices::ActivationContext {
            mem: GuestMemoryAtomic::new(mem),
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            queues: vec![
                (0, inflate_q, inflate_evt),
                (1, deflate_q, deflate_evt),
                (2, stats_q, stats_evt),
            ],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();
    balloon.wait_for_epoll_threads();
    let _ = balloon.stats();
    balloon.reset();
}

fn bounded_pfn(v: u8) -> u32 {
    u32::from(v) & ((MEM_SIZE as u32 >> 12) - 1)
}

fn create_guest_memory(shared: bool) -> Option<GuestMemoryMmap> {
    let mem_region = vmm::memory_manager::MemoryManager::create_ram_region(
        &None,
        0,
        GuestAddress(0),
        MEM_SIZE,
        false,
        false,
        shared,
        None,
        None,
        None,
        false,
    )
    .ok()?;
    let reporting_tail_region = vmm::memory_manager::MemoryManager::create_ram_region(
        &None,
        0,
        GuestAddress(MEM_SIZE as u64),
        REPORTING_TAIL_SIZE,
        false,
        false,
        shared,
        None,
        None,
        None,
        false,
    )
    .ok()?;
    let queue_region = vmm::memory_manager::MemoryManager::create_ram_region(
        &None,
        0,
        GuestAddress(QUEUE_REGION_BASE),
        QUEUE_REGION_SIZE,
        false,
        false,
        true,
        None,
        None,
        None,
        false,
    )
    .ok()?;

    GuestMemoryMmap::from_arc_regions(vec![mem_region, reporting_tail_region, queue_region]).ok()
}

fn run_failing_interrupt_case(
    bytes: &[u8],
    queue_data: &[u8],
    kick_inflate: bool,
    kick_deflate: bool,
    kick_reporting: bool,
) {
    let Some(mem) = create_guest_memory(bytes[23] & 0x1 == 0) else {
        return;
    };

    if mem
        .write_slice(&bytes[CONTROL_SIZE..], GuestAddress(0))
        .is_err()
    {
        return;
    }

    let (mut queues, queue_layouts) = setup_virt_queues(
        &[
            &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
            &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                .try_into()
                .unwrap(),
            &queue_data[QUEUE_DATA_SIZE * 2..QUEUE_DATA_SIZE * 3]
                .try_into()
                .unwrap(),
        ],
        QUEUE_REGION_BASE,
    );
    if !populate_queue_memory(&mem, &queue_layouts, bytes) {
        return;
    }

    let guest_memory = GuestMemoryAtomic::new(mem);
    let inflate_q = queues.remove(0);
    let inflate_evt = EventFd::new(0).unwrap();
    let inflate_kick_evt = inflate_evt.try_clone().unwrap();
    let deflate_q = queues.remove(0);
    let deflate_evt = EventFd::new(0).unwrap();
    let deflate_kick_evt = deflate_evt.try_clone().unwrap();
    let reporting_q = queues.remove(0);
    let reporting_evt = EventFd::new(0).unwrap();
    let reporting_kick_evt = reporting_evt.try_clone().unwrap();

    let mut balloon = virtio_devices::Balloon::new(
        "fuzzer_balloon_fail_signal".to_owned(),
        BALLOON_SIZE,
        true,
        true,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    )
    .unwrap();
    balloon.ack_features(1u64 << VIRTIO_BALLOON_F_REPORTING);

    if kick_inflate {
        inflate_kick_evt.write(1).ok();
    }
    if kick_deflate {
        deflate_kick_evt.write(1).ok();
    }
    if kick_reporting {
        reporting_kick_evt.write(1).ok();
    }

    balloon
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(FailingVirtioInterrupt {}),
            queues: vec![
                (0, inflate_q, inflate_evt),
                (1, deflate_q, deflate_evt),
                (2, reporting_q, reporting_evt),
            ],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();
    let resized = BALLOON_SIZE.saturating_sub((u64::from(bytes[22] & 0x3f)) << 12);
    balloon.resize(resized).ok();
    balloon.wait_for_epoll_threads();
}

fn exercise_activation_edges(bytes: &[u8], queue_data: &[u8]) {
    match bytes[1] & 0x3 {
        0 => activate_with_too_few_queues(queue_data),
        1 => activate_reporting_acked_without_reporting_queue(queue_data),
        2 => activate_reporting_available_unacked(queue_data),
        _ => {}
    }
}

fn activate_with_too_few_queues(queue_data: &[u8]) {
    let Some(guest_memory) = create_guest_memory(true).map(GuestMemoryAtomic::new) else {
        return;
    };
    let (mut queues, _) = setup_virt_queues(
        &[&queue_data[..QUEUE_DATA_SIZE].try_into().unwrap()],
        QUEUE_REGION_BASE,
    );
    let inflate_q = queues.remove(0);
    let inflate_evt = EventFd::new(0).unwrap();

    let mut balloon = virtio_devices::Balloon::new(
        "fuzzer_balloon_bad_activate".to_owned(),
        BALLOON_SIZE,
        true,
        false,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    )
    .unwrap();

    balloon
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            queues: vec![(0, inflate_q, inflate_evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();
    balloon.reset();
}

fn activate_reporting_acked_without_reporting_queue(queue_data: &[u8]) {
    let Some(guest_memory) = create_guest_memory(true).map(GuestMemoryAtomic::new) else {
        return;
    };
    let (mut queues, _) = setup_virt_queues(
        &[
            &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
            &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                .try_into()
                .unwrap(),
        ],
        QUEUE_REGION_BASE,
    );
    let inflate_q = queues.remove(0);
    let inflate_evt = EventFd::new(0).unwrap();
    let inflate_kick_evt = inflate_evt.try_clone().unwrap();
    let deflate_q = queues.remove(0);
    let deflate_evt = EventFd::new(0).unwrap();
    let deflate_kick_evt = deflate_evt.try_clone().unwrap();

    inflate_kick_evt.write(1).ok();
    deflate_kick_evt.write(1).ok();

    let mut balloon = virtio_devices::Balloon::new(
        "fuzzer_balloon_acked_no_reporting_queue".to_owned(),
        BALLOON_SIZE,
        true,
        true,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    )
    .unwrap();
    balloon.ack_features(1u64 << VIRTIO_BALLOON_F_REPORTING);

    balloon
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            queues: vec![(0, inflate_q, inflate_evt), (1, deflate_q, deflate_evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();
    balloon.wait_for_epoll_threads();
    balloon.reset();
}

fn activate_reporting_available_unacked(queue_data: &[u8]) {
    let Some(guest_memory) = create_guest_memory(true).map(GuestMemoryAtomic::new) else {
        return;
    };
    let (mut queues, _) = setup_virt_queues(
        &[
            &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
            &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                .try_into()
                .unwrap(),
            &queue_data[QUEUE_DATA_SIZE * 2..QUEUE_DATA_SIZE * 3]
                .try_into()
                .unwrap(),
        ],
        QUEUE_REGION_BASE,
    );
    let inflate_q = queues.remove(0);
    let inflate_evt = EventFd::new(0).unwrap();
    let inflate_kick_evt = inflate_evt.try_clone().unwrap();
    let deflate_q = queues.remove(0);
    let deflate_evt = EventFd::new(0).unwrap();
    let deflate_kick_evt = deflate_evt.try_clone().unwrap();
    let reporting_q = queues.remove(0);
    let reporting_evt = EventFd::new(0).unwrap();
    let reporting_kick_evt = reporting_evt.try_clone().unwrap();

    inflate_kick_evt.write(1).ok();
    deflate_kick_evt.write(1).ok();
    reporting_kick_evt.write(1).ok();

    let mut balloon = virtio_devices::Balloon::new(
        "fuzzer_balloon_unacked_reporting".to_owned(),
        BALLOON_SIZE,
        true,
        true,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    )
    .unwrap();

    balloon
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            queues: vec![
                (0, inflate_q, inflate_evt),
                (1, deflate_q, deflate_evt),
                (2, reporting_q, reporting_evt),
            ],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();
    balloon.wait_for_epoll_threads();
    balloon.reset();
}

fn populate_queue_memory(
    mem: &GuestMemoryMmap,
    queue_layouts: &[QueueLayout],
    bytes: &[u8],
) -> bool {
    if queue_layouts.len() != QUEUE_NUM {
        return false;
    }

    let pbp_base_pfn = u32::from(bytes[24] & 0x70);
    for pfn_offset in 0..16 {
        if !write_obj(
            mem,
            pbp_base_pfn + pfn_offset,
            INFLATE_DATA_ADDR + 0x40 + u64::from(pfn_offset) * 4,
        ) {
            return false;
        }
    }

    if !write_obj(mem, bounded_pfn(bytes[24]), INFLATE_DATA_ADDR + 0x10)
        || !write_obj(mem, bounded_pfn(bytes[25]), INFLATE_DATA_ADDR + 0x14)
        || !write_obj(
            mem,
            u32::MAX - u32::from(bytes[26]),
            INFLATE_DATA_ADDR + 0x30,
        )
        || !write_obj(mem, bounded_pfn(bytes[27]), DEFLATE_DATA_ADDR)
        || !write_obj(mem, bounded_pfn(bytes[28]), DEFLATE_DATA_ADDR + 0x4)
        || !write_obj(
            mem,
            u32::MAX - u32::from(bytes[29]),
            DEFLATE_DATA_ADDR + 0x20,
        )
    {
        return false;
    }

    let inflate = queue_layouts[0];
    if !write_descriptor(
        mem,
        inflate.desc_table_addr,
        0,
        INFLATE_DATA_ADDR,
        4,
        VIRTQ_DESC_F_WRITE,
        0,
    ) || !write_descriptor(
        mem,
        inflate.desc_table_addr,
        1,
        INFLATE_DATA_ADDR + 0x4,
        3,
        0,
        0,
    ) || !write_descriptor(
        mem,
        inflate.desc_table_addr,
        2,
        INFLATE_DATA_ADDR + 0x8,
        VIRTIO_BALLOON_MAX_PFN_BYTES + 4,
        0,
        0,
    ) || !write_descriptor(
        mem,
        inflate.desc_table_addr,
        3,
        INFLATE_DATA_ADDR + 0x10,
        8,
        0,
        0,
    ) || !write_descriptor(
        mem,
        inflate.desc_table_addr,
        4,
        INFLATE_DATA_ADDR + 0x30,
        4,
        0,
        0,
    ) || !write_descriptor(mem, inflate.desc_table_addr, 5, INVALID_DATA_ADDR, 4, 0, 0)
        || !write_descriptor(
            mem,
            inflate.desc_table_addr,
            6,
            INFLATE_DATA_ADDR + 0x40,
            64,
            0,
            0,
        )
        || !write_avail_ring(mem, inflate.avail_ring_addr, &[0, 1, 2, 3, 4, 5, 6])
    {
        return false;
    }

    let deflate = queue_layouts[1];
    if !write_descriptor(mem, deflate.desc_table_addr, 0, DEFLATE_DATA_ADDR, 8, 0, 0)
        || !write_descriptor(
            mem,
            deflate.desc_table_addr,
            1,
            DEFLATE_DATA_ADDR + 0x10,
            4,
            VIRTQ_DESC_F_WRITE,
            0,
        )
        || !write_descriptor(
            mem,
            deflate.desc_table_addr,
            2,
            DEFLATE_DATA_ADDR + 0x20,
            4,
            0,
            0,
        )
        || !write_avail_ring(mem, deflate.avail_ring_addr, &[0, 1, 2])
    {
        return false;
    }

    let reporting = queue_layouts[2];
    write_descriptor(
        mem,
        reporting.desc_table_addr,
        0,
        REPORTING_DATA_ADDR,
        0x2_000,
        0,
        0,
    ) && write_descriptor(
        mem,
        reporting.desc_table_addr,
        1,
        REPORTING_DATA_ADDR + 0x40,
        0,
        0,
        0,
    ) && write_descriptor(
        mem,
        reporting.desc_table_addr,
        2,
        INVALID_DATA_ADDR,
        0,
        0,
        0,
    ) && write_descriptor(
        mem,
        reporting.desc_table_addr,
        3,
        INVALID_DATA_ADDR,
        64,
        0,
        0,
    ) && write_avail_ring(mem, reporting.avail_ring_addr, &[0, 1, 2, 3])
}

fn write_avail_ring(mem: &GuestMemoryMmap, avail_ring_addr: u64, heads: &[u16]) -> bool {
    if !write_obj(mem, 0u16, avail_ring_addr)
        || !write_obj(mem, heads.len() as u16, avail_ring_addr + 2)
    {
        return false;
    }

    heads.iter().enumerate().all(|(i, head)| {
        write_obj(
            mem,
            *head,
            avail_ring_addr + 4 + (i * std::mem::size_of::<u16>()) as u64,
        )
    })
}

fn write_descriptor(
    mem: &GuestMemoryMmap,
    desc_table_addr: u64,
    index: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> bool {
    let offset = desc_table_addr + u64::from(index) * 16;
    write_obj(mem, addr, offset)
        && write_obj(mem, len, offset + 8)
        && write_obj(mem, flags, offset + 12)
        && write_obj(mem, next, offset + 14)
}

fn write_obj<T: ByteValued>(mem: &GuestMemoryMmap, value: T, addr: u64) -> bool {
    mem.write_obj(value, GuestAddress(addr)).is_ok()
}
