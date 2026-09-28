// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Mutex};

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::mem::{MemState, VirtioMemConfig};
use virtio_devices::{
    ActivationContext, BlocksState, Mem, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
    VirtioMemMappingSource,
};
use virtio_queue::{Queue, QueueT};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vm_migration::{Pausable, Snapshottable};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

const MEM_SIZE: usize = 128 * 1024 * 1024;
const BLOCK_SIZE: u64 = 2 * 1024 * 1024;
const REQUESTED_SIZE: u64 = 8 * BLOCK_SIZE;

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

// Guest memory gap
const GUEST_MEM_GAP: u64 = 1024 * 1024;
// Guest physical address for descriptor table.
const DESC_TABLE_ADDR: u64 = align!(MEM_SIZE as u64 + GUEST_MEM_GAP, DESC_TABLE_ALIGN_SIZE);
// Guest physical address for available ring
const AVAIL_RING_ADDR: u64 = align!(DESC_TABLE_ADDR + DESC_TABLE_SIZE, AVAIL_RING_ALIGN_SIZE);
// Guest physical address for used ring
const USED_RING_ADDR: u64 = align!(AVAIL_RING_ADDR + AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE);
// Virtio-queue size in bytes
const QUEUE_BYTES_SIZE: usize = (USED_RING_ADDR + USED_RING_SIZE - DESC_TABLE_ADDR) as usize;
const QUEUE_AUX_SIZE: usize = 0x20_000;
const QUEUE_REGION_SIZE: usize = QUEUE_BYTES_SIZE + QUEUE_AUX_SIZE;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const VIRTIO_MEM_REQ_PLUG: u16 = 0;
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
const VIRTIO_MEM_REQ_STATE: u16 = 3;

const REQ_SIZE: u32 = 24;
const RESP_SIZE: u32 = 10;
const CONFIG_SIZE: usize = size_of::<VirtioMemConfig>();

const AUX_REGION_START: u64 = DESC_TABLE_ADDR + QUEUE_BYTES_SIZE as u64;
const AUX_REGION_END: u64 = DESC_TABLE_ADDR + QUEUE_REGION_SIZE as u64;

const REQ_BASE_ADDR: u64 = AUX_REGION_START + 0x1_000;
const REQ_STRIDE: u64 = 0x80;
const RESP_BASE_ADDR: u64 = AUX_REGION_START + 0x8_000;
const RESP_STRIDE: u64 = 0x20;

#[derive(Debug)]
struct HarnessInterrupt {
    fail_trigger: bool,
}

impl VirtioInterrupt for HarnessInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> io::Result<()> {
        if self.fail_trigger {
            return Err(io::Error::other("fuzz interrupt failure"));
        }
        Ok(())
    }

    fn set_notifier(
        &self,
        _interrupt: u32,
        _eventfd: Option<EventFd>,
        _vm: &dyn hypervisor::Vm,
    ) -> io::Result<()> {
        Ok(())
    }
}

struct FuzzDmaMapping {
    fail_on_map: bool,
    fail_on_unmap: bool,
}

impl FuzzDmaMapping {
    fn new(fail_on_map: bool, fail_on_unmap: bool) -> Self {
        Self {
            fail_on_map,
            fail_on_unmap,
        }
    }
}

impl ExternalDmaMapping for FuzzDmaMapping {
    fn map(&self, _iova: u64, _gpa: u64, _size: u64) -> io::Result<()> {
        if self.fail_on_map {
            return Err(io::Error::other("fuzz map failure"));
        }
        Ok(())
    }

    fn unmap(&self, _iova: u64, _size: u64) -> io::Result<()> {
        if self.fail_on_unmap {
            return Err(io::Error::other("fuzz unmap failure"));
        }
        Ok(())
    }
}

struct ByteStream<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> ByteStream<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.bytes[self.cursor % self.bytes.len()];
        self.cursor = self.cursor.wrapping_add(1);
        value
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }
}

#[derive(Clone)]
struct ChainSpec {
    req_type: u16,
    addr: u64,
    nb_blocks: u16,
    req_len: u32,
    req_write_only: bool,
    include_status: bool,
    status_write_only: bool,
    status_len: u32,
    req_addr_override: Option<u64>,
    status_addr_override: Option<u64>,
}

impl ChainSpec {
    fn valid(req_type: u16, addr: u64, nb_blocks: u16) -> Self {
        Self {
            req_type,
            addr,
            nb_blocks,
            req_len: REQ_SIZE,
            req_write_only: false,
            include_status: true,
            status_write_only: true,
            status_len: RESP_SIZE,
            req_addr_override: None,
            status_addr_override: None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum ScenarioKind {
    Nominal,
    MapFailure,
    UnmapFailure,
    InterruptFailure,
    FileBacked,
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() || bytes.len() > (1 << 20) {
        return Corpus::Reject;
    }

    let mut stream = ByteStream::new(bytes);
    exercise_constructor_paths(&mut stream);

    let mut success = false;
    success |= run_device_scenario(&mut stream, ScenarioKind::Nominal).is_ok();
    success |= run_device_scenario(&mut stream, ScenarioKind::MapFailure).is_ok();
    success |= run_device_scenario(&mut stream, ScenarioKind::UnmapFailure).is_ok();
    success |= run_device_scenario(&mut stream, ScenarioKind::InterruptFailure).is_ok();
    success |= run_device_scenario(&mut stream, ScenarioKind::FileBacked).is_ok();

    if success {
        Corpus::Keep
    } else {
        Corpus::Reject
    }
});

fn exercise_constructor_paths(stream: &mut ByteStream) {
    if let Some(region) = create_region(MEM_SIZE / 2, None) {
        let blocks_state = Arc::new(Mutex::new(BlocksState::new(region.size() as u64)));
        let _ = Mem::new(
            "fuzzer_mem_ctor_bad_region".to_owned(),
            &region,
            SeccompAction::Allow,
            None,
            0,
            false,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            blocks_state,
            None,
        );
    }

    if let Some(region) =
        create_region_with_options(MEM_SIZE, GuestAddress(BLOCK_SIZE / 2), None, false)
    {
        let blocks_state = Arc::new(Mutex::new(BlocksState::new(region.size() as u64)));
        let _ = Mem::new(
            "fuzzer_mem_ctor_bad_addr".to_owned(),
            &region,
            SeccompAction::Allow,
            None,
            0,
            false,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            blocks_state,
            None,
        );
    }

    if let Some(region) = create_region(MEM_SIZE, Some(0)) {
        let blocks_state = Arc::new(Mutex::new(BlocksState::new(region.size() as u64)));

        let _ = Mem::new(
            "fuzzer_mem_ctor_bad_size".to_owned(),
            &region,
            SeccompAction::Allow,
            Some(0),
            BLOCK_SIZE / 2,
            false,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            blocks_state.clone(),
            None,
        );

        let _ = Mem::new(
            "fuzzer_mem_ctor_too_big".to_owned(),
            &region,
            SeccompAction::Allow,
            None,
            MEM_SIZE as u64 + BLOCK_SIZE,
            false,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            blocks_state,
            None,
        );
    }

    if let Some((mut virtio_mem, _region)) = create_mem_device(REQUESTED_SIZE, stream.next_bool()) {
        let _ = virtio_mem.device_type();
        let _ = virtio_mem.queue_max_sizes();
        let _ = virtio_mem.features();
        virtio_mem.ack_features(stream.next_u64());

        let mut config = [0u8; CONFIG_SIZE];
        virtio_mem.read_config(0, &mut config);
        virtio_mem.read_config(48, &mut config[..8]);

        let _ = virtio_mem.resize(REQUESTED_SIZE);
        let _ = virtio_mem.resize(BLOCK_SIZE / 2);
        let _ = virtio_mem.resize(MEM_SIZE as u64 + BLOCK_SIZE);
        let _ = virtio_mem.resize(BLOCK_SIZE * (1 + u64::from(stream.next_u8() % 8)));

        let _ = virtio_mem.add_dma_mapping_handler(
            VirtioMemMappingSource::Device(7),
            Arc::new(FuzzDmaMapping::new(false, false)),
        );
        let _ = virtio_mem.remove_dma_mapping_handler(&VirtioMemMappingSource::Device(7));
        let _ = virtio_mem.remove_dma_mapping_handler(&VirtioMemMappingSource::Device(8));

        let _ = Pausable::pause(&mut virtio_mem);
        let _ = Pausable::resume(&mut virtio_mem);
        let _ = Snapshottable::id(&virtio_mem);
        if let Ok(snapshot) = virtio_mem.snapshot() {
            if let (Ok(state), Some(region)) = (
                snapshot.to_state::<MemState>(),
                create_region(MEM_SIZE, None),
            ) {
                let blocks_state = Arc::new(Mutex::new(BlocksState::new(region.size() as u64)));
                let _ = Mem::new(
                    "fuzzer_mem_restore".to_owned(),
                    &region,
                    SeccompAction::Allow,
                    None,
                    0,
                    false,
                    EventFd::new(EFD_NONBLOCK).unwrap(),
                    blocks_state,
                    Some(state),
                );
            }
        }
        virtio_mem.reset();
    }

    let blocks = BlocksState::new(u64::from(65 + (stream.next_u8() % 4)) * BLOCK_SIZE);
    let _ = blocks.memory_ranges(0, true);
    let _ = blocks.memory_ranges(0, false);
}

fn run_device_scenario(stream: &mut ByteStream, kind: ScenarioKind) -> Result<(), ()> {
    let (mut virtio_mem, virtio_mem_region) = create_mem_device_with_options(
        REQUESTED_SIZE,
        stream.next_bool(),
        kind == ScenarioKind::FileBacked,
    )
    .ok_or(())?;

    virtio_mem.ack_features(stream.next_u64());
    let _ = virtio_mem.features();
    let _ = virtio_mem.device_type();
    let _ = virtio_mem.queue_max_sizes();

    let mut queue = setup_virt_queue(stream).ok_or(())?;

    let mut mem =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(DESC_TABLE_ADDR), QUEUE_REGION_SIZE)])
            .map_err(|_| ())?;
    mem = mem.insert_region(virtio_mem_region).map_err(|_| ())?;

    let chains = build_chains(kind, stream);
    if !populate_queue_memory(&mem, &mut queue, &chains) {
        return Err(());
    }

    let dma_handler = match kind {
        ScenarioKind::MapFailure => FuzzDmaMapping::new(true, false),
        ScenarioKind::UnmapFailure => FuzzDmaMapping::new(false, true),
        _ => FuzzDmaMapping::new(false, false),
    };
    let _ = virtio_mem
        .add_dma_mapping_handler(VirtioMemMappingSource::Container, Arc::new(dma_handler));

    let guest_memory = GuestMemoryAtomic::new(mem);

    let evt = EventFd::new(0).map_err(|_| ())?;
    let queue_evt = duplicate_eventfd(&evt).map_err(|_| ())?;
    if kind == ScenarioKind::Nominal {
        let _ = Pausable::pause(&mut virtio_mem);
        let _ = Pausable::resume(&mut virtio_mem);
        let _ = Snapshottable::id(&virtio_mem);
        let _ = virtio_mem.snapshot();
    }

    // Kick the 'queue' event before activating the device: under cfg(fuzzing)
    // the epoll loop returns as soon as no event is pending.
    let kicks = if kind == ScenarioKind::InterruptFailure {
        3
    } else {
        2
    };
    for _ in 0..kicks {
        let _ = queue_evt.write(1);
    }

    if virtio_mem
        .activate(ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(HarnessInterrupt {
                fail_trigger: kind == ScenarioKind::InterruptFailure,
            }),
            queues: vec![(0, queue, evt)],
            device_status: Arc::new(AtomicU8::new(0)),
        })
        .is_err()
    {
        return Err(());
    }

    virtio_mem.wait_for_epoll_threads();

    if kind == ScenarioKind::InterruptFailure {
        let size = BLOCK_SIZE * u64::from(1 + stream.next_u8() % 7);
        let _ = virtio_mem.resize(size);
    }
    if kind == ScenarioKind::UnmapFailure {
        let source_id = u32::from(stream.next_u8());
        let source = VirtioMemMappingSource::Device(source_id);
        let _ =
            virtio_mem.add_dma_mapping_handler(source, Arc::new(FuzzDmaMapping::new(false, false)));
        let _ = virtio_mem.add_dma_mapping_handler(
            VirtioMemMappingSource::Device(source_id + 1),
            Arc::new(FuzzDmaMapping::new(true, false)),
        );
        let _ = virtio_mem.remove_dma_mapping_handler(&VirtioMemMappingSource::Device(source_id));
    }

    let _ = virtio_mem.plugged_size();
    let _ = virtio_mem.remove_dma_mapping_handler(&VirtioMemMappingSource::Container);
    let _ = virtio_mem.remove_dma_mapping_handler(&VirtioMemMappingSource::Device(99));

    virtio_mem.reset();

    Ok(())
}

fn create_region(size: usize, numa_id: Option<u32>) -> Option<Arc<GuestRegionMmap>> {
    create_region_with_options(size, GuestAddress(0), numa_id, false)
}

fn create_region_with_options(
    size: usize,
    start_addr: GuestAddress,
    numa_id: Option<u32>,
    shared: bool,
) -> Option<Arc<GuestRegionMmap>> {
    vmm::memory_manager::MemoryManager::create_ram_region(
        &None, 0, start_addr, size, false, false, shared, None, numa_id, None, false,
    )
    .ok()
}

fn create_mem_device(initial_size: u64, with_numa: bool) -> Option<(Mem, Arc<GuestRegionMmap>)> {
    create_mem_device_with_options(initial_size, with_numa, false)
}

fn create_mem_device_with_options(
    initial_size: u64,
    with_numa: bool,
    shared: bool,
) -> Option<(Mem, Arc<GuestRegionMmap>)> {
    let numa_id = if with_numa { Some(0) } else { None };

    let region = create_region_with_options(MEM_SIZE, GuestAddress(0), numa_id, shared)?;
    let blocks_state = Arc::new(Mutex::new(BlocksState::new(region.size() as u64)));

    Mem::new(
        "fuzzer_mem".to_owned(),
        &region,
        SeccompAction::Allow,
        numa_id.map(|i| i as u16),
        initial_size,
        false,
        EventFd::new(EFD_NONBLOCK).ok()?,
        blocks_state,
        None,
    )
    .ok()
    .map(|mem| (mem, region))
}

fn setup_virt_queue(stream: &mut ByteStream) -> Option<Queue> {
    let mut queue = Queue::new(QUEUE_SIZE).ok()?;
    queue.set_size(QUEUE_SIZE);
    queue.set_next_avail(0);
    queue.set_next_used(stream.next_u8() as u16 % QUEUE_SIZE);
    queue.set_event_idx(stream.next_bool());

    queue
        .try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .ok()?;
    queue
        .try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .ok()?;
    queue
        .try_set_used_ring_address(GuestAddress(USED_RING_ADDR))
        .ok()?;
    queue.set_ready(true);

    Some(queue)
}

fn build_chains(kind: ScenarioKind, stream: &mut ByteStream) -> Vec<ChainSpec> {
    match kind {
        ScenarioKind::Nominal => {
            let mut chains = vec![
                ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 2),
                ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, BLOCK_SIZE, 4),
                ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 6 * BLOCK_SIZE, 4),
                ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, BLOCK_SIZE / 2, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG_ALL, 0, 0),
                ChainSpec::valid(9, 0, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_STATE, MEM_SIZE as u64 + BLOCK_SIZE, 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_STATE, u64::MAX - (BLOCK_SIZE / 2), 1),
                ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG_ALL, 0, 0),
            ];

            let mut short_chain = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            short_chain.include_status = false;
            chains.push(short_chain);

            let mut write_only_req = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            write_only_req.req_write_only = true;
            chains.push(write_only_req);

            let mut read_only_status = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            read_only_status.status_write_only = false;
            chains.push(read_only_status);

            let mut short_status = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            short_status.status_len = RESP_SIZE - 1;
            chains.push(short_status);

            let mut short_req = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            short_req.req_len = REQ_SIZE - 1;
            chains.push(short_req);

            let mut bad_req_addr = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            bad_req_addr.req_addr_override = Some(AUX_REGION_END - 4);
            chains.push(bad_req_addr);

            let mut bad_status_addr = ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1);
            bad_status_addr.status_addr_override = Some(AUX_REGION_END - 2);
            chains.push(bad_status_addr);

            let mut fuzzed_req = ChainSpec::valid(stream.next_u8() as u16, 0, 1);
            fuzzed_req.addr = u64::from(stream.next_u8() % 8) * BLOCK_SIZE;
            fuzzed_req.nb_blocks = 1 + u16::from(stream.next_u8() % 4);
            chains.push(fuzzed_req);

            chains
        }
        ScenarioKind::MapFailure => vec![
            ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 0, 1),
            ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1),
        ],
        ScenarioKind::UnmapFailure => vec![
            ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 0, 1),
            ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG, 0, 1),
            ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 0, 1),
            ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG_ALL, 0, 0),
        ],
        ScenarioKind::InterruptFailure => vec![ChainSpec::valid(VIRTIO_MEM_REQ_STATE, 0, 1)],
        ScenarioKind::FileBacked => vec![
            ChainSpec::valid(VIRTIO_MEM_REQ_PLUG, 0, 1),
            ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG, 0, 1),
            ChainSpec::valid(VIRTIO_MEM_REQ_UNPLUG_ALL, 0, 0),
        ],
    }
}

fn populate_queue_memory(mem: &GuestMemoryMmap, queue: &mut Queue, chains: &[ChainSpec]) -> bool {
    if chains.len() * 2 > QUEUE_SIZE as usize {
        return false;
    }

    let mut desc_index: u16 = 0;
    let mut req_slot: u16 = 0;
    let mut resp_slot: u16 = 0;
    let mut avail_heads = Vec::with_capacity(chains.len());

    for chain in chains {
        let head_index = desc_index;

        let req_addr = chain
            .req_addr_override
            .unwrap_or(REQ_BASE_ADDR + u64::from(req_slot) * REQ_STRIDE);
        if queue_region_contains(req_addr, REQ_SIZE) {
            let req = build_request_bytes(chain.req_type, chain.addr, chain.nb_blocks);
            if mem.write_slice(&req, GuestAddress(req_addr)).is_err() {
                return false;
            }
        }

        let mut req_flags = if chain.req_write_only {
            VRING_DESC_F_WRITE
        } else {
            0
        };
        let req_next = if chain.include_status {
            req_flags |= VRING_DESC_F_NEXT;
            head_index + 1
        } else {
            0
        };

        if !write_desc(
            mem,
            head_index,
            req_addr,
            chain.req_len,
            req_flags,
            req_next,
        ) {
            return false;
        }

        desc_index = desc_index.saturating_add(1);
        req_slot = req_slot.saturating_add(1);

        if chain.include_status {
            if desc_index >= QUEUE_SIZE {
                return false;
            }

            let status_addr = chain
                .status_addr_override
                .unwrap_or(RESP_BASE_ADDR + u64::from(resp_slot) * RESP_STRIDE);
            let status_flags = if chain.status_write_only {
                VRING_DESC_F_WRITE
            } else {
                0
            };

            if !write_desc(
                mem,
                desc_index,
                status_addr,
                chain.status_len,
                status_flags,
                0,
            ) {
                return false;
            }

            desc_index = desc_index.saturating_add(1);
            resp_slot = resp_slot.saturating_add(1);
        }

        avail_heads.push(head_index);
    }

    if !write_u16(mem, AVAIL_RING_ADDR, 0)
        || !write_u16(mem, AVAIL_RING_ADDR + 2, avail_heads.len() as u16)
    {
        return false;
    }

    for (slot, head) in avail_heads.iter().enumerate() {
        if !write_u16(mem, AVAIL_RING_ADDR + 4 + (slot as u64 * 2), *head) {
            return false;
        }
    }

    if !write_u16(mem, USED_RING_ADDR, 0) || !write_u16(mem, USED_RING_ADDR + 2, 0) {
        return false;
    }

    queue.set_next_avail(0);
    true
}

fn write_u16(mem: &GuestMemoryMmap, addr: u64, value: u16) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_desc(
    mem: &GuestMemoryMmap,
    index: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> bool {
    let desc_addr = DESC_TABLE_ADDR + u64::from(index) * 16;
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&addr.to_le_bytes());
    raw[8..12].copy_from_slice(&len.to_le_bytes());
    raw[12..14].copy_from_slice(&flags.to_le_bytes());
    raw[14..16].copy_from_slice(&next.to_le_bytes());
    mem.write_slice(&raw, GuestAddress(desc_addr)).is_ok()
}

fn build_request_bytes(req_type: u16, addr: u64, nb_blocks: u16) -> [u8; REQ_SIZE as usize] {
    let mut raw = [0u8; REQ_SIZE as usize];
    raw[..2].copy_from_slice(&req_type.to_le_bytes());
    raw[8..16].copy_from_slice(&addr.to_le_bytes());
    raw[16..18].copy_from_slice(&nb_blocks.to_le_bytes());
    raw
}

fn queue_region_contains(addr: u64, len: u32) -> bool {
    addr >= DESC_TABLE_ADDR
        && addr
            .checked_add(u64::from(len))
            .is_some_and(|end| end <= AUX_REGION_END)
}

fn duplicate_eventfd(evt: &EventFd) -> io::Result<EventFd> {
    let raw_fd = unsafe { libc::dup(evt.as_raw_fd()) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: raw_fd is freshly duplicated and owned by this function.
    unsafe { Ok(EventFd::from_raw_fd(raw_fd)) }
}
