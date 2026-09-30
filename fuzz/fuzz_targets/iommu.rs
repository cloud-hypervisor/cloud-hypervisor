// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io;
use std::mem::size_of;
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{
    AccessPlatformMapping, DmaRemapping, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
};
use virtio_queue::{Queue, QueueT};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vm_migration::{Pausable, Snapshottable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

const MEM_SIZE: usize = 32 * 1024 * 1024;
// Reuse what's being done from DeviceManager::get_msi_iova_space()
const IOVA_SPACE_SIZE: usize = (0xfeef_ffff - 0xfee0_0000) + 1;

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
const GUEST_MEM_GAP: u64 = 1024 * 1024;
// Guest physical address for descriptor table.
const DESC_TABLE_ADDR: u64 = align!(MEM_SIZE as u64 + GUEST_MEM_GAP, DESC_TABLE_ALIGN_SIZE);
// Guest physical address for available ring
const AVAIL_RING_ADDR: u64 = align!(DESC_TABLE_ADDR + DESC_TABLE_SIZE, AVAIL_RING_ALIGN_SIZE);
// Guest physical address for used ring
const USED_RING_ADDR: u64 = align!(AVAIL_RING_ADDR + AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE);
// Virtio-queue size in bytes
const QUEUE_BYTES_SIZE: usize = (USED_RING_ADDR + USED_RING_SIZE - DESC_TABLE_ADDR) as usize;

// Address width passed to Iommu::new. Using 63 bits (< 64) causes the device
// to populate input_range = Some((0, (1<<63)-1)), exercising the MAP/UNMAP
// range-check branches that are unreachable when address_width_bits == 64.
const IOMMU_ADDR_WIDTH_BITS: u8 = 63;
const INPUT_RANGE_MAX: u64 = (1u64 << IOMMU_ADDR_WIDTH_BITS) - 1;
const PAGE_SIZE: u64 = 4 * 1024;

const PAYLOAD_ADDR_START: u64 = 0x2000;
const STATUS_BUFFER_LEN: u32 = 64;
const STATUS_TAIL_LEN: u32 = 4;
const INVALID_DESC_ADDR: u64 = MEM_SIZE as u64 + 0x1000;
const INVALID_STATUS_ADDR: u64 = MEM_SIZE as u64 + 0x2000;
const VIRTIO_IOMMU_F_BYPASS_CONFIG_BIT: u64 = 1 << 6;
const IOMMU_BYPASS_CONFIG_OFFSET: u64 = 36;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
const VIRTIO_IOMMU_T_DETACH: u8 = 2;
const VIRTIO_IOMMU_T_MAP: u8 = 3;
const VIRTIO_IOMMU_T_UNMAP: u8 = 4;
const VIRTIO_IOMMU_T_PROBE: u8 = 5;

const VIRTIO_IOMMU_ATTACH_F_BYPASS: u32 = 1;
const VIRTIO_IOMMU_MAP_F_READ: u32 = 1;
const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 1 << 1;
const VIRTIO_IOMMU_MAP_F_MMIO: u32 = 1 << 2;
const VIRTIO_IOMMU_MAP_F_MASK: u32 =
    VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO;

#[derive(Clone)]
struct ChainSpec {
    request: Vec<u8>,
    request_len: u32,
    request_write_only: bool,
    include_status: bool,
    status_write_only: bool,
    status_len: u32,
    request_addr_override: Option<u64>,
    status_addr_override: Option<u64>,
}

impl ChainSpec {
    fn valid(request: Vec<u8>) -> Self {
        let request_len = request.len() as u32;
        Self {
            request,
            request_len,
            request_write_only: false,
            include_status: true,
            status_write_only: true,
            status_len: STATUS_BUFFER_LEN,
            request_addr_override: None,
            status_addr_override: None,
        }
    }

    fn without_status(request: Vec<u8>) -> Self {
        let mut chain = Self::valid(request);
        chain.include_status = false;
        chain
    }
}

#[derive(Copy, Clone)]
struct FuzzPlan {
    address_width_bits: u8,
    access_platform_enabled: bool,
    fail_queue_signal: bool,
    trans_domain: u32,
    trans_ep_a: u32,
    trans_ep_b: u32,
    trans_virt: u64,
    trans_phys: u64,
    gap_domain: u32,
    gap_ep: u32,
    gap_virt: u64,
    gap_phys: u64,
    bypass_domain: u32,
    bypass_ep: u32,
    move_domain_a: u32,
    move_domain_b: u32,
    move_ep: u32,
    mismatch_ep: u32,
    ext_domain: u32,
    ext_success_ep_a: u32,
    ext_success_ep_b: u32,
    rollback_domain: u32,
    rollback_success_ep: u32,
    ext_fail_map_ep: u32,
    unmap_fail_domain: u32,
    ext_fail_unmap_ep: u32,
    detach_ext_domain: u32,
    detach_ext_ep: u32,
    overflow_domain: u32,
    overflow_virt_start: u64,
}

impl FuzzPlan {
    fn new(bytes: &[u8]) -> Self {
        let mut stream = ByteStream::new(bytes);
        let address_width_bits = if (stream.next_u8() & 1) == 0 {
            IOMMU_ADDR_WIDTH_BITS
        } else {
            64
        };
        let access_platform_enabled = (stream.next_u8() & 1) != 0;
        let fail_queue_signal = (stream.next_u8() & 1) != 0;
        let trans_virt = pick_guest_window(stream.next_u64(), 12);
        let trans_phys = pick_guest_window(stream.next_u64(), 12);
        let gap_virt = pick_guest_window(stream.next_u64(), 12);
        let gap_phys = pick_guest_window(stream.next_u64(), 12);
        let overflow_pages = (stream.next_u8() as u64 % 4) + 1;

        Self {
            address_width_bits,
            access_platform_enabled,
            fail_queue_signal,
            trans_domain: 128 + (stream.next_u32() % 16),
            trans_ep_a: 144 + (stream.next_u32() % 16),
            trans_ep_b: 160 + (stream.next_u32() % 16),
            trans_virt,
            trans_phys,
            gap_domain: 176 + (stream.next_u32() % 16),
            gap_ep: 192 + (stream.next_u32() % 16),
            gap_virt,
            gap_phys,
            bypass_domain: 208 + (stream.next_u32() % 16),
            bypass_ep: 224 + (stream.next_u32() % 16),
            move_domain_a: 240 + (stream.next_u32() % 16),
            move_domain_b: 256 + (stream.next_u32() % 16),
            move_ep: 272 + (stream.next_u32() % 16),
            mismatch_ep: 288 + (stream.next_u32() % 16),
            ext_domain: 304 + (stream.next_u32() % 16),
            ext_success_ep_a: 320 + (stream.next_u32() % 8),
            ext_success_ep_b: 328 + (stream.next_u32() % 8),
            rollback_domain: 336 + (stream.next_u32() % 16),
            rollback_success_ep: 344 + (stream.next_u32() % 8),
            ext_fail_map_ep: 352 + (stream.next_u32() % 8),
            unmap_fail_domain: 368 + (stream.next_u32() % 16),
            ext_fail_unmap_ep: 384 + (stream.next_u32() % 8),
            detach_ext_domain: 400 + (stream.next_u32() % 16),
            detach_ext_ep: 416 + (stream.next_u32() % 8),
            overflow_domain: 432 + (stream.next_u32() % 16),
            overflow_virt_start: u64::MAX - (overflow_pages * PAGE_SIZE) + 1,
        }
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

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
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
}

#[derive(Copy, Clone)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

struct FuzzExternalMapping {
    fail_on_map: bool,
    fail_on_unmap: bool,
}

impl FuzzExternalMapping {
    fn new(fail_on_map: bool, fail_on_unmap: bool) -> Self {
        Self {
            fail_on_map,
            fail_on_unmap,
        }
    }
}

impl ExternalDmaMapping for FuzzExternalMapping {
    fn map(&self, _iova: u64, _gpa: u64, _size: u64) -> io::Result<()> {
        if self.fail_on_map {
            Err(io::Error::other("fuzz map failure"))
        } else {
            Ok(())
        }
    }

    fn unmap(&self, _iova: u64, _size: u64) -> io::Result<()> {
        if self.fail_on_unmap {
            Err(io::Error::other("fuzz unmap failure"))
        } else {
            Ok(())
        }
    }
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() || bytes.len() > MEM_SIZE {
        return Corpus::Reject;
    }

    let fuzz_plan = FuzzPlan::new(bytes);
    let (mut iommu, mapping) = virtio_devices::Iommu::new(
        "fuzzer_iommu".to_owned(),
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        ((MEM_SIZE - IOVA_SPACE_SIZE) as u64, (MEM_SIZE - 1) as u64),
        Vec::new(),
        fuzz_plan.address_width_bits,
        fuzz_plan.access_platform_enabled,
        None,
    )
    .unwrap();

    let _ = iommu.device_type();
    let _ = iommu.queue_max_sizes();
    let _ = iommu.features();
    iommu.ack_features(0);
    let mut config_bytes = [0u8; 40];
    iommu.read_config(0, &mut config_bytes);
    iommu.write_config(IOMMU_BYPASS_CONFIG_OFFSET + 1, &[1]);
    iommu.write_config(IOMMU_BYPASS_CONFIG_OFFSET, &[]);
    iommu.write_config(IOMMU_BYPASS_CONFIG_OFFSET, &[1]);
    iommu.ack_features(VIRTIO_IOMMU_F_BYPASS_CONFIG_BIT);
    iommu.write_config(IOMMU_BYPASS_CONFIG_OFFSET, &[0]);
    let _ = mapping.translate_gva(u32::MAX, 0x1000, 0x100);
    iommu.write_config(IOMMU_BYPASS_CONFIG_OFFSET, &[1]);
    let _ = mapping.translate_gva(u32::MAX, 0x1000, 0x100);
    let _ = mapping.translate_gpa(u32::MAX, 0x1000, 0x100);
    let _ = mapping.translate_gva(u32::MAX, 0x1000, 0);

    install_external_mappings(&mut iommu, &fuzz_plan);

    let request_queue = setup_virt_queue();
    // Given the "event queue" events are not handled from the current
    // implementation of virtio-iommu, we simply setup the 'event_queue'
    // with exactly the same shape as the 'request_queue'.
    let event_queue = setup_virt_queue();

    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(DESC_TABLE_ADDR), QUEUE_BYTES_SIZE),
    ])
    .unwrap();
    let mut chains = baseline_chains();
    append_fuzz_chains(&mut chains, bytes, &fuzz_plan);
    if write_request_queue(&mem, &chains).is_err() {
        return Corpus::Reject;
    }

    let guest_memory = GuestMemoryAtomic::new(mem);

    let request_evt = EventFd::new(0).unwrap();
    let event_evt = EventFd::new(0).unwrap();

    // Kick the 'queue' event before activate the vIOMMU device
    request_evt.write(1).unwrap();

    iommu
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(FuzzVirtioInterrupt {
                fail_queue_signal: fuzz_plan.fail_queue_signal,
            }),
            queues: vec![(0, request_queue, request_evt), (1, event_queue, event_evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();

    // Wait for the events to finish and vIOMMU device worker thread to return
    iommu.wait_for_epoll_threads();
    exercise_translation_paths(&mapping, &fuzz_plan);

    let access_mapping = AccessPlatformMapping::new(21, mapping.clone());
    let _ = access_mapping.translate_gva(0x28100, 0x80);
    let _ = access_mapping.translate_gpa(0x38100, 0x80);

    let _ = iommu.id();
    if let Ok(snapshot) = iommu.snapshot() {
        if let Ok(state) = snapshot.to_state() {
            let (mut restored, restored_mapping) = virtio_devices::Iommu::new(
                "fuzzer_iommu_restore".to_owned(),
                SeccompAction::Allow,
                EventFd::new(EFD_NONBLOCK).unwrap(),
                ((MEM_SIZE - IOVA_SPACE_SIZE) as u64, (MEM_SIZE - 1) as u64),
                Vec::new(),
                if fuzz_plan.address_width_bits == 64 {
                    IOMMU_ADDR_WIDTH_BITS
                } else {
                    64
                },
                !fuzz_plan.access_platform_enabled,
                Some(state),
            )
            .unwrap();
            let _ = restored.resume();
            let _ = restored.pause();
            let _ = restored.pause();
            let _ = restored.resume();
            let _ = restored_mapping.translate_gva(
                fuzz_plan.trans_ep_b,
                fuzz_plan.trans_virt + PAGE_SIZE - 0x80,
                0x100,
            );
            let _ = restored.snapshot();
        }
    }
    let removed = iommu.remove_external_mapping(41);
    if let Some(ext_map) = removed {
        iommu.add_external_mapping(41, ext_map);
    }
    let _ = iommu.remove_external_mapping(u32::MAX);
    iommu.reset();

    Corpus::Keep
});

pub struct FuzzVirtioInterrupt {
    fail_queue_signal: bool,
}

impl VirtioInterrupt for FuzzVirtioInterrupt {
    fn trigger(&self, int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        if self.fail_queue_signal && matches!(int_type, VirtioInterruptType::Queue(0)) {
            return Err(io::Error::other("fuzz interrupt failure"));
        }
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

fn setup_virt_queue() -> Queue {
    let mut q = Queue::new(QUEUE_SIZE).unwrap();
    q.set_next_avail(0);
    q.set_next_used(0);
    q.set_event_idx(false);
    q.set_size(QUEUE_SIZE);

    q.try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .unwrap();
    q.try_set_used_ring_address(GuestAddress(USED_RING_ADDR))
        .unwrap();
    q.set_ready(true);

    q
}

fn baseline_chains() -> Vec<ChainSpec> {
    let mut chains = vec![
        // Valid lifecycle: attach -> map -> unmap -> probe -> detach.
        ChainSpec::valid(build_attach_request(1, 1, 0, [0; 4])),
        ChainSpec::valid(build_map_request(
            1,
            0x2000,
            0x2fff,
            0x4000,
            VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
        )),
        ChainSpec::valid(build_unmap_request(1, 0x2000, 0x2fff, [0; 4])),
        ChainSpec::valid(build_probe_request(1)),
        ChainSpec::valid(build_detach_request(1, 1)),
        // Missing-domain, bypass-domain and attach validation paths.
        ChainSpec::valid(build_map_request(
            1,
            0x3000,
            0x3fff,
            0x5000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_attach_request(
            2,
            2,
            VIRTIO_IOMMU_ATTACH_F_BYPASS,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            2,
            0x6000,
            0x6fff,
            0x7000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_unmap_request(2, 0x6000, 0x6fff, [0; 4])),
        ChainSpec::valid(build_detach_request(2, 2)),
        ChainSpec::valid(build_attach_request(3, 3, 0, [1, 0, 0, 0])),
        ChainSpec::valid(build_attach_request(3, 3, 2, [0; 4])),
        ChainSpec::valid(build_attach_request(13, 13, 0, [0; 4])),
        ChainSpec::valid(build_attach_request(
            13,
            14,
            VIRTIO_IOMMU_ATTACH_F_BYPASS,
            [0; 4],
        )),
        ChainSpec::valid(build_detach_request(13, 13)),
        // Endpoint move path (old_domain_id != domain_id).
        ChainSpec::valid(build_attach_request(14, 20, 0, [0; 4])),
        ChainSpec::valid(build_attach_request(15, 20, 0, [0; 4])),
        ChainSpec::valid(build_detach_request(15, 20)),
        // Map/unmap validations including overlap and range checks.
        ChainSpec::valid(build_attach_request(4, 4, 0, [0; 4])),
        ChainSpec::valid(build_map_request(4, 0x8000, 0x8fff, 0x9000, 0x80)),
        ChainSpec::valid(build_map_request(
            4,
            0xa000,
            0x9fff,
            0xb000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_map_request(
            4,
            0xa001,
            0xafff,
            0xc000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_map_request(
            4,
            1u64 << IOMMU_ADDR_WIDTH_BITS,
            (1u64 << IOMMU_ADDR_WIDTH_BITS) + 0xfff,
            0xd000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_map_request(
            4,
            0xe000,
            0xefff,
            u64::MAX - 0x7ff,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_map_request(
            4,
            0x10000,
            0x10fff,
            0x11000,
            VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
        )),
        ChainSpec::valid(build_map_request(
            4,
            0x10000,
            0x10fff,
            0x12000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_map_request(
            4,
            0x12000,
            0x13fff,
            0x14000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_unmap_request(4, 0x12000, 0x12fff, [0; 4])),
        ChainSpec::valid(build_unmap_request(4, 0x12000, 0x13fff, [0; 4])),
        ChainSpec::valid(build_unmap_request(
            4,
            1u64 << IOMMU_ADDR_WIDTH_BITS,
            (1u64 << IOMMU_ADDR_WIDTH_BITS) + 0xfff,
            [0; 4],
        )),
        ChainSpec::valid(build_unmap_request(4, 0x3000, 0x2fff, [0; 4])),
        ChainSpec::valid(build_probe_request(4)),
        ChainSpec::valid(build_detach_request(4, 4)),
        // External mapping success and error paths.
        ChainSpec::valid(build_attach_request(30, 30, 0, [0; 4])),
        ChainSpec::valid(build_map_request(
            30,
            0x22000,
            0x22fff,
            0x23000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_detach_request(30, 30)),
        ChainSpec::valid(build_attach_request(31, 31, 0, [0; 4])),
        ChainSpec::valid(build_map_request(
            31,
            0x24000,
            0x24fff,
            0x25000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_unmap_request(31, 0x24000, 0x24fff, [0; 4])),
        ChainSpec::valid(build_detach_request(31, 31)),
        ChainSpec::valid(build_attach_request(40, 40, 0, [0; 4])),
        ChainSpec::valid(build_map_request(
            40,
            0x26000,
            0x26fff,
            0x27000,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_attach_request(40, 41, 0, [0; 4])),
        ChainSpec::valid(build_detach_request(40, 40)),
        // Keep one active domain/mapping for post-queue translation coverage.
        ChainSpec::valid(build_attach_request(21, 21, 0, [0; 4])),
        ChainSpec::valid(build_map_request(
            21,
            0x28000,
            0x28fff,
            0x38000,
            VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
        )),
        // Unknown request type path (must not write status).
        ChainSpec::without_status(vec![0x55, 0, 0, 0]),
    ];

    let mut no_status = ChainSpec::valid(build_attach_request(6, 6, 0, [0; 4]));
    no_status.include_status = false;
    chains.push(no_status);

    let mut request_write_only = ChainSpec::valid(build_attach_request(7, 7, 0, [0; 4]));
    request_write_only.request_write_only = true;
    chains.push(request_write_only);

    let mut status_read_only = ChainSpec::valid(build_attach_request(8, 8, 0, [0; 4]));
    status_read_only.status_write_only = false;
    chains.push(status_read_only);

    let mut probe_short_status = ChainSpec::valid(build_probe_request(8));
    probe_short_status.status_len = STATUS_TAIL_LEN;
    chains.push(probe_short_status);

    let mut short_head = ChainSpec::without_status(vec![VIRTIO_IOMMU_T_MAP, 0, 0]);
    short_head.request_len = 3;
    chains.push(short_head);

    let mut bad_request_addr = ChainSpec::without_status(build_attach_request(9, 9, 0, [0; 4]));
    bad_request_addr.request_addr_override = Some(INVALID_DESC_ADDR);
    chains.push(bad_request_addr);

    let mut bad_status_addr = ChainSpec::valid(build_attach_request(10, 10, 0, [0; 4]));
    bad_status_addr.status_addr_override = Some(INVALID_STATUS_ADDR);
    chains.push(bad_status_addr);

    let mut bad_attach_len = ChainSpec::valid(build_attach_request(11, 11, 0, [0; 4]));
    bad_attach_len.request_len = bad_attach_len.request_len.saturating_sub(1);
    chains.push(bad_attach_len);

    let mut bad_detach_len = ChainSpec::valid(build_detach_request(11, 11));
    bad_detach_len.request_len = bad_detach_len.request_len.saturating_sub(1);
    chains.push(bad_detach_len);

    let mut bad_map_len = ChainSpec::valid(build_map_request(
        11,
        0x20000,
        0x20fff,
        0x30000,
        VIRTIO_IOMMU_MAP_F_READ,
    ));
    bad_map_len.request_len = bad_map_len.request_len.saturating_sub(1);
    chains.push(bad_map_len);

    let mut bad_unmap_len = ChainSpec::valid(build_unmap_request(11, 0x20000, 0x20fff, [0; 4]));
    bad_unmap_len.request_len = bad_unmap_len.request_len.saturating_sub(1);
    chains.push(bad_unmap_len);

    let mut bad_probe_len = ChainSpec::valid(build_probe_request(11));
    bad_probe_len.request_len = bad_probe_len.request_len.saturating_sub(1);
    chains.push(bad_probe_len);

    chains
}

fn append_fuzz_chains(chains: &mut Vec<ChainSpec>, bytes: &[u8], plan: &FuzzPlan) {
    let mut stream = ByteStream::new(bytes);
    append_guided_chains(chains, plan);
    let extra_chains = 1 + (stream.next_u8() as usize % 24);
    for _ in 0..extra_chains {
        chains.push(next_fuzz_chain(&mut stream));
    }
}

fn append_guided_chains(chains: &mut Vec<ChainSpec>, plan: &FuzzPlan) {
    chains.extend([
        ChainSpec::valid(build_attach_request(
            plan.trans_domain,
            plan.trans_ep_a,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.trans_domain,
            plan.trans_ep_b,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.trans_domain,
            plan.trans_virt,
            plan.trans_virt + PAGE_SIZE - 1,
            plan.trans_phys,
            VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
        )),
        ChainSpec::valid(build_map_request(
            plan.trans_domain,
            plan.trans_virt + PAGE_SIZE,
            plan.trans_virt + 2 * PAGE_SIZE - 1,
            plan.trans_phys + PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
        )),
        ChainSpec::valid(build_map_request(
            plan.trans_domain,
            plan.trans_virt + 2 * PAGE_SIZE,
            plan.trans_virt + 3 * PAGE_SIZE - 1,
            plan.trans_phys + 4 * PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_detach_request(plan.trans_domain, plan.trans_ep_a)),
        ChainSpec::valid(build_probe_request(plan.trans_ep_b)),
        ChainSpec::valid(build_attach_request(
            plan.gap_domain,
            plan.gap_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.gap_domain,
            plan.gap_virt,
            plan.gap_virt + PAGE_SIZE - 1,
            plan.gap_phys,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_map_request(
            plan.gap_domain,
            plan.gap_virt + 2 * PAGE_SIZE,
            plan.gap_virt + 3 * PAGE_SIZE - 1,
            plan.gap_phys + 2 * PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_attach_request(
            plan.bypass_domain,
            plan.bypass_ep,
            VIRTIO_IOMMU_ATTACH_F_BYPASS,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.bypass_domain,
            plan.trans_virt,
            plan.trans_virt + PAGE_SIZE - 1,
            plan.trans_phys,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_unmap_request(
            plan.bypass_domain,
            plan.trans_virt,
            plan.trans_virt + PAGE_SIZE - 1,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.move_domain_a,
            plan.move_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.move_domain_b,
            plan.move_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.move_domain_b,
            plan.mismatch_ep,
            VIRTIO_IOMMU_ATTACH_F_BYPASS,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.ext_domain,
            plan.ext_success_ep_a,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.ext_domain,
            plan.trans_virt + 4 * PAGE_SIZE,
            plan.trans_virt + 5 * PAGE_SIZE - 1,
            plan.trans_phys + 8 * PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_attach_request(
            plan.ext_domain,
            plan.ext_success_ep_b,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.rollback_domain,
            plan.rollback_success_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.rollback_domain,
            plan.ext_fail_map_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.rollback_domain,
            plan.gap_virt + 4 * PAGE_SIZE,
            plan.gap_virt + 5 * PAGE_SIZE - 1,
            plan.gap_phys + 4 * PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
        )),
        ChainSpec::valid(build_attach_request(
            plan.unmap_fail_domain,
            plan.ext_fail_unmap_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.unmap_fail_domain,
            plan.gap_virt + 6 * PAGE_SIZE,
            plan.gap_virt + 7 * PAGE_SIZE - 1,
            plan.gap_phys + 6 * PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_unmap_request(
            plan.unmap_fail_domain,
            plan.gap_virt + 6 * PAGE_SIZE,
            plan.gap_virt + 7 * PAGE_SIZE - 1,
            [0; 4],
        )),
        ChainSpec::valid(build_attach_request(
            plan.detach_ext_domain,
            plan.detach_ext_ep,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.detach_ext_domain,
            plan.gap_virt + 8 * PAGE_SIZE,
            plan.gap_virt + 9 * PAGE_SIZE - 1,
            plan.gap_phys + 8 * PAGE_SIZE,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
        ChainSpec::valid(build_detach_request(
            plan.detach_ext_domain,
            plan.detach_ext_ep,
        )),
        ChainSpec::valid(build_attach_request(
            plan.overflow_domain,
            plan.ext_success_ep_a,
            0,
            [0; 4],
        )),
        ChainSpec::valid(build_map_request(
            plan.overflow_domain,
            plan.overflow_virt_start,
            u64::MAX,
            plan.trans_phys,
            VIRTIO_IOMMU_MAP_F_READ,
        )),
    ]);
}

fn next_fuzz_chain(stream: &mut ByteStream) -> ChainSpec {
    let domain = stream.next_u32() % 64;
    let endpoint = stream.next_u32() % 128;
    let virt_start = pick_guest_page(stream.next_u64());
    let pages = (stream.next_u8() as u64 % 8) + 1;
    let size = pages * PAGE_SIZE;
    let virt_end = virt_start.saturating_add(size - 1).min(INPUT_RANGE_MAX);
    let phys_start = pick_guest_page(stream.next_u64());

    let mut chain = match stream.next_u8() % 8 {
        0 => ChainSpec::valid(build_attach_request(
            domain,
            endpoint,
            (stream.next_u8() & 1) as u32,
            [0; 4],
        )),
        1 => ChainSpec::valid(build_detach_request(domain, endpoint)),
        2 => ChainSpec::valid(build_map_request(
            domain,
            virt_start,
            virt_end,
            phys_start,
            stream.next_u32() & VIRTIO_IOMMU_MAP_F_MASK,
        )),
        3 => ChainSpec::valid(build_map_request(
            domain,
            virt_start,
            virt_end,
            phys_start,
            stream.next_u32(),
        )),
        4 => ChainSpec::valid(build_unmap_request(domain, virt_start, virt_end, [0; 4])),
        5 => ChainSpec::valid(build_probe_request(endpoint)),
        6 => {
            let unknown_type = {
                let t = stream.next_u8();
                if (1..=VIRTIO_IOMMU_T_PROBE).contains(&t) {
                    t.wrapping_add(0x40)
                } else {
                    t
                }
            };
            ChainSpec::without_status(vec![unknown_type, 0, 0, 0])
        }
        _ => ChainSpec::valid(build_attach_request(
            domain,
            endpoint,
            stream.next_u32(),
            [stream.next_u8(), 0, 0, 0],
        )),
    };

    let tweak = stream.next_u8();
    if chain.include_status && (tweak & 0x1) != 0 {
        chain.status_len = (tweak as u32 & 0x7) + 1;
    }
    if chain.include_status && (tweak & 0x2) != 0 {
        chain.status_write_only = false;
    }
    if (tweak & 0x4) != 0 {
        chain.request_write_only = true;
    }
    if chain.include_status && (tweak & 0x8) != 0 {
        chain.include_status = false;
    }
    if (tweak & 0x10) != 0 {
        chain.request_len = chain
            .request_len
            .saturating_sub(((stream.next_u8() % 4) + 1) as u32);
    }

    chain
}

fn pick_guest_page(raw: u64) -> u64 {
    let pages = ((MEM_SIZE as u64) / PAGE_SIZE).saturating_sub(1).max(1);
    (raw % pages) * PAGE_SIZE
}

fn pick_guest_window(raw: u64, window_pages: u64) -> u64 {
    let total_pages = (MEM_SIZE as u64) / PAGE_SIZE;
    let first_page = 16;
    let usable_pages = total_pages
        .saturating_sub(window_pages)
        .saturating_sub(first_page)
        .max(1);
    (first_page + (raw % usable_pages)) * PAGE_SIZE
}

fn build_attach_request(domain: u32, endpoint: u32, flags: u32, reserved: [u8; 4]) -> Vec<u8> {
    let mut req = build_req_header(VIRTIO_IOMMU_T_ATTACH);
    append_u32(&mut req, domain);
    append_u32(&mut req, endpoint);
    append_u32(&mut req, flags);
    req.extend_from_slice(&reserved);
    req
}

fn build_detach_request(domain: u32, endpoint: u32) -> Vec<u8> {
    let mut req = build_req_header(VIRTIO_IOMMU_T_DETACH);
    append_u32(&mut req, domain);
    append_u32(&mut req, endpoint);
    req.extend_from_slice(&[0; 8]);
    req
}

fn build_map_request(
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    phys_start: u64,
    flags: u32,
) -> Vec<u8> {
    let mut req = build_req_header(VIRTIO_IOMMU_T_MAP);
    append_u32(&mut req, domain);
    append_u64(&mut req, virt_start);
    append_u64(&mut req, virt_end);
    append_u64(&mut req, phys_start);
    append_u32(&mut req, flags);
    req
}

fn build_unmap_request(domain: u32, virt_start: u64, virt_end: u64, reserved: [u8; 4]) -> Vec<u8> {
    let mut req = build_req_header(VIRTIO_IOMMU_T_UNMAP);
    append_u32(&mut req, domain);
    append_u64(&mut req, virt_start);
    append_u64(&mut req, virt_end);
    req.extend_from_slice(&reserved);
    req
}

fn build_probe_request(endpoint: u32) -> Vec<u8> {
    let mut req = build_req_header(VIRTIO_IOMMU_T_PROBE);
    append_u32(&mut req, endpoint);
    req.extend_from_slice(&[0; 64]);
    req
}

fn build_req_header(req_type: u8) -> Vec<u8> {
    vec![req_type, 0, 0, 0]
}

fn append_u32(vec: &mut Vec<u8>, value: u32) {
    vec.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(vec: &mut Vec<u8>, value: u64) {
    vec.extend_from_slice(&value.to_le_bytes());
}

fn write_request_queue(mem: &GuestMemoryMmap, chains: &[ChainSpec]) -> Result<(), ()> {
    let mut next_desc: u16 = 0;
    let mut next_payload_addr = PAYLOAD_ADDR_START;
    let mut avail_count: u16 = 0;

    for chain in chains {
        let desc_needed = if chain.include_status { 2 } else { 1 };
        if (next_desc as usize + desc_needed) > QUEUE_SIZE as usize {
            break;
        }

        let req_addr = if let Some(addr) = chain.request_addr_override {
            addr
        } else {
            let addr =
                allocate_payload(&mut next_payload_addr, chain.request.len() as u32).ok_or(())?;
            mem.write_slice(chain.request.as_slice(), GuestAddress(addr))
                .map_err(|_| ())?;
            addr
        };

        let req_flags = (if chain.include_status {
            VIRTQ_DESC_F_NEXT
        } else {
            0
        }) | if chain.request_write_only {
            VIRTQ_DESC_F_WRITE
        } else {
            0
        };
        let head_idx = next_desc;
        write_desc(
            mem,
            head_idx,
            VirtqDesc {
                addr: req_addr,
                len: chain.request_len,
                flags: req_flags,
                next: if chain.include_status {
                    head_idx + 1
                } else {
                    0
                },
            },
        )?;
        next_desc = next_desc.wrapping_add(1);

        if chain.include_status {
            let status_addr = if let Some(addr) = chain.status_addr_override {
                addr
            } else {
                let alloc_len = chain.status_len.max(1);
                let addr = allocate_payload(&mut next_payload_addr, alloc_len).ok_or(())?;
                let zeroes = vec![0u8; alloc_len as usize];
                mem.write_slice(&zeroes, GuestAddress(addr))
                    .map_err(|_| ())?;
                addr
            };

            write_desc(
                mem,
                next_desc,
                VirtqDesc {
                    addr: status_addr,
                    len: chain.status_len,
                    flags: if chain.status_write_only {
                        VIRTQ_DESC_F_WRITE
                    } else {
                        0
                    },
                    next: 0,
                },
            )?;
            next_desc = next_desc.wrapping_add(1);
        }

        write_u16(
            mem,
            AVAIL_RING_ADDR + 4 + (avail_count as u64 * size_of::<u16>() as u64),
            head_idx,
        )?;
        avail_count = avail_count.wrapping_add(1);
        if avail_count as usize >= QUEUE_SIZE as usize {
            break;
        }
    }

    write_u16(mem, AVAIL_RING_ADDR, 0)?;
    write_u16(mem, AVAIL_RING_ADDR + 2, avail_count)?;
    write_u16(mem, USED_RING_ADDR, 0)?;
    write_u16(mem, USED_RING_ADDR + 2, 0)?;
    Ok(())
}

fn allocate_payload(next_payload_addr: &mut u64, len: u32) -> Option<u64> {
    let start = align!(*next_payload_addr, 8);
    let end = start.checked_add(len as u64)?;
    if end > MEM_SIZE as u64 {
        return None;
    }
    *next_payload_addr = end;
    Some(start)
}

fn write_desc(mem: &GuestMemoryMmap, desc_index: u16, desc: VirtqDesc) -> Result<(), ()> {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&desc.addr.to_le_bytes());
    raw[8..12].copy_from_slice(&desc.len.to_le_bytes());
    raw[12..14].copy_from_slice(&desc.flags.to_le_bytes());
    raw[14..16].copy_from_slice(&desc.next.to_le_bytes());
    mem.write_slice(
        &raw,
        GuestAddress(DESC_TABLE_ADDR + desc_index as u64 * size_of::<VirtqDesc>() as u64),
    )
    .map_err(|_| ())
}

fn write_u16(mem: &GuestMemoryMmap, addr: u64, value: u16) -> Result<(), ()> {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .map_err(|_| ())
}

fn install_external_mappings(iommu: &mut virtio_devices::Iommu, plan: &FuzzPlan) {
    iommu.add_external_mapping(1, Arc::new(FuzzExternalMapping::new(false, false)));
    iommu.add_external_mapping(4, Arc::new(FuzzExternalMapping::new(false, false)));
    iommu.add_external_mapping(20, Arc::new(FuzzExternalMapping::new(false, false)));
    iommu.add_external_mapping(21, Arc::new(FuzzExternalMapping::new(false, false)));
    iommu.add_external_mapping(30, Arc::new(FuzzExternalMapping::new(true, false)));
    iommu.add_external_mapping(31, Arc::new(FuzzExternalMapping::new(false, true)));
    iommu.add_external_mapping(40, Arc::new(FuzzExternalMapping::new(false, false)));
    iommu.add_external_mapping(41, Arc::new(FuzzExternalMapping::new(true, false)));
    iommu.add_external_mapping(
        plan.ext_success_ep_a,
        Arc::new(FuzzExternalMapping::new(false, false)),
    );
    iommu.add_external_mapping(
        plan.ext_success_ep_b,
        Arc::new(FuzzExternalMapping::new(false, false)),
    );
    iommu.add_external_mapping(
        plan.rollback_success_ep,
        Arc::new(FuzzExternalMapping::new(false, false)),
    );
    iommu.add_external_mapping(
        plan.ext_fail_map_ep,
        Arc::new(FuzzExternalMapping::new(true, false)),
    );
    iommu.add_external_mapping(
        plan.ext_fail_unmap_ep,
        Arc::new(FuzzExternalMapping::new(false, true)),
    );
    iommu.add_external_mapping(
        plan.detach_ext_ep,
        Arc::new(FuzzExternalMapping::new(false, false)),
    );
}

fn exercise_translation_paths(mapping: &Arc<virtio_devices::IommuMapping>, plan: &FuzzPlan) {
    let _ = mapping.translate_gva(21, 0x28100, 0x100);
    let _ = mapping.translate_gva(21, 0x28f00, 0x200);
    let _ = mapping.translate_gpa(21, 0x38100, 0x100);
    let _ = mapping.translate_gpa(21, 0x38f00, 0x200);
    let _ = mapping.translate_gva(21, 0x28100, 0);
    let _ = mapping.translate_gva(plan.trans_ep_b, plan.trans_virt + PAGE_SIZE - 0x80, 0x100);
    let _ = mapping.translate_gva(plan.trans_ep_b, plan.trans_virt + PAGE_SIZE, 2 * PAGE_SIZE);
    let _ = mapping.translate_gva(plan.trans_ep_b, plan.trans_virt - PAGE_SIZE, 0x100);
    let _ = mapping.translate_gva(plan.trans_ep_b, plan.trans_virt + 5 * PAGE_SIZE, 0x100);
    let _ = mapping.translate_gva(plan.gap_ep, plan.gap_virt, 2 * PAGE_SIZE);
    let _ = mapping.translate_gpa(plan.trans_ep_b, plan.trans_phys + 0x80, 0x100);
    let _ = mapping.translate_gpa(plan.trans_ep_b, plan.trans_phys + PAGE_SIZE - 0x80, 0x100);
    let _ = mapping.translate_gva(plan.bypass_ep, plan.trans_virt, 0x100);
    let _ = mapping.translate_gpa(plan.bypass_ep, plan.trans_phys, 0x100);
    let _ = mapping.translate_gva(plan.trans_ep_b, u64::MAX - 0x10, 0x100);
}
