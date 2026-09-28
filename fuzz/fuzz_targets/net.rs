// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Once};

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::net::{
    AnnounceOps, AnnounceOutcome, AnnouncementState, Announcer, NetCtrlEpollHandler, NetState,
};
use virtio_devices::{
    EpollHelper, EpollHelperHandler, RateLimiterConfig, TokenBucketConfig, VirtioDevice,
    VirtioInterrupt, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vm_migration::{Migratable, Pausable, Snapshottable};
use vm_virtio::AccessPlatform;
use vmm::EpollContext;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
use vmm_sys_util::timerfd::TimerFd;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

const TAP_INPUT_SIZE: usize = 128;
const TX_BACKPRESSURE_DRAIN_THRESHOLD: i32 = 7 * 1024;
const TX_BACKPRESSURE_READY_POLLS: u8 = 8;
const MEM_SIZE: usize = 2 * 1024 * 1024;
const GUEST_MEM_GAP: u64 = 1024 * 1024;
const BASE_VIRT_QUEUE_ADDR: u64 = MEM_SIZE as u64 + GUEST_MEM_GAP;
const QUEUE_NUM: usize = 2;
const TOTAL_QUEUES: usize = QUEUE_NUM + 1;
const MAX_VIRTQUEUE_PAIRS: u16 = (QUEUE_NUM / 2) as u16;
const QUEUE_SIZE: u16 = 256;
const DESC_TABLE_ALIGN_SIZE: u64 = 16;
const USED_RING_ALIGN_SIZE: u64 = 4;
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
const PADDING_SIZE: u64 = align!(AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE) - AVAIL_RING_SIZE;
const USED_RING_SIZE: u64 = 6_u64 + 8 * QUEUE_SIZE as u64;
const QUEUE_BYTES_SIZE: usize = align!(
    DESC_TABLE_SIZE + AVAIL_RING_SIZE + PADDING_SIZE + USED_RING_SIZE,
    DESC_TABLE_ALIGN_SIZE
) as usize;

// Frame/buffer regions are spaced by more than the largest frame the harness
// builds (vnet header + 64 KiB) so that a large TX frame cannot overlap the
// neighbouring RX buffers or the control-queue area.
const FRAME_REGION_STRIDE: u64 = 0x12_000;
const TX_FRAME0_ADDR: u64 = 0x20_000;
const TX_FRAME1_ADDR: u64 = TX_FRAME0_ADDR + FRAME_REGION_STRIDE;
const TX_FRAME2_ADDR: u64 = TX_FRAME1_ADDR + FRAME_REGION_STRIDE;
const RX_BUF0_ADDR: u64 = TX_FRAME2_ADDR + FRAME_REGION_STRIDE;
const RX_BUF1_ADDR: u64 = RX_BUF0_ADDR + FRAME_REGION_STRIDE;
const RX_BUF2_ADDR: u64 = RX_BUF1_ADDR + FRAME_REGION_STRIDE;

const CTRL_BASE_ADDR: u64 = RX_BUF2_ADDR + FRAME_REGION_STRIDE;
const CTRL_STRIDE: u64 = 0x80;
const CTRL_HDR0_ADDR: u64 = CTRL_BASE_ADDR;
const CTRL_STATUS0_ADDR: u64 = CTRL_BASE_ADDR + 0x20;
const CTRL_HDR1_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE;
const CTRL_DATA1_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE + 0x10;
const CTRL_STATUS1_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE + 0x20;
const CTRL_HDR2_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 2;
const CTRL_DATA2_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 2 + 0x10;
const CTRL_STATUS2_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 2 + 0x20;
const CTRL_HDR3_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 3;
const CTRL_DATA3_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 3 + 0x10;
const CTRL_STATUS3_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 3 + 0x20;
const CTRL_HDR4_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 4;
const CTRL_DATA4_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 4 + 0x10;
const CTRL_STATUS4_ADDR: u64 = CTRL_BASE_ADDR + CTRL_STRIDE * 4 + 0x20;

const RX_QUEUE_INDEX: usize = 0;
const TX_QUEUE_INDEX: usize = 1;
const CTRL_QUEUE_INDEX: usize = 2;

const VIRTIO_RING_F_EVENT_IDX: u64 = 29;
const VIRTIO_F_VERSION_1: u64 = 32;
const VIRTIO_F_ACCESS_PLATFORM: u64 = 33;

const VIRTIO_NET_F_MAC: u64 = 5;
const VIRTIO_NET_F_STATUS: u64 = 16;
const VIRTIO_NET_F_CTRL_VQ: u64 = 17;
const VIRTIO_NET_F_GUEST_ANNOUNCE: u64 = 21;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const VIRTIO_NET_CTRL_RX: u8 = 0;
const VIRTIO_NET_CTRL_ANNOUNCE: u8 = 3;
const VIRTIO_NET_CTRL_MQ: u8 = 4;
const VIRTIO_NET_CTRL_GUEST_OFFLOADS: u8 = 5;

const VIRTIO_NET_CTRL_ANNOUNCE_ACK: u8 = 0;
const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u8 = 0;
const VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET: u8 = 0;
const VIRTIO_NET_CTRL_RX_PROMISC: u8 = 0;
const CTRL_QUEUE_EVENT_ID: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const START_ANNOUNCEMENTS_EVENT_ID: u16 = CTRL_QUEUE_EVENT_ID + 1;
const RETRY_ANNOUNCEMENTS_EVENT_ID: u16 = START_ANNOUNCEMENTS_EVENT_ID + 1;

struct InputReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> InputReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let b = self.bytes[self.cursor % self.bytes.len()];
        self.cursor = self.cursor.wrapping_add(1);
        b
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
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

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }

    fn fill_slice(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.next_u8();
        }
    }
}

#[derive(Default)]
struct FlakyAnnounceOps {
    retries_left: u8,
}

impl AnnounceOps for FlakyAnnounceOps {
    fn send_announce(&mut self) -> AnnounceOutcome {
        if self.retries_left == 0 {
            AnnounceOutcome::Done
        } else {
            self.retries_left -= 1;
            AnnounceOutcome::Retry
        }
    }
}

#[derive(Debug)]
struct IdentityAccessPlatform;

impl AccessPlatform for IdentityAccessPlatform {
    fn translate_gva(&self, base: u64, _size: u64) -> io::Result<u64> {
        Ok(base)
    }

    fn translate_gpa(&self, base: u64, _size: u64) -> io::Result<u64> {
        Ok(base)
    }
}

#[derive(Clone, Copy)]
enum TapBackendMode {
    DropPeer,
    RxWorker,
    TxBackpressure,
}

#[derive(Clone, Copy)]
enum CtrlAnnounceMode {
    Ack,
    Nack,
    Malformed,
}

#[derive(Clone, Copy)]
enum InterruptFault {
    None,
    Queue,
    Config,
}

#[inline]
fn queue_region_offset(queue_index: usize) -> usize {
    queue_index * QUEUE_BYTES_SIZE
}

#[inline]
fn queue_avail_offset(queue_index: usize) -> usize {
    queue_region_offset(queue_index) + DESC_TABLE_SIZE as usize
}

#[inline]
fn queue_used_offset(queue_index: usize) -> usize {
    queue_region_offset(queue_index)
        + DESC_TABLE_SIZE as usize
        + AVAIL_RING_SIZE as usize
        + PADDING_SIZE as usize
}

fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_desc(
    queue_bytes: &mut [u8],
    queue_index: usize,
    desc_index: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) {
    let offset = queue_region_offset(queue_index) + desc_index as usize * 16;
    write_u64_le(queue_bytes, offset, addr);
    write_u32_le(queue_bytes, offset + 8, len);
    write_u16_le(queue_bytes, offset + 12, flags);
    write_u16_le(queue_bytes, offset + 14, next);
}

fn write_avail_head(queue_bytes: &mut [u8], queue_index: usize, slot: u16, head: u16) {
    let ring_offset = queue_avail_offset(queue_index) + 4 + slot as usize * 2;
    write_u16_le(queue_bytes, ring_offset, head);
}

fn set_avail_idx(queue_bytes: &mut [u8], queue_index: usize, idx: u16) {
    write_u16_le(queue_bytes, queue_avail_offset(queue_index) + 2, idx);
}

fn set_used_idx(queue_bytes: &mut [u8], queue_index: usize, idx: u16) {
    write_u16_le(queue_bytes, queue_used_offset(queue_index) + 2, idx);
}

fn set_used_event(queue_bytes: &mut [u8], queue_index: usize, idx: u16) {
    write_u16_le(
        queue_bytes,
        queue_avail_offset(queue_index) + 4 + usize::from(QUEUE_SIZE) * 2,
        idx,
    );
}

fn build_rx_queue_layout(queue_bytes: &mut [u8], rx_len0: u32, rx_len1: u32, invalid_desc: bool) {
    write_desc(
        queue_bytes,
        RX_QUEUE_INDEX,
        0,
        RX_BUF0_ADDR,
        rx_len0,
        VRING_DESC_F_WRITE,
        0,
    );
    write_desc(
        queue_bytes,
        RX_QUEUE_INDEX,
        1,
        RX_BUF1_ADDR,
        rx_len1,
        VRING_DESC_F_WRITE,
        0,
    );
    write_avail_head(queue_bytes, RX_QUEUE_INDEX, 0, 0);
    write_avail_head(queue_bytes, RX_QUEUE_INDEX, 1, 1);
    let mut avail_idx = 2;

    if invalid_desc {
        write_desc(queue_bytes, RX_QUEUE_INDEX, 2, RX_BUF2_ADDR, rx_len0, 0, 0);
        write_avail_head(queue_bytes, RX_QUEUE_INDEX, 2, 2);
        avail_idx = 3;
    }

    set_avail_idx(queue_bytes, RX_QUEUE_INDEX, avail_idx);
    set_used_idx(queue_bytes, RX_QUEUE_INDEX, 0);
}

fn build_tx_queue_layout(
    queue_bytes: &mut [u8],
    tx_len0: u32,
    tx_len1: u32,
    invalid_desc: bool,
    extra_descs: u16,
) {
    write_desc(
        queue_bytes,
        TX_QUEUE_INDEX,
        0,
        TX_FRAME0_ADDR,
        tx_len0,
        0,
        0,
    );
    write_desc(
        queue_bytes,
        TX_QUEUE_INDEX,
        1,
        TX_FRAME1_ADDR,
        tx_len1,
        0,
        0,
    );
    write_avail_head(queue_bytes, TX_QUEUE_INDEX, 0, 0);
    write_avail_head(queue_bytes, TX_QUEUE_INDEX, 1, 1);

    let mut avail_idx = 2_u16;
    for i in 0..extra_descs {
        let desc_index = 2 + i;
        write_desc(
            queue_bytes,
            TX_QUEUE_INDEX,
            desc_index,
            TX_FRAME0_ADDR,
            tx_len0,
            0,
            0,
        );
        write_avail_head(queue_bytes, TX_QUEUE_INDEX, avail_idx, desc_index);
        avail_idx += 1;
    }

    if invalid_desc {
        write_desc(
            queue_bytes,
            TX_QUEUE_INDEX,
            avail_idx,
            TX_FRAME2_ADDR,
            tx_len0,
            VRING_DESC_F_WRITE,
            0,
        );
        write_avail_head(queue_bytes, TX_QUEUE_INDEX, avail_idx, avail_idx);
        avail_idx += 1;
    }

    set_avail_idx(queue_bytes, TX_QUEUE_INDEX, avail_idx);
    set_used_idx(queue_bytes, TX_QUEUE_INDEX, 0);
}

fn build_ctrl_queue_layout(queue_bytes: &mut [u8]) {
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        0,
        CTRL_HDR0_ADDR,
        2,
        VRING_DESC_F_NEXT,
        1,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        1,
        CTRL_STATUS0_ADDR,
        1,
        VRING_DESC_F_WRITE,
        0,
    );
    write_avail_head(queue_bytes, CTRL_QUEUE_INDEX, 0, 0);

    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        2,
        CTRL_HDR1_ADDR,
        2,
        VRING_DESC_F_NEXT,
        3,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        3,
        CTRL_DATA1_ADDR,
        2,
        VRING_DESC_F_NEXT,
        4,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        4,
        CTRL_STATUS1_ADDR,
        1,
        VRING_DESC_F_WRITE,
        0,
    );
    write_avail_head(queue_bytes, CTRL_QUEUE_INDEX, 1, 2);

    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        5,
        CTRL_HDR2_ADDR,
        2,
        VRING_DESC_F_NEXT,
        6,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        6,
        CTRL_DATA2_ADDR,
        8,
        VRING_DESC_F_NEXT,
        7,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        7,
        CTRL_STATUS2_ADDR,
        1,
        VRING_DESC_F_WRITE,
        0,
    );
    write_avail_head(queue_bytes, CTRL_QUEUE_INDEX, 2, 5);

    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        8,
        CTRL_HDR3_ADDR,
        2,
        VRING_DESC_F_NEXT,
        9,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        9,
        CTRL_DATA3_ADDR,
        2,
        VRING_DESC_F_NEXT,
        10,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        10,
        CTRL_STATUS3_ADDR,
        1,
        VRING_DESC_F_WRITE,
        0,
    );
    write_avail_head(queue_bytes, CTRL_QUEUE_INDEX, 3, 8);

    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        11,
        CTRL_HDR4_ADDR,
        2,
        VRING_DESC_F_NEXT,
        12,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        12,
        CTRL_DATA4_ADDR,
        4,
        VRING_DESC_F_NEXT,
        13,
    );
    write_desc(
        queue_bytes,
        CTRL_QUEUE_INDEX,
        13,
        CTRL_STATUS4_ADDR,
        1,
        VRING_DESC_F_WRITE,
        0,
    );
    write_avail_head(queue_bytes, CTRL_QUEUE_INDEX, 4, 11);

    set_avail_idx(queue_bytes, CTRL_QUEUE_INDEX, 5);
}

fn write_ctrl_plane(
    mem: &GuestMemoryMmap,
    input: &mut InputReader,
    announce_mode: CtrlAnnounceMode,
) -> bool {
    let mq_pairs = if input.next_bool() { 1_u16 } else { 0_u16 };
    let offload_features = input.next_u64();
    let tolerated_payload = input.next_u16();
    let unsupported_payload = input.next_u32();
    let unsupported_class = input.next_u8() | 0x80;
    let unsupported_cmd = input.next_u8();

    let status_addrs = [
        CTRL_STATUS0_ADDR,
        CTRL_STATUS1_ADDR,
        CTRL_STATUS2_ADDR,
        CTRL_STATUS3_ADDR,
        CTRL_STATUS4_ADDR,
    ];
    for addr in status_addrs {
        if mem.write_obj(0xff_u8, GuestAddress(addr)).is_err() {
            return false;
        }
    }

    let announce_hdr = match announce_mode {
        CtrlAnnounceMode::Ack => [VIRTIO_NET_CTRL_ANNOUNCE, VIRTIO_NET_CTRL_ANNOUNCE_ACK],
        CtrlAnnounceMode::Nack => [VIRTIO_NET_CTRL_ANNOUNCE, unsupported_cmd | 0x80],
        CtrlAnnounceMode::Malformed => [unsupported_class, unsupported_cmd],
    };

    mem.write_slice(&announce_hdr, GuestAddress(CTRL_HDR0_ADDR))
        .is_ok()
        && mem
            .write_slice(&mq_pairs.to_le_bytes(), GuestAddress(CTRL_DATA1_ADDR))
            .is_ok()
        && mem
            .write_slice(
                &[VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET],
                GuestAddress(CTRL_HDR1_ADDR),
            )
            .is_ok()
        && mem
            .write_slice(
                &[
                    VIRTIO_NET_CTRL_GUEST_OFFLOADS,
                    VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET,
                ],
                GuestAddress(CTRL_HDR2_ADDR),
            )
            .is_ok()
        && mem
            .write_slice(
                &offload_features.to_le_bytes(),
                GuestAddress(CTRL_DATA2_ADDR),
            )
            .is_ok()
        && mem
            .write_slice(
                &[VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC],
                GuestAddress(CTRL_HDR3_ADDR),
            )
            .is_ok()
        && mem
            .write_slice(
                &tolerated_payload.to_le_bytes(),
                GuestAddress(CTRL_DATA3_ADDR),
            )
            .is_ok()
        && mem
            .write_slice(
                &[unsupported_class, unsupported_cmd],
                GuestAddress(CTRL_HDR4_ADDR),
            )
            .is_ok()
        && mem
            .write_slice(
                &unsupported_payload.to_le_bytes(),
                GuestAddress(CTRL_DATA4_ADDR),
            )
            .is_ok()
}

fn exercise_announcer(input: &mut InputReader) {
    let Ok(announce) = AnnouncementState::new(true) else {
        return;
    };

    announce.notify(true);
    announce.invalidate();

    let retry_budget = input.next_u8() % 4;
    let mut announcer = Announcer::new(
        &announce,
        vec![
            Box::new(FlakyAnnounceOps {
                retries_left: retry_budget,
            }) as Box<dyn AnnounceOps>,
            Box::new(FlakyAnnounceOps::default()) as Box<dyn AnnounceOps>,
        ]
        .into_boxed_slice(),
    );

    announcer.initialize();
    let _ = announcer.send_announce();
    announce.invalidate();
    let _ = announcer.send_announce();
    announcer.initialize();
    for _ in 0..7 {
        let _ = announcer.send_announce();
    }
    announce.reset();
}

fn exercise_api_surface(net: &mut virtio_devices::Net, input: &mut InputReader) {
    let _ = VirtioDevice::device_type(net);
    let _ = VirtioDevice::queue_max_sizes(net);

    let all_features = VirtioDevice::features(net);
    let mut pre_ack_cfg = [0_u8; size_of::<net_util::VirtioNetConfig>()];
    VirtioDevice::read_config(net, 0, &mut pre_ack_cfg);
    VirtioDevice::ack_features(net, !all_features);
    VirtioDevice::ack_features(net, all_features);
    if input.next_bool() {
        VirtioDevice::ack_features(net, 1_u64 << VIRTIO_RING_F_EVENT_IDX);
    }

    let mut full_cfg = [0_u8; size_of::<net_util::VirtioNetConfig>()];
    VirtioDevice::read_config(net, 0, &mut full_cfg);
    let mut partial_cfg = [0_u8; 8];
    VirtioDevice::read_config(net, u64::from(input.next_u8()), &mut partial_cfg);

    let _ = VirtioDevice::counters(net);
    let _ = VirtioDevice::access_platform(net);
    VirtioDevice::set_access_platform(net, Arc::new(IdentityAccessPlatform));
    VirtioDevice::ack_features(net, 1_u64 << VIRTIO_F_ACCESS_PLATFORM);
    let _ = VirtioDevice::access_platform(net);

    let _ = Snapshottable::id(net);
    let _ = Snapshottable::snapshot(net);
    let _ = net.notify_started_migration();
    let _ = Pausable::pause(net);
    let _ = Pausable::resume(net);
}

fn setup_virt_queues(base_addr: u64, event_idx: bool) -> Vec<Queue> {
    let mut queues = Vec::new();
    for i in 0..TOTAL_QUEUES {
        let mut q = Queue::new(QUEUE_SIZE).unwrap();
        let desc_table_addr = base_addr + (QUEUE_BYTES_SIZE * i) as u64;
        let avail_ring_addr = desc_table_addr + DESC_TABLE_SIZE;
        let used_ring_addr = avail_ring_addr + PADDING_SIZE + AVAIL_RING_SIZE;
        q.try_set_desc_table_address(GuestAddress(desc_table_addr))
            .unwrap();
        q.try_set_avail_ring_address(GuestAddress(avail_ring_addr))
            .unwrap();
        q.try_set_used_ring_address(GuestAddress(used_ring_addr))
            .unwrap();
        q.set_next_avail(0);
        q.set_next_used(0);
        q.set_event_idx(event_idx);
        q.set_size(QUEUE_SIZE);
        q.set_ready(true);
        queues.push(q);
    }
    queues
}

#[expect(clippy::too_many_arguments)]
fn run_stateful_activation(
    input: &mut InputReader,
    guest_mac: [u8; 6],
    guest_mac_addr: net_util::MacAddr,
    avail_features: u64,
    acked_features: u64,
    rate_limiter_config: Option<RateLimiterConfig>,
    tx_extra_descs: u16,
    large_tx_frame: bool,
    force_rx_invalid: bool,
    force_tx_invalid: bool,
    used_event: Option<u16>,
    rx_avail_override: Option<u16>,
    post_activation_kicks: usize,
    tap_backend_mode: TapBackendMode,
    announce_mode: CtrlAnnounceMode,
    interrupt_fault: InterruptFault,
    include_ctrl_queue: bool,
) {
    let vnet_hdr_len = net_util::vnet_hdr_len();
    let (dummy_tap_frontend, dummy_tap_backend) = match create_socketpair() {
        Ok(pair) => pair,
        Err(_) => return,
    };
    if matches!(tap_backend_mode, TapBackendMode::TxBackpressure) {
        shrink_socket_buffers(dummy_tap_frontend.as_raw_fd());
        shrink_socket_buffers(dummy_tap_backend.as_raw_fd());
    }
    let tap = net_util::Tap::new_for_fuzzing(dummy_tap_frontend, "fz_tap1");

    let restored_state = NetState {
        avail_features,
        acked_features,
        config: restored_net_config(guest_mac),
        queue_size: vec![QUEUE_SIZE; TOTAL_QUEUES],
        curr_queue_pairs: None,
    };

    let mut net = match virtio_devices::Net::new_with_tap(
        "fuzzer_net_stateful".to_owned(),
        vec![tap],
        guest_mac_addr,
        false,
        QUEUE_NUM,
        QUEUE_SIZE,
        SeccompAction::Allow,
        rate_limiter_config,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        Some(restored_state),
        true,
        true,
        true,
    ) {
        Ok(net) => net,
        Err(_) => return,
    };
    exercise_api_surface(&mut net, input);

    let tx_len0 = if large_tx_frame {
        (vnet_hdr_len + 65536) as u32
    } else if rate_limiter_config.is_some() {
        (vnet_hdr_len + 96 + usize::from(input.next_u8() % 64)) as u32
    } else {
        (vnet_hdr_len + 32 + usize::from(input.next_u8() % 96)) as u32
    };
    let tx_len1 = usize::max(1, usize::from(input.next_u8() % (vnet_hdr_len as u8 + 1))) as u32;
    let rx_len0 = (vnet_hdr_len + TAP_INPUT_SIZE + usize::from(input.next_u8() % 64)) as u32;
    let rx_len1 = usize::max(1, usize::from(input.next_u8() % (vnet_hdr_len as u8 + 1))) as u32;

    let mut queue_bytes = vec![0_u8; QUEUE_BYTES_SIZE * TOTAL_QUEUES];
    let rx_invalid = force_rx_invalid || input.next_bool();
    let tx_invalid = force_tx_invalid || input.next_bool();
    build_rx_queue_layout(&mut queue_bytes, rx_len0, rx_len1, rx_invalid);
    build_tx_queue_layout(
        &mut queue_bytes,
        tx_len0,
        tx_len1,
        tx_invalid,
        tx_extra_descs,
    );
    build_ctrl_queue_layout(&mut queue_bytes);
    if let Some(used_event) = used_event {
        for queue_index in [RX_QUEUE_INDEX, TX_QUEUE_INDEX, CTRL_QUEUE_INDEX] {
            set_used_event(&mut queue_bytes, queue_index, used_event);
        }
    }
    if let Some(rx_avail_idx) = rx_avail_override {
        set_avail_idx(&mut queue_bytes, RX_QUEUE_INDEX, rx_avail_idx);
    }

    let mem = match GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(BASE_VIRT_QUEUE_ADDR), queue_bytes.len()),
    ]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    if mem
        .write_slice(&queue_bytes, GuestAddress(BASE_VIRT_QUEUE_ADDR))
        .is_err()
    {
        return;
    }

    let mut tx_frame0 = vec![0_u8; tx_len0 as usize];
    let mut tx_frame1 = vec![0_u8; tx_len1 as usize];
    let mut tx_frame2 = vec![0_u8; tx_len0 as usize];
    input.fill_slice(&mut tx_frame0);
    input.fill_slice(&mut tx_frame1);
    input.fill_slice(&mut tx_frame2);
    tx_frame0[..vnet_hdr_len].fill(0);
    let tx_frame1_hdr_len = usize::min(vnet_hdr_len, tx_frame1.len());
    tx_frame1[..tx_frame1_hdr_len].fill(0);
    tx_frame2[..vnet_hdr_len].fill(0);

    if mem
        .write_slice(&tx_frame0, GuestAddress(TX_FRAME0_ADDR))
        .is_err()
        || mem
            .write_slice(&tx_frame1, GuestAddress(TX_FRAME1_ADDR))
            .is_err()
        || mem
            .write_slice(&tx_frame2, GuestAddress(TX_FRAME2_ADDR))
            .is_err()
    {
        return;
    }

    if !write_ctrl_plane(&mem, input, announce_mode) {
        return;
    }

    let guest_memory = GuestMemoryAtomic::new(mem);
    let mut queues = setup_virt_queues(BASE_VIRT_QUEUE_ADDR, input.next_bool());

    let input_queue = queues.remove(0);
    let input_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let input_queue_evt = match input_evt.try_clone() {
        Ok(evt) => evt,
        Err(_) => return,
    };

    let output_queue = queues.remove(0);
    let output_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let output_queue_evt = match output_evt.try_clone() {
        Ok(evt) => evt,
        Err(_) => return,
    };

    let ctrl_queue = queues.remove(0);
    let ctrl_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let ctrl_queue_evt = match ctrl_evt.try_clone() {
        Ok(evt) => evt,
        Err(_) => return,
    };

    let mut tap_input_primary = [0_u8; TAP_INPUT_SIZE];
    let mut tap_input_secondary = [0_u8; TAP_INPUT_SIZE];
    input.fill_slice(&mut tap_input_primary);
    input.fill_slice(&mut tap_input_secondary);
    tap_input_primary[..vnet_hdr_len].fill(0);
    tap_input_secondary[..vnet_hdr_len].fill(0);
    let rx_burst = 3 + (input.next_u8() % 2) as usize;

    let mut backend_exit_evt = None;
    let mut tap_backend_thread = None;
    match tap_backend_mode {
        TapBackendMode::RxWorker => {
            let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
            let worker_tap = dummy_tap_backend.try_clone().unwrap();
            let worker_exit_evt = exit_evt.try_clone().unwrap();
            tap_backend_thread = Some(
                std::thread::Builder::new()
                    .name("dummy_tap_backend".to_owned())
                    .spawn(move || {
                        tap_backend_stub(
                            worker_tap,
                            tap_input_primary,
                            tap_input_secondary,
                            rx_burst,
                            worker_exit_evt,
                        );
                    })
                    .unwrap(),
            );
            backend_exit_evt = Some(exit_evt);
        }
        TapBackendMode::TxBackpressure => {
            let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
            let worker_tap = dummy_tap_backend.try_clone().unwrap();
            let worker_exit_evt = exit_evt.try_clone().unwrap();
            tap_backend_thread = Some(
                std::thread::Builder::new()
                    .name("dummy_tap_backpressure".to_owned())
                    .spawn(move || {
                        tap_backpressure_stub(worker_tap, worker_exit_evt);
                    })
                    .unwrap(),
            );
            backend_exit_evt = Some(exit_evt);
        }
        TapBackendMode::DropPeer => drop(dummy_tap_backend),
    }

    let kicks = 16 + usize::from(input.next_u8() % 16);
    for _ in 0..kicks {
        let _ = input_queue_evt.write(1);
        let _ = output_queue_evt.write(1);
        if include_ctrl_queue {
            let _ = ctrl_queue_evt.write(1);
        }
    }

    let mut active_queues = vec![(0, input_queue, input_evt), (1, output_queue, output_evt)];
    if include_ctrl_queue {
        active_queues.push((2, ctrl_queue, ctrl_evt));
    }

    let activation = net.activate(virtio_devices::ActivationContext {
        mem: guest_memory,
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fault: interrupt_fault,
        }),
        queues: active_queues,
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
    });

    if activation.is_ok() {
        // Under cfg(fuzzing) the epoll loop is non-blocking and returns as soon
        // as no event is pending, so re-kick the queues a few times to let the
        // worker observe RX/TX activity before the threads are torn down.
        for _ in 0..post_activation_kicks {
            let _ = input_queue_evt.write(1);
            let _ = output_queue_evt.write(1);
            if include_ctrl_queue {
                let _ = ctrl_queue_evt.write(1);
            }
            if rate_limiter_config.is_some()
                || matches!(tap_backend_mode, TapBackendMode::TxBackpressure)
            {
                std::thread::yield_now();
            }
        }
        net.wait_for_epoll_threads();
    }

    if let Some(exit_evt) = backend_exit_evt {
        let _ = exit_evt.write(1);
    }
    if let Some(backend_thread) = tap_backend_thread {
        let _ = backend_thread.join();
    }

    let mut post_cfg = [0_u8; 16];
    VirtioDevice::read_config(&net, u64::from(input.next_u8()), &mut post_cfg);
    let _ = VirtioDevice::counters(&net);
    VirtioDevice::reset(&mut net);
}

fn exercise_bad_activate(guest_mac_addr: net_util::MacAddr) {
    let (tap_frontend, _tap_backend) = match create_socketpair() {
        Ok(pair) => pair,
        Err(_) => return,
    };
    let tap = net_util::Tap::new_for_fuzzing(tap_frontend, "fz_tap_bad");
    let mut net = match virtio_devices::Net::new_with_tap(
        "fuzzer_net_bad_activate".to_owned(),
        vec![tap],
        guest_mac_addr,
        false,
        QUEUE_NUM,
        QUEUE_SIZE,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
        true,
        true,
        true,
    ) {
        Ok(net) => net,
        Err(_) => return,
    };
    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    let queue = Queue::new(QUEUE_SIZE).unwrap();
    let queue_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let _ = net.activate(virtio_devices::ActivationContext {
        mem: GuestMemoryAtomic::new(mem),
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fault: InterruptFault::None,
        }),
        queues: vec![(0, queue, queue_evt)],
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
    });
    VirtioDevice::reset(&mut net);
}

fn write_desc_to_mem(
    mem: &GuestMemoryMmap,
    table_addr: u64,
    desc_index: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> bool {
    let mut desc = [0_u8; 16];
    write_u64_le(&mut desc, 0, addr);
    write_u32_le(&mut desc, 8, len);
    write_u16_le(&mut desc, 12, flags);
    write_u16_le(&mut desc, 14, next);
    mem.write_slice(&desc, GuestAddress(table_addr + u64::from(desc_index) * 16))
        .is_ok()
}

fn dispatch_ctrl_handler_event(handler: &mut NetCtrlEpollHandler, event_id: u16) -> Result<(), ()> {
    let helper_kill = EventFd::new(EFD_NONBLOCK).map_err(|_| ())?;
    let helper_pause = EventFd::new(EFD_NONBLOCK).map_err(|_| ())?;
    let mut helper = EpollHelper::new(&helper_kill, &helper_pause).map_err(|_| ())?;
    let event = epoll::Event::new(epoll::Events::EPOLLIN, u64::from(event_id));
    let _ = EpollHelperHandler::handle_event(handler, &mut helper, &event);
    Ok(())
}

fn new_direct_ctrl_handler(
    mem: GuestMemoryMmap,
    queue: Queue,
    queue_evt: EventFd,
    announce_evt: EventFd,
    announce_retries: u8,
    interrupt_fault: InterruptFault,
) -> Option<NetCtrlEpollHandler> {
    let announce = AnnouncementState::new(true).ok()?;
    let announcer = Announcer::new(
        &announce,
        vec![Box::new(FlakyAnnounceOps {
            retries_left: announce_retries,
        }) as Box<dyn AnnounceOps>]
        .into_boxed_slice(),
    );

    Some(NetCtrlEpollHandler {
        mem: GuestMemoryAtomic::new(mem),
        kill_evt: EventFd::new(EFD_NONBLOCK).ok()?,
        pause_evt: EventFd::new(EFD_NONBLOCK).ok()?,
        ctrl_q: net_util::CtrlQueue::new(
            Vec::new(),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            MAX_VIRTQUEUE_PAIRS,
            Arc::new(std::sync::atomic::AtomicU16::new(MAX_VIRTQUEUE_PAIRS)),
        ),
        queue_evt,
        queue,
        access_platform: None,
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fault: interrupt_fault,
        }),
        queue_index: CTRL_QUEUE_INDEX as u16,
        announce_evt,
        announce_retry_timer: TimerFd::new().ok()?,
        announcer,
    })
}

fn exercise_ctrl_handler_edges(input: &mut InputReader) {
    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    let queue = Queue::new(QUEUE_SIZE).unwrap();
    let queue_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let announce_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };

    let Some(mut handler) =
        new_direct_ctrl_handler(mem, queue, queue_evt, announce_evt, 1, InterruptFault::None)
    else {
        return;
    };

    match input.next_u8() % 4 {
        0 => {
            let _ = dispatch_ctrl_handler_event(&mut handler, CTRL_QUEUE_EVENT_ID);
        }
        1 => {
            let _ = dispatch_ctrl_handler_event(&mut handler, START_ANNOUNCEMENTS_EVENT_ID);
        }
        2 => {
            let _ = dispatch_ctrl_handler_event(
                &mut handler,
                RETRY_ANNOUNCEMENTS_EVENT_ID.wrapping_add(1),
            );
        }
        _ => exercise_ctrl_needs_notification_error(),
    }

    exercise_ctrl_start_success(input.next_u8() & 1);
    exercise_ctrl_start_success((input.next_u8() & 1) ^ 1);
    exercise_ctrl_retry_spurious();
}

fn exercise_ctrl_start_success(retries_left: u8) {
    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    let queue = Queue::new(QUEUE_SIZE).unwrap();
    let queue_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let announce_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let _ = announce_evt.write(1);

    let Some(mut handler) = new_direct_ctrl_handler(
        mem,
        queue,
        queue_evt,
        announce_evt,
        retries_left,
        InterruptFault::None,
    ) else {
        return;
    };
    let _ = dispatch_ctrl_handler_event(&mut handler, START_ANNOUNCEMENTS_EVENT_ID);
}

fn exercise_ctrl_retry_spurious() {
    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    let queue = Queue::new(QUEUE_SIZE).unwrap();
    let queue_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let announce_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let Some(mut handler) =
        new_direct_ctrl_handler(mem, queue, queue_evt, announce_evt, 1, InterruptFault::None)
    else {
        return;
    };

    // SAFETY: fcntl only changes the timerfd status flags for this handler.
    let ret = unsafe {
        let fd = handler.announce_retry_timer.as_raw_fd();
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
    };
    if ret < 0 {
        return;
    }
    let _ = dispatch_ctrl_handler_event(&mut handler, RETRY_ANNOUNCEMENTS_EVENT_ID);
}

fn exercise_ctrl_needs_notification_error() {
    const DIRECT_DESC_TABLE_ADDR: u64 = 0x1_000;
    const DIRECT_USED_RING_ADDR: u64 = 0x2_000;
    const DIRECT_AVAIL_RING_ADDR: u64 = MEM_SIZE as u64 - 64;

    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };

    if !write_desc_to_mem(
        &mem,
        DIRECT_DESC_TABLE_ADDR,
        0,
        CTRL_HDR0_ADDR,
        2,
        VRING_DESC_F_NEXT,
        1,
    ) || !write_desc_to_mem(
        &mem,
        DIRECT_DESC_TABLE_ADDR,
        1,
        CTRL_STATUS0_ADDR,
        1,
        VRING_DESC_F_WRITE,
        0,
    ) {
        return;
    }

    if mem
        .write_slice(
            &[VIRTIO_NET_CTRL_ANNOUNCE, VIRTIO_NET_CTRL_ANNOUNCE_ACK],
            GuestAddress(CTRL_HDR0_ADDR),
        )
        .is_err()
        || mem
            .write_obj(0xff_u8, GuestAddress(CTRL_STATUS0_ADDR))
            .is_err()
        || mem
            .write_obj(0_u16, GuestAddress(DIRECT_AVAIL_RING_ADDR))
            .is_err()
        || mem
            .write_obj(1_u16, GuestAddress(DIRECT_AVAIL_RING_ADDR + 2))
            .is_err()
        || mem
            .write_obj(0_u16, GuestAddress(DIRECT_AVAIL_RING_ADDR + 4))
            .is_err()
        || mem
            .write_obj(0_u16, GuestAddress(DIRECT_USED_RING_ADDR))
            .is_err()
        || mem
            .write_obj(0_u16, GuestAddress(DIRECT_USED_RING_ADDR + 2))
            .is_err()
    {
        return;
    }

    let mut queue = Queue::new(QUEUE_SIZE).unwrap();
    if queue
        .try_set_desc_table_address(GuestAddress(DIRECT_DESC_TABLE_ADDR))
        .is_err()
        || queue
            .try_set_avail_ring_address(GuestAddress(DIRECT_AVAIL_RING_ADDR))
            .is_err()
        || queue
            .try_set_used_ring_address(GuestAddress(DIRECT_USED_RING_ADDR))
            .is_err()
    {
        return;
    }
    queue.set_next_avail(0);
    queue.set_next_used(0);
    queue.set_event_idx(true);
    queue.set_size(QUEUE_SIZE);
    queue.set_ready(true);

    let queue_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let _ = queue_evt.write(1);
    let announce_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let Some(mut handler) =
        new_direct_ctrl_handler(mem, queue, queue_evt, announce_evt, 1, InterruptFault::None)
    else {
        return;
    };
    let _ = dispatch_ctrl_handler_event(&mut handler, CTRL_QUEUE_EVENT_ID);
}

fn restored_net_config(mac: [u8; 6]) -> net_util::VirtioNetConfig {
    net_util::VirtioNetConfig {
        mac,
        max_virtqueue_pairs: MAX_VIRTQUEUE_PAIRS,
        ..Default::default()
    }
}

fn exercise_bad_tap_activation(guest_mac_addr: net_util::MacAddr, rx_avail_idx: u16) {
    let tap_file = match File::open("/dev/null") {
        Ok(file) => file,
        Err(_) => return,
    };
    let tap = net_util::Tap::new_for_fuzzing(tap_file, "fz_tap_badfd");
    let features = (1_u64 << VIRTIO_F_VERSION_1) | (1_u64 << VIRTIO_NET_F_STATUS);
    let restored_state = NetState {
        avail_features: features,
        acked_features: features,
        config: restored_net_config([0; 6]),
        queue_size: vec![QUEUE_SIZE; TOTAL_QUEUES],
        curr_queue_pairs: None,
    };
    let mut net = match virtio_devices::Net::new_with_tap(
        "fuzzer_net_bad_tap".to_owned(),
        vec![tap],
        guest_mac_addr,
        false,
        QUEUE_NUM,
        QUEUE_SIZE,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        Some(restored_state),
        true,
        true,
        true,
    ) {
        Ok(net) => net,
        Err(_) => return,
    };

    let vnet_hdr_len = net_util::vnet_hdr_len();
    let mut queue_bytes = vec![0_u8; QUEUE_BYTES_SIZE * TOTAL_QUEUES];
    build_rx_queue_layout(
        &mut queue_bytes,
        (vnet_hdr_len + TAP_INPUT_SIZE) as u32,
        (vnet_hdr_len + TAP_INPUT_SIZE) as u32,
        false,
    );
    build_tx_queue_layout(
        &mut queue_bytes,
        (vnet_hdr_len + 64) as u32,
        (vnet_hdr_len + 64) as u32,
        false,
        0,
    );
    set_avail_idx(&mut queue_bytes, RX_QUEUE_INDEX, rx_avail_idx);

    let mem = match GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(BASE_VIRT_QUEUE_ADDR), queue_bytes.len()),
    ]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    if mem
        .write_slice(&queue_bytes, GuestAddress(BASE_VIRT_QUEUE_ADDR))
        .is_err()
    {
        return;
    }

    let mut queues = setup_virt_queues(BASE_VIRT_QUEUE_ADDR, false);
    let input_queue = queues.remove(0);
    let input_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let input_queue_evt = match input_evt.try_clone() {
        Ok(evt) => evt,
        Err(_) => return,
    };
    let output_queue = queues.remove(0);
    let output_evt = EventFd::new(EFD_NONBLOCK).unwrap();

    let _ = input_queue_evt.write(1);
    let activation = net.activate(virtio_devices::ActivationContext {
        mem: GuestMemoryAtomic::new(mem),
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fault: InterruptFault::None,
        }),
        queues: vec![(0, input_queue, input_evt), (1, output_queue, output_evt)],
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
    });
    if activation.is_ok() {
        net.wait_for_epoll_threads();
    }
    VirtioDevice::reset(&mut net);
}

fn exercise_bad_queue_activation(guest_mac_addr: net_util::MacAddr, bad_avail_ring: bool) {
    let (tap_frontend, tap_backend) = match create_socketpair() {
        Ok(pair) => pair,
        Err(_) => return,
    };
    drop(tap_backend);
    let tap = net_util::Tap::new_for_fuzzing(tap_frontend, "fz_tap_badq");
    let features = (1_u64 << VIRTIO_F_VERSION_1) | (1_u64 << VIRTIO_NET_F_STATUS);
    let restored_state = NetState {
        avail_features: features,
        acked_features: features,
        config: restored_net_config([0; 6]),
        queue_size: vec![QUEUE_SIZE; TOTAL_QUEUES],
        curr_queue_pairs: None,
    };
    let mut net = match virtio_devices::Net::new_with_tap(
        "fuzzer_net_bad_queue".to_owned(),
        vec![tap],
        guest_mac_addr,
        false,
        QUEUE_NUM,
        QUEUE_SIZE,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        Some(restored_state),
        true,
        true,
        true,
    ) {
        Ok(net) => net,
        Err(_) => return,
    };

    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };

    let mut input_queue = Queue::new(QUEUE_SIZE).unwrap();
    let desc_table_addr = GuestAddress(0x3_000);
    let avail_ring_addr = if bad_avail_ring {
        GuestAddress(BASE_VIRT_QUEUE_ADDR)
    } else {
        GuestAddress(0x4_000)
    };
    let used_ring_addr = if bad_avail_ring {
        GuestAddress(0x5_000)
    } else {
        GuestAddress(BASE_VIRT_QUEUE_ADDR)
    };
    if input_queue
        .try_set_desc_table_address(desc_table_addr)
        .is_err()
        || input_queue
            .try_set_avail_ring_address(avail_ring_addr)
            .is_err()
        || input_queue
            .try_set_used_ring_address(used_ring_addr)
            .is_err()
    {
        return;
    }
    input_queue.set_next_avail(0);
    input_queue.set_next_used(0);
    input_queue.set_size(QUEUE_SIZE);
    input_queue.set_ready(true);

    let mut output_queue = Queue::new(QUEUE_SIZE).unwrap();
    output_queue
        .try_set_desc_table_address(GuestAddress(0x6_000))
        .unwrap();
    output_queue
        .try_set_avail_ring_address(GuestAddress(0x7_000))
        .unwrap();
    output_queue
        .try_set_used_ring_address(GuestAddress(0x8_000))
        .unwrap();
    output_queue.set_size(QUEUE_SIZE);
    output_queue.set_ready(true);

    let input_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let output_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let activation = net.activate(virtio_devices::ActivationContext {
        mem: GuestMemoryAtomic::new(mem),
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fault: InterruptFault::None,
        }),
        queues: vec![(0, input_queue, input_evt), (1, output_queue, output_evt)],
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
    });
    if activation.is_ok() {
        net.wait_for_epoll_threads();
    }
    VirtioDevice::reset(&mut net);
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    static IGNORE_SIGPIPE: Once = Once::new();
    IGNORE_SIGPIPE.call_once(|| unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    });

    let mut input = InputReader::new(bytes);

    exercise_announcer(&mut input);

    let mut guest_mac = [0_u8; 6];
    input.fill_slice(&mut guest_mac);
    guest_mac[0] |= 0x02;
    let Ok(guest_mac_addr) = net_util::MacAddr::from_bytes(&guest_mac) else {
        return Corpus::Reject;
    };

    if let Ok(exit_evt) = EventFd::new(EFD_NONBLOCK) {
        let _ = virtio_devices::Net::new(
            "ctor_new".to_owned(),
            Some("fuzzer_tap_name"),
            None,
            None,
            guest_mac_addr,
            None,
            None,
            false,
            QUEUE_NUM,
            QUEUE_SIZE,
            SeccompAction::Allow,
            None,
            exit_evt,
            None,
            true,
            true,
            true,
        );
    }
    if let Ok(exit_evt) = EventFd::new(EFD_NONBLOCK) {
        let invalid_fds = [-1];
        let _ = virtio_devices::Net::from_tap_fds(
            "ctor_from_bad_fd".to_owned(),
            &invalid_fds,
            guest_mac_addr,
            None,
            false,
            QUEUE_SIZE,
            SeccompAction::Allow,
            None,
            exit_evt,
            None,
            true,
            true,
            true,
        );
    }
    if let (Ok((fd0, _fd1)), Ok(exit_evt)) = (create_socketpair(), EventFd::new(EFD_NONBLOCK)) {
        let fds = [fd0.as_raw_fd()];
        let _ = virtio_devices::Net::from_tap_fds(
            "ctor_from_fds".to_owned(),
            &fds,
            guest_mac_addr,
            None,
            false,
            QUEUE_SIZE,
            SeccompAction::Allow,
            None,
            exit_evt,
            None,
            true,
            true,
            true,
        );
    }

    let (stateless_front, _stateless_back) = match create_socketpair() {
        Ok(pair) => pair,
        Err(_) => return Corpus::Reject,
    };
    let stateless_tap = net_util::Tap::new_for_fuzzing(stateless_front, "fz_tap0");
    let mut stateless_net = match virtio_devices::Net::new_with_tap(
        "fuzzer_net_stateless".to_owned(),
        vec![stateless_tap],
        guest_mac_addr,
        false,
        QUEUE_NUM,
        QUEUE_SIZE,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
        true,
        true,
        true,
    ) {
        Ok(net) => net,
        Err(_) => return Corpus::Reject,
    };
    exercise_api_surface(&mut stateless_net, &mut input);
    VirtioDevice::reset(&mut stateless_net);
    exercise_bad_activate(guest_mac_addr);
    exercise_ctrl_handler_edges(&mut input);
    exercise_bad_tap_activation(guest_mac_addr, 0);
    exercise_bad_tap_activation(guest_mac_addr, 2);
    exercise_bad_queue_activation(guest_mac_addr, false);
    exercise_bad_queue_activation(guest_mac_addr, true);

    if let (Ok((cfg_front, _cfg_back)), Ok(exit_evt)) =
        (create_socketpair(), EventFd::new(EFD_NONBLOCK))
    {
        let cfg_tap = net_util::Tap::new_for_fuzzing(cfg_front, "fz_tap_cfg");
        if let Ok(mut cfg_net) = virtio_devices::Net::new_with_tap(
            "fuzzer_net_cfg".to_owned(),
            vec![cfg_tap],
            guest_mac_addr,
            true,
            QUEUE_NUM,
            QUEUE_SIZE,
            SeccompAction::Allow,
            None,
            exit_evt,
            None,
            false,
            false,
            false,
        ) {
            exercise_api_surface(&mut cfg_net, &mut input);
            VirtioDevice::reset(&mut cfg_net);
        }
    }

    if let (Ok((offload_front, _offload_back)), Ok(exit_evt)) =
        (create_socketpair(), EventFd::new(EFD_NONBLOCK))
    {
        let offload_tap = net_util::Tap::new_for_fuzzing(offload_front, "fz_tap_offload");
        if let Ok(mut offload_net) = virtio_devices::Net::new_with_tap(
            "fuzzer_net_offload".to_owned(),
            vec![offload_tap],
            guest_mac_addr,
            false,
            QUEUE_NUM,
            QUEUE_SIZE,
            SeccompAction::Allow,
            None,
            exit_evt,
            None,
            false,
            false,
            true,
        ) {
            exercise_api_surface(&mut offload_net, &mut input);
            VirtioDevice::reset(&mut offload_net);
        }
    }

    let mut restored_features_a = (1_u64 << VIRTIO_F_VERSION_1)
        | (1_u64 << VIRTIO_NET_F_CTRL_VQ)
        | (1_u64 << VIRTIO_NET_F_STATUS)
        | (1_u64 << VIRTIO_NET_F_GUEST_ANNOUNCE)
        | (1_u64 << VIRTIO_NET_F_MAC);
    if input.next_bool() {
        restored_features_a |= 1_u64 << VIRTIO_RING_F_EVENT_IDX;
    }
    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_a,
        restored_features_a & !(1_u64 << VIRTIO_RING_F_EVENT_IDX),
        None,
        0,
        false,
        false,
        false,
        None,
        None,
        4,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Ack,
        InterruptFault::None,
        true,
    );

    let restored_features_b = (1_u64 << VIRTIO_F_VERSION_1)
        | (1_u64 << VIRTIO_NET_F_CTRL_VQ)
        | (1_u64 << VIRTIO_NET_F_STATUS);
    let limiter = Some(RateLimiterConfig {
        bandwidth: Some(TokenBucketConfig {
            size: 64,
            one_time_burst: Some(0),
            refill_time: 2,
        }),
        ops: Some(TokenBucketConfig {
            size: 256,
            one_time_burst: Some(0),
            refill_time: 1,
        }),
    });
    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_b,
        restored_features_b,
        limiter,
        64,
        false,
        false,
        false,
        None,
        Some(2),
        512,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Ack,
        InterruptFault::None,
        true,
    );

    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_b,
        restored_features_b,
        limiter,
        0,
        false,
        false,
        true,
        None,
        Some(1),
        512,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Ack,
        InterruptFault::None,
        true,
    );

    let restored_features_c = (1_u64 << VIRTIO_F_VERSION_1)
        | (1_u64 << VIRTIO_NET_F_CTRL_VQ)
        | (1_u64 << VIRTIO_NET_F_STATUS)
        | (1_u64 << VIRTIO_NET_F_GUEST_ANNOUNCE)
        | (1_u64 << VIRTIO_NET_F_MAC);
    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_c,
        restored_features_c,
        None,
        0,
        false,
        false,
        false,
        None,
        None,
        8,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Nack,
        InterruptFault::Config,
        true,
    );

    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_c,
        restored_features_c,
        None,
        0,
        false,
        false,
        false,
        None,
        None,
        4,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Ack,
        InterruptFault::Queue,
        true,
    );

    let restored_features_event_idx = restored_features_c | (1_u64 << VIRTIO_RING_F_EVENT_IDX);
    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_event_idx,
        restored_features_event_idx,
        None,
        0,
        false,
        false,
        false,
        Some(u16::MAX),
        None,
        4,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Ack,
        InterruptFault::None,
        true,
    );

    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_c,
        restored_features_c,
        None,
        0,
        false,
        false,
        false,
        None,
        Some(2),
        4,
        TapBackendMode::RxWorker,
        CtrlAnnounceMode::Nack,
        InterruptFault::None,
        false,
    );

    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_c,
        restored_features_c,
        None,
        128,
        true,
        false,
        false,
        None,
        Some(2),
        512,
        TapBackendMode::TxBackpressure,
        CtrlAnnounceMode::Nack,
        InterruptFault::None,
        true,
    );

    run_stateful_activation(
        &mut input,
        guest_mac,
        guest_mac_addr,
        restored_features_c,
        restored_features_c,
        None,
        8,
        false,
        false,
        false,
        None,
        Some(0),
        4,
        TapBackendMode::DropPeer,
        CtrlAnnounceMode::Malformed,
        InterruptFault::None,
        true,
    );

    Corpus::Keep
});

struct FuzzVirtioInterrupt {
    fault: InterruptFault,
}

impl VirtioInterrupt for FuzzVirtioInterrupt {
    fn trigger(&self, int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        if matches!(
            (self.fault, int_type),
            (InterruptFault::Queue, VirtioInterruptType::Queue(_))
                | (InterruptFault::Config, VirtioInterruptType::Config)
        ) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }

    fn set_notifier(
        &self,
        _interrupt: u32,
        _eventfd: Option<EventFd>,
        _vm: &dyn hypervisor::Vm,
    ) -> std::io::Result<()> {
        Ok(())
    }
}

fn create_socketpair() -> Result<(File, File), std::io::Error> {
    let mut fds = [-1, -1];
    unsafe {
        let ret = libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
            0,
            fds.as_mut_ptr(),
        );
        if ret == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let socket1 = unsafe { File::from_raw_fd(fds[0]) };
    let socket2 = unsafe { File::from_raw_fd(fds[1]) };
    Ok((socket1, socket2))
}

fn shrink_socket_buffers(fd: RawFd) {
    let size: libc::c_int = 4096;
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: setsockopt only reads the provided integer during this call.
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&size as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
}

fn pending_socket_bytes(fd: RawFd) -> io::Result<i32> {
    let mut pending: libc::c_int = 0;
    // SAFETY: ioctl writes an integer to the valid pointer provided here.
    let ret = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut pending) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pending)
    }
}

fn drain_tap(dummy_tap: &mut File) {
    let mut buffer = [0_u8; 4096];
    loop {
        match dummy_tap.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

enum EpollEvent {
    Exit = 0,
    Tx = 1,
    Unknown,
}

impl From<u64> for EpollEvent {
    fn from(v: u64) -> Self {
        use EpollEvent::*;
        match v {
            0 => Exit,
            1 => Tx,
            _ => Unknown,
        }
    }
}

fn tap_backend_stub(
    mut dummy_tap: File,
    tap_input_primary: [u8; TAP_INPUT_SIZE],
    tap_input_secondary: [u8; TAP_INPUT_SIZE],
    rx_burst: usize,
    exit_evt: EventFd,
) {
    // Prime the RX direction up front. The socketpair is writable from the
    // moment it is created, so registering EPOLLOUT would only spin.
    for i in 0..rx_burst {
        let frame = if i % 2 == 0 {
            &tap_input_primary
        } else {
            &tap_input_secondary
        };
        if dummy_tap.write_all(frame).is_err() {
            break;
        }
    }

    let mut epoll = EpollContext::new().unwrap();
    epoll
        .add_event_custom(&exit_evt, EpollEvent::Exit as u64, epoll::Events::EPOLLIN)
        .unwrap();
    epoll
        .add_event_custom(&dummy_tap, EpollEvent::Tx as u64, epoll::Events::EPOLLIN)
        .unwrap();

    let epoll_fd = epoll.as_raw_fd();
    let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 2];

    loop {
        let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
            Ok(num_events) => num_events,
            Err(e) => match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => return,
            },
        };

        for event in events.iter().take(num_events) {
            match EpollEvent::from(event.data) {
                EpollEvent::Exit => return,
                EpollEvent::Tx => drain_tap(&mut dummy_tap),
                EpollEvent::Unknown => return,
            }
        }
    }
}

fn tap_backpressure_stub(mut dummy_tap: File, exit_evt: EventFd) {
    let mut epoll = EpollContext::new().unwrap();
    epoll
        .add_event_custom(&exit_evt, EpollEvent::Exit as u64, epoll::Events::EPOLLIN)
        .unwrap();
    epoll
        .add_event_custom(&dummy_tap, EpollEvent::Tx as u64, epoll::Events::EPOLLIN)
        .unwrap();

    let epoll_fd = epoll.as_raw_fd();
    let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 2];
    let mut drain_enabled = false;
    let mut ready_polls = 0_u8;

    loop {
        let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
            Ok(num_events) => num_events,
            Err(e) => match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => return,
            },
        };

        for event in events.iter().take(num_events) {
            match EpollEvent::from(event.data) {
                EpollEvent::Exit => return,
                EpollEvent::Tx => {
                    if !drain_enabled {
                        let pending =
                            pending_socket_bytes(dummy_tap.as_raw_fd()).unwrap_or_default();
                        if pending < TX_BACKPRESSURE_DRAIN_THRESHOLD {
                            std::thread::yield_now();
                            continue;
                        }
                        ready_polls = ready_polls.saturating_add(1);
                        if ready_polls < TX_BACKPRESSURE_READY_POLLS {
                            std::thread::yield_now();
                            continue;
                        }
                        drain_enabled = true;
                    }
                    drain_tap(&mut dummy_tap);
                }
                EpollEvent::Unknown => return,
            }
        }
    }
}
