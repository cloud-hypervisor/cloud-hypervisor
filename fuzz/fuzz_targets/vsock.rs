// Copyright © 2025 Microsoft
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::vsock::tests::{TestBackend, TestContext};
use virtio_devices::vsock::VsockError;
use virtio_devices::{
    ActivationContext, VirtioDevice, VirtioInterrupt, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
};
use virtio_queue::{Queue, QueueT};
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

const NUM_QUEUES: usize = 3;
const QUEUE_DATA_SIZE: usize = 4;
const MEM_SIZE: usize = 1024 * 1024;
const QUEUE_SIZE: u16 = 256;
const DESC_TABLE_ALIGN_SIZE: u64 = 16;
const AVAIL_RING_ALIGN_SIZE: u64 = 2;
const USED_RING_ALIGN_SIZE: u64 = 4;
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
const USED_RING_SIZE: u64 = 6_u64 + 8 * QUEUE_SIZE as u64;
const GUEST_MEM_GAP: u64 = 1024 * 1024;
const BASE_VIRT_QUEUE_ADDR: u64 = align!(MEM_SIZE as u64 + GUEST_MEM_GAP, DESC_TABLE_ALIGN_SIZE);
const AVAIL_RING_OFFSET: u64 = align!(DESC_TABLE_SIZE, AVAIL_RING_ALIGN_SIZE);
const USED_RING_OFFSET: u64 = align!(AVAIL_RING_OFFSET + AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE);
const QUEUE_BYTES_SIZE: usize =
    align!(USED_RING_OFFSET + USED_RING_SIZE, DESC_TABLE_ALIGN_SIZE) as usize;

const RX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const TX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
const EVT_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
const BACKEND_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;

const VSOCK_PKT_HDR_SIZE: u32 = 44;
const VSOCK_HDR_LEN_OFF: u64 = 24;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const RX_HDR_ADDR: u64 = 0x10_000;
const RX_BUF_ADDR: u64 = 0x11_000;
const RX_BAD_HDR_ADDR: u64 = 0x12_000;
const TX_HDR_ADDR: u64 = 0x20_000;
const TX_BUF_ADDR: u64 = 0x21_000;
const TX_BUF2_ADDR: u64 = 0x22_000;
const TX_BAD_HDR_ADDR: u64 = 0x23_000;
const EVT_BUF_ADDR: u64 = 0x30_000;

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() || bytes.len() > MEM_SIZE {
        return Corpus::Reject;
    }

    // The queue descriptions and ring images have a fixed size that is far
    // larger than libFuzzer's default '-max_len'. Derive them by cycling over
    // the input instead of rejecting anything shorter, so the device paths stay
    // reachable for arbitrary input lengths.
    let cycle = |len: usize, skip: usize| -> Vec<u8> {
        bytes.iter().copied().cycle().skip(skip).take(len).collect()
    };
    let queue_data = cycle(QUEUE_DATA_SIZE * NUM_QUEUES, 0);
    let queue_bytes_all = cycle(
        QUEUE_BYTES_SIZE * NUM_QUEUES,
        (QUEUE_DATA_SIZE * NUM_QUEUES) % bytes.len(),
    );

    if !run_worker_scenario(bytes, &queue_data, &queue_bytes_all, bytes, false) {
        return Corpus::Reject;
    }
    let _ = run_worker_scenario(bytes, &queue_data, &queue_bytes_all, bytes, true);

    exercise_handler_paths(bytes);
    exercise_device_paths(bytes);
    exercise_access_platform_path(bytes);

    Corpus::Keep
});

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

fn pick(bytes: &[u8], idx: usize) -> u8 {
    bytes.get(idx).copied().unwrap_or(0)
}

fn vsock_path(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/tmp/ch-vsock-fuzz-{}-{name}.sock",
        std::process::id()
    ))
}

fn queue_base(queue_index: usize) -> u64 {
    BASE_VIRT_QUEUE_ADDR + (QUEUE_BYTES_SIZE * queue_index) as u64
}

fn write_le16(mem: &GuestMemoryMmap, addr: u64, value: u16) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_le32(mem: &GuestMemoryMmap, addr: u64, value: u32) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_le64(mem: &GuestMemoryMmap, addr: u64, value: u64) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_desc(
    mem: &GuestMemoryMmap,
    table_addr: u64,
    idx: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> bool {
    let desc_addr = table_addr + u64::from(idx) * 16;
    write_le64(mem, desc_addr, addr)
        && write_le32(mem, desc_addr + 8, len)
        && write_le16(mem, desc_addr + 12, flags)
        && write_le16(mem, desc_addr + 14, next)
}

fn write_avail(mem: &GuestMemoryMmap, avail_addr: u64, ring: &[u16]) -> bool {
    if !write_le16(mem, avail_addr, 0) {
        return false;
    }
    if !write_le16(mem, avail_addr + 2, ring.len() as u16) {
        return false;
    }
    for (i, head) in ring.iter().enumerate() {
        if !write_le16(mem, avail_addr + 4 + (i as u64 * 2), *head) {
            return false;
        }
    }
    true
}

fn write_tx_hdr_len(mem: &GuestMemoryMmap, hdr_addr: u64, len: u32) -> bool {
    write_le32(mem, hdr_addr + VSOCK_HDR_LEN_OFF, len)
}

fn program_queue_memory(mem: &GuestMemoryMmap, bytes: &[u8], edge: bool) -> bool {
    let rx_base = queue_base(0);
    let tx_base = queue_base(1);
    let evt_base = queue_base(2);

    let mut ok = true;

    let rx_len = if edge && (pick(bytes, 0) & 1 != 0) {
        70_000
    } else {
        (pick(bytes, 1) as u32) & 0x7f
    };
    ok = ok && write_tx_hdr_len(mem, RX_HDR_ADDR, rx_len);
    ok =
        ok && write_desc(
            mem,
            rx_base,
            0,
            RX_HDR_ADDR,
            VSOCK_PKT_HDR_SIZE,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            1,
        ) && write_desc(
            mem,
            rx_base,
            1,
            RX_BUF_ADDR,
            512,
            if edge && (pick(bytes, 2) & 1 != 0) {
                VRING_DESC_F_WRITE | VRING_DESC_F_NEXT
            } else {
                VRING_DESC_F_WRITE
            },
            2,
        ) && write_desc(
            mem,
            rx_base,
            2,
            RX_BAD_HDR_ADDR,
            VSOCK_PKT_HDR_SIZE,
            VRING_DESC_F_WRITE,
            0,
        );

    let rx_bad_len = if pick(bytes, 3) & 1 == 0 {
        0
    } else {
        VSOCK_PKT_HDR_SIZE - 1
    };
    ok = ok && write_desc(mem, rx_base, 3, RX_BAD_HDR_ADDR, rx_bad_len, 0, 0);
    let rx_ring = if edge { [0_u16, 3_u16] } else { [0_u16, 0_u16] };
    ok = ok
        && write_avail(
            mem,
            rx_base + AVAIL_RING_OFFSET,
            if edge { &rx_ring } else { &rx_ring[..1] },
        );

    let tx_len = 32 + (pick(bytes, 4) as u32 % 96);
    let tx_invalid_len = edge && (pick(bytes, 5) & 1 != 0);
    let tx_hdr_len = if tx_invalid_len { 70_000 } else { tx_len };

    if edge && (pick(bytes, 6) & 1 != 0) {
        ok = ok
            && write_desc(
                mem,
                tx_base,
                0,
                TX_HDR_ADDR,
                VSOCK_PKT_HDR_SIZE + tx_len,
                0,
                0,
            );
    } else {
        ok =
            ok && write_desc(
                mem,
                tx_base,
                0,
                TX_HDR_ADDR,
                VSOCK_PKT_HDR_SIZE,
                VRING_DESC_F_NEXT,
                1,
            ) && write_desc(
                mem,
                tx_base,
                1,
                TX_BUF_ADDR,
                tx_len / 2 + 32,
                if edge && (pick(bytes, 7) & 1 != 0) {
                    VRING_DESC_F_NEXT
                } else {
                    0
                },
                2,
            ) && write_desc(mem, tx_base, 2, TX_BUF2_ADDR, tx_len / 2 + 32, 0, 0);
    }

    ok = ok && write_tx_hdr_len(mem, TX_HDR_ADDR, tx_hdr_len);

    ok =
        ok && write_desc(
            mem,
            tx_base,
            4,
            TX_BAD_HDR_ADDR,
            if pick(bytes, 8) & 1 == 0 {
                0
            } else {
                VSOCK_PKT_HDR_SIZE
            },
            if pick(bytes, 9) & 1 == 0 {
                VRING_DESC_F_WRITE
            } else {
                0
            },
            0,
        ) && write_tx_hdr_len(mem, TX_BAD_HDR_ADDR, tx_len);

    let tx_ring = if edge { [0_u16, 4_u16] } else { [0_u16, 0_u16] };
    ok = ok
        && write_avail(
            mem,
            tx_base + AVAIL_RING_OFFSET,
            if edge { &tx_ring } else { &tx_ring[..1] },
        );

    ok = ok
        && write_desc(mem, evt_base, 0, EVT_BUF_ADDR, 64, VRING_DESC_F_WRITE, 0)
        && write_avail(mem, evt_base + AVAIL_RING_OFFSET, &[0]);

    ok
}

fn build_queue(base_addr: u64, queue_data: &[u8], edge: bool) -> Option<Queue> {
    let mut q = Queue::new(QUEUE_SIZE).ok()?;

    if edge {
        q.set_next_avail((queue_data[0] as u16) % 2);
        q.set_next_used((queue_data[1] as u16) % 2);
        q.set_event_idx(queue_data[2] & 1 != 0);
        q.set_size(match queue_data[3] & 0x3 {
            0 => 2,
            1 => 4,
            2 => 8,
            _ => QUEUE_SIZE,
        });
    } else {
        q.set_next_avail(0);
        q.set_next_used(0);
        q.set_event_idx(true);
        q.set_size(QUEUE_SIZE);
    }

    q.try_set_desc_table_address(GuestAddress(base_addr)).ok()?;
    q.try_set_avail_ring_address(GuestAddress(base_addr + AVAIL_RING_OFFSET))
        .ok()?;
    q.try_set_used_ring_address(GuestAddress(base_addr + USED_RING_OFFSET))
        .ok()?;
    q.set_ready(true);

    Some(q)
}

fn run_worker_scenario(
    bytes: &[u8],
    queue_data: &[u8],
    queue_bytes_all: &[u8],
    mem_bytes: &[u8],
    edge: bool,
) -> bool {
    let mut backend = TestBackend::new();
    backend.set_pending_rx(!edge || (pick(bytes, 10) & 1 != 0));
    if edge && (pick(bytes, 11) & 1 != 0) {
        backend.set_rx_err(Some(VsockError::NoData));
    }
    if edge && (pick(bytes, 12) & 1 != 0) {
        backend.set_tx_err(Some(VsockError::NoData));
    }
    if !edge || (pick(bytes, 13) & 1 != 0) {
        let _ = backend.evfd.write(1);
    }

    let mem = match GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (
            GuestAddress(BASE_VIRT_QUEUE_ADDR),
            QUEUE_BYTES_SIZE * NUM_QUEUES,
        ),
    ]) {
        Ok(mem) => mem,
        Err(_) => return false,
    };

    if mem
        .write_slice(queue_bytes_all, GuestAddress(BASE_VIRT_QUEUE_ADDR))
        .is_err()
    {
        return false;
    }
    if mem.write_slice(mem_bytes, GuestAddress(0)).is_err() {
        return false;
    }
    if !program_queue_memory(&mem, bytes, edge) {
        return false;
    }

    let guest_memory = GuestMemoryAtomic::new(mem);
    let mut queues_with_evts = Vec::with_capacity(NUM_QUEUES);
    for i in 0..NUM_QUEUES {
        let q = match build_queue(
            queue_base(i),
            &queue_data[i * QUEUE_DATA_SIZE..(i + 1) * QUEUE_DATA_SIZE],
            edge,
        ) {
            Some(q) => q,
            None => return false,
        };

        let evt = match EventFd::new(0) {
            Ok(evt) => evt,
            Err(_) => return false,
        };

        let kick_count = if edge {
            u64::from(pick(bytes, 14 + i) % 3)
        } else {
            1 + u64::from(pick(bytes, 20 + i) & 1)
        };
        if kick_count > 0 {
            let _ = evt.write(kick_count);
        }
        queues_with_evts.push((i as u16, q, evt));
    }

    let _ = queues_with_evts[1].2.write(1);
    if !edge || (pick(bytes, 24) & 1 != 0) {
        let _ = queues_with_evts[2].2.write(1);
    }

    let mut vsock = match virtio_devices::Vsock::new(
        if edge {
            "fuzzer_vsock_edge".to_owned()
        } else {
            "fuzzer_vsock_primary".to_owned()
        },
        0,
        if edge {
            vsock_path("edge")
        } else {
            vsock_path("primary")
        },
        backend,
        edge,
        SeccompAction::Allow,
        match EventFd::new(EFD_NONBLOCK) {
            Ok(fd) => fd,
            Err(_) => return false,
        },
        None,
    ) {
        Ok(vsock) => vsock,
        Err(_) => return false,
    };

    let interrupt_cb: Arc<dyn VirtioInterrupt> = Arc::new(HarnessInterrupt {
        fail_trigger: edge && (pick(bytes, 25) & 1 != 0),
    });

    let _ = vsock.activate(ActivationContext {
        mem: guest_memory,
        interrupt_cb,
        queues: queues_with_evts,
        device_status: Arc::new(AtomicU8::new(0)),
    });
    vsock.wait_for_epoll_threads();
    vsock.reset();
    vsock.shutdown();

    true
}

fn dispatch_fuzzed_event(
    ctx: &mut virtio_devices::vsock::tests::EpollHandlerContext<'_>,
    ev_type: u16,
    kick_queue: bool,
    invalid_evset: bool,
) {
    if invalid_evset {
        ctx.dispatch_raw_event(u32::MAX, ev_type);
        return;
    }

    match ev_type {
        RX_QUEUE_EVENT if kick_queue => ctx.signal_rxq_event(),
        TX_QUEUE_EVENT if kick_queue => ctx.signal_txq_event(),
        BACKEND_EVENT => ctx.signal_backend_event(),
        _ => ctx.dispatch_event(epoll::Events::EPOLLIN, ev_type),
    }
}

fn configure_handler_context(
    test_ctx: &TestContext,
    ctx: &mut virtio_devices::vsock::tests::EpollHandlerContext<'_>,
    bytes: &[u8],
    offset: usize,
) {
    ctx.configure_backend(
        pick(bytes, offset) & 1 != 0,
        (pick(bytes, offset + 1) & 1 != 0).then_some(VsockError::NoData),
        (pick(bytes, offset + 2) & 1 != 0).then_some(VsockError::NoData),
    );
    if pick(bytes, offset + 3) & 1 != 0 {
        ctx.fail_interrupt(true);
    }

    match pick(bytes, offset + 4) % 10 {
        0 => {}
        1 => ctx.guest_txvq.dtable[0].len.set(0),
        2 => ctx.guest_txvq.dtable[0].set(0x0050_0000, VSOCK_PKT_HDR_SIZE, VRING_DESC_F_WRITE, 0),
        3 => {
            let len = VSOCK_PKT_HDR_SIZE + 64;
            ctx.guest_txvq.dtable[0].set(0x0050_0000, len, 0, 0);
            let _ = write_tx_hdr_len(&test_ctx.mem, 0x0050_0000, len - VSOCK_PKT_HDR_SIZE);
        }
        4 => {
            ctx.guest_txvq.dtable[1].set(0x0050_1000, 16, 0, 0);
            let _ = write_tx_hdr_len(&test_ctx.mem, 0x0050_0000, 4096);
        }
        5 => ctx.guest_rxvq.dtable[0].len.set(0),
        6 => ctx.guest_rxvq.dtable[0].set(0x0040_0000, VSOCK_PKT_HDR_SIZE, 0, 0),
        7 => ctx.guest_rxvq.dtable[1].set(
            0x0040_1000,
            4096,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            0,
        ),
        8 => {
            let rx_hdr_addr = ctx.guest_rxvq.dtable[0].addr.get();
            let _ = write_tx_hdr_len(&test_ctx.mem, rx_hdr_addr, 70_000);
        }
        _ => {
            let tx_hdr_addr = ctx.guest_txvq.dtable[0].addr.get();
            let _ = write_tx_hdr_len(&test_ctx.mem, tx_hdr_addr, 70_000);
        }
    }
}

fn fuzzed_event_type(selector: u8) -> u16 {
    match selector % 5 {
        0 => RX_QUEUE_EVENT,
        1 => TX_QUEUE_EVENT,
        2 => EVT_QUEUE_EVENT,
        3 => BACKEND_EVENT,
        _ => 0xff,
    }
}

fn exercise_fixed_handler_events() {
    let test_ctx = TestContext::new();
    let mut ctx = test_ctx.create_epoll_handler_context();

    // Exercise the private handler directly so every event does not depend on
    // an asynchronous worker winning a scheduling race.
    ctx.dispatch_raw_event(u32::MAX, 0);
    ctx.dispatch_event(epoll::Events::EPOLLIN, 0xff);
    ctx.dispatch_event(epoll::Events::EPOLLIN, EVT_QUEUE_EVENT);
    ctx.dispatch_event(epoll::Events::EPOLLIN, RX_QUEUE_EVENT);
    ctx.dispatch_event(epoll::Events::EPOLLIN, TX_QUEUE_EVENT);
    ctx.configure_backend(true, None, None);
    ctx.signal_backend_event();
    ctx.configure_backend(true, Some(VsockError::NoData), Some(VsockError::NoData));
    ctx.fail_interrupt(true);
    ctx.signal_backend_event();
}

fn exercise_fuzzed_handler_context(bytes: &[u8], offset: usize) {
    let test_ctx = TestContext::new();
    let mut ctx = test_ctx.create_epoll_handler_context();
    configure_handler_context(&test_ctx, &mut ctx, bytes, offset);

    let event_count = 1 + usize::from(pick(bytes, offset + 5) % 4);
    for event_idx in 0..event_count {
        let event_offset = offset + 6 + event_idx * 3;
        dispatch_fuzzed_event(
            &mut ctx,
            fuzzed_event_type(pick(bytes, event_offset)),
            pick(bytes, event_offset + 1) & 1 != 0,
            pick(bytes, event_offset + 2) & 0x7 == 0,
        );
    }
}

fn exercise_handler_paths(bytes: &[u8]) {
    exercise_fixed_handler_events();
    exercise_fuzzed_handler_context(bytes, 26);
    exercise_fuzzed_handler_context(bytes, 48);
}

fn exercise_device_paths(bytes: &[u8]) {
    let mut device = match virtio_devices::Vsock::new(
        "fuzzer_vsock_device".to_owned(),
        52,
        vsock_path("device"),
        TestBackend::new(),
        pick(bytes, 42) & 1 != 0,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    ) {
        Ok(device) => device,
        Err(_) => return,
    };

    let _ = device.device_type();
    let _ = device.queue_max_sizes();
    let _ = device.features();

    let mut data_64 = [0u8; 8];
    let mut data_32 = [0u8; 4];
    device.read_config(0, &mut data_64);
    device.read_config(0, &mut data_32);
    device.read_config(4, &mut data_32);
    device.read_config(2, &mut data_64);
    device.write_config(0, &data_32);

    let feature_page = ((pick(bytes, 40) as u64) << 32) | pick(bytes, 41) as u64;
    device.ack_features(feature_page);

    let _ = device.pause();
    let _ = device.resume();
    let _ = device.snapshot();
    let _ = device.id();

    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return,
    };
    let memory = GuestMemoryAtomic::new(mem);
    let _ = device.activate(ActivationContext {
        mem: memory.clone(),
        interrupt_cb: Arc::new(HarnessInterrupt {
            fail_trigger: false,
        }),
        queues: Vec::new(),
        device_status: Arc::new(AtomicU8::new(0)),
    });

    let mut queues = Vec::with_capacity(NUM_QUEUES);
    for queue_index in 0..NUM_QUEUES {
        let queue_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let _ = queue_evt.write(1);
        queues.push((
            queue_index as u16,
            Queue::new(QUEUE_SIZE).unwrap(),
            queue_evt,
        ));
    }

    let _ = device.activate(ActivationContext {
        mem: memory,
        interrupt_cb: Arc::new(HarnessInterrupt {
            fail_trigger: false,
        }),
        queues,
        device_status: Arc::new(AtomicU8::new(0)),
    });
    device.wait_for_epoll_threads();
    device.reset();
    device.shutdown();
}

fn exercise_access_platform_path(bytes: &[u8]) {
    let mut backend = TestBackend::new();
    backend.set_pending_rx(pick(bytes, 45) & 1 != 0);

    let mut vsock = match virtio_devices::Vsock::new(
        "fuzzer_vsock_ap".to_owned(),
        0,
        vsock_path("access-platform"),
        backend,
        true,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
    ) {
        Ok(vsock) => vsock,
        Err(_) => return,
    };

    vsock.set_access_platform(Arc::new(IdentityAccessPlatform));
    let _ = vsock.access_platform();
    vsock.ack_features(1u64 << 33);
    let _ = vsock.access_platform();
}
