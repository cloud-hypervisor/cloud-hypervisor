// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{VirtioDevice, VirtioInterrupt, VirtioInterruptType};
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

const MEM_SIZE: usize = 1024 * 1024;
const DESC_COUNT: u16 = 8;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

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

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() {
        return Corpus::Reject;
    }

    let mut success = false;
    for (i, mode) in [0_u8, 1_u8, 2_u8, 3_u8, 4_u8].iter().enumerate() {
        if run_rng_case(bytes, i * 19, *mode).is_ok() {
            success = true;
        }
    }

    run_restore_case(bytes);
    run_bad_activate_case(bytes);
    run_invalid_path_case();

    if success {
        Corpus::Keep
    } else {
        Corpus::Reject
    }
});

fn run_rng_case(bytes: &[u8], offset: usize, mode: u8) -> Result<(), ()> {
    let mut cursor = FuzzCursor::with_index(bytes, offset);
    let enable_access_platform = mode != 0 || cursor.next_bool();
    let fail_on_odd = mode == 1 || cursor.next_bool();
    let fail_interrupt = mode == 2;
    let rng_source = if mode == 4 { "/" } else { "/dev/urandom" };

    let mut rng = virtio_devices::Rng::new(
        "fuzzer_rng".to_owned(),
        rng_source,
        enable_access_platform,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).map_err(|_| ())?,
        None,
    )
    .map_err(|_| ())?;

    let _ = rng.config_size();
    let _ = rng.device_type();
    let _ = rng.queue_max_sizes();

    if enable_access_platform {
        rng.set_access_platform(Arc::new(FuzzAccessPlatform { fail_on_odd }));
    }
    let features = rng.features();
    let acked = if cursor.next_bool() {
        features
    } else {
        u64::from(cursor.next_u16())
    };
    rng.ack_features(acked);
    if enable_access_platform {
        rng.ack_features(features);
    }
    let _ = rng.access_platform();

    let _ = rng.pause();
    let _ = rng.resume();
    let _ = Snapshottable::id(&rng);
    let _ = rng.snapshot();

    let mut q = setup_virt_queue(&mut cursor);
    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(DESC_TABLE_ADDR), QUEUE_BYTES_SIZE),
    ])
    .map_err(|_| ())?;

    populate_queue_memory(&mem, &mut q, &mut cursor, mode, fail_on_odd)?;
    let guest_memory = GuestMemoryAtomic::new(mem);

    let evt = EventFd::new(0).map_err(|_| ())?;
    let queue_evt_fd = unsafe { libc::dup(evt.as_raw_fd()) };
    if queue_evt_fd < 0 {
        return Err(());
    }
    let queue_evt = unsafe { EventFd::from_raw_fd(queue_evt_fd) };

    // Kick the 'queue' event before activating the device: under cfg(fuzzing)
    // the epoll loop returns as soon as no event is pending.
    let kicks = 1 + u64::from(cursor.next_u8() % 3);
    for _ in 0..kicks {
        let _ = queue_evt.write(1);
    }

    if rng
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(FuzzVirtioInterrupt { fail_interrupt }),
            queues: vec![(0, q, evt)],
            device_status: Arc::new(AtomicU8::new(cursor.next_u8())),
        })
        .is_err()
    {
        return Err(());
    }

    let _ = Snapshottable::id(&rng);
    let _ = rng.snapshot();
    rng.reset();
    rng.wait_for_epoll_threads();

    Ok(())
}

fn run_restore_case(bytes: &[u8]) {
    let mut cursor = FuzzCursor::with_index(bytes, 5);
    let Ok(exit_evt) = EventFd::new(EFD_NONBLOCK) else {
        return;
    };
    let Ok(mut source) = virtio_devices::Rng::new(
        "fuzzer_rng_restore_source".to_owned(),
        "/dev/urandom",
        cursor.next_bool(),
        SeccompAction::Allow,
        exit_evt,
        None,
    ) else {
        return;
    };

    let features = source.features();
    let acked = if cursor.next_bool() {
        features
    } else {
        u64::from(cursor.next_u16())
    };
    source.ack_features(acked);

    let Ok(snapshot) = source.snapshot() else {
        return;
    };
    let Ok(state) = snapshot.to_state() else {
        return;
    };
    let Ok(exit_evt) = EventFd::new(EFD_NONBLOCK) else {
        return;
    };
    let Ok(mut restored) = virtio_devices::Rng::new(
        "fuzzer_rng_restored".to_owned(),
        "/dev/urandom",
        cursor.next_bool(),
        SeccompAction::Allow,
        exit_evt,
        Some(state),
    ) else {
        return;
    };

    let _ = restored.pause();
    let _ = restored.resume();
    let _ = Snapshottable::id(&restored);
    let _ = restored.snapshot();
    restored.reset();
}

fn run_bad_activate_case(bytes: &[u8]) {
    let Ok(exit_evt) = EventFd::new(EFD_NONBLOCK) else {
        return;
    };
    let Ok(mut rng) = virtio_devices::Rng::new(
        "fuzzer_rng_bad_activate".to_owned(),
        "/dev/urandom",
        false,
        SeccompAction::Allow,
        exit_evt,
        None,
    ) else {
        return;
    };
    let Ok(mem) = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]) else {
        return;
    };
    let _ = rng.activate(virtio_devices::ActivationContext {
        mem: GuestMemoryAtomic::new(mem),
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fail_interrupt: false,
        }),
        queues: vec![],
        device_status: Arc::new(AtomicU8::new(bytes[0])),
    });
}

fn run_invalid_path_case() {
    if let Ok(exit_evt) = EventFd::new(EFD_NONBLOCK) {
        let _ = virtio_devices::Rng::new(
            "fuzzer_rng_invalid_path".to_owned(),
            "/__fuzz_rng_missing_source__",
            false,
            SeccompAction::Allow,
            exit_evt,
            None,
        );
    }
}

pub struct FuzzVirtioInterrupt {
    fail_interrupt: bool,
}

impl VirtioInterrupt for FuzzVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        if self.fail_interrupt {
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
        Ok(())
    }
}

#[derive(Debug)]
struct FuzzAccessPlatform {
    fail_on_odd: bool,
}

impl AccessPlatform for FuzzAccessPlatform {
    fn translate_gva(&self, base: u64, _size: u64) -> io::Result<u64> {
        if self.fail_on_odd && (base & 1) != 0 {
            return Err(io::Error::other("fuzz translation failure"));
        }
        Ok(base)
    }

    fn translate_gpa(&self, base: u64, _size: u64) -> io::Result<u64> {
        if self.fail_on_odd && (base & 1) != 0 {
            return Err(io::Error::other("fuzz translation failure"));
        }
        Ok(base)
    }
}

struct FuzzCursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> FuzzCursor<'a> {
    fn with_index(bytes: &'a [u8], index: usize) -> Self {
        Self {
            bytes,
            index: index % bytes.len(),
        }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.bytes[self.index % self.bytes.len()];
        self.index = self.index.wrapping_add(1);
        value
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }
}

fn setup_virt_queue(cursor: &mut FuzzCursor) -> Queue {
    let mut q = Queue::new(QUEUE_SIZE).unwrap();
    q.set_size(16);
    q.set_next_avail(0);
    q.set_next_used(cursor.next_u8() as u16 % q.size());
    q.set_event_idx(cursor.next_bool());

    q.try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .unwrap();
    q.try_set_used_ring_address(GuestAddress(USED_RING_ADDR))
        .unwrap();
    q.set_ready(true);

    q
}

fn populate_queue_memory(
    mem: &GuestMemoryMmap,
    q: &mut Queue,
    cursor: &mut FuzzCursor,
    mode: u8,
    fail_on_odd: bool,
) -> Result<(), ()> {
    let mut base = 0x1000_u64 + u64::from(cursor.next_u16()) * 32;
    base %= MEM_SIZE as u64 - 0x8000;
    base += 0x1000;
    base &= !1_u64;

    let valid_a = base;
    let valid_b = base + 0x400;
    let valid_c = base + 0x800;
    let valid_d = base + 0xc00;
    let invalid = MEM_SIZE as u64 - 16;
    let odd = valid_b | 1;
    let translate_sensitive = if fail_on_odd { odd } else { valid_b };

    if mode != 3 {
        write_desc(mem, 0, valid_a, 64, VRING_DESC_F_WRITE, 0)?;
        write_desc(mem, 1, valid_b, 32, 0, 0)?;
        write_desc(mem, 2, valid_c, 0, VRING_DESC_F_WRITE, 0)?;
        write_desc(mem, 3, invalid, 128, VRING_DESC_F_WRITE, 0)?;
        write_desc(mem, 4, translate_sensitive, 48, VRING_DESC_F_WRITE, 0)?;
        write_desc(
            mem,
            5,
            valid_d,
            24,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            6,
        )?;
        write_desc(mem, 6, valid_d + 0x100, 24, VRING_DESC_F_WRITE, 0)?;
        write_desc(
            mem,
            7,
            valid_d + 0x200,
            16,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            q.size() + 1,
        )?;
    }

    let avail_flags = cursor.next_u16();
    let avail_idx = if mode == 3 { 0 } else { DESC_COUNT };
    write_u16(mem, AVAIL_RING_ADDR, avail_flags)?;
    write_u16(mem, AVAIL_RING_ADDR + 2, avail_idx)?;

    for i in 0..avail_idx {
        write_u16(mem, AVAIL_RING_ADDR + 4 + u64::from(i) * 2, i)?;
    }
    write_u16(mem, AVAIL_RING_ADDR + 4 + u64::from(q.size()) * 2, 0)?;

    q.set_next_avail(0);
    Ok(())
}

fn write_u16(mem: &GuestMemoryMmap, addr: u64, value: u16) -> Result<(), ()> {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .map_err(|_| ())
}

fn write_desc(
    mem: &GuestMemoryMmap,
    index: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> Result<(), ()> {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&addr.to_le_bytes());
    raw[8..12].copy_from_slice(&len.to_le_bytes());
    raw[12..14].copy_from_slice(&flags.to_le_bytes());
    raw[14..16].copy_from_slice(&next.to_le_bytes());
    let offset = DESC_TABLE_ADDR + u64::from(index) * 16;
    mem.write_slice(&raw, GuestAddress(offset)).map_err(|_| ())
}
