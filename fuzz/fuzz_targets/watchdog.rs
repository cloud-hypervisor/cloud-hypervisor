// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::watchdog::WatchdogState;
use virtio_devices::{VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vm_migration::{Pausable, Snapshottable};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEM_SIZE: usize = 2 * 1024 * 1024;
const QUEUE_SIZE: u16 = 8;
const DESC_TABLE_ADDR: u64 = 0x1000;
const DESC_TABLE_SIZE: u64 = 16 * QUEUE_SIZE as u64;
const AVAIL_RING_ADDR: u64 = DESC_TABLE_ADDR + DESC_TABLE_SIZE;
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
const USED_RING_ADDR: u64 = (AVAIL_RING_ADDR + AVAIL_RING_SIZE + 3) & !3_u64;
const DATA_ADDR: u64 = 0x4000;
const VRING_DESC_F_WRITE: u16 = 2;

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() {
        return Corpus::Reject;
    }

    if run_watchdog_harness(bytes).is_err() {
        return Corpus::Reject;
    }

    Corpus::Keep
});

#[derive(Clone, Copy)]
enum DescriptorMode {
    None,
    ValidWrite,
    ReadOnly,
    EmptyWrite,
    OobWrite,
}

#[derive(Clone, Copy)]
enum ActivationMode {
    Normal,
    EmptyQueues,
}

#[derive(Clone, Copy)]
enum QueueEventMode {
    EventFd,
    ShortPipe,
}

struct CaseConfig {
    desc_mode: DescriptorMode,
    activation_mode: ActivationMode,
    queue_event_mode: QueueEventMode,
    fail_interrupt: bool,
    invalid_used_ring: bool,
    pre_activate_pause_resume: bool,
    post_activate_pause_resume: bool,
    access_platform_enabled: bool,
    state: Option<WatchdogState>,
    arm_short_timer: bool,
    pre_kicks: usize,
    post_kicks: usize,
}

fn run_watchdog_harness(bytes: &[u8]) -> Result<(), ()> {
    let mut success = false;

    for mode in 0..12 {
        if run_watchdog_case(bytes, mode).is_ok() {
            success = true;
        }
    }

    if success {
        Ok(())
    } else {
        Err(())
    }
}

fn case_config(mode: usize, cursor: &mut FuzzCursor) -> CaseConfig {
    let (pre_kicks, post_kicks) = kick_counts(cursor);

    match mode {
        0 => CaseConfig {
            desc_mode: DescriptorMode::ValidWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        1 => CaseConfig {
            desc_mode: DescriptorMode::ReadOnly,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        2 => CaseConfig {
            desc_mode: DescriptorMode::EmptyWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        3 => CaseConfig {
            desc_mode: DescriptorMode::OobWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        4 => CaseConfig {
            desc_mode: DescriptorMode::ValidWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: true,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: true,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        5 => CaseConfig {
            desc_mode: DescriptorMode::ValidWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: true,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        6 => CaseConfig {
            desc_mode: DescriptorMode::None,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: true,
            post_activate_pause_resume: false,
            access_platform_enabled: true,
            state: Some(WatchdogState {
                avail_features: u64::from(cursor.next_u8()),
                acked_features: u64::from(cursor.next_u8()),
                enabled: false,
            }),
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        7 => CaseConfig {
            desc_mode: DescriptorMode::ValidWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: true,
            post_activate_pause_resume: false,
            access_platform_enabled: true,
            state: Some(WatchdogState {
                avail_features: u64::from(cursor.next_u8()),
                acked_features: u64::from(cursor.next_u8()),
                enabled: true,
            }),
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        8 => CaseConfig {
            desc_mode: DescriptorMode::None,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: true,
            access_platform_enabled: true,
            state: Some(WatchdogState {
                avail_features: u64::from(cursor.next_u8()),
                acked_features: u64::from(cursor.next_u8()),
                enabled: true,
            }),
            arm_short_timer: cursor.next_u8() != 0,
            pre_kicks,
            post_kicks,
        },
        9 => CaseConfig {
            desc_mode: DescriptorMode::None,
            activation_mode: if cursor.next_bool() {
                ActivationMode::EmptyQueues
            } else {
                ActivationMode::Normal
            },
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        10 => CaseConfig {
            desc_mode: DescriptorMode::ValidWrite,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: if cursor.next_bool() {
                QueueEventMode::ShortPipe
            } else {
                QueueEventMode::EventFd
            },
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: false,
            state: None,
            arm_short_timer: false,
            pre_kicks,
            post_kicks,
        },
        _ => CaseConfig {
            desc_mode: DescriptorMode::None,
            activation_mode: ActivationMode::Normal,
            queue_event_mode: QueueEventMode::EventFd,
            fail_interrupt: false,
            invalid_used_ring: false,
            pre_activate_pause_resume: false,
            post_activate_pause_resume: false,
            access_platform_enabled: true,
            state: Some(WatchdogState {
                avail_features: u64::from(cursor.next_u8()),
                acked_features: u64::from(cursor.next_u8()),
                enabled: true,
            }),
            arm_short_timer: true,
            pre_kicks,
            post_kicks,
        },
    }
}

fn kick_counts(cursor: &mut FuzzCursor) -> (usize, usize) {
    (
        1 + usize::from(cursor.next_u8() % 3),
        usize::from(cursor.next_u8() % 3),
    )
}

fn run_watchdog_case(bytes: &[u8], mode: usize) -> Result<(), ()> {
    let mut cursor = FuzzCursor::with_index(bytes, mode * 17);
    let config = case_config(mode, &mut cursor);

    let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(|_| ())?;
    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(|_| ())?;

    let mut watchdog = virtio_devices::Watchdog::new(
        format!("fuzzer_watchdog_{mode}"),
        config.access_platform_enabled,
        reset_evt.try_clone().map_err(|_| ())?,
        SeccompAction::Allow,
        exit_evt,
        config.state,
    )
    .map_err(|_| ())?;

    let _ = watchdog.config_size();
    let _ = watchdog.device_type();
    let _ = watchdog.queue_max_sizes();
    let features = watchdog.features();
    watchdog.ack_features(features);
    watchdog.ack_features(u64::from(cursor.next_u8()) << 56);

    if config.pre_activate_pause_resume {
        let _ = watchdog.pause();
        let _ = watchdog.resume();
    }

    if config.arm_short_timer || mode == 8 || mode == 11 {
        watchdog.arm_timer_for_fuzzing().map_err(|_| ())?;
    }
    if mode == 11 {
        let (timer, writer) = timer_pipe()?;
        let _old_timer = watchdog.inject_timer_for_fuzzing(timer);
        drop(writer);
    }

    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).map_err(|_| ())?;
    seed_memory(&mem, &mut cursor)?;
    let queue = setup_virt_queue(&mut cursor, config.invalid_used_ring)?;
    populate_queue_memory(&mem, config.desc_mode, &mut cursor)?;
    let guest_memory = GuestMemoryAtomic::new(mem);

    let (evt, queue_evt) = make_queue_event(config.queue_event_mode, config.pre_kicks)?;

    let queues = match config.activation_mode {
        ActivationMode::Normal => vec![(0, queue, evt)],
        ActivationMode::EmptyQueues => Vec::new(),
    };
    let activate_result = watchdog.activate(virtio_devices::ActivationContext {
        mem: guest_memory,
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fail_on_trigger: config.fail_interrupt,
        }),
        queues,
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
    });
    match config.activation_mode {
        ActivationMode::Normal => activate_result.map_err(|_| ())?,
        ActivationMode::EmptyQueues => {
            if activate_result.is_ok() {
                watchdog.wait_for_epoll_threads();
                return Err(());
            }
            let _ = Snapshottable::id(&watchdog);
            let _ = watchdog.snapshot();
            watchdog.reset();
            return Ok(());
        }
    }

    if config.post_activate_pause_resume {
        let _ = watchdog.pause();
        let _ = watchdog.resume();
    }

    if let Some(queue_evt) = queue_evt {
        let _ = queue_evt.write(1);
        for _ in 0..config.post_kicks {
            let _ = queue_evt.write(1);
        }
    }

    watchdog.wait_for_epoll_threads();

    let _ = Snapshottable::id(&watchdog);
    let _ = watchdog.snapshot();
    watchdog.reset();
    let _ = watchdog.pause();
    let _ = watchdog.resume();

    Ok(())
}

fn dup_eventfd(evt: &EventFd) -> Result<EventFd, ()> {
    // SAFETY: dup() is called with a valid eventfd owned by evt.
    let fd = unsafe { libc::dup(evt.as_raw_fd()) };
    if fd < 0 {
        return Err(());
    }

    // SAFETY: dup() returned a new owned file descriptor.
    Ok(unsafe { EventFd::from_raw_fd(fd) })
}

fn make_queue_event(
    mode: QueueEventMode,
    pre_kicks: usize,
) -> Result<(EventFd, Option<EventFd>), ()> {
    match mode {
        QueueEventMode::EventFd => {
            let evt = EventFd::new(EFD_NONBLOCK).map_err(|_| ())?;
            let queue_evt = dup_eventfd(&evt)?;
            for _ in 0..pre_kicks {
                let _ = queue_evt.write(1);
            }
            Ok((evt, Some(queue_evt)))
        }
        QueueEventMode::ShortPipe => Ok((short_pipe_queue_event()?, None)),
    }
}

fn short_pipe_queue_event() -> Result<EventFd, ()> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two valid integers for pipe2 to initialize.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        return Err(());
    }

    let byte = [1u8];
    // SAFETY: fds[1] is the pipe write end and byte points to one initialized byte.
    let written = unsafe { libc::write(fds[1], byte.as_ptr().cast(), byte.len()) };
    close_fd(fds[1]);
    if written != 1 {
        close_fd(fds[0]);
        return Err(());
    }

    // SAFETY: fds[0] is an owned read end. The watchdog only reads from it.
    Ok(unsafe { EventFd::from_raw_fd(fds[0]) })
}

fn close_fd(fd: RawFd) {
    // SAFETY: callers pass owned raw fds that should be closed here.
    let _ = unsafe { libc::close(fd) };
}

fn timer_pipe() -> Result<(std::fs::File, std::fs::File), ()> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two valid integers for pipe2 to initialize.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        return Err(());
    }
    // SAFETY: pipe2 returned two owned descriptors.
    Ok((unsafe { std::fs::File::from_raw_fd(fds[0]) }, unsafe {
        std::fs::File::from_raw_fd(fds[1])
    }))
}

fn seed_memory(mem: &GuestMemoryMmap, cursor: &mut FuzzCursor) -> Result<(), ()> {
    let mut seed = [0u8; 512];
    cursor.fill_slice(&mut seed);
    mem.write_slice(&seed, GuestAddress(DATA_ADDR))
        .map_err(|_| ())?;

    Ok(())
}

fn setup_virt_queue(_cursor: &mut FuzzCursor, invalid_used_ring: bool) -> Result<Queue, ()> {
    let mut q = Queue::new(QUEUE_SIZE).map_err(|_| ())?;
    q.set_next_avail(0);
    // Keep one valid baseline queue deterministic; malformed descriptor and
    // event cases are selected by the per-mode configuration below.
    q.set_next_used(0);
    q.set_event_idx(false);
    q.set_size(QUEUE_SIZE);

    q.try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .map_err(|_| ())?;
    q.try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .map_err(|_| ())?;

    let used_ring_addr = if invalid_used_ring {
        (MEM_SIZE as u64).saturating_sub(4)
    } else {
        USED_RING_ADDR
    };
    q.try_set_used_ring_address(GuestAddress(used_ring_addr))
        .map_err(|_| ())?;
    q.set_ready(true);

    Ok(q)
}

fn populate_queue_memory(
    mem: &GuestMemoryMmap,
    desc_mode: DescriptorMode,
    cursor: &mut FuzzCursor,
) -> Result<(), ()> {
    let (addr, len, flags) = match desc_mode {
        DescriptorMode::None => (DATA_ADDR, 1, VRING_DESC_F_WRITE),
        DescriptorMode::ValidWrite => (
            DATA_ADDR + u64::from(cursor.next_u8()) * 8,
            1 + u32::from(cursor.next_u8() % 32),
            VRING_DESC_F_WRITE,
        ),
        DescriptorMode::ReadOnly => (
            DATA_ADDR + u64::from(cursor.next_u8()) * 8,
            1 + u32::from(cursor.next_u8() % 32),
            0,
        ),
        DescriptorMode::EmptyWrite => (DATA_ADDR, 0, VRING_DESC_F_WRITE),
        DescriptorMode::OobWrite => (MEM_SIZE as u64, 16, VRING_DESC_F_WRITE),
    };

    write_desc(mem, 0, addr, len, flags, 0)?;

    write_u16(mem, AVAIL_RING_ADDR, cursor.next_u8() as u16)?;
    if matches!(desc_mode, DescriptorMode::None) {
        write_u16(mem, AVAIL_RING_ADDR + 2, 0)?;
    } else {
        write_u16(mem, AVAIL_RING_ADDR + 2, 1)?;
        write_u16(mem, AVAIL_RING_ADDR + 6, 0)?;
    }
    write_u16(mem, AVAIL_RING_ADDR + 4, 0)?;

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

pub struct FuzzVirtioInterrupt {
    fail_on_trigger: bool,
}

impl VirtioInterrupt for FuzzVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        if self.fail_on_trigger {
            Err(io::Error::other("fuzz interrupt error"))
        } else {
            Ok(())
        }
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
        let v = self.bytes[self.index % self.bytes.len()];
        self.index = self.index.wrapping_add(1);
        v
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }

    fn fill_slice(&mut self, slice: &mut [u8]) {
        for b in slice {
            *b = self.next_u8();
        }
    }
}
