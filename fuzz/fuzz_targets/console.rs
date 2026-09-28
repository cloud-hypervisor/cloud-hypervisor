// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{Endpoint, VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vm_migration::{Pausable, Snapshot, Snapshottable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

const CONSOLE_INPUT_SIZE: usize = 128;
const MEM_SIZE: usize = 32 * 1024 * 1024;
const MIN_INPUT_SIZE: usize = 64;
// Guest memory gap
const GUEST_MEM_GAP: u64 = 1024 * 1024;
// Guest physical address for the first virt queue
const BASE_VIRT_QUEUE_ADDR: u64 = MEM_SIZE as u64 + GUEST_MEM_GAP;
// Number of queues
const QUEUE_NUM: usize = 2;
// Max entries in the queue.
const QUEUE_SIZE: u16 = 256;
// Descriptor table alignment
const DESC_TABLE_ALIGN_SIZE: u64 = 16;
// Used ring alignment
const USED_RING_ALIGN_SIZE: u64 = 4;
// Descriptor table size
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
// Available ring size
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
// Padding size before used ring
const PADDING_SIZE: u64 = align!(AVAIL_RING_SIZE, USED_RING_ALIGN_SIZE) - AVAIL_RING_SIZE;
// Used ring size
const USED_RING_SIZE: u64 = 6_u64 + 8 * QUEUE_SIZE as u64;
// Virtio-queue size in bytes
const QUEUE_BYTES_SIZE: usize = align!(
    DESC_TABLE_SIZE + AVAIL_RING_SIZE + PADDING_SIZE + USED_RING_SIZE,
    DESC_TABLE_ALIGN_SIZE
) as usize;
const QUEUE_REGION_SIZE: usize = QUEUE_BYTES_SIZE * QUEUE_NUM;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;
const DESCRIPTORS_PER_QUEUE: u16 = 4;
const VIRTIO_CONSOLE_F_SIZE: u64 = 0;
const VIRTIO_F_ACCESS_PLATFORM: u64 = 33;

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputDescriptorMode {
    Fuzz,
    Readable,
    Writable,
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < MIN_INPUT_SIZE {
        return Corpus::Reject;
    }

    if run_console_harness(bytes).is_err() {
        return Corpus::Reject;
    }

    Corpus::Keep
});

fn run_console_harness(bytes: &[u8]) -> Result<(), ()> {
    let mut success = false;
    let modes = [0_u8, 1, 2, 3, 4, 5, 6, bytes[0] % 8];
    for (i, mode) in modes.iter().enumerate() {
        if run_console_case(bytes, i * 23, *mode).is_ok() {
            success = true;
        }
    }

    if success {
        Ok(())
    } else {
        Err(())
    }
}

fn run_console_case(bytes: &[u8], cursor_offset: usize, mode: u8) -> Result<(), ()> {
    let mut cursor = FuzzCursor::with_index(bytes, cursor_offset);
    let mut endpoint = create_endpoint(mode).map_err(|_| ())?;
    let use_resize_pipe = mode != 6 || cursor.next_bool();
    let (resize_rx, mut resize_tx) = if use_resize_pipe {
        let (rx, tx) = create_pipe().map_err(|_| ())?;
        (Some(rx), Some(tx))
    } else {
        (None, None)
    };
    let access_platform_enabled = mode == 6 || cursor.next_bool();

    let (mut console, _) = virtio_devices::Console::new(
        "fuzzer_console".to_owned(),
        endpoint.endpoint.clone(),
        resize_rx,
        access_platform_enabled,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).map_err(|_| ())?,
        None,
    )
    .map_err(|_| ())?;

    let _ = console.device_type();
    let _ = console.queue_max_sizes();
    if mode != 2 || cursor.next_bool() {
        let mut acked_features = 1u64 << VIRTIO_CONSOLE_F_SIZE;
        if access_platform_enabled && (mode == 6 || cursor.next_bool()) {
            acked_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }
        console.ack_features(console.features() & acked_features);
    }
    if access_platform_enabled || cursor.next_bool() {
        console.set_access_platform(Arc::new(FuzzAccessPlatform {
            fail_on_odd: cursor.next_bool(),
        }));
    }
    let _ = console.access_platform();
    if mode == 2 || cursor.next_bool() {
        let _ = Pausable::pause(&mut console);
        let _ = Pausable::resume(&mut console);
    }

    if mode == 2 || cursor.next_u8() == 0 {
        exercise_activation_failure(endpoint.endpoint.clone(), access_platform_enabled)?;
    }

    if mode == 0 || mode == 1 || cursor.next_u8() & 0x7 == 0 {
        if let Ok(snapshot) = console.snapshot() {
            let restored_state = snapshot.to_state().ok();
            let (restored_resize_rx, restored_resize_tx) = if use_resize_pipe {
                let (rx, tx) = create_pipe().map_err(|_| ())?;
                (Some(rx), Some(tx))
            } else {
                (None, None)
            };
            let (mut restored_console, _) = virtio_devices::Console::new(
                "fuzzer_console_restored".to_owned(),
                endpoint.endpoint.clone(),
                restored_resize_rx,
                access_platform_enabled,
                SeccompAction::Allow,
                EventFd::new(EFD_NONBLOCK).map_err(|_| ())?,
                restored_state,
            )
            .map_err(|_| ())?;
            if access_platform_enabled {
                restored_console.set_access_platform(Arc::new(FuzzAccessPlatform {
                    fail_on_odd: cursor.next_bool(),
                }));
            }
            console = restored_console;
            resize_tx = restored_resize_tx;
        }
    }

    let bad_used_ring_mask = match mode {
        6 => 1,
        7 => 2,
        _ if cursor.next_u8() & 0x3f == 0 => 1 << (cursor.next_u8() & 1),
        _ => 0,
    };
    let mut queues = setup_virt_queues(&mut cursor, BASE_VIRT_QUEUE_ADDR, bad_used_ring_mask);
    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(BASE_VIRT_QUEUE_ADDR), QUEUE_REGION_SIZE),
    ])
    .map_err(|_| ())?;

    for (queue_index, queue) in queues.iter_mut().enumerate() {
        let input_mode = if mode == 6 {
            InputDescriptorMode::Readable
        } else {
            InputDescriptorMode::Fuzz
        };
        if !populate_queue_memory(
            &mem,
            queue_index,
            queue,
            queue_index == 0,
            input_mode,
            &mut cursor,
        ) {
            return Err(());
        }
    }

    let guest_memory = GuestMemoryAtomic::new(mem);

    let input_queue = queues.remove(0);
    let input_evt = EventFd::new(0).map_err(|_| ())?;
    let input_queue_evt = dup_eventfd(&input_evt).map_err(|_| ())?;
    let output_queue = queues.remove(0);
    let output_evt = EventFd::new(0).map_err(|_| ())?;
    let output_queue_evt = dup_eventfd(&output_evt).map_err(|_| ())?;

    let bursts = 1 + (cursor.next_u8() as usize % 3);
    let mut staged_input = Vec::new();
    for _ in 0..bursts {
        let len = 1 + (cursor.next_u8() as usize % CONSOLE_INPUT_SIZE);
        let mut chunk = vec![0u8; len];
        cursor.fill_slice(&mut chunk);
        staged_input.extend(chunk);
    }
    if let Some(input_tx) = endpoint.input_tx.as_mut() {
        let _ = input_tx.write_all(&staged_input);
        let _ = input_tx.flush();
    }
    if endpoint.is_pty && cursor.next_bool() {
        endpoint.input_tx = None;
    }

    // Stage every stimulus before activating: under cfg(fuzzing) the epoll loop
    // returns as soon as no event is pending, so later writes race the worker.
    if mode == 3 {
        drop(resize_tx.take());
    } else if let Some(resize_tx) = resize_tx.as_mut() {
        let _ = resize_tx.write_all(&[cursor.next_u8()]);
    }
    let _ = input_queue_evt.write(1);
    let _ = output_queue_evt.write(1);
    let _ = input_queue_evt.write(1);
    let _ = output_queue_evt.write(1);
    let interrupt = Arc::new(FuzzVirtioInterrupt {
        fail_config: mode == 5 || cursor.next_u8() == 0,
        fail_queue: mode == 4 || cursor.next_u8() == 0,
    });

    if console
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: interrupt,
            queues: vec![(0, input_queue, input_evt), (1, output_queue, output_evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .is_err()
    {
        return Err(());
    }

    let mut config = [0u8; std::mem::size_of::<u64>()];
    console.read_config(0, &mut config);
    let _ = Snapshottable::id(&console);
    let _ = console.snapshot();
    console.wait_for_epoll_threads();
    if mode == 6 {
        if let Ok(snapshot) = console.snapshot() {
            let _ = exercise_restored_input_queue(
                endpoint.endpoint.clone(),
                &snapshot,
                &mut cursor,
                access_platform_enabled,
                false,
                true,
            );
            let _ = exercise_restored_input_queue(
                endpoint.endpoint.clone(),
                &snapshot,
                &mut cursor,
                access_platform_enabled,
                true,
                false,
            );
        }
        let _ = exercise_queue_event_read_error(&mut cursor, true);
        let _ = exercise_queue_event_read_error(&mut cursor, false);
    }
    console.reset();

    Ok(())
}

fn exercise_queue_event_read_error(
    cursor: &mut FuzzCursor,
    input_event_error: bool,
) -> Result<(), ()> {
    let (mut console, _) = virtio_devices::Console::new(
        "fuzzer_console_bad_queue_evt".to_owned(),
        Endpoint::Null,
        None,
        false,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).map_err(|_| ())?,
        None,
    )
    .map_err(|_| ())?;

    let mut queues = setup_virt_queues(cursor, BASE_VIRT_QUEUE_ADDR, 0);
    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(BASE_VIRT_QUEUE_ADDR), QUEUE_REGION_SIZE),
    ])
    .map_err(|_| ())?;
    for (queue_index, queue) in queues.iter_mut().enumerate() {
        if !populate_queue_memory(
            &mem,
            queue_index,
            queue,
            queue_index == 0,
            InputDescriptorMode::Writable,
            cursor,
        ) {
            return Err(());
        }
    }

    let input_queue = queues.remove(0);
    let output_queue = queues.remove(0);
    let input_evt = if input_event_error {
        create_broken_eventfd().map_err(|_| ())?
    } else {
        EventFd::new(0).map_err(|_| ())?
    };
    let output_evt = if input_event_error {
        EventFd::new(0).map_err(|_| ())?
    } else {
        create_broken_eventfd().map_err(|_| ())?
    };

    if console
        .activate(virtio_devices::ActivationContext {
            mem: GuestMemoryAtomic::new(mem),
            interrupt_cb: Arc::new(FuzzVirtioInterrupt {
                fail_config: false,
                fail_queue: false,
            }),
            queues: vec![(0, input_queue, input_evt), (1, output_queue, output_evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .is_err()
    {
        return Err(());
    }
    console.wait_for_epoll_threads();
    console.reset();

    Ok(())
}

fn exercise_activation_failure(
    endpoint: Endpoint,
    access_platform_enabled: bool,
) -> Result<(), ()> {
    let (mut console, _) = virtio_devices::Console::new(
        "fuzzer_console_bad_activate".to_owned(),
        endpoint,
        None,
        access_platform_enabled,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).map_err(|_| ())?,
        None,
    )
    .map_err(|_| ())?;
    let mem = GuestMemoryAtomic::new(
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).map_err(|_| ())?,
    );

    let _ = console.activate(virtio_devices::ActivationContext {
        mem,
        interrupt_cb: Arc::new(FuzzVirtioInterrupt {
            fail_config: false,
            fail_queue: false,
        }),
        queues: Vec::new(),
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
    });

    Ok(())
}

fn exercise_restored_input_queue(
    endpoint: Endpoint,
    snapshot: &Snapshot,
    cursor: &mut FuzzCursor,
    access_platform_enabled: bool,
    bad_used_ring: bool,
    fail_queue: bool,
) -> Result<(), ()> {
    let restored_state = snapshot.to_state().ok();
    let (mut console, _) = virtio_devices::Console::new(
        "fuzzer_console_restored_input".to_owned(),
        endpoint,
        None,
        access_platform_enabled,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK).map_err(|_| ())?,
        restored_state,
    )
    .map_err(|_| ())?;
    if access_platform_enabled {
        console.set_access_platform(Arc::new(FuzzAccessPlatform { fail_on_odd: false }));
    }

    let bad_used_ring_mask = if bad_used_ring { 1 } else { 0 };
    let mut queues = setup_virt_queues(cursor, BASE_VIRT_QUEUE_ADDR, bad_used_ring_mask);
    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(BASE_VIRT_QUEUE_ADDR), QUEUE_REGION_SIZE),
    ])
    .map_err(|_| ())?;
    for (queue_index, queue) in queues.iter_mut().enumerate() {
        if !populate_queue_memory(
            &mem,
            queue_index,
            queue,
            queue_index == 0,
            InputDescriptorMode::Writable,
            cursor,
        ) {
            return Err(());
        }
    }

    let guest_memory = GuestMemoryAtomic::new(mem);
    let input_queue = queues.remove(0);
    let input_evt = EventFd::new(0).map_err(|_| ())?;
    let input_queue_evt = dup_eventfd(&input_evt).map_err(|_| ())?;
    let output_queue = queues.remove(0);
    let output_evt = EventFd::new(0).map_err(|_| ())?;
    let _ = input_queue_evt.write(1);

    if console
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(FuzzVirtioInterrupt {
                fail_config: false,
                fail_queue,
            }),
            queues: vec![(0, input_queue, input_evt), (1, output_queue, output_evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .is_err()
    {
        return Err(());
    }
    console.wait_for_epoll_threads();
    console.reset();

    Ok(())
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

pub struct FuzzVirtioInterrupt {
    fail_config: bool,
    fail_queue: bool,
}

impl VirtioInterrupt for FuzzVirtioInterrupt {
    fn trigger(&self, int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        match int_type {
            VirtioInterruptType::Config if self.fail_config => {
                return Err(io::Error::other("fuzz config interrupt failure"));
            }
            VirtioInterruptType::Queue(_) if self.fail_queue => {
                return Err(io::Error::other("fuzz queue interrupt failure"));
            }
            _ => {}
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

    fn fill_slice(&mut self, slice: &mut [u8]) {
        for byte in slice.iter_mut() {
            *byte = self.next_u8();
        }
    }
}

struct EndpointContext {
    endpoint: Endpoint,
    input_tx: Option<File>,
    is_pty: bool,
}

fn create_endpoint(mode: u8) -> Result<EndpointContext, std::io::Error> {
    match mode % 8 {
        0 => {
            let output = Arc::new(create_output_file()?);
            let (pipe_rx, pipe_tx) = create_pipe()?;
            Ok(EndpointContext {
                endpoint: Endpoint::FilePair(output, Arc::new(pipe_rx)),
                input_tx: Some(pipe_tx),
                is_pty: false,
            })
        }
        1 => {
            let output = Arc::new(create_output_file()?);
            let (pipe_rx, pipe_tx) = create_pipe()?;
            Ok(EndpointContext {
                endpoint: Endpoint::PtyPair(output, Arc::new(pipe_rx)),
                input_tx: Some(pipe_tx),
                is_pty: true,
            })
        }
        2 => Ok(EndpointContext {
            endpoint: Endpoint::Null,
            input_tx: None,
            is_pty: false,
        }),
        3 => {
            let output = Arc::new(create_output_file()?);
            Ok(EndpointContext {
                endpoint: Endpoint::File(output),
                input_tx: None,
                is_pty: false,
            })
        }
        4 | 6 => {
            let output = Arc::new(create_read_only_file()?);
            let (pipe_rx, pipe_tx) = create_pipe()?;
            Ok(EndpointContext {
                endpoint: Endpoint::FilePair(output, Arc::new(pipe_rx)),
                input_tx: Some(pipe_tx),
                is_pty: false,
            })
        }
        5 => {
            let output = Arc::new(create_read_only_file()?);
            let (pipe_rx, pipe_tx) = create_pipe()?;
            Ok(EndpointContext {
                endpoint: Endpoint::PtyPair(output, Arc::new(pipe_rx)),
                input_tx: Some(pipe_tx),
                is_pty: true,
            })
        }
        _ => {
            let output = Arc::new(create_read_only_file()?);
            Ok(EndpointContext {
                endpoint: Endpoint::File(output),
                input_tx: None,
                is_pty: false,
            })
        }
    }
}

fn create_output_file() -> Result<File, std::io::Error> {
    let name = CString::new("fuzz_console_output")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid memfd name"))?;
    // SAFETY: memfd_create returns a valid owned fd on success.
    unsafe { Ok(File::from_raw_fd(memfd_create(&name)?)) }
}

fn create_read_only_file() -> Result<File, std::io::Error> {
    let (pipe_rx, _) = create_pipe()?;
    Ok(pipe_rx)
}

fn setup_virt_queues(
    cursor: &mut FuzzCursor,
    base_addr: u64,
    bad_used_ring_mask: u8,
) -> Vec<Queue> {
    let mut queues = Vec::new();
    for i in 0..QUEUE_NUM {
        let mut q = Queue::new(QUEUE_SIZE).unwrap();

        let desc_table_addr = base_addr + (QUEUE_BYTES_SIZE * i) as u64;
        let avail_ring_addr = desc_table_addr + DESC_TABLE_SIZE;
        let used_ring_addr = if bad_used_ring_mask & (1 << i) != 0 {
            MEM_SIZE as u64 + QUEUE_REGION_SIZE as u64 + GUEST_MEM_GAP
        } else {
            avail_ring_addr + PADDING_SIZE + AVAIL_RING_SIZE
        };
        q.try_set_desc_table_address(GuestAddress(desc_table_addr))
            .unwrap();
        q.try_set_avail_ring_address(GuestAddress(avail_ring_addr))
            .unwrap();
        q.try_set_used_ring_address(GuestAddress(used_ring_addr))
            .unwrap();

        let mut queue_size = 1u16 << ((cursor.next_u8() % 5) + 2);
        queue_size = queue_size.clamp(DESCRIPTORS_PER_QUEUE, QUEUE_SIZE);
        q.set_size(queue_size);
        q.set_next_avail(0);
        q.set_next_used(cursor.next_u8() as u16 % queue_size);
        q.set_event_idx(cursor.next_bool());

        q.set_ready(true);
        queues.push(q);
    }

    queues
}

fn populate_queue_memory(
    mem: &GuestMemoryMmap,
    queue_index: usize,
    queue: &mut Queue,
    is_input: bool,
    input_mode: InputDescriptorMode,
    cursor: &mut FuzzCursor,
) -> bool {
    if queue.size() < DESCRIPTORS_PER_QUEUE {
        return false;
    }

    let desc_table_addr = BASE_VIRT_QUEUE_ADDR + (QUEUE_BYTES_SIZE * queue_index) as u64;
    let avail_ring_addr = desc_table_addr + DESC_TABLE_SIZE;

    let second_chain = cursor.next_bool();
    let mut avail_idx = if is_input {
        if second_chain {
            2
        } else {
            1
        }
    } else {
        (cursor.next_u8() % 3) as u16
    };
    if !is_input && avail_idx == 0 && cursor.next_bool() {
        avail_idx = 1;
    }

    let mut data_addr = 0x1000 + ((cursor.next_u16() as u64) * 64 % (MEM_SIZE as u64 - 0x4000));
    for desc_index in 0..DESCRIPTORS_PER_QUEUE {
        let mut len = (cursor.next_u8() as u32 % 192) + 1;
        if input_mode != InputDescriptorMode::Writable && cursor.next_u8() & 0x7 == 0 {
            len = 0;
        }

        let invalid_desc =
            input_mode != InputDescriptorMode::Writable && cursor.next_u8() & 0x1f == 0;
        let addr = if invalid_desc {
            len = 256;
            MEM_SIZE as u64 - 32
        } else if cursor.next_u8() & 0x3f == 0 {
            data_addr | 1
        } else {
            data_addr
        };

        if !invalid_desc {
            data_addr = data_addr.saturating_add(len as u64 + 0x80);
            if data_addr + 0x400 >= MEM_SIZE as u64 {
                data_addr = 0x1000;
            }
        }

        let write_only = if is_input {
            match input_mode {
                InputDescriptorMode::Fuzz => desc_index == 0 || cursor.next_bool(),
                InputDescriptorMode::Readable => false,
                InputDescriptorMode::Writable => true,
            }
        } else {
            desc_index != 0 && cursor.next_bool()
        };

        let mut flags = if write_only { VRING_DESC_F_WRITE } else { 0 };
        let next = match desc_index {
            0 => {
                flags |= VRING_DESC_F_NEXT;
                1
            }
            2 if second_chain => {
                flags |= VRING_DESC_F_NEXT;
                3
            }
            _ => 0,
        };

        if !write_desc(mem, desc_table_addr, desc_index, addr, len, flags, next) {
            return false;
        }

        if !write_only && len > 0 && addr + len as u64 <= MEM_SIZE as u64 {
            let mut payload = vec![0u8; len as usize];
            cursor.fill_slice(&mut payload);
            let _ = mem.write_slice(&payload, GuestAddress(addr));
        }
    }

    if !write_u16(mem, avail_ring_addr, cursor.next_u16()) {
        return false;
    }
    if !write_u16(mem, avail_ring_addr + 2, avail_idx) {
        return false;
    }
    if !write_u16(mem, avail_ring_addr + 4, 0) {
        return false;
    }
    if !write_u16(mem, avail_ring_addr + 6, 2) {
        return false;
    }

    let next_avail = if is_input || cursor.next_bool() {
        0
    } else {
        avail_idx
    };
    queue.set_next_avail(next_avail);

    true
}

fn write_u16(mem: &GuestMemoryMmap, addr: u64, value: u16) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_desc(
    mem: &GuestMemoryMmap,
    table_addr: u64,
    index: u16,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> bool {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&addr.to_le_bytes());
    raw[8..12].copy_from_slice(&len.to_le_bytes());
    raw[12..14].copy_from_slice(&flags.to_le_bytes());
    raw[14..16].copy_from_slice(&next.to_le_bytes());
    let offset = table_addr + u64::from(index) * 16;
    mem.write_slice(&raw, GuestAddress(offset)).is_ok()
}

fn dup_eventfd(evt: &EventFd) -> Result<EventFd, std::io::Error> {
    let fd = unsafe { libc::dup(evt.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: dup returned a new owned eventfd file descriptor.
    Ok(unsafe { EventFd::from_raw_fd(fd) })
}

fn create_broken_eventfd() -> Result<EventFd, std::io::Error> {
    let (read_end, write_end) = create_pipe()?;
    drop(read_end);
    let fd = write_end.into_raw_fd();

    // SAFETY: fd is valid and owned. It intentionally is not an eventfd so the
    // console worker exercises its queue-event read error handling.
    Ok(unsafe { EventFd::from_raw_fd(fd) })
}

fn memfd_create(name: &std::ffi::CStr) -> Result<RawFd, std::io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };

    if res < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

fn create_pipe() -> Result<(File, File), std::io::Error> {
    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let rx = unsafe { File::from_raw_fd(pipe[0]) };
    let tx = unsafe { File::from_raw_fd(pipe[1]) };

    Ok((rx, tx))
}
