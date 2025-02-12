// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;

use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vmm::EpollContext;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

macro_rules! align {
    ($n:expr, $align:expr) => {{
        $n.div_ceil($align) * $align
    }};
}

const TAP_INPUT_SIZE: usize = 128;
const QUEUE_DATA_SIZE: usize = 4;
const MEM_SIZE: usize = 32 * 1024 * 1024;
// Guest memory gap
const GUEST_MEM_GAP: u64 = 1 * 1024 * 1024;
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

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < TAP_INPUT_SIZE + (QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE) * QUEUE_NUM
        || bytes.len()
            > TAP_INPUT_SIZE + (QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE) * QUEUE_NUM + MEM_SIZE
    {
        return Corpus::Reject;
    }

    let (dummy_tap_frontend, dummy_tap_backend) = create_socketpair().unwrap();
    let if_name = "fuzzer_tap_name".as_bytes().to_vec();
    let tap = net_util::Tap::new_for_fuzzing(dummy_tap_frontend, if_name);

    let mut net = virtio_devices::Net::new_with_tap(
        "fuzzer_net".to_owned(),
        vec![tap],
        None,  // guest_mac
        false, // iommu
        QUEUE_NUM,
        QUEUE_SIZE,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
        true,
        true,
        true,
    )
    .unwrap();

    let tap_input_bytes = &bytes[..TAP_INPUT_SIZE];
    let queue_data = &bytes[TAP_INPUT_SIZE..TAP_INPUT_SIZE + QUEUE_DATA_SIZE * QUEUE_NUM];
    let queue_bytes = &bytes[TAP_INPUT_SIZE + QUEUE_DATA_SIZE * QUEUE_NUM
        ..TAP_INPUT_SIZE + (QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE) * QUEUE_NUM];
    let mem_bytes = &bytes[TAP_INPUT_SIZE + (QUEUE_DATA_SIZE + QUEUE_BYTES_SIZE) * QUEUE_NUM..];

    // Setup the virt queues with the input bytes
    let mut queues = setup_virt_queues(
        &[
            &queue_data[..QUEUE_DATA_SIZE].try_into().unwrap(),
            &queue_data[QUEUE_DATA_SIZE..QUEUE_DATA_SIZE * 2]
                .try_into()
                .unwrap(),
        ],
        BASE_VIRT_QUEUE_ADDR,
    );

    // Setup the guest memory with the input bytes
    let mem = GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), MEM_SIZE),
        (GuestAddress(BASE_VIRT_QUEUE_ADDR), queue_bytes.len()),
    ])
    .unwrap();
    if mem
        .write_slice(queue_bytes, GuestAddress(BASE_VIRT_QUEUE_ADDR))
        .is_err()
    {
        return Corpus::Reject;
    }
    if mem.write_slice(mem_bytes, GuestAddress(0 as u64)).is_err() {
        return Corpus::Reject;
    }
    let guest_memory = GuestMemoryAtomic::new(mem);

    let input_queue = queues.remove(0);
    let input_evt = EventFd::new(0).unwrap();
    let input_queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(input_evt.as_raw_fd())) };
    let output_queue = queues.remove(0);
    let output_evt = EventFd::new(0).unwrap();
    let output_queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(output_evt.as_raw_fd())) };

    // Start the thread of dummy tap backend to handle the rx and tx from the virtio-net
    let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
    let tap_backend_thread = {
        let dummy_tap_backend = dummy_tap_backend.try_clone().unwrap();
        let tap_input_bytes: [u8; TAP_INPUT_SIZE] = tap_input_bytes[..].try_into().unwrap();
        let exit_evt = exit_evt.try_clone().unwrap();
        std::thread::Builder::new()
            .name("dummy_tap_backend".to_string())
            .spawn(move || {
                tap_backend_stub(dummy_tap_backend, &tap_input_bytes, exit_evt);
            })
            .unwrap()
    };

    // Kick the 'queue' events and endpoint event before activate the net device
    input_queue_evt.write(1).unwrap();
    output_queue_evt.write(1).unwrap();

    net.activate(
        guest_memory,
        Arc::new(NoopVirtioInterrupt {}),
        vec![(0, input_queue, input_evt), (1, output_queue, output_evt)],
    )
    .unwrap();

    // Wait for the events to finish and net device worker thread to return
    net.wait_for_epoll_threads();
    // Terminate the thread for the dummy tap backend
    exit_evt.write(1).ok();
    tap_backend_thread.join().unwrap();

    return Corpus::Keep;
});

pub struct NoopVirtioInterrupt {}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

fn setup_virt_queues(bytes: &[&[u8; QUEUE_DATA_SIZE]], base_addr: u64) -> Vec<Queue> {
    let mut queues = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
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

        q.set_next_avail(b[0] as u16); // 'u8' is enough given the 'QUEUE_SIZE' is small
        q.set_next_used(b[1] as u16);
        q.set_event_idx(b[2] % 2 != 0);
        q.set_size(b[3] as u16 % QUEUE_SIZE);

        q.set_ready(true);
        queues.push(q);
    }

    queues
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

enum EpollEvent {
    Exit = 0,
    Rx = 1,
    Tx = 2,
    Unknown,
}

impl From<u64> for EpollEvent {
    fn from(v: u64) -> Self {
        use EpollEvent::*;
        match v {
            0 => Exit,
            1 => Rx,
            2 => Tx,
            _ => Unknown,
        }
    }
}

// Handle the rx and tx requests from the virtio-net device
fn tap_backend_stub(
    mut dummy_tap: File,
    tap_input_bytes: &[u8; TAP_INPUT_SIZE],
    exit_evt: EventFd,
) {
    let mut epoll = EpollContext::new().unwrap();
    epoll
        .add_event_custom(&exit_evt, EpollEvent::Exit as u64, epoll::Events::EPOLLIN)
        .unwrap();
    let dummy_tap_write = dummy_tap.try_clone().unwrap();
    epoll
        .add_event_custom(
            &dummy_tap_write,
            EpollEvent::Rx as u64,
            epoll::Events::EPOLLOUT,
        )
        .unwrap();
    epoll
        .add_event_custom(&dummy_tap, EpollEvent::Tx as u64, epoll::Events::EPOLLIN)
        .unwrap();

    let epoll_fd = epoll.as_raw_fd();
    let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 3];
    loop {
        let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
            Ok(num_events) => num_events,
            Err(e) => match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => panic!("Unexpected epoll::wait error!"),
            },
        };

        for event in events.iter().take(num_events) {
            let dispatch_event: EpollEvent = event.data.into();
            match dispatch_event {
                EpollEvent::Exit => {
                    return;
                }
                EpollEvent::Rx => {
                    dummy_tap.write_all(tap_input_bytes).unwrap();
                    break;
                }
                EpollEvent::Tx => {
                    let mut buffer = Vec::new();
                    dummy_tap.read_to_end(&mut buffer).ok();
                    break;
                }
                _ => {
                    panic!("Unexpected Epoll event");
                }
            }
        }
    }
}
