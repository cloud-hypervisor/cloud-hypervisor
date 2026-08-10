// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![no_main]

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::{ffi, io};

use arbitrary::Unstructured;
use block::fcntl::LockGranularityChoice;
use block::formats::raw::{RawBackend, RawDisk};
use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{Block, VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

// Guest memory size. Kept small: everything the device touches lives in the
// first megabyte, and a smaller mapping keeps the executions per second up.
const MEM_SIZE: usize = 16 * 1024 * 1024;
// Max entries in the queue.
const QUEUE_SIZE: u16 = 256;
// Guest physical address for descriptor table.
const DESC_TABLE_ADDR: u64 = 0;
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
// Guest physical address for available ring
const AVAIL_RING_ADDR: u64 = DESC_TABLE_ADDR + DESC_TABLE_SIZE;
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
// Guest physical address for used ring (requires to 4-bytes aligned)
const USED_RING_ADDR: u64 = (AVAIL_RING_ADDR + AVAIL_RING_SIZE + 3) & !3_u64;

// Guest physical address of the region holding request headers, request
// payloads and status bytes. It is placed well beyond the rings above so
// that a buggy chain can not corrupt the queue layout itself.
const DATA_ADDR: u64 = 64 * 1024;
const DATA_SIZE: u64 = 1024 * 1024;

// Size of the backing disk exposed to the device.
const DISK_SIZE: u64 = 1024 * 1024;
const DISK_SECTORS: u64 = DISK_SIZE / 512;

// Size of 'struct virtio_blk_outhdr': type, reserved, sector.
const REQUEST_HEADER_SIZE: u64 = 16;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;
const VIRTIO_BLK_T_DISCARD: u32 = 11;
const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

// Upper bounds on what a single input may build. They keep an input cheap to
// execute while still allowing multi descriptor chains.
const MAX_CHAINS: usize = 16;
const MAX_DATA_DESCRIPTORS: usize = 4;
const MAX_DATA_DESCRIPTOR_LEN: u32 = 8 * 1024;

/// One descriptor of the data part of a request.
struct FuzzDataDescriptor {
    len: u32,
    // Flip the writability that the request type would normally require. This
    // is rare on purpose: most chains must be valid so that the request parser
    // is actually entered, but the rejection paths deserve coverage too.
    flip_writable: bool,
}

/// One request, i.e. one descriptor chain.
struct FuzzChain {
    request_type: u32,
    sector: u64,
    data: Vec<FuzzDataDescriptor>,
    status_len: u32,
    header_write_only: bool,
    status_read_only: bool,
}

/// The whole input: queue geometry plus the requests to submit.
struct FuzzInput {
    queue_size: u16,
    event_idx: bool,
    payload: Vec<u8>,
    chains: Vec<FuzzChain>,
}

fn arbitrary_request_type(u: &mut Unstructured<'_>) -> arbitrary::Result<u32> {
    Ok(match u.arbitrary::<u8>()? % 8 {
        0 => VIRTIO_BLK_T_IN,
        1 => VIRTIO_BLK_T_OUT,
        2 => VIRTIO_BLK_T_FLUSH,
        3 => VIRTIO_BLK_T_GET_ID,
        4 => VIRTIO_BLK_T_DISCARD,
        5 => VIRTIO_BLK_T_WRITE_ZEROES,
        _ => u.arbitrary::<u32>()?,
    })
}

/// Rarely true, and false once the input is exhausted (`arbitrary` then
/// returns zeroes). Every "make this chain invalid" knob is expressed this
/// way so that a short or truncated input still describes a *valid* queue.
fn rarely(u: &mut Unstructured<'_>) -> arbitrary::Result<bool> {
    Ok(u.arbitrary::<u8>()? == 0xff)
}

fn arbitrary_chain(u: &mut Unstructured<'_>) -> arbitrary::Result<FuzzChain> {
    let request_type = arbitrary_request_type(u)?;

    // Mostly stay inside the disk, but leave room for out-of-bounds requests.
    let sector = if rarely(u)? {
        u.arbitrary::<u64>()?
    } else {
        u.arbitrary::<u64>()? % (DISK_SECTORS + 1)
    };

    // At least one data descriptor, except for the rare chain that has none
    // (only valid for FLUSH requests).
    let num_data = if rarely(u)? {
        0
    } else {
        1 + usize::from(u.arbitrary::<u8>()?) % MAX_DATA_DESCRIPTORS
    };
    let mut data = Vec::with_capacity(num_data);
    for _ in 0..num_data {
        let len = if rarely(u)? {
            u.arbitrary::<u32>()? % (MAX_DATA_DESCRIPTOR_LEN + 1)
        } else {
            512 * (1 + u32::from(u.arbitrary::<u8>()?) % 8)
        };
        data.push(FuzzDataDescriptor {
            len,
            flip_writable: rarely(u)?,
        });
    }

    Ok(FuzzChain {
        request_type,
        sector,
        data,
        // A status descriptor is normally a single byte.
        status_len: if rarely(u)? {
            u32::from(u.arbitrary::<u8>()?)
        } else {
            1
        },
        header_write_only: rarely(u)?,
        status_read_only: rarely(u)?,
    })
}

fn arbitrary_input(u: &mut Unstructured<'_>) -> arbitrary::Result<FuzzInput> {
    // The queue size must be a power of two, otherwise the queue is invalid
    // and no descriptor is ever handed to the device. Keep it big enough to
    // hold at least one chain even when the input runs out of bytes.
    let queue_size = 16u16 << (u.arbitrary::<u8>()? % 5);
    let event_idx = u.arbitrary::<bool>()?;

    let num_chains = 1 + usize::from(u.arbitrary::<u8>()?) % MAX_CHAINS;
    let mut chains = Vec::with_capacity(num_chains);
    for _ in 0..num_chains {
        chains.push(arbitrary_chain(u)?);
    }

    // Whatever is left becomes the content of the request headers' payload
    // area, so that e.g. DISCARD/WRITE_ZEROES segments are fuzzed too.
    let payload = u.arbitrary::<Vec<u8>>().unwrap_or_default();

    Ok(FuzzInput {
        queue_size,
        event_idx,
        payload,
        chains,
    })
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    let mut unstructured = Unstructured::new(bytes);
    let Ok(input) = arbitrary_input(&mut unstructured) else {
        return Corpus::Reject;
    };

    // Create a virtio-block device backed by a synchronous raw file
    let shm = memfd_create(&ffi::CString::new("fuzz").unwrap(), 0).unwrap();
    let disk_file: File = unsafe { File::from_raw_fd(shm) };
    // Give the disk a non-zero size, otherwise every request is rejected
    // before any I/O is attempted.
    disk_file.set_len(DISK_SIZE).unwrap();
    let queue_affinity = BTreeMap::new();
    let mut block = Block::new(
        "tmp".to_owned(),
        Box::new(RawDisk::new(disk_file, RawBackend::Sync, false)),
        PathBuf::from(""),
        false,
        false,
        2,
        256,
        None,
        SeccompAction::Allow,
        None,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        None,
        queue_affinity,
        true,
        false,
        LockGranularityChoice::default(),
        None,
    )
    .unwrap();

    // Setup the guest memory and lay out a virtio queue the device can
    // actually consume: a descriptor table, an available ring referring to
    // it, and request headers/payloads/status bytes in the data region.
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    build_queue_content(&mem, &input);
    let guest_memory = GuestMemoryAtomic::new(mem);

    let q = setup_virt_queue(&input);

    let evt = EventFd::new(0).unwrap();
    let queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };

    // Kick the 'queue' event before activate the block device
    queue_evt.write(1).unwrap();

    block
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            queues: vec![(0, q, evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .ok();

    // Wait for the events to finish and block device worker thread to return
    block.wait_for_epoll_threads();

    Corpus::Keep
});

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

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

/// Write a single descriptor into the descriptor table.
fn write_descriptor(mem: &GuestMemoryMmap, index: u16, addr: u64, len: u32, flags: u16, next: u16) {
    let desc_addr = GuestAddress(DESC_TABLE_ADDR + 16 * u64::from(index));
    let _ = mem.write_obj(addr.to_le(), desc_addr);
    let _ = mem.write_obj(len.to_le(), GuestAddress(desc_addr.0 + 8));
    let _ = mem.write_obj(flags.to_le(), GuestAddress(desc_addr.0 + 12));
    let _ = mem.write_obj(next.to_le(), GuestAddress(desc_addr.0 + 14));
}

/// Does the given request type require the data descriptors to be device
/// writable?
fn data_is_write_only(request_type: u32) -> bool {
    matches!(request_type, VIRTIO_BLK_T_IN | VIRTIO_BLK_T_GET_ID)
}

/// Build the descriptor table, the available ring and the request contents
/// from the fuzz input. Returns the number of chains published in the
/// available ring.
fn build_queue_content(mem: &GuestMemoryMmap, input: &FuzzInput) {
    // Fill the data region with the leftover fuzz bytes, repeated so that
    // request payloads (e.g. DISCARD segments) are never all zeroes.
    if !input.payload.is_empty() {
        let mut offset = 0u64;
        while offset < DATA_SIZE {
            let len = std::cmp::min(input.payload.len() as u64, DATA_SIZE - offset) as usize;
            if mem
                .write_slice(&input.payload[..len], GuestAddress(DATA_ADDR + offset))
                .is_err()
            {
                break;
            }
            offset += len as u64;
        }
    }

    let mut next_desc: u16 = 0;
    let mut data_cursor: u64 = 0;
    let mut heads: Vec<u16> = Vec::new();

    let mut alloc = |len: u64| -> u64 {
        let len = std::cmp::max(len, 1);
        if data_cursor + len > DATA_SIZE {
            data_cursor = 0;
        }
        let addr = DATA_ADDR + data_cursor;
        // Keep the allocations 16 bytes apart and inside the data region.
        data_cursor = (data_cursor + len + 15) & !15;
        if data_cursor >= DATA_SIZE {
            data_cursor = 0;
        }
        addr
    };

    for chain in input.chains.iter() {
        let chain_len = 2 + chain.data.len() as u16;
        if u64::from(next_desc) + u64::from(chain_len) > u64::from(input.queue_size) {
            break;
        }

        let head = next_desc;

        // The request header.
        let hdr_addr = alloc(REQUEST_HEADER_SIZE);
        let _ = mem.write_obj(chain.request_type.to_le(), GuestAddress(hdr_addr));
        let _ = mem.write_obj(0u32, GuestAddress(hdr_addr + 4));
        let _ = mem.write_obj(chain.sector.to_le(), GuestAddress(hdr_addr + 8));

        let mut flags = VIRTQ_DESC_F_NEXT;
        if chain.header_write_only {
            flags |= VIRTQ_DESC_F_WRITE;
        }
        write_descriptor(
            mem,
            next_desc,
            hdr_addr,
            REQUEST_HEADER_SIZE as u32,
            flags,
            next_desc + 1,
        );
        next_desc += 1;

        // The data descriptors.
        for data in chain.data.iter() {
            let addr = alloc(u64::from(data.len));
            let mut flags = VIRTQ_DESC_F_NEXT;
            if data_is_write_only(chain.request_type) != data.flip_writable {
                flags |= VIRTQ_DESC_F_WRITE;
            }
            write_descriptor(mem, next_desc, addr, data.len, flags, next_desc + 1);
            next_desc += 1;
        }

        // The status byte, which must be device writable.
        let status_addr = alloc(u64::from(chain.status_len));
        let flags = if chain.status_read_only {
            0
        } else {
            VIRTQ_DESC_F_WRITE
        };
        write_descriptor(mem, next_desc, status_addr, chain.status_len, flags, 0);
        next_desc += 1;

        heads.push(head);
    }

    // The available ring: flags, idx, then the ring itself.
    let _ = mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR));
    for (i, head) in heads.iter().enumerate() {
        let _ = mem.write_obj(
            head.to_le(),
            GuestAddress(AVAIL_RING_ADDR + 4 + 2 * i as u64),
        );
    }
    let idx = heads.len() as u16;
    let _ = mem.write_obj(idx.to_le(), GuestAddress(AVAIL_RING_ADDR + 2));

    // The used ring starts empty.
    let _ = mem.write_obj(0u16, GuestAddress(USED_RING_ADDR));
    let _ = mem.write_obj(0u16, GuestAddress(USED_RING_ADDR + 2));
}

fn setup_virt_queue(input: &FuzzInput) -> Queue {
    let mut q = Queue::new(QUEUE_SIZE).unwrap();
    q.set_size(input.queue_size);
    q.set_next_avail(0);
    q.set_next_used(0);
    q.set_event_idx(input.event_idx);

    q.try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .unwrap();
    q.try_set_used_ring_address(GuestAddress(USED_RING_ADDR))
        .unwrap();
    q.set_ready(true);

    q
}
