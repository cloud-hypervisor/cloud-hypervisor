// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;
use std::{ffi, io};

use libc::{MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use libfuzzer_sys::{fuzz_target, Corpus};
use seccompiler::SeccompAction;
use virtio_devices::{Pmem, VirtioDevice, VirtioInterrupt, VirtioInterruptType};
use virtio_queue::{Queue, QueueT};
use vm_device::UserspaceMapping;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::guest_memory::FileOffset;
use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, MmapRegion};
use vm_migration::{Pausable, Snapshottable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEM_SIZE: usize = 2 * 1024 * 1024;
const PMEM_FILE_SIZE: usize = 128 * 1024 * 1024;
const QUEUE_SIZE: u16 = 256;
const DESC_TABLE_ADDR: u64 = 0;
const DESC_TABLE_SIZE: u64 = 16_u64 * QUEUE_SIZE as u64;
const AVAIL_RING_ADDR: u64 = DESC_TABLE_ADDR + DESC_TABLE_SIZE;
const AVAIL_RING_SIZE: u64 = 6_u64 + 2 * QUEUE_SIZE as u64;
const USED_RING_ADDR: u64 = (AVAIL_RING_ADDR + AVAIL_RING_SIZE + 3) & !3_u64;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const REQ_BASE_ADDR: u64 = 0x10_000;
const STATUS_BASE_ADDR: u64 = 0x20_000;
const BAD_USED_RING_ADDR: u64 = MEM_SIZE as u64 + 0x1000;

struct FuzzCursor<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> FuzzCursor<'a> {
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

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }
}

#[derive(Copy, Clone)]
struct ChainCase {
    request_addr: u64,
    request_len: u32,
    request_flags: u16,
    request_type: u32,
    include_status: bool,
    status_addr: u64,
    status_len: u32,
    status_flags: u16,
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Corpus::Reject;
    }

    let mut cursor = FuzzCursor::new(bytes);
    let mut keep = false;
    keep |= run_pmem_case(&mut cursor, false, false, false, false);
    keep |= run_pmem_case(&mut cursor, false, true, false, false);
    keep |= run_pmem_case(&mut cursor, true, true, false, false);
    keep |= run_pmem_case(&mut cursor, false, true, true, true);
    keep |= run_restore_case(&mut cursor);
    keep |= run_bad_activate_case(&mut cursor);

    if keep {
        Corpus::Keep
    } else {
        Corpus::Reject
    }
});

fn run_pmem_case(
    cursor: &mut FuzzCursor<'_>,
    fail_interrupt: bool,
    enable_access_platform: bool,
    fail_flush: bool,
    bad_used_ring: bool,
) -> bool {
    let constructor_access_platform = cursor.next_bool();
    let mut pmem = match create_dummy_pmem(
        enable_access_platform || constructor_access_platform,
        fail_flush,
    ) {
        Ok(pmem) => pmem,
        Err(_) => return false,
    };

    exercise_device_api(&mut pmem, cursor, enable_access_platform);

    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return false,
    };

    let chain_cases = build_chain_cases(cursor);
    if !populate_queue(&mem, &chain_cases) {
        return false;
    }

    let queue = setup_virt_queue(cursor.next_bool(), bad_used_ring);
    let guest_memory = GuestMemoryAtomic::new(mem);
    let evt = match EventFd::new(0) {
        Ok(evt) => evt,
        Err(_) => return false,
    };
    let queue_evt_fd = unsafe { libc::dup(evt.as_raw_fd()) };
    if queue_evt_fd < 0 {
        return false;
    }
    let queue_evt = unsafe { EventFd::from_raw_fd(queue_evt_fd) };

    // Kick the 'queue' event before activating the device: under cfg(fuzzing)
    // the epoll loop returns as soon as no event is pending.
    let burst_count = 2 + usize::from(cursor.next_u8() % 3);
    for _ in 0..burst_count {
        let _ = queue_evt.write(1);
    }

    if pmem
        .activate(virtio_devices::ActivationContext {
            mem: guest_memory,
            interrupt_cb: Arc::new(HarnessInterrupt { fail_interrupt }),
            queues: vec![(0, queue, evt)],
            device_status: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
        .is_err()
    {
        return false;
    }

    pmem.wait_for_epoll_threads();
    let _ = pmem.snapshot();
    pmem.reset();

    true
}

fn run_restore_case(cursor: &mut FuzzCursor<'_>) -> bool {
    let mut source = match create_dummy_pmem(cursor.next_bool(), false) {
        Ok(pmem) => pmem,
        Err(_) => return false,
    };
    let snapshot = match source.snapshot() {
        Ok(snapshot) => snapshot,
        Err(_) => return false,
    };
    let state = match snapshot.to_state() {
        Ok(state) => state,
        Err(_) => return false,
    };

    let (file, guest_addr, mapping) = match create_backing_file_and_mapping() {
        Ok(parts) => parts,
        Err(_) => return false,
    };
    let exit_evt = match EventFd::new(EFD_NONBLOCK) {
        Ok(evt) => evt,
        Err(_) => return false,
    };

    let mut restored = match Pmem::new(
        "restored".to_owned(),
        file,
        guest_addr,
        mapping,
        true,
        SeccompAction::Allow,
        exit_evt,
        Some(state),
    ) {
        Ok(pmem) => pmem,
        Err(_) => return false,
    };

    exercise_device_api(&mut restored, cursor, true);
    let _ = restored.pause();
    let _ = restored.resume();
    let _ = restored.snapshot();
    restored.reset();

    true
}

fn run_bad_activate_case(cursor: &mut FuzzCursor<'_>) -> bool {
    let mut pmem = match create_dummy_pmem(cursor.next_bool(), false) {
        Ok(pmem) => pmem,
        Err(_) => return false,
    };
    let mem = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(mem) => mem,
        Err(_) => return false,
    };

    pmem.activate(virtio_devices::ActivationContext {
        mem: GuestMemoryAtomic::new(mem),
        interrupt_cb: Arc::new(HarnessInterrupt {
            fail_interrupt: false,
        }),
        queues: vec![],
        device_status: Arc::new(std::sync::atomic::AtomicU8::new(cursor.next_u8())),
    })
    .is_err()
}

fn exercise_device_api(pmem: &mut Pmem, cursor: &mut FuzzCursor<'_>, enable_access_platform: bool) {
    let _ = pmem.device_type();
    let _ = pmem.queue_max_sizes();
    let features = pmem.features();
    if enable_access_platform {
        pmem.set_access_platform(Arc::new(FuzzAccessPlatform { fail_on_odd: true }));
    }
    let access_platform_feature = 1_u64 << 33;
    let feature_noise = cursor.next_u64();
    let acked_features = if enable_access_platform {
        features | (feature_noise & features)
    } else {
        (features & !access_platform_feature) & feature_noise
    };
    pmem.ack_features(acked_features);
    let _ = pmem.userspace_mappings();

    let mut config = [0u8; size_of::<u64>() * 2];
    let config_len = 1 + (cursor.next_u8() as usize % config.len());
    pmem.read_config(u64::from(cursor.next_u8()), &mut config[..config_len]);

    let _ = pmem.access_platform();
    let _ = Snapshottable::id(pmem);
}

fn build_chain_cases(cursor: &mut FuzzCursor<'_>) -> Vec<ChainCase> {
    let unknown_req = cursor.next_u32() | 1;
    let short_req_len = u32::from(cursor.next_u8() & 0x3);
    let short_status_len = u32::from(cursor.next_u8() & 0x3);

    vec![
        ChainCase {
            request_addr: REQ_BASE_ADDR,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: 0,
            include_status: true,
            status_addr: STATUS_BASE_ADDR,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            request_addr: REQ_BASE_ADDR + 0x20,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: unknown_req,
            include_status: true,
            status_addr: STATUS_BASE_ADDR + 0x20,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            // Odd but in-range: exercises AccessPlatform translation failure.
            request_addr: REQ_BASE_ADDR + 0x41,
            request_len: size_of::<u32>() as u32,
            request_flags: VRING_DESC_F_WRITE,
            request_type: 0,
            include_status: true,
            status_addr: STATUS_BASE_ADDR + 0x40,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            request_addr: REQ_BASE_ADDR + 0x60,
            request_len: short_req_len,
            request_flags: 0,
            request_type: 0,
            include_status: true,
            status_addr: STATUS_BASE_ADDR + 0x60,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            request_addr: REQ_BASE_ADDR + 0x80,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: 0,
            include_status: false,
            status_addr: STATUS_BASE_ADDR + 0x80,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            request_addr: REQ_BASE_ADDR + 0xa0,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: 0,
            include_status: true,
            status_addr: STATUS_BASE_ADDR + 0xa0,
            status_len: size_of::<u32>() as u32,
            status_flags: 0,
        },
        ChainCase {
            request_addr: REQ_BASE_ADDR + 0xc0,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: 0,
            include_status: true,
            status_addr: STATUS_BASE_ADDR + 0xc0,
            status_len: short_status_len,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            request_addr: MEM_SIZE as u64 + 0x100,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: 0,
            include_status: true,
            status_addr: STATUS_BASE_ADDR + 0xe0,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
        ChainCase {
            request_addr: REQ_BASE_ADDR + 0x100,
            request_len: size_of::<u32>() as u32,
            request_flags: 0,
            request_type: 0,
            include_status: true,
            status_addr: MEM_SIZE as u64 + 0x200,
            status_len: size_of::<u32>() as u32,
            status_flags: VRING_DESC_F_WRITE,
        },
    ]
}

fn populate_queue(mem: &GuestMemoryMmap, chain_cases: &[ChainCase]) -> bool {
    if chain_cases.is_empty() || chain_cases.len() > (QUEUE_SIZE as usize / 2) {
        return false;
    }

    if !write_u16(mem, AVAIL_RING_ADDR, 0)
        || !write_u16(mem, USED_RING_ADDR, 0)
        || !write_u16(mem, USED_RING_ADDR + 2, 0)
    {
        return false;
    }

    for (slot, chain_case) in chain_cases.iter().enumerate() {
        let head_idx = (slot as u16) * 2;

        if chain_case.request_addr < MEM_SIZE as u64
            && mem
                .write_slice(
                    &chain_case.request_type.to_le_bytes(),
                    GuestAddress(chain_case.request_addr),
                )
                .is_err()
        {
            return false;
        }

        let mut request_flags = chain_case.request_flags;
        let request_next = if chain_case.include_status {
            request_flags |= VRING_DESC_F_NEXT;
            head_idx + 1
        } else {
            request_flags &= !VRING_DESC_F_NEXT;
            0
        };

        if !write_desc(
            mem,
            head_idx,
            chain_case.request_addr,
            chain_case.request_len,
            request_flags,
            request_next,
        ) {
            return false;
        }

        if chain_case.include_status
            && !write_desc(
                mem,
                head_idx + 1,
                chain_case.status_addr,
                chain_case.status_len,
                chain_case.status_flags,
                0,
            )
        {
            return false;
        }

        if !write_u16(mem, AVAIL_RING_ADDR + 4 + (slot as u64 * 2), head_idx) {
            return false;
        }
    }

    write_u16(mem, AVAIL_RING_ADDR + 2, chain_cases.len() as u16)
}

fn write_desc(mem: &GuestMemoryMmap, idx: u16, addr: u64, len: u32, flags: u16, next: u16) -> bool {
    let desc_addr = DESC_TABLE_ADDR + u64::from(idx) * 16;
    write_u64(mem, desc_addr, addr)
        && write_u32(mem, desc_addr + 8, len)
        && write_u16(mem, desc_addr + 12, flags)
        && write_u16(mem, desc_addr + 14, next)
}

fn write_u16(mem: &GuestMemoryMmap, addr: u64, value: u16) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_u32(mem: &GuestMemoryMmap, addr: u64, value: u32) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn write_u64(mem: &GuestMemoryMmap, addr: u64, value: u64) -> bool {
    mem.write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .is_ok()
}

fn memfd_create_with_size(name: &ffi::CStr, flags: u32, size: usize) -> Result<RawFd, io::Error> {
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let res = unsafe { libc::syscall(libc::SYS_ftruncate, fd, size) };
    if res < 0 {
        let _ = unsafe { libc::close(fd as i32) };
        return Err(io::Error::last_os_error());
    }

    Ok(fd as RawFd)
}

#[derive(Debug)]
struct HarnessInterrupt {
    fail_interrupt: bool,
}

impl VirtioInterrupt for HarnessInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error> {
        if self.fail_interrupt {
            Err(io::Error::other("fuzz interrupt failure"))
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

#[derive(Debug)]
struct FuzzAccessPlatform {
    fail_on_odd: bool,
}

impl AccessPlatform for FuzzAccessPlatform {
    fn translate_gva(&self, base: u64, _size: u64) -> io::Result<u64> {
        if self.fail_on_odd && (base & 1) != 0 {
            Err(io::Error::other("fuzz gva translation failure"))
        } else {
            Ok(base)
        }
    }

    fn translate_gpa(&self, base: u64, _size: u64) -> io::Result<u64> {
        if self.fail_on_odd && (base & 1) != 0 {
            Err(io::Error::other("fuzz gpa translation failure"))
        } else {
            Ok(base)
        }
    }
}

fn create_backing_file_and_mapping() -> io::Result<(File, GuestAddress, UserspaceMapping)> {
    let shm = memfd_create_with_size(&ffi::CString::new("fuzz").unwrap(), 0, PMEM_FILE_SIZE)?;
    let file: File = unsafe { File::from_raw_fd(shm) };

    let dummy_mapping_size = 1;
    let cloned_file = file.try_clone()?;
    let dummy_mmap_region = MmapRegion::build(
        Some(FileOffset::new(cloned_file, 0)),
        dummy_mapping_size,
        PROT_READ | PROT_WRITE,
        MAP_NORESERVE | MAP_PRIVATE,
    )
    .map_err(|e| io::Error::other(format!("failed building mmap region: {e}")))?;
    let guest_addr = GuestAddress(0);
    let dummy_user_mapping = UserspaceMapping {
        mem_slot: 0,
        addr: guest_addr,
        mapping: Arc::new(dummy_mmap_region),
        mergeable: false,
    };

    Ok((file, guest_addr, dummy_user_mapping))
}

fn create_dummy_pmem(access_platform_enabled: bool, fail_flush: bool) -> io::Result<Pmem> {
    let (file, guest_addr, dummy_user_mapping) = create_backing_file_and_mapping()?;
    let disk = if fail_flush {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?
    } else {
        file
    };

    Pmem::new(
        "tmp".to_owned(),
        disk,
        guest_addr,
        dummy_user_mapping,
        access_platform_enabled,
        SeccompAction::Allow,
        EventFd::new(EFD_NONBLOCK)?,
        None,
    )
}

fn setup_virt_queue(event_idx: bool, bad_used_ring: bool) -> Queue {
    let mut q = Queue::new(QUEUE_SIZE).unwrap();
    q.set_next_avail(0);
    q.set_next_used(0);
    q.set_event_idx(event_idx);
    q.set_size(QUEUE_SIZE);

    q.try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
        .unwrap();
    let used_ring_addr = if bad_used_ring {
        BAD_USED_RING_ADDR
    } else {
        USED_RING_ADDR
    };
    q.try_set_used_ring_address(GuestAddress(used_ring_addr))
        .unwrap();
    q.set_ready(true);

    q
}
