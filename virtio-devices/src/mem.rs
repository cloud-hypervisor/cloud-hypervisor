// Copyright (c) 2020 Ant Financial
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DescriptorChain, EpollHelper, EpollHelperError,
    EpollHelperHandler, Queue, VirtioDevice, VirtioDeviceType, EPOLL_HELPER_EVENT_LAST,
    VIRTIO_F_VERSION_1,
};

use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{VirtioInterrupt, VirtioInterruptType};
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use std::cmp;
use std::io;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// Use 2 MiB alignment so transparent hugepages can be used by KVM.
pub const VIRTIO_MEM_DEFAULT_BLOCK_SIZE: u64 = 512 * 4096;
const VIRTIO_MEM_USABLE_EXTENT: u64 = 256 * 1024 * 1024;

// Request processed successfully, applicable for
// - VIRTIO_MEM_REQ_PLUG
// - VIRTIO_MEM_REQ_UNPLUG
// - VIRTIO_MEM_REQ_UNPLUG_ALL
// - VIRTIO_MEM_REQ_STATE
const VIRTIO_MEM_RESP_ACK: u16 = 0;

// Request denied - e.g. trying to plug more than requested, applicable for
// - VIRTIO_MEM_REQ_PLUG
const VIRTIO_MEM_RESP_NACK: u16 = 1;

// Request cannot be processed right now, try again later, applicable for
// - VIRTIO_MEM_REQ_PLUG
// - VIRTIO_MEM_REQ_UNPLUG
// - VIRTIO_MEM_REQ_UNPLUG_ALL
// VIRTIO_MEM_RESP_BUSY: u16 = 2;

// Error in request (e.g. addresses/alignemnt), applicable for
// - VIRTIO_MEM_REQ_PLUG
// - VIRTIO_MEM_REQ_UNPLUG
// - VIRTIO_MEM_REQ_STATE
const VIRTIO_MEM_RESP_ERROR: u16 = 3;

// State of memory blocks is "plugged"
const VIRTIO_MEM_STATE_PLUGGED: u16 = 0;
// State of memory blocks is "unplugged"
const VIRTIO_MEM_STATE_UNPLUGGED: u16 = 1;
// State of memory blocks is "mixed"
const VIRTIO_MEM_STATE_MIXED: u16 = 2;

// request to plug memory blocks
const VIRTIO_MEM_REQ_PLUG: u16 = 0;
// request to unplug memory blocks
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
// request to unplug all blocks and shrink the usable size
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
// request information about the plugged state of memory blocks
const VIRTIO_MEM_REQ_STATE: u16 = 3;

// Get resize event.
const RESIZE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

#[derive(Debug)]
pub enum Error {
    // Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    // Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    // Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    // Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    // Guest gave us a buffer that was too short to use.
    BufferLengthTooSmall,
    // Guest sent us invalid request.
    InvalidRequest,
    // Failed to EventFd write.
    EventFdWriteFail(std::io::Error),
    // Failed to EventFd try_clone.
    EventFdTryCloneFail(std::io::Error),
    // Failed to MpscRecv.
    MpscRecvFail(mpsc::RecvError),
    // Resize invalid argument
    ResizeInval(String),
    // Fail to resize trigger
    ResizeTriggerFail(DeviceError),
}

// Got from qemu/include/standard-headers/linux/virtio_mem.h
// rust union doesn't support std::default::Default that
// need by mem.read_obj.
// Then move virtio_mem_req_plug, virtio_mem_req_unplug and
// virtio_mem_req_state to virtio_mem_req.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemReq {
    req_type: u16,
    padding: [u16; 3],
    addr: u64,
    nb_blocks: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioMemReq {}

// Got from qemu/include/standard-headers/linux/virtio_mem.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemRespState {
    state: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemResp {
    resp_type: u16,
    padding: [u16; 3],

    state: VirtioMemRespState,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioMemResp {}

// Got from qemu/include/standard-headers/linux/virtio_mem.h
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemConfig {
    // Block size and alignment. Cannot change.
    block_size: u64,
    // Valid with VIRTIO_MEM_F_ACPI_PXM. Cannot change.
    node_id: u16,
    padding: [u8; 6],
    // Start address of the memory region. Cannot change.
    addr: u64,
    // Region size (maximum). Cannot change.
    region_size: u64,
    // Currently usable region size. Can grow up to region_size. Can
    // shrink due to VIRTIO_MEM_REQ_UNPLUG_ALL (in which case no config
    // update will be sent).
    usable_region_size: u64,
    // Currently used size. Changes due to plug/unplug requests, but no
    // config updates will be sent.
    plugged_size: u64,
    // Requested size. New plug requests cannot exceed it. Can change.
    requested_size: u64,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioMemConfig {}

fn virtio_mem_config_resize(config: &mut VirtioMemConfig, size: u64) -> result::Result<(), Error> {
    if config.requested_size == size {
        return Err(Error::ResizeInval(format!(
            "Virtio-mem resize {} is same with current config.requested_size",
            size
        )));
    } else if size > config.region_size {
        let region_size = config.region_size;
        return Err(Error::ResizeInval(format!(
            "Virtio-mem resize {} is bigger than config.region_size {}",
            size, region_size
        )));
    } else if size % (config.block_size as u64) != 0 {
        let block_size = config.block_size;
        return Err(Error::ResizeInval(format!(
            "Virtio-mem resize {} is not aligned with config.block_size {}",
            size, block_size
        )));
    }

    config.requested_size = size;
    let tmp_size = cmp::min(
        config.region_size,
        config.requested_size + VIRTIO_MEM_USABLE_EXTENT,
    );
    config.usable_region_size = cmp::max(config.usable_region_size, tmp_size);

    Ok(())
}

struct Request {
    req: VirtioMemReq,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> result::Result<Request, Error> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }
        if avail_desc.len as usize != size_of::<VirtioMemReq>() {
            return Err(Error::InvalidRequest);
        }
        let req: VirtioMemReq = mem.read_obj(avail_desc.addr).map_err(Error::GuestMemory)?;

        let status_desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if (status_desc.len as usize) < size_of::<VirtioMemResp>() {
            return Err(Error::BufferLengthTooSmall);
        }

        Ok(Request {
            req,
            status_addr: status_desc.addr,
        })
    }
}

pub struct Resize {
    size: Arc<AtomicU64>,
    tx: mpsc::Sender<Result<(), Error>>,
    rx: Option<mpsc::Receiver<Result<(), Error>>>,
    evt: EventFd,
}

impl Resize {
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();

        Ok(Resize {
            size: Arc::new(AtomicU64::new(0)),
            tx,
            rx: Some(rx),
            evt: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(Resize {
            size: self.size.clone(),
            tx: self.tx.clone(),
            rx: None,
            evt: self.evt.try_clone().map_err(Error::EventFdTryCloneFail)?,
        })
    }

    pub fn work(&self, size: u64) -> Result<(), Error> {
        if let Some(rx) = &self.rx {
            self.size.store(size, Ordering::SeqCst);
            self.evt.write(1).map_err(Error::EventFdWriteFail)?;
            rx.recv().map_err(Error::MpscRecvFail)?
        } else {
            panic!("work should not work with cloned resize")
        }
    }

    fn get_size(&self) -> u64 {
        self.size.load(Ordering::SeqCst)
    }

    fn send(&self, r: Result<(), Error>) -> Result<(), mpsc::SendError<Result<(), Error>>> {
        self.tx.send(r)
    }
}

struct MemEpollHandler {
    host_addr: u64,
    host_fd: Option<RawFd>,
    mem_state: Vec<bool>,
    config: Arc<Mutex<VirtioMemConfig>>,
    resize: Resize,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

struct StateChangeRequest<'a> {
    config: VirtioMemConfig,
    addr: u64,
    size: u64,
    nb_blocks: u16,
    mem_state: &'a mut Vec<bool>,
    host_addr: u64,
    host_fd: Option<RawFd>,
    plug: bool,
}

impl MemEpollHandler {
    fn virtio_mem_valid_range(config: &VirtioMemConfig, addr: u64, size: u64) -> bool {
        // address properly aligned?
        if addr % config.block_size as u64 != 0 {
            return false;
        }

        // reasonable size
        if addr + size <= addr || size == 0 {
            return false;
        }

        // start address in usable range?
        if addr < config.addr || addr >= config.addr + config.usable_region_size {
            return false;
        }

        // end address in usable range?
        if addr + size > config.addr + config.usable_region_size {
            return false;
        }

        true
    }

    fn virtio_mem_check_bitmap(
        bit_index: usize,
        nb_blocks: u16,
        mem_state: &[bool],
        plug: bool,
    ) -> bool {
        for state in mem_state.iter().skip(bit_index).take(nb_blocks as usize) {
            if *state != plug {
                return false;
            }
        }
        true
    }

    fn virtio_mem_set_bitmap(
        bit_index: usize,
        nb_blocks: u16,
        mem_state: &mut Vec<bool>,
        plug: bool,
    ) {
        for state in mem_state
            .iter_mut()
            .skip(bit_index)
            .take(nb_blocks as usize)
        {
            *state = plug;
        }
    }

    fn virtio_mem_state_change_request(r: StateChangeRequest) -> u16 {
        if r.plug && (r.config.plugged_size + r.size > r.config.requested_size) {
            return VIRTIO_MEM_RESP_NACK;
        }
        if !MemEpollHandler::virtio_mem_valid_range(&r.config, r.addr, r.size) {
            return VIRTIO_MEM_RESP_ERROR;
        }

        let offset = r.addr - r.config.addr;

        let bit_index = (offset / r.config.block_size as u64) as usize;
        if !MemEpollHandler::virtio_mem_check_bitmap(bit_index, r.nb_blocks, r.mem_state, !r.plug) {
            return VIRTIO_MEM_RESP_ERROR;
        }

        if !r.plug {
            if let Some(fd) = r.host_fd {
                let res = unsafe {
                    libc::fallocate64(
                        fd,
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        offset as libc::off64_t,
                        r.size as libc::off64_t,
                    )
                };
                if res != 0 {
                    error!("fallocate64 get error {}", io::Error::last_os_error());
                    return VIRTIO_MEM_RESP_ERROR;
                }
            }
            let res = unsafe {
                libc::madvise(
                    (r.host_addr + offset) as *mut libc::c_void,
                    r.size as libc::size_t,
                    libc::MADV_DONTNEED,
                )
            };
            if res != 0 {
                error!("madvise get error {}", io::Error::last_os_error());
                return VIRTIO_MEM_RESP_ERROR;
            }
        }

        MemEpollHandler::virtio_mem_set_bitmap(bit_index, r.nb_blocks, r.mem_state, r.plug);

        VIRTIO_MEM_RESP_ACK
    }

    fn virtio_mem_unplug_all(
        config: VirtioMemConfig,
        mem_state: &mut Vec<bool>,
        host_addr: u64,
        host_fd: Option<RawFd>,
    ) -> u16 {
        for x in 0..(config.region_size / config.block_size as u64) as usize {
            if mem_state[x] {
                let resp_type =
                    MemEpollHandler::virtio_mem_state_change_request(StateChangeRequest {
                        config,
                        addr: config.addr + x as u64 * config.block_size as u64,
                        size: config.block_size as u64,
                        nb_blocks: 1,
                        mem_state,
                        host_addr,
                        host_fd,
                        plug: false,
                    });
                if resp_type != VIRTIO_MEM_RESP_ACK {
                    return resp_type;
                }
                mem_state[x] = false;
            }
        }

        VIRTIO_MEM_RESP_ACK
    }

    fn virtio_mem_state_request(
        config: VirtioMemConfig,
        addr: u64,
        nb_blocks: u16,
        mem_state: &mut Vec<bool>,
    ) -> (u16, u16) {
        let size: u64 = nb_blocks as u64 * config.block_size as u64;
        let resp_type = if MemEpollHandler::virtio_mem_valid_range(&config, addr, size) {
            VIRTIO_MEM_RESP_ACK
        } else {
            VIRTIO_MEM_RESP_ERROR
        };

        let offset = addr - config.addr;
        let bit_index = (offset / config.block_size as u64) as usize;
        let resp_state =
            if MemEpollHandler::virtio_mem_check_bitmap(bit_index, nb_blocks, mem_state, true) {
                VIRTIO_MEM_STATE_PLUGGED
            } else if MemEpollHandler::virtio_mem_check_bitmap(
                bit_index, nb_blocks, mem_state, false,
            ) {
                VIRTIO_MEM_STATE_UNPLUGGED
            } else {
                VIRTIO_MEM_STATE_MIXED
            };

        (resp_type, resp_state)
    }

    fn virtio_mem_send_response(
        mem: &GuestMemoryMmap,
        resp_type: u16,
        resp_state: u16,
        status_addr: GuestAddress,
    ) -> u32 {
        let mut resp = VirtioMemResp::default();
        resp.resp_type = resp_type;
        resp.state.state = resp_state;
        match mem.write_obj(resp, status_addr) {
            Ok(_) => size_of::<VirtioMemResp>() as u32,
            Err(e) => {
                error!("bad guest memory address: {}", e);
                0
            }
        }
    }

    fn signal(&self, int_type: &VirtioInterruptType) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(int_type, Some(&self.queue))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn process_queue(&mut self) -> bool {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in self.queue.iter(&mem) {
            let len = match Request::parse(&avail_desc, &mem) {
                Err(e) => {
                    error!("failed parse VirtioMemReq: {:?}", e);
                    0
                }
                Ok(r) => {
                    let mut config = self.config.lock().unwrap();
                    match r.req.req_type {
                        VIRTIO_MEM_REQ_PLUG => {
                            let size: u64 = r.req.nb_blocks as u64 * config.block_size as u64;
                            let resp_type = MemEpollHandler::virtio_mem_state_change_request(
                                StateChangeRequest {
                                    config: *config,
                                    addr: r.req.addr,
                                    size,
                                    nb_blocks: r.req.nb_blocks,
                                    mem_state: &mut self.mem_state,
                                    host_addr: self.host_addr,
                                    host_fd: self.host_fd,
                                    plug: true,
                                },
                            );
                            if resp_type == VIRTIO_MEM_RESP_ACK {
                                config.plugged_size += size;
                            }
                            MemEpollHandler::virtio_mem_send_response(
                                &mem,
                                resp_type,
                                0u16,
                                r.status_addr,
                            )
                        }
                        VIRTIO_MEM_REQ_UNPLUG => {
                            let size: u64 = r.req.nb_blocks as u64 * config.block_size as u64;
                            let resp_type = MemEpollHandler::virtio_mem_state_change_request(
                                StateChangeRequest {
                                    config: *config,
                                    addr: r.req.addr,
                                    size,
                                    nb_blocks: r.req.nb_blocks,
                                    mem_state: &mut self.mem_state,
                                    host_addr: self.host_addr,
                                    host_fd: self.host_fd,
                                    plug: false,
                                },
                            );
                            if resp_type == VIRTIO_MEM_RESP_ACK {
                                config.plugged_size -= size;
                            }
                            MemEpollHandler::virtio_mem_send_response(
                                &mem,
                                resp_type,
                                0u16,
                                r.status_addr,
                            )
                        }
                        VIRTIO_MEM_REQ_UNPLUG_ALL => {
                            let resp_type = MemEpollHandler::virtio_mem_unplug_all(
                                *config,
                                &mut self.mem_state,
                                self.host_addr,
                                self.host_fd,
                            );
                            if resp_type == VIRTIO_MEM_RESP_ACK {
                                config.plugged_size = 0;
                                config.usable_region_size = cmp::min(
                                    config.region_size,
                                    config.requested_size + VIRTIO_MEM_USABLE_EXTENT,
                                );
                            }
                            MemEpollHandler::virtio_mem_send_response(
                                &mem,
                                resp_type,
                                0u16,
                                r.status_addr,
                            )
                        }
                        VIRTIO_MEM_REQ_STATE => {
                            let (resp_type, resp_state) = MemEpollHandler::virtio_mem_state_request(
                                *config,
                                r.req.addr,
                                r.req.nb_blocks,
                                &mut self.mem_state,
                            );
                            MemEpollHandler::virtio_mem_send_response(
                                &mem,
                                resp_type,
                                resp_state,
                                r.status_addr,
                            )
                        }
                        _ => {
                            error!("VirtioMemReq unknown request type {:?}", r.req.req_type);
                            0
                        }
                    }
                }
            };
            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queue.add_used(&mem, desc_index, len);
        }
        used_count > 0
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.resize.evt.as_raw_fd(), RESIZE_EVENT)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for MemEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            RESIZE_EVENT => {
                if let Err(e) = self.resize.evt.read() {
                    error!("Failed to get resize event: {:?}", e);
                    return true;
                } else {
                    let size = self.resize.get_size();
                    let mut config = self.config.lock().unwrap();
                    let mut signal_error = false;
                    let mut r = virtio_mem_config_resize(&mut config, size);
                    r = match r {
                        Err(e) => Err(e),
                        _ => match self.signal(&VirtioInterruptType::Config) {
                            Err(e) => {
                                signal_error = true;
                                Err(Error::ResizeTriggerFail(e))
                            }
                            _ => Ok(()),
                        },
                    };
                    if let Err(e) = self.resize.send(r) {
                        error!("Sending \"resize\" reponse: {:?}", e);
                        return true;
                    }
                    if signal_error {
                        return true;
                    }
                }
            }
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.process_queue() {
                    if let Err(e) = self.signal(&VirtioInterruptType::Queue) {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            _ => {
                error!("Unexpected event: {}", ev_type);
                return true;
            }
        }
        false
    }
}

// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Mem {
    id: String,
    resize: Resize,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    avail_features: u64,
    pub acked_features: u64,
    host_addr: u64,
    host_fd: Option<RawFd>,
    config: Arc<Mutex<VirtioMemConfig>>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<()>>>,
    paused: Arc<AtomicBool>,
    paused_sync: Arc<Barrier>,
    seccomp_action: SeccompAction,
}

impl Mem {
    // Create a new virtio-mem device.
    pub fn new(
        id: String,
        region: &Arc<GuestRegionMmap>,
        resize: Resize,
        seccomp_action: SeccompAction,
    ) -> io::Result<Mem> {
        let region_len = region.len();

        if region_len != region_len / VIRTIO_MEM_DEFAULT_BLOCK_SIZE * VIRTIO_MEM_DEFAULT_BLOCK_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Virtio-mem size is not aligned with {}",
                    VIRTIO_MEM_DEFAULT_BLOCK_SIZE
                ),
            ));
        }

        // Fixme: Not support VIRTIO_MEM_F_ACPI_PXM
        let avail_features = 1u64 << VIRTIO_F_VERSION_1;

        let mut config = VirtioMemConfig::default();
        config.block_size = VIRTIO_MEM_DEFAULT_BLOCK_SIZE;
        config.addr = region.start_addr().raw_value();
        config.region_size = region.len();
        config.usable_region_size = cmp::min(
            config.region_size,
            config.requested_size + VIRTIO_MEM_USABLE_EXTENT,
        );

        let host_fd = if let Some(f_offset) = region.file_offset() {
            Some(f_offset.file().as_raw_fd())
        } else {
            None
        };

        Ok(Mem {
            id,
            resize,
            kill_evt: None,
            pause_evt: None,
            avail_features,
            acked_features: 0u64,
            host_addr: region.as_ptr() as u64,
            host_fd,
            config: Arc::new(Mutex::new(config)),
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            paused: Arc::new(AtomicBool::new(false)),
            paused_sync: Arc::new(Barrier::new(2)),
            seccomp_action,
        })
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Mem {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_MEM as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.lock().unwrap().as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        let config = self.config.lock().unwrap();
        let mut handler = MemEpollHandler {
            host_addr: self.host_addr,
            host_fd: self.host_fd,
            mem_state: vec![false; config.region_size as usize / config.block_size as usize],
            config: self.config.clone(),
            resize: self.resize.try_clone().map_err(|e| {
                error!("failed to clone resize EventFd: {:?}", e);
                ActivateError::BadActivate
            })?,
            queue: queues.remove(0),
            mem,
            interrupt_cb,
            queue_evt: queue_evts.remove(0),
            kill_evt,
            pause_evt,
        };

        let paused = self.paused.clone();
        let paused_sync = self.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        // Retrieve seccomp filter for virtio_mem thread
        let virtio_mem_seccomp_filter = get_seccomp_filter(&self.seccomp_action, Thread::VirtioMem)
            .map_err(ActivateError::CreateSeccompFilter)?;
        thread::Builder::new()
            .name("virtio_mem".to_string())
            .spawn(move || {
                if let Err(e) = SeccompFilter::apply(virtio_mem_seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                } else if let Err(e) = handler.run(paused, paused_sync) {
                    error!("Error running worker: {:?}", e);
                }
            })
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone virtio-mem epoll thread: {}", e);
                ActivateError::BadActivate
            })?;
        self.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }
}

virtio_pausable!(Mem);
impl Snapshottable for Mem {
    fn id(&self) -> String {
        self.id.clone()
    }
}
impl Transportable for Mem {}
impl Migratable for Mem {}
