// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::Error as DeviceError;
use super::{
    ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, VirtioCommon, VirtioDevice,
    VirtioDeviceType, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::GuestMemoryMmap;
use crate::{DmaRemapping, VirtioInterrupt, VirtioInterruptType};
use seccompiler::SeccompAction;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::io;
use std::mem::size_of;
use std::ops::Bound::Included;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, RwLock};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_queue::{DescriptorChain, Queue};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryError,
    GuestMemoryLoadGuard,
};
use vm_migration::VersionMapped;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

/// Queues sizes
const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

/// New descriptors are pending on the request queue.
/// "requestq" is meant to be used anytime an action is required to be
/// performed on behalf of the guest driver.
const REQUEST_Q_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
/// New descriptors are pending on the event queue.
/// "eventq" lets the device report any fault or other asynchronous event to
/// the guest driver.
const EVENT_Q_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

/// PROBE properties size.
/// This is the minimal size to provide at least one RESV_MEM property.
/// Because virtio-iommu expects one MSI reserved region, we must provide it,
/// otherwise the driver in the guest will define a predefined one between
/// 0x8000000 and 0x80FFFFF, which is only relevant for ARM architecture, but
/// will conflict with x86.
const PROBE_PROP_SIZE: u32 =
    (size_of::<VirtioIommuProbeProperty>() + size_of::<VirtioIommuProbeResvMem>()) as u32;

/// Virtio IOMMU features
#[allow(unused)]
const VIRTIO_IOMMU_F_INPUT_RANGE: u32 = 0;
#[allow(unused)]
const VIRTIO_IOMMU_F_DOMAIN_RANGE: u32 = 1;
#[allow(unused)]
const VIRTIO_IOMMU_F_MAP_UNMAP: u32 = 2;
#[allow(unused)]
const VIRTIO_IOMMU_F_BYPASS: u32 = 3;
const VIRTIO_IOMMU_F_PROBE: u32 = 4;
#[allow(unused)]
const VIRTIO_IOMMU_F_MMIO: u32 = 5;
#[allow(unused)]
const VIRTIO_IOMMU_F_BYPASS_CONFIG: u32 = 6;

// Support 2MiB and 4KiB page sizes.
const VIRTIO_IOMMU_PAGE_SIZE_MASK: u64 = (2 << 20) | (4 << 10);

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuRange32 {
    start: u32,
    end: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuRange64 {
    start: u64,
    end: u64,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuConfig {
    page_size_mask: u64,
    input_range: VirtioIommuRange64,
    domain_range: VirtioIommuRange32,
    probe_size: u32,
    bypass: u8,
    _reserved: [u8; 7],
}

/// Virtio IOMMU request type
const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
const VIRTIO_IOMMU_T_DETACH: u8 = 2;
const VIRTIO_IOMMU_T_MAP: u8 = 3;
const VIRTIO_IOMMU_T_UNMAP: u8 = 4;
const VIRTIO_IOMMU_T_PROBE: u8 = 5;

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioIommuReqHead {
    type_: u8,
    _reserved: [u8; 3],
}

/// Virtio IOMMU request status
const VIRTIO_IOMMU_S_OK: u8 = 0;
#[allow(unused)]
const VIRTIO_IOMMU_S_IOERR: u8 = 1;
#[allow(unused)]
const VIRTIO_IOMMU_S_UNSUPP: u8 = 2;
#[allow(unused)]
const VIRTIO_IOMMU_S_DEVERR: u8 = 3;
#[allow(unused)]
const VIRTIO_IOMMU_S_INVAL: u8 = 4;
#[allow(unused)]
const VIRTIO_IOMMU_S_RANGE: u8 = 5;
#[allow(unused)]
const VIRTIO_IOMMU_S_NOENT: u8 = 6;
#[allow(unused)]
const VIRTIO_IOMMU_S_FAULT: u8 = 7;
#[allow(unused)]
const VIRTIO_IOMMU_S_NOMEM: u8 = 8;

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuReqTail {
    status: u8,
    _reserved: [u8; 3],
}

/// ATTACH request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioIommuReqAttach {
    domain: u32,
    endpoint: u32,
    _reserved: [u8; 8],
}

/// DETACH request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioIommuReqDetach {
    domain: u32,
    endpoint: u32,
    _reserved: [u8; 8],
}

/// Virtio IOMMU request MAP flags
#[allow(unused)]
const VIRTIO_IOMMU_MAP_F_READ: u32 = 1;
#[allow(unused)]
const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 1 << 1;
#[allow(unused)]
const VIRTIO_IOMMU_MAP_F_MMIO: u32 = 1 << 2;
#[allow(unused)]
const VIRTIO_IOMMU_MAP_F_MASK: u32 =
    VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO;

/// MAP request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioIommuReqMap {
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    phys_start: u64,
    _flags: u32,
}

/// UNMAP request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioIommuReqUnmap {
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    _reserved: [u8; 4],
}

/// Virtio IOMMU request PROBE types
#[allow(unused)]
const VIRTIO_IOMMU_PROBE_T_NONE: u16 = 0;
const VIRTIO_IOMMU_PROBE_T_RESV_MEM: u16 = 1;
#[allow(unused)]
const VIRTIO_IOMMU_PROBE_T_MASK: u16 = 0xfff;

/// PROBE request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuReqProbe {
    endpoint: u32,
    _reserved: [u64; 8],
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuProbeProperty {
    type_: u16,
    length: u16,
}

/// Virtio IOMMU request PROBE property RESV_MEM subtypes
#[allow(unused)]
const VIRTIO_IOMMU_RESV_MEM_T_RESERVED: u8 = 0;
const VIRTIO_IOMMU_RESV_MEM_T_MSI: u8 = 1;

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioIommuProbeResvMem {
    subtype: u8,
    _reserved: [u8; 3],
    start: u64,
    end: u64,
}

/// Virtio IOMMU fault flags
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_F_READ: u32 = 1;
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_F_WRITE: u32 = 1 << 1;
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_F_EXEC: u32 = 1 << 2;
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_F_ADDRESS: u32 = 1 << 8;

/// Virtio IOMMU fault reasons
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_R_UNKNOWN: u32 = 0;
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_R_DOMAIN: u32 = 1;
#[allow(unused)]
const VIRTIO_IOMMU_FAULT_R_MAPPING: u32 = 2;

/// Fault reporting through eventq
#[allow(unused)]
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioIommuFault {
    reason: u8,
    reserved: [u8; 3],
    flags: u32,
    endpoint: u32,
    reserved2: [u8; 4],
    address: u64,
}

// SAFETY: these data structures only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuRange32 {}
unsafe impl ByteValued for VirtioIommuRange64 {}
unsafe impl ByteValued for VirtioIommuConfig {}
unsafe impl ByteValued for VirtioIommuReqHead {}
unsafe impl ByteValued for VirtioIommuReqTail {}
unsafe impl ByteValued for VirtioIommuReqAttach {}
unsafe impl ByteValued for VirtioIommuReqDetach {}
unsafe impl ByteValued for VirtioIommuReqMap {}
unsafe impl ByteValued for VirtioIommuReqUnmap {}
unsafe impl ByteValued for VirtioIommuReqProbe {}
unsafe impl ByteValued for VirtioIommuProbeProperty {}
unsafe impl ByteValued for VirtioIommuProbeResvMem {}
unsafe impl ByteValued for VirtioIommuFault {}

#[derive(Debug)]
enum Error {
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a buffer that was too short to use.
    BufferLengthTooSmall,
    /// Guest sent us invalid request.
    InvalidRequest,
    /// Guest sent us invalid ATTACH request.
    InvalidAttachRequest,
    /// Guest sent us invalid DETACH request.
    InvalidDetachRequest,
    /// Guest sent us invalid MAP request.
    InvalidMapRequest,
    /// Guest sent us invalid UNMAP request.
    InvalidUnmapRequest,
    /// Guest sent us invalid PROBE request.
    InvalidProbeRequest,
    /// Failed to performing external mapping.
    ExternalMapping(io::Error),
    /// Failed to performing external unmapping.
    ExternalUnmapping(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            BufferLengthTooSmall => write!(f, "buffer length too small"),
            DescriptorChainTooShort => write!(f, "descriptor chain too short"),
            GuestMemory(e) => write!(f, "bad guest memory address: {}", e),
            InvalidRequest => write!(f, "invalid request"),
            InvalidAttachRequest => write!(f, "invalid attach request"),
            InvalidDetachRequest => write!(f, "invalid detach request"),
            InvalidMapRequest => write!(f, "invalid map request"),
            InvalidUnmapRequest => write!(f, "invalid unmap request"),
            InvalidProbeRequest => write!(f, "invalid probe request"),
            UnexpectedReadOnlyDescriptor => write!(f, "unexpected read-only descriptor"),
            UnexpectedWriteOnlyDescriptor => write!(f, "unexpected write-only descriptor"),
            ExternalMapping(e) => write!(f, "failed performing external mapping: {}", e),
            ExternalUnmapping(e) => write!(f, "failed performing external unmapping: {}", e),
        }
    }
}

struct Request {}

impl Request {
    // Parse the available vring buffer. Based on the hashmap table of external
    // mappings required from various devices such as VFIO or vhost-user ones,
    // this function might update the hashmap table of external mappings per
    // domain.
    // Basically, the VMM knows about the device_id <=> mapping relationship
    // before running the VM, but at runtime, a new domain <=> mapping hashmap
    // is created based on the information provided from the guest driver for
    // virtio-iommu (giving the link device_id <=> domain).
    fn parse(
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        mapping: &Arc<IommuMapping>,
        ext_mapping: &BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
        ext_domain_mapping: &mut BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
        msi_iova_space: (u64, u64),
    ) -> result::Result<usize, Error> {
        let desc = desc_chain
            .next()
            .ok_or(Error::DescriptorChainTooShort)
            .map_err(|e| {
                error!("Missing head descriptor");
                e
            })?;

        // The descriptor contains the request type which MUST be readable.
        if desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        if (desc.len() as usize) < size_of::<VirtioIommuReqHead>() {
            return Err(Error::InvalidRequest);
        }

        let req_head: VirtioIommuReqHead = desc_chain
            .memory()
            .read_obj(desc.addr())
            .map_err(Error::GuestMemory)?;
        let req_offset = size_of::<VirtioIommuReqHead>();
        let desc_size_left = (desc.len() as usize) - req_offset;
        let req_addr = if let Some(addr) = desc.addr().checked_add(req_offset as u64) {
            addr
        } else {
            return Err(Error::InvalidRequest);
        };

        let (msi_iova_start, msi_iova_end) = msi_iova_space;

        // Create the reply
        let mut reply: Vec<u8> = Vec::new();

        let hdr_len = match req_head.type_ {
            VIRTIO_IOMMU_T_ATTACH => {
                if desc_size_left != size_of::<VirtioIommuReqAttach>() {
                    return Err(Error::InvalidAttachRequest);
                }

                let req: VirtioIommuReqAttach = desc_chain
                    .memory()
                    .read_obj(req_addr as GuestAddress)
                    .map_err(Error::GuestMemory)?;
                debug!("Attach request {:?}", req);

                // Copy the value to use it as a proper reference.
                let domain = req.domain;
                let endpoint = req.endpoint;

                // Add endpoint associated with specific domain
                mapping.endpoints.write().unwrap().insert(endpoint, domain);

                // If the endpoint is part of the list of devices with an
                // external mapping, insert a new entry for the corresponding
                // domain, with the same reference to the trait.
                if let Some(map) = ext_mapping.get(&endpoint) {
                    ext_domain_mapping.insert(domain, map.clone());
                }

                // Add new domain with no mapping if the entry didn't exist yet
                let mut mappings = mapping.mappings.write().unwrap();
                mappings.entry(domain).or_insert_with(BTreeMap::new);

                0
            }
            VIRTIO_IOMMU_T_DETACH => {
                if desc_size_left != size_of::<VirtioIommuReqDetach>() {
                    return Err(Error::InvalidDetachRequest);
                }

                let req: VirtioIommuReqDetach = desc_chain
                    .memory()
                    .read_obj(req_addr as GuestAddress)
                    .map_err(Error::GuestMemory)?;
                debug!("Detach request {:?}", req);

                // Copy the value to use it as a proper reference.
                let domain = req.domain;
                let endpoint = req.endpoint;

                // If the endpoint is part of the list of devices with an
                // external mapping, remove the entry for the corresponding
                // domain.
                if ext_mapping.contains_key(&endpoint) {
                    ext_domain_mapping.remove(&domain);
                }

                // Remove endpoint associated with specific domain
                mapping.endpoints.write().unwrap().remove(&endpoint);

                0
            }
            VIRTIO_IOMMU_T_MAP => {
                if desc_size_left != size_of::<VirtioIommuReqMap>() {
                    return Err(Error::InvalidMapRequest);
                }

                let req: VirtioIommuReqMap = desc_chain
                    .memory()
                    .read_obj(req_addr as GuestAddress)
                    .map_err(Error::GuestMemory)?;
                debug!("Map request {:?}", req);

                // Copy the value to use it as a proper reference.
                let domain = req.domain;

                // Trigger external mapping if necessary.
                if let Some(ext_map) = ext_domain_mapping.get(&domain) {
                    let size = req.virt_end - req.virt_start + 1;
                    ext_map
                        .map(req.virt_start, req.phys_start, size)
                        .map_err(Error::ExternalMapping)?;
                }

                // Add new mapping associated with the domain
                if let Some(entry) = mapping.mappings.write().unwrap().get_mut(&domain) {
                    entry.insert(
                        req.virt_start,
                        Mapping {
                            gpa: req.phys_start,
                            size: req.virt_end - req.virt_start + 1,
                        },
                    );
                } else {
                    return Err(Error::InvalidMapRequest);
                }

                0
            }
            VIRTIO_IOMMU_T_UNMAP => {
                if desc_size_left != size_of::<VirtioIommuReqUnmap>() {
                    return Err(Error::InvalidUnmapRequest);
                }

                let req: VirtioIommuReqUnmap = desc_chain
                    .memory()
                    .read_obj(req_addr as GuestAddress)
                    .map_err(Error::GuestMemory)?;
                debug!("Unmap request {:?}", req);

                // Copy the value to use it as a proper reference.
                let domain = req.domain;
                let virt_start = req.virt_start;

                // Trigger external unmapping if necessary.
                if let Some(ext_map) = ext_domain_mapping.get(&domain) {
                    let size = req.virt_end - virt_start + 1;
                    ext_map
                        .unmap(virt_start, size)
                        .map_err(Error::ExternalUnmapping)?;
                }

                // Add new mapping associated with the domain
                if let Some(entry) = mapping.mappings.write().unwrap().get_mut(&domain) {
                    entry.remove(&virt_start);
                }

                0
            }
            VIRTIO_IOMMU_T_PROBE => {
                if desc_size_left != size_of::<VirtioIommuReqProbe>() {
                    return Err(Error::InvalidProbeRequest);
                }

                let req: VirtioIommuReqProbe = desc_chain
                    .memory()
                    .read_obj(req_addr as GuestAddress)
                    .map_err(Error::GuestMemory)?;
                debug!("Probe request {:?}", req);

                let probe_prop = VirtioIommuProbeProperty {
                    type_: VIRTIO_IOMMU_PROBE_T_RESV_MEM,
                    length: size_of::<VirtioIommuProbeResvMem>() as u16,
                };
                reply.extend_from_slice(probe_prop.as_slice());

                let resv_mem = VirtioIommuProbeResvMem {
                    subtype: VIRTIO_IOMMU_RESV_MEM_T_MSI,
                    start: msi_iova_start,
                    end: msi_iova_end,
                    ..Default::default()
                };
                reply.extend_from_slice(resv_mem.as_slice());

                PROBE_PROP_SIZE
            }
            _ => return Err(Error::InvalidRequest),
        };

        let status_desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len() < hdr_len + size_of::<VirtioIommuReqTail>() as u32 {
            return Err(Error::BufferLengthTooSmall);
        }

        let tail = VirtioIommuReqTail {
            status: VIRTIO_IOMMU_S_OK,
            ..Default::default()
        };
        reply.extend_from_slice(tail.as_slice());

        desc_chain
            .memory()
            .write_slice(reply.as_slice(), status_desc.addr())
            .map_err(Error::GuestMemory)?;

        Ok((hdr_len as usize) + size_of::<VirtioIommuReqTail>())
    }
}

struct IommuEpollHandler {
    queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evts: Vec<EventFd>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    mapping: Arc<IommuMapping>,
    ext_mapping: BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
    ext_domain_mapping: BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
    msi_iova_space: (u64, u64),
}

impl IommuEpollHandler {
    fn request_queue(&mut self) -> bool {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for mut desc_chain in self.queues[0].iter().unwrap() {
            let len = match Request::parse(
                &mut desc_chain,
                &self.mapping,
                &self.ext_mapping,
                &mut self.ext_domain_mapping,
                self.msi_iova_space,
            ) {
                Ok(len) => len as u32,
                Err(e) => {
                    error!("failed parsing descriptor: {}", e);
                    0
                }
            };

            used_desc_heads[used_count] = (desc_chain.head_index(), len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queues[0].add_used(desc_index, len).unwrap();
        }
        used_count > 0
    }

    fn event_queue(&mut self) -> bool {
        false
    }

    fn signal_used_queue(&self, queue_index: u16) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evts[0].as_raw_fd(), REQUEST_Q_EVENT)?;
        helper.add_event(self.queue_evts[1].as_raw_fd(), EVENT_Q_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for IommuEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            REQUEST_Q_EVENT => {
                if let Err(e) = self.queue_evts[0].read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.request_queue() {
                    if let Err(e) = self.signal_used_queue(0) {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            EVENT_Q_EVENT => {
                if let Err(e) = self.queue_evts[1].read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.event_queue() {
                    if let Err(e) = self.signal_used_queue(1) {
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

#[derive(Clone, Copy, Debug, Versionize)]
struct Mapping {
    gpa: u64,
    size: u64,
}

#[derive(Debug)]
pub struct IommuMapping {
    // Domain related to an endpoint.
    endpoints: Arc<RwLock<BTreeMap<u32, u32>>>,
    // List of mappings per domain.
    mappings: Arc<RwLock<BTreeMap<u32, BTreeMap<u64, Mapping>>>>,
}

impl DmaRemapping for IommuMapping {
    fn translate(&self, id: u32, addr: u64) -> std::result::Result<u64, std::io::Error> {
        debug!("Translate addr 0x{:x}", addr);
        if let Some(domain) = self.endpoints.read().unwrap().get(&id) {
            if let Some(mapping) = self.mappings.read().unwrap().get(domain) {
                let range_start = if VIRTIO_IOMMU_PAGE_SIZE_MASK > addr {
                    0
                } else {
                    addr - VIRTIO_IOMMU_PAGE_SIZE_MASK
                };
                for (&key, &value) in mapping.range((Included(&range_start), Included(&addr))) {
                    if addr >= key && addr < key + value.size {
                        let new_addr = addr - key + value.gpa;
                        debug!("Into new_addr 0x{:x}", new_addr);
                        return Ok(new_addr);
                    }
                }
            }
        }

        debug!("Into same addr...");
        Ok(addr)
    }
}

#[derive(Debug)]
pub struct AccessPlatformMapping {
    id: u32,
    mapping: Arc<IommuMapping>,
}

impl AccessPlatformMapping {
    pub fn new(id: u32, mapping: Arc<IommuMapping>) -> Self {
        AccessPlatformMapping { id, mapping }
    }
}

impl AccessPlatform for AccessPlatformMapping {
    fn translate(&self, base: u64, _size: u64) -> std::result::Result<u64, std::io::Error> {
        self.mapping.translate(self.id, base)
    }
}

pub struct Iommu {
    common: VirtioCommon,
    id: String,
    config: VirtioIommuConfig,
    mapping: Arc<IommuMapping>,
    ext_mapping: BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    msi_iova_space: (u64, u64),
}

#[derive(Versionize)]
struct IommuState {
    avail_features: u64,
    acked_features: u64,
    endpoints: Vec<(u32, u32)>,
    mappings: Vec<(u32, Vec<(u64, Mapping)>)>,
}

impl VersionMapped for IommuState {}

impl Iommu {
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        msi_iova_space: (u64, u64),
    ) -> io::Result<(Self, Arc<IommuMapping>)> {
        let config = VirtioIommuConfig {
            page_size_mask: VIRTIO_IOMMU_PAGE_SIZE_MASK,
            probe_size: PROBE_PROP_SIZE,
            ..Default::default()
        };

        let mapping = Arc::new(IommuMapping {
            endpoints: Arc::new(RwLock::new(BTreeMap::new())),
            mappings: Arc::new(RwLock::new(BTreeMap::new())),
        });

        Ok((
            Iommu {
                id,
                common: VirtioCommon {
                    device_type: VirtioDeviceType::Iommu as u32,
                    queue_sizes: QUEUE_SIZES.to_vec(),
                    avail_features: 1u64 << VIRTIO_F_VERSION_1
                        | 1u64 << VIRTIO_IOMMU_F_MAP_UNMAP
                        | 1u64 << VIRTIO_IOMMU_F_PROBE,
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    ..Default::default()
                },
                config,
                mapping: mapping.clone(),
                ext_mapping: BTreeMap::new(),
                seccomp_action,
                exit_evt,
                msi_iova_space,
            },
            mapping,
        ))
    }

    fn state(&self) -> IommuState {
        IommuState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            endpoints: self
                .mapping
                .endpoints
                .read()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
            mappings: self
                .mapping
                .mappings
                .read()
                .unwrap()
                .clone()
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().collect()))
                .collect(),
        }
    }

    fn set_state(&mut self, state: &IommuState) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        *(self.mapping.endpoints.write().unwrap()) = state.endpoints.clone().into_iter().collect();
        *(self.mapping.mappings.write().unwrap()) = state
            .mappings
            .clone()
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
    }

    pub fn add_external_mapping(&mut self, device_id: u32, mapping: Arc<dyn ExternalDmaMapping>) {
        self.ext_mapping.insert(device_id, mapping);
    }
}

impl Drop for Iommu {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Iommu {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        _mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        queue_evts: Vec<EventFd>,
        _resample_evt: Option<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();
        let mut handler = IommuEpollHandler {
            queues,
            interrupt_cb,
            queue_evts,
            kill_evt,
            pause_evt,
            mapping: self.mapping.clone(),
            ext_mapping: self.ext_mapping.clone(),
            ext_domain_mapping: BTreeMap::new(),
            msi_iova_space: self.msi_iova_space,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioIommu,
            &mut epoll_threads,
            &self.exit_evt,
            move || {
                if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running worker: {:?}", e);
                }
            },
        )?;

        self.common.epoll_threads = Some(epoll_threads);

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }
}

impl Pausable for Iommu {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Iommu {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_versioned_state(&self.id, &self.state())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}
impl Transportable for Iommu {}
impl Migratable for Iommu {}
