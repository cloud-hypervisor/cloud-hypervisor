// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{debug, error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_device::dma_mapping::{ExternalDmaMapping, ExternalDmaMappingError};
use vm_device::interrupt::{InterruptRemapping, MsiIrqSourceConfig};
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryBackend,
    GuestMemoryError,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::{AccessPlatform, AccessType};
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    Error as DeviceError, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice,
    VirtioDeviceType,
};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::thread_helper::PauseCommon;
use crate::{DmaRemapping, GuestMemory, VirtioInterrupt, VirtioInterruptType};

/// Queues sizes
const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: u16 = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES as usize];

/// New descriptors are pending on the request queue.
/// "requestq" is meant to be used anytime an action is required to be
/// performed on behalf of the guest driver.
const REQUEST_Q_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
/// New descriptors are pending on the event queue.
/// "eventq" lets the device report any fault or other asynchronous event to
/// the guest driver.
const _EVENT_Q_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

/// PROBE properties size.
/// This is the minimal size to provide at least one RESV_MEM property.
/// Because virtio-iommu expects one MSI reserved region, we must provide it,
/// otherwise the driver in the guest will define a predefined one between
/// 0x8000000 and 0x80FFFFF, which is only relevant for ARM architecture, but
/// will conflict with x86.
const PROBE_PROP_SIZE: u32 =
    (size_of::<VirtioIommuProbeProperty>() + size_of::<VirtioIommuProbeResvMem>()) as u32;

// Virtio IOMMU features

const VIRTIO_IOMMU_F_INPUT_RANGE: u32 = 0;
#[expect(dead_code)]
const VIRTIO_IOMMU_F_DOMAIN_RANGE: u32 = 1;
const VIRTIO_IOMMU_F_MAP_UNMAP: u32 = 2;
#[expect(dead_code)]
const VIRTIO_IOMMU_F_BYPASS: u32 = 3;
const VIRTIO_IOMMU_F_PROBE: u32 = 4;
const VIRTIO_IOMMU_F_MMIO: u32 = 5;
const VIRTIO_IOMMU_F_BYPASS_CONFIG: u32 = 6;

// Support 2MiB and 4KiB page sizes.
const VIRTIO_IOMMU_PAGE_SIZE_MASK: u64 = (2 << 20) | (4 << 10);
const VIRTIO_IOMMU_PAGE_GRANULE: u64 = 1u64 << VIRTIO_IOMMU_PAGE_SIZE_MASK.trailing_zeros();

// ~64 MiB at ~64 bytes/entry, well above any legitimate workload.
const MAX_MAPPINGS_PER_DOMAIN: usize = 1 << 20;

// Bound the per-device domain count so a guest cannot grow the
// domain map indefinitely with ATTACH-only requests.
const MAX_DOMAINS: usize = 1 << 16;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuRange32 {
    start: u32,
    end: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuRange64 {
    start: u64,
    end: u64,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuConfig {
    page_size_mask: u64,
    input_range: VirtioIommuRange64,
    domain_range: VirtioIommuRange32,
    probe_size: u32,
    bypass: u8,
    _reserved: [u8; 3],
}

/// Virtio IOMMU request type
const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
const VIRTIO_IOMMU_T_DETACH: u8 = 2;
const VIRTIO_IOMMU_T_MAP: u8 = 3;
const VIRTIO_IOMMU_T_UNMAP: u8 = 4;
const VIRTIO_IOMMU_T_PROBE: u8 = 5;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqHead {
    type_: u8,
    _reserved: [u8; 3],
}

/// Virtio IOMMU request status
const VIRTIO_IOMMU_S_OK: u8 = 0;
#[expect(dead_code)]
const VIRTIO_IOMMU_S_IOERR: u8 = 1;
#[expect(dead_code)]
const VIRTIO_IOMMU_S_UNSUPP: u8 = 2;
const VIRTIO_IOMMU_S_DEVERR: u8 = 3;
const VIRTIO_IOMMU_S_INVAL: u8 = 4;
const VIRTIO_IOMMU_S_RANGE: u8 = 5;
const VIRTIO_IOMMU_S_NOENT: u8 = 6;
#[expect(dead_code)]
const VIRTIO_IOMMU_S_FAULT: u8 = 7;
const VIRTIO_IOMMU_S_NOMEM: u8 = 8;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqTail {
    status: u8,
    _reserved: [u8; 3],
}

/// ATTACH request
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqAttach {
    domain: u32,
    endpoint: u32,
    flags: u32,
    reserved: [u8; 4],
}

const VIRTIO_IOMMU_ATTACH_F_BYPASS: u32 = 1;

/// DETACH request
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqDetach {
    domain: u32,
    endpoint: u32,
    _reserved: [u8; 8],
}

/// Virtio IOMMU request MAP flags
const VIRTIO_IOMMU_MAP_F_READ: u32 = 1;
const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 1 << 1;
const VIRTIO_IOMMU_MAP_F_MMIO: u32 = 1 << 2;
const VIRTIO_IOMMU_MAP_F_MASK: u32 =
    VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO;

/// MAP request
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqMap {
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    phys_start: u64,
    flags: u32,
}

/// UNMAP request
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqUnmap {
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    _reserved: [u8; 4],
}

/// Virtio IOMMU request PROBE types
#[expect(dead_code)]
const VIRTIO_IOMMU_PROBE_T_NONE: u16 = 0;
const VIRTIO_IOMMU_PROBE_T_RESV_MEM: u16 = 1;
#[expect(dead_code)]
const VIRTIO_IOMMU_PROBE_T_MASK: u16 = 0xfff;

/// PROBE request
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqProbe {
    endpoint: u32,
    _reserved: [u64; 8],
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuProbeProperty {
    type_: u16,
    length: u16,
}

/// Virtio IOMMU request PROBE property RESV_MEM subtypes
const VIRTIO_IOMMU_RESV_MEM_T_RESERVED: u8 = 0;
const VIRTIO_IOMMU_RESV_MEM_T_MSI: u8 = 1;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuProbeResvMem {
    subtype: u8,
    _reserved: [u8; 3],
    start: u64,
    end: u64,
}

/// Virtio IOMMU fault flags
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_F_READ: u32 = 1;
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_F_WRITE: u32 = 1 << 1;
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_F_EXEC: u32 = 1 << 2;
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_F_ADDRESS: u32 = 1 << 8;

/// Virtio IOMMU fault reasons
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_R_UNKNOWN: u32 = 0;
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_R_DOMAIN: u32 = 1;
#[expect(dead_code)]
const VIRTIO_IOMMU_FAULT_R_MAPPING: u32 = 2;

/// Fault reporting through eventq
#[expect(dead_code)]
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuFault {
    reason: u8,
    reserved: [u8; 3],
    flags: u32,
    endpoint: u32,
    reserved2: [u8; 4],
    address: u64,
}

// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuRange32 {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuRange64 {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuConfig {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqHead {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqTail {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqAttach {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqDetach {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqMap {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqUnmap {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuReqProbe {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuProbeProperty {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuProbeResvMem {}
// SAFETY: data structure only contain integers and have no implicit padding
unsafe impl ByteValued for VirtioIommuFault {}

#[derive(Error, Debug)]
enum Error {
    #[error("Guest gave us bad memory addresses")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Guest gave us a write only descriptor that protocol says to read from")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Guest gave us a read only descriptor that protocol says to write to")]
    UnexpectedReadOnlyDescriptor,
    #[error("Guest gave us too few descriptors in a descriptor chain")]
    DescriptorChainTooShort,
    #[error("Guest gave us a buffer that was too short to use")]
    BufferLengthTooSmall,
    #[error("Guest sent us invalid request")]
    InvalidRequest,
    #[error("Guest sent us invalid ATTACH request")]
    InvalidAttachRequest,
    #[error("Guest sent us invalid DETACH request")]
    InvalidDetachRequest,
    #[error("Invalid to detach because the endpoint is not attached to the domain")]
    InvalidDetachRequestWrongDomain,
    #[error("Guest sent us invalid MAP request")]
    InvalidMapRequest,
    #[error("Guest sent us MAP request with an invalid range")]
    InvalidMapRequestRange,
    #[error("Invalid to map because the domain is in bypass mode")]
    InvalidMapRequestBypassDomain,
    #[error("Invalid to map because the domain is missing")]
    InvalidMapRequestMissingDomain,
    #[error("Guest sent us invalid UNMAP request")]
    InvalidUnmapRequest,
    #[error("Guest sent us UNMAP request with an invalid range")]
    InvalidUnmapRequestRange,
    #[error("Invalid to unmap because the domain is in bypass mode")]
    InvalidUnmapRequestBypassDomain,
    #[error("Invalid to unmap because the domain is missing")]
    InvalidUnmapRequestMissingDomain,
    #[error("UNMAP range partially overlaps an existing mapping")]
    InvalidUnmapRequestPartialOverlap,
    #[error("Per-domain mapping count cap exceeded")]
    MappingCountExceeded,
    #[error("Per-device domain count cap exceeded: current:{0}, max:{MAX_DOMAINS}")]
    DomainCountExceeded(usize),
    #[error("Guest sent us invalid PROBE request")]
    InvalidProbeRequest,
    #[error("Failed to perform external mapping")]
    ExternalMapping(#[source] ExternalDmaMappingError),
    #[error("Failed to perform external unmapping")]
    ExternalUnmapping(#[source] ExternalDmaMappingError),
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
}

impl Error {
    /// Returns the raw virtio-iommu error status, if available.
    /// See Virtio 1.2, section 5.13.6 (Device operations).
    fn status(&self) -> Option<u8> {
        match self {
            Self::InvalidAttachRequest
            | Self::InvalidDetachRequest
            | Self::InvalidDetachRequestWrongDomain
            | Self::InvalidMapRequest
            | Self::InvalidMapRequestBypassDomain
            | Self::InvalidUnmapRequest
            | Self::InvalidUnmapRequestBypassDomain
            | Self::InvalidProbeRequest => Some(VIRTIO_IOMMU_S_INVAL),
            Self::InvalidMapRequestRange
            | Self::InvalidUnmapRequestRange
            | Self::InvalidUnmapRequestPartialOverlap => Some(VIRTIO_IOMMU_S_RANGE),
            Self::InvalidMapRequestMissingDomain | Self::InvalidUnmapRequestMissingDomain => {
                Some(VIRTIO_IOMMU_S_NOENT)
            }
            Self::MappingCountExceeded | Self::DomainCountExceeded(_) => Some(VIRTIO_IOMMU_S_NOMEM),
            Self::ExternalMapping(_) | Self::ExternalUnmapping(_) => Some(VIRTIO_IOMMU_S_DEVERR),
            // Some errors do not produce a virtio-iommu error status
            Self::GuestMemory(_)
            | Self::UnexpectedWriteOnlyDescriptor
            | Self::UnexpectedReadOnlyDescriptor
            | Self::DescriptorChainTooShort
            | Self::BufferLengthTooSmall
            | Self::InvalidRequest
            | Self::QueueAddUsed(_) => None,
        }
    }
}

struct TrackedDmaMapping {
    backend: Arc<dyn ExternalDmaMapping>,
    ranges: BTreeMap<u64, u64>,
}

impl TrackedDmaMapping {
    fn new(backend: Arc<dyn ExternalDmaMapping>) -> Self {
        Self {
            backend,
            ranges: BTreeMap::new(),
        }
    }

    fn map(
        &mut self,
        iova: u64,
        gpa: u64,
        size: u64,
    ) -> result::Result<(), ExternalDmaMappingError> {
        let invalid_map = |message: &'static str| ExternalDmaMappingError::Map {
            iova,
            gpa,
            size,
            source: io::Error::new(io::ErrorKind::InvalidInput, message).into(),
        };
        let end = inclusive_end(iova, size).ok_or_else(|| invalid_map("Invalid DMA range"))?;
        if let Some((&base, &len)) = self.ranges.range(..=end).next_back()
            && (base, len) != (iova, size)
            && inclusive_end(base, len).is_some_and(|last| last >= iova)
        {
            return Err(invalid_map(
                "DMA range overlaps an existing backend mapping",
            ));
        }
        self.backend.map(iova, gpa, size)?;
        self.ranges.insert(iova, size);
        Ok(())
    }

    fn splits_range(&self, start: u64, end: u64) -> bool {
        self.ranges
            .range(..start)
            .next_back()
            .and_then(|(&base, &size)| inclusive_end(base, size))
            .is_some_and(|last| last >= start)
            || self
                .ranges
                .range(start..=end)
                .next_back()
                .and_then(|(&base, &size)| inclusive_end(base, size))
                .is_some_and(|last| last > end)
    }

    fn unmap(&mut self, iova: u64, size: u64) -> result::Result<(), ExternalDmaMappingError> {
        self.backend.unmap(iova, size)?;
        let end = iova + (size - 1);
        while let Some((&start, _)) = self.ranges.range(iova..=end).next() {
            self.ranges.remove(&start);
        }
        Ok(())
    }

    fn unmap_all(&mut self) -> result::Result<(), ExternalDmaMappingError> {
        while let Some((&iova, &size)) = self.ranges.first_key_value() {
            self.unmap(iova, size)?;
        }
        Ok(())
    }
}

type ExternalDmaRegistry = BTreeMap<u32, TrackedDmaMapping>;

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
    fn parse<M>(
        desc_chain: &mut DescriptorChain<M>,
        mapping: &Arc<IommuMapping>,
        ext_mapping: &mut ExternalDmaRegistry,
        msi_iova_space: (u64, u64),
        reserved_regions: &[(u64, u64)],
        input_range: Option<(u64, u64)>,
    ) -> result::Result<usize, Error>
    where
        M: Deref,
        M::Target: GuestMemoryBackend,
    {
        let desc = desc_chain
            .next()
            .ok_or(Error::DescriptorChainTooShort)
            .inspect_err(|_| {
                error!("Missing head descriptor");
            })?;

        // The descriptor contains the request type which MUST be readable.
        if desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        if (desc.len() as usize) < size_of::<VirtioIommuReqHead>() {
            return Err(Error::InvalidRequest);
        }

        if !desc_chain
            .memory()
            .check_range(desc.addr(), desc.len() as usize)
        {
            return Err(Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(
                desc.addr(),
            )));
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
        let mut hdr_len = 0;

        // Unknown request types must leave the reply buffer untouched and
        // report a used length of zero.
        if !matches!(
            req_head.type_,
            VIRTIO_IOMMU_T_ATTACH
                | VIRTIO_IOMMU_T_DETACH
                | VIRTIO_IOMMU_T_MAP
                | VIRTIO_IOMMU_T_UNMAP
                | VIRTIO_IOMMU_T_PROBE
        ) {
            return Ok(0);
        }

        let result = (|| -> result::Result<(), Error> {
            match req_head.type_ {
                VIRTIO_IOMMU_T_ATTACH => {
                    if desc_size_left != size_of::<VirtioIommuReqAttach>() {
                        return Err(Error::InvalidAttachRequest);
                    }

                    let req: VirtioIommuReqAttach = desc_chain
                        .memory()
                        .read_obj(req_addr as GuestAddress)
                        .map_err(Error::GuestMemory)?;
                    debug!("Attach request 0x{req:x?}");

                    if req.reserved.iter().any(|&b| b != 0)
                        || (req.flags & !VIRTIO_IOMMU_ATTACH_F_BYPASS) != 0
                    {
                        return Err(Error::InvalidAttachRequest);
                    }

                    // Copy the value to use it as a proper reference.
                    let domain_id = req.domain;
                    let endpoint = req.endpoint;
                    let bypass =
                        (req.flags & VIRTIO_IOMMU_ATTACH_F_BYPASS) == VIRTIO_IOMMU_ATTACH_F_BYPASS;

                    {
                        let domains = mapping.domains.read().unwrap();
                        if let Some(d) = domains.get(&domain_id)
                            && d.bypass != bypass
                        {
                            return Err(Error::InvalidAttachRequest);
                        }

                        // Refuse before mutating any state so a failed ATTACH
                        // does not leave a phantom endpoint pointing at a
                        // domain that was never created.
                        if !domains.contains_key(&domain_id) && domains.len() >= MAX_DOMAINS {
                            return Err(Error::DomainCountExceeded(domains.len()));
                        }
                    }

                    let mut old_domain_id = domain_id;
                    if let Some(&id) = mapping.endpoints.read().unwrap().get(&endpoint) {
                        old_domain_id = id;
                    }

                    if old_domain_id != domain_id {
                        detach_endpoint_from_domain(endpoint, old_domain_id, mapping, ext_mapping)?;
                    }

                    // Add endpoint associated with specific domain
                    mapping
                        .endpoints
                        .write()
                        .unwrap()
                        .insert(endpoint, domain_id);

                    // If any other mappings exist in the domain for other containers,
                    // make sure to issue these mappings for the new endpoint/container
                    if let Some(domain_mappings) = &mapping.domains.read().unwrap().get(&domain_id)
                        && let Some(ext_map) = ext_mapping.get_mut(&endpoint)
                    {
                        for (virt_start, addr_map) in &domain_mappings.mappings {
                            ext_map
                                .map(*virt_start, addr_map.gpa, addr_map.size)
                                .map_err(Error::ExternalMapping)?;
                        }
                    }

                    // Add new domain with no mapping if the entry didn't exist yet
                    let mut domains = mapping.domains.write().unwrap();
                    if !domains.contains_key(&domain_id) && domains.len() >= MAX_DOMAINS {
                        // Defensive re-check under write lock. Single-threaded
                        // today, but keeps the invariant if processing ever
                        // becomes concurrent. Drop the domains write lock
                        // before taking the endpoints write lock so we never
                        // hold both simultaneously.
                        let count = domains.len();
                        drop(domains);
                        mapping.endpoints.write().unwrap().remove(&endpoint);
                        return Err(Error::DomainCountExceeded(count));
                    }
                    let domain = Domain {
                        mappings: BTreeMap::new(),
                        bypass,
                    };
                    domains.entry(domain_id).or_insert_with(|| domain);
                }
                VIRTIO_IOMMU_T_DETACH => {
                    if desc_size_left != size_of::<VirtioIommuReqDetach>() {
                        return Err(Error::InvalidDetachRequest);
                    }

                    let req: VirtioIommuReqDetach = desc_chain
                        .memory()
                        .read_obj(req_addr as GuestAddress)
                        .map_err(Error::GuestMemory)?;
                    debug!("Detach request 0x{req:x?}");

                    // Copy the value to use it as a proper reference.
                    let domain_id = req.domain;
                    let endpoint = req.endpoint;

                    // The endpoint must be attached to this very domain.
                    if mapping.endpoints.read().unwrap().get(&endpoint) != Some(&domain_id) {
                        return Err(Error::InvalidDetachRequestWrongDomain);
                    }

                    // Remove endpoint associated with specific domain
                    detach_endpoint_from_domain(endpoint, domain_id, mapping, ext_mapping)?;
                }
                VIRTIO_IOMMU_T_MAP => {
                    if desc_size_left != size_of::<VirtioIommuReqMap>() {
                        return Err(Error::InvalidMapRequest);
                    }

                    let req: VirtioIommuReqMap = desc_chain
                        .memory()
                        .read_obj(req_addr as GuestAddress)
                        .map_err(Error::GuestMemory)?;
                    debug!("Map request 0x{req:x?}");

                    if (req.flags & !VIRTIO_IOMMU_MAP_F_MASK) != 0 {
                        return Err(Error::InvalidMapRequest);
                    }

                    if let Some((lo, hi)) = input_range
                        && (req.virt_start < lo || req.virt_end > hi)
                    {
                        return Err(Error::InvalidMapRequestRange);
                    }

                    // Copy the value to use it as a proper reference.
                    let domain_id = req.domain;

                    if let Some(domain) = mapping.domains.read().unwrap().get(&domain_id) {
                        if domain.bypass {
                            return Err(Error::InvalidMapRequestBypassDomain);
                        }
                    } else {
                        return Err(Error::InvalidMapRequestMissingDomain);
                    }

                    // Find the list of endpoints attached to the given domain.
                    let endpoints: Vec<u32> = mapping
                        .endpoints
                        .write()
                        .unwrap()
                        .iter()
                        .filter(|&(_, &d)| d == domain_id)
                        .map(|(&e, _)| e)
                        .collect();

                    let Some(size) = req
                        .virt_end
                        .checked_sub(req.virt_start)
                        .and_then(|delta| delta.checked_add(1))
                    else {
                        return Err(Error::InvalidMapRequestRange);
                    };

                    if req.phys_start > u64::MAX - size || req.virt_start > u64::MAX - size {
                        return Err(Error::InvalidMapRequestRange);
                    }

                    let mask = VIRTIO_IOMMU_PAGE_GRANULE - 1;
                    if (req.virt_start & mask) != 0
                        || (req.phys_start & mask) != 0
                        || (size & mask) != 0
                    {
                        return Err(Error::InvalidMapRequestRange);
                    }

                    {
                        let domains = mapping.domains.read().unwrap();

                        // Going forward MAP rejects overlap, so within a domain
                        // mappings are disjoint and the rightmost mapping with
                        // start <= virt_end is the only candidate to overlap.
                        if let Some(d) = domains.get(&domain_id)
                            && let Some((&start, m)) = d.mappings.range(..=req.virt_end).next_back()
                            && let Some(end) = inclusive_end(start, m.size)
                            && end >= req.virt_start
                        {
                            return Err(Error::InvalidMapRequest);
                        }

                        if let Some(d) = domains.get(&domain_id)
                            && d.mappings.len() >= MAX_MAPPINGS_PER_DOMAIN
                        {
                            return Err(Error::MappingCountExceeded);
                        }
                    }

                    let mut mapped: Vec<u32> = Vec::new();
                    let rollback = |mapped: &[u32], ext_mapping: &mut ExternalDmaRegistry| {
                        for ep in mapped {
                            if let Some(pmap) = ext_mapping.get_mut(ep)
                                && let Err(e) = pmap.unmap(req.virt_start, size)
                            {
                                warn!(
                                    "Failed to roll back external DMA mapping for endpoint {ep}: {e:?}"
                                );
                            }
                        }
                    };
                    // For viommu all endpoints receive their own VFIO container, as a result
                    // Each endpoint within the domain needs to be separately mapped, as the
                    // mapping is done on a per-container level, not a per-domain level
                    for endpoint in endpoints {
                        if let Some(ext_map) = ext_mapping.get_mut(&endpoint) {
                            if let Err(e) = ext_map.map(req.virt_start, req.phys_start, size) {
                                rollback(&mapped, ext_mapping);
                                return Err(Error::ExternalMapping(e));
                            }
                            mapped.push(endpoint);
                        }
                    }

                    let mut domains = mapping.domains.write().unwrap();
                    let Some(domain) = domains.get_mut(&domain_id) else {
                        rollback(&mapped, ext_mapping);
                        return Err(Error::InvalidMapRequestMissingDomain);
                    };
                    if domain.mappings.len() >= MAX_MAPPINGS_PER_DOMAIN {
                        rollback(&mapped, ext_mapping);
                        return Err(Error::MappingCountExceeded);
                    }
                    domain.mappings.insert(
                        req.virt_start,
                        Mapping {
                            gpa: req.phys_start,
                            size,
                            flags: req.flags,
                        },
                    );
                }
                VIRTIO_IOMMU_T_UNMAP => {
                    if desc_size_left != size_of::<VirtioIommuReqUnmap>() {
                        return Err(Error::InvalidUnmapRequest);
                    }

                    let req: VirtioIommuReqUnmap = desc_chain
                        .memory()
                        .read_obj(req_addr as GuestAddress)
                        .map_err(Error::GuestMemory)?;
                    debug!("Unmap request 0x{req:x?}");

                    if let Some((lo, hi)) = input_range
                        && (req.virt_start < lo || req.virt_end > hi)
                    {
                        return Err(Error::InvalidUnmapRequestRange);
                    }

                    // Copy the value to use it as a proper reference.
                    let domain_id = req.domain;
                    let virt_start = req.virt_start;
                    let virt_end = req.virt_end;

                    if let Some(domain) = mapping.domains.read().unwrap().get(&domain_id) {
                        if domain.bypass {
                            return Err(Error::InvalidUnmapRequestBypassDomain);
                        }
                    } else {
                        return Err(Error::InvalidUnmapRequestMissingDomain);
                    }

                    let Some(size) = virt_end
                        .checked_sub(virt_start)
                        .and_then(|d| d.checked_add(1))
                    else {
                        return Err(Error::InvalidUnmapRequestRange);
                    };

                    // An UNMAP that would split an existing mapping must be
                    // rejected with VIRTIO_IOMMU_S_RANGE without removing
                    // anything. Inspect bookkeeping before touching VFIO so
                    // a rejection cannot leave VFIO out of sync.
                    {
                        let domains = mapping.domains.read().unwrap();
                        let Some(domain) = domains.get(&domain_id) else {
                            return Err(Error::InvalidUnmapRequestMissingDomain);
                        };
                        let split_before = domain
                            .mappings
                            .range(..virt_start)
                            .next_back()
                            .and_then(|(&start, m)| inclusive_end(start, m.size))
                            .is_some_and(|end| end >= virt_start);
                        if split_before {
                            return Err(Error::InvalidUnmapRequestPartialOverlap);
                        }
                        let split_after = domain
                            .mappings
                            .range(virt_start..=virt_end)
                            .next_back()
                            .and_then(|(&start, m)| inclusive_end(start, m.size))
                            .is_some_and(|end| end > virt_end);
                        if split_after {
                            return Err(Error::InvalidUnmapRequestPartialOverlap);
                        }
                    }

                    // Find the list of endpoints attached to the given domain.
                    let endpoints: Vec<u32> = mapping
                        .endpoints
                        .write()
                        .unwrap()
                        .iter()
                        .filter(|&(_, &d)| d == domain_id)
                        .map(|(&e, _)| e)
                        .collect();

                    // Trigger external unmapping if necessary.
                    if endpoints.iter().any(|endpoint| {
                        ext_mapping
                            .get(endpoint)
                            .is_some_and(|mapping| mapping.splits_range(virt_start, virt_end))
                    }) {
                        return Err(Error::InvalidUnmapRequestPartialOverlap);
                    }
                    for endpoint in endpoints {
                        if let Some(ext_map) = ext_mapping.get_mut(&endpoint) {
                            ext_map
                                .unmap(virt_start, size)
                                .map_err(Error::ExternalUnmapping)?;
                        }
                    }

                    let mut domains = mapping.domains.write().unwrap();
                    let Some(domain) = domains.get_mut(&domain_id) else {
                        return Err(Error::InvalidUnmapRequestMissingDomain);
                    };
                    while let Some((&start, _)) =
                        domain.mappings.range(virt_start..=virt_end).next()
                    {
                        domain.mappings.remove(&start);
                    }
                }
                VIRTIO_IOMMU_T_PROBE => {
                    if desc_size_left != size_of::<VirtioIommuReqProbe>() {
                        return Err(Error::InvalidProbeRequest);
                    }

                    let req: VirtioIommuReqProbe = desc_chain
                        .memory()
                        .read_obj(req_addr as GuestAddress)
                        .map_err(Error::GuestMemory)?;
                    debug!("Probe request 0x{req:x?}");

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

                    for &(start, end) in reserved_regions {
                        reply.extend_from_slice(probe_prop.as_slice());
                        let resv_mem = VirtioIommuProbeResvMem {
                            subtype: VIRTIO_IOMMU_RESV_MEM_T_RESERVED,
                            start,
                            end,
                            ..Default::default()
                        };
                        reply.extend_from_slice(resv_mem.as_slice());
                    }

                    hdr_len = reply.len() as u32;
                }
                _ => unreachable!(),
            }
            Ok(())
        })();

        let status = match result {
            Ok(()) => VIRTIO_IOMMU_S_OK,
            Err(e) => {
                let Some(status) = e.status() else {
                    return Err(e);
                };
                warn!("Failed to process virtio-iommu request: {e:?}");
                status
            }
        };

        let status_desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        let reply_len = (hdr_len as usize)
            .checked_add(size_of::<VirtioIommuReqTail>())
            .ok_or(Error::BufferLengthTooSmall)?;
        if (status_desc.len() as usize) < reply_len {
            return Err(Error::BufferLengthTooSmall);
        }

        if !desc_chain
            .memory()
            .check_range(status_desc.addr(), status_desc.len() as usize)
        {
            return Err(Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(
                status_desc.addr(),
            )));
        }

        let tail = VirtioIommuReqTail {
            status,
            ..Default::default()
        };
        reply.extend_from_slice(tail.as_slice());

        // Report the full reply length even when the request was rejected so
        // the driver copies back the status.
        desc_chain
            .memory()
            .write_slice(reply.as_slice(), status_desc.addr())
            .map_err(Error::GuestMemory)?;

        Ok(reply_len)
    }
}

fn detach_endpoint_from_domain(
    endpoint: u32,
    domain_id: u32,
    mapping: &Arc<IommuMapping>,
    ext_mapping: &mut ExternalDmaRegistry,
) -> result::Result<(), Error> {
    if let Some(ext_map) = ext_mapping.get_mut(&endpoint) {
        ext_map.unmap_all().map_err(Error::ExternalUnmapping)?;
    }
    remove_endpoint_from_domain(endpoint, domain_id, mapping);
    Ok(())
}

fn remove_endpoint_from_domain(endpoint: u32, domain_id: u32, mapping: &IommuMapping) {
    mapping.endpoints.write().unwrap().remove(&endpoint);
    if mapping
        .endpoints
        .write()
        .unwrap()
        .iter()
        .filter(|&(_, &d)| d == domain_id)
        .count()
        == 0
    {
        mapping.domains.write().unwrap().remove(&domain_id);
    }
}

struct IommuEpollHandler {
    mem: GuestMemory,
    request_queue: Queue,
    _event_queue: Queue,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    request_queue_evt: EventFd,
    _event_queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    mapping: Arc<IommuMapping>,
    ext_mapping: Arc<Mutex<ExternalDmaRegistry>>,
    msi_iova_space: (u64, u64),
    reserved_regions: Vec<(u64, u64)>,
    input_range: Option<(u64, u64)>,
}

impl IommuEpollHandler {
    fn request_queue(&mut self) -> Result<bool, Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) = self.request_queue.pop_descriptor_chain(self.mem.memory())
        {
            // If the request fails to parse, that's the guest's error. Notify
            // it with a 0 length response in the used queue.
            let head_index = desc_chain.head_index();
            let len = match Request::parse(
                &mut desc_chain,
                &self.mapping,
                &mut self.ext_mapping.lock().unwrap(),
                self.msi_iova_space,
                &self.reserved_regions,
                self.input_range,
            ) {
                Ok(len) => len as u32,
                Err(e) => {
                    warn!("Failed to parse virtio-iommu request: {e:?}");
                    0
                }
            };

            self.request_queue
                .add_used(desc_chain.memory(), head_index, len)
                .map_err(Error::QueueAddUsed)?;

            used_descs = true;
        }

        Ok(used_descs)
    }

    fn signal_used_queue(&self, queue_index: u16) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(&mut self, pause_common: &PauseCommon) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.request_queue_evt.as_raw_fd(), REQUEST_Q_EVENT)?;
        helper.run(pause_common, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for IommuEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            REQUEST_Q_EVENT => {
                self.request_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                let needs_notification = self.request_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to process request queue : {e:?}"
                    ))
                })?;
                if needs_notification {
                    self.signal_used_queue(0).map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
                    })?;
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Mapping {
    gpa: u64,
    size: u64,
    #[serde(default = "Mapping::unrestricted_flags")]
    flags: u32,
}

impl Mapping {
    fn unrestricted_flags() -> u32 {
        VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE
    }

    fn allows(&self, access_type: AccessType) -> bool {
        match access_type {
            AccessType::Read => self.flags & VIRTIO_IOMMU_MAP_F_READ != 0,
            AccessType::Write => self.flags & VIRTIO_IOMMU_MAP_F_WRITE != 0,
        }
    }
}

#[derive(Clone, Debug)]
struct Domain {
    mappings: BTreeMap<u64, Mapping>,
    bypass: bool,
}

#[derive(Debug)]
pub struct IommuMapping {
    // Domain related to an endpoint.
    endpoints: Arc<RwLock<BTreeMap<u32, u32>>>,
    // Information related to each domain.
    domains: Arc<RwLock<BTreeMap<u32, Domain>>>,
    // Global flag indicating if endpoints that are not attached to any domain
    // are in bypass mode.
    bypass: AtomicBool,
    msi_iova_space: (u64, u64),
}

// Inclusive end of `[addr, addr+size)`. Returns None for zero size or
// overflow so range checks cannot be bypassed.
fn inclusive_end(addr: u64, size: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    addr.checked_add(size - 1)
}

fn span_end(addr: u64, size: u64) -> io::Result<u64> {
    inclusive_end(addr, size).ok_or_else(|| {
        io::Error::other(format!(
            "translate span overflow or zero size: addr 0x{addr:x} size 0x{size:x}"
        ))
    })
}

/// Translate `[addr, end]` (inclusive end) into a physical address. The span
/// may cross more than one mapping as long as those mappings are adjacent in
/// IOVA space and contiguous in GPA space, so a buffer the guest mapped with
/// several mappings still resolves to a single physical range. Returns None
/// when `addr` is unmapped, a gap is hit before `end`, the covered range is
/// not physically contiguous, or a covering mapping doesn't allow
/// `access_type`.
fn translate_contiguous_range(
    mappings: &BTreeMap<u64, Mapping>,
    addr: u64,
    end: u64,
    access_type: AccessType,
) -> Option<u64> {
    // The mapping containing `addr` is the one with the greatest start <= addr.
    let (&start_key, start) = mappings.range(..=addr).next_back()?;
    if addr > inclusive_end(start_key, start.size)? || !start.allows(access_type) {
        return None;
    }
    let base_gpa = addr - start_key + start.gpa;

    let mut covered = start_key.checked_add(start.size)?;
    let mut next_gpa = start.gpa.checked_add(start.size)?;

    // Walk forward across adjacent mappings until `end` is covered.
    for (&key, value) in mappings.range(start_key.checked_add(1)?..) {
        if end < covered {
            break;
        }
        if key != covered || value.gpa != next_gpa || !value.allows(access_type) {
            return None;
        }
        covered = key.checked_add(value.size)?;
        next_gpa = value.gpa.checked_add(value.size)?;
    }

    (end < covered).then_some(base_gpa)
}

impl DmaRemapping for IommuMapping {
    fn translate_gva(
        &self,
        id: u32,
        addr: u64,
        size: u64,
        access_type: AccessType,
    ) -> io::Result<u64> {
        debug!("Translate GVA addr 0x{addr:x} size 0x{size:x} access {access_type:?}");
        let end = span_end(addr, size)?;
        if let Some(domain_id) = self.endpoints.read().unwrap().get(&id) {
            if let Some(domain) = self.domains.read().unwrap().get(domain_id) {
                // Directly return identity mapping in case the domain is in
                // bypass mode.
                if domain.bypass {
                    return Ok(addr);
                }

                if let Some(new_addr) =
                    translate_contiguous_range(&domain.mappings, addr, end, access_type)
                {
                    debug!("Into GPA addr 0x{new_addr:x}");
                    return Ok(new_addr);
                }
            }
        } else if self.bypass.load(Ordering::Acquire) {
            return Ok(addr);
        }

        Err(io::Error::other(format!(
            "failed to translate GVA addr 0x{addr:x} size 0x{size:x} access {access_type:?}"
        )))
    }

    fn translate_gpa(&self, id: u32, addr: u64, size: u64) -> io::Result<u64> {
        debug!("Translate GPA addr 0x{addr:x} size 0x{size:x}");
        let end = span_end(addr, size)?;
        if let Some(domain_id) = self.endpoints.read().unwrap().get(&id) {
            if let Some(domain) = self.domains.read().unwrap().get(domain_id) {
                // Directly return identity mapping in case the domain is in
                // bypass mode.
                if domain.bypass {
                    return Ok(addr);
                }

                for (&key, &value) in domain.mappings.iter() {
                    if let Some(mapping_gpa_end) = inclusive_end(value.gpa, value.size)
                        && addr >= value.gpa
                        && end <= mapping_gpa_end
                    {
                        let new_addr = addr - value.gpa + key;
                        debug!("Into GVA addr 0x{new_addr:x}");
                        return Ok(new_addr);
                    }
                }
            }
        } else if self.bypass.load(Ordering::Acquire) {
            return Ok(addr);
        }

        Err(io::Error::other(format!(
            "failed to translate GPA addr 0x{addr:x} size 0x{size:x}"
        )))
    }
}

impl InterruptRemapping for IommuMapping {
    fn translate_msi(&self, dev_id: u32, cfg: MsiIrqSourceConfig) -> Option<MsiIrqSourceConfig> {
        let addr = (u64::from(cfg.high_addr) << 32) | u64::from(cfg.low_addr);
        let (start, end) = self.msi_iova_space;
        let gpa = if (start..=end).contains(&addr) {
            addr
        } else {
            // An MSI is a device write to the doorbell.
            self.translate_gva(dev_id, addr, size_of::<u32>() as u64, AccessType::Write)
                .ok()?
        };

        Some(MsiIrqSourceConfig {
            high_addr: (gpa >> 32) as u32,
            low_addr: gpa as u32,
            ..cfg
        })
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
    fn translate_gva(&self, base: u64, size: u64, access_type: AccessType) -> io::Result<u64> {
        self.mapping.translate_gva(self.id, base, size, access_type)
    }
    fn translate_gpa(&self, base: u64, size: u64) -> io::Result<u64> {
        self.mapping.translate_gpa(self.id, base, size)
    }
}

pub struct Iommu {
    common: VirtioCommon,
    id: String,
    config: VirtioIommuConfig,
    mapping: Arc<IommuMapping>,
    ext_mapping: Arc<Mutex<ExternalDmaRegistry>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    msi_iova_space: (u64, u64),
    reserved_regions: Vec<(u64, u64)>,
    input_range: Option<(u64, u64)>,
}

type EndpointsState = Vec<(u32, u32)>;
type DomainsState = Vec<(u32, (Vec<(u64, Mapping)>, bool))>;

#[derive(Serialize, Deserialize)]
pub struct IommuState {
    avail_features: u64,
    acked_features: u64,
    endpoints: EndpointsState,
    domains: DomainsState,
    #[serde(default)]
    probe_size: u32,
}

fn restore_domain_mappings(entries: Vec<(u64, Mapping)>) -> io::Result<BTreeMap<u64, Mapping>> {
    let mut mappings: BTreeMap<u64, Mapping> = BTreeMap::new();
    for (start, m) in entries {
        let end = inclusive_end(start, m.size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid restored IOMMU mapping: start 0x{start:x} size 0x{:x}",
                    m.size
                ),
            )
        })?;
        if mappings
            .range(..=end)
            .next_back()
            .and_then(|(&s, prev)| inclusive_end(s, prev.size))
            .is_some_and(|prev_end| prev_end >= start)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "overlapping restored IOMMU mapping: start 0x{start:x} size 0x{:x}",
                    m.size
                ),
            ));
        }
        mappings.insert(start, m);
    }
    Ok(mappings)
}

impl Iommu {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        msi_iova_space: (u64, u64),
        reserved_regions: Vec<(u64, u64)>,
        address_width_bits: u8,
        access_platform_enabled: bool,
        state: Option<IommuState>,
    ) -> io::Result<(Self, Arc<IommuMapping>)> {
        let (mut avail_features, acked_features, endpoints, domains, paused, restored_probe_size) =
            if let Some(state) = state {
                info!("Restoring virtio-iommu {id}");
                (
                    state.avail_features,
                    state.acked_features,
                    state.endpoints.into_iter().collect(),
                    state
                        .domains
                        .into_iter()
                        .map(|(k, (entries, bypass))| {
                            Ok((
                                k,
                                Domain {
                                    mappings: restore_domain_mappings(entries)?,
                                    bypass,
                                },
                            ))
                        })
                        .collect::<io::Result<BTreeMap<_, _>>>()?,
                    true,
                    Some(state.probe_size),
                )
            } else {
                let avail_features = (1u64 << VIRTIO_F_VERSION_1)
                    | (1u64 << VIRTIO_IOMMU_F_MAP_UNMAP)
                    | (1u64 << VIRTIO_IOMMU_F_MMIO)
                    | (1u64 << VIRTIO_IOMMU_F_PROBE)
                    | (1u64 << VIRTIO_IOMMU_F_BYPASS_CONFIG);

                (
                    avail_features,
                    0,
                    BTreeMap::new(),
                    BTreeMap::new(),
                    false,
                    None,
                )
            };

        // A restored guest sized its PROBE buffers from the probe_size it read
        // before, so report no more reserved regions than that holds.
        let mut reserved_regions = reserved_regions;
        if let Some(probe_size) = restored_probe_size {
            reserved_regions.truncate((probe_size / PROBE_PROP_SIZE).saturating_sub(1) as usize);
        }

        let mut config = VirtioIommuConfig {
            page_size_mask: VIRTIO_IOMMU_PAGE_SIZE_MASK,
            probe_size: PROBE_PROP_SIZE * (1 + reserved_regions.len() as u32),
            ..Default::default()
        };

        let input_range = if address_width_bits < 64 {
            avail_features |= 1u64 << VIRTIO_IOMMU_F_INPUT_RANGE;
            let end = (1u64 << address_width_bits) - 1;
            config.input_range = VirtioIommuRange64 { start: 0, end };
            Some((0, end))
        } else {
            None
        };

        if access_platform_enabled {
            avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }

        let mapping = Arc::new(IommuMapping {
            endpoints: Arc::new(RwLock::new(endpoints)),
            domains: Arc::new(RwLock::new(domains)),
            bypass: AtomicBool::new(true),
            msi_iova_space,
        });

        Ok((
            Iommu {
                id,
                common: VirtioCommon {
                    device_type: VirtioDeviceType::Iommu as u32,
                    queue_sizes: QUEUE_SIZES.to_vec(),
                    avail_features,
                    acked_features,
                    min_queues: NUM_QUEUES,
                    ..VirtioCommon::new(paused)?
                },
                config,
                mapping: Arc::clone(&mapping),
                ext_mapping: Arc::new(Mutex::new(BTreeMap::new())),
                seccomp_action,
                exit_evt,
                msi_iova_space,
                reserved_regions,
                input_range,
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
            domains: self
                .mapping
                .domains
                .read()
                .unwrap()
                .clone()
                .into_iter()
                .map(|(k, v)| (k, (v.mappings.into_iter().collect(), v.bypass)))
                .collect(),
            probe_size: self.config.probe_size,
        }
    }

    fn update_bypass(&mut self) {
        // Use bypass from config if VIRTIO_IOMMU_F_BYPASS_CONFIG has been negotiated
        if !self
            .common
            .feature_acked(VIRTIO_IOMMU_F_BYPASS_CONFIG.into())
        {
            return;
        }

        let bypass = self.config.bypass == 1;
        info!("Updating bypass mode to {bypass}");
        self.mapping.bypass.store(bypass, Ordering::Release);
    }

    pub fn add_external_mapping(
        &mut self,
        device_id: u32,
        mapping: Arc<dyn ExternalDmaMapping>,
    ) -> result::Result<(), ExternalDmaMappingError> {
        let mut mappings = self.ext_mapping.lock().unwrap();
        let Entry::Vacant(entry) = mappings.entry(device_id) else {
            return Err(ExternalDmaMappingError::BackendAlreadyRegistered {
                endpoint: device_id,
            });
        };
        entry.insert(TrackedDmaMapping::new(mapping));
        Ok(())
    }

    /// Unmaps all tracked DMA ranges before releasing the backend.
    /// On failure, the backend and its remaining ranges stay registered.
    pub fn remove_external_mapping(
        &mut self,
        device_id: u32,
    ) -> result::Result<Option<Arc<dyn ExternalDmaMapping>>, ExternalDmaMappingError> {
        let mut mappings = self.ext_mapping.lock().unwrap();
        let Some(mapping) = mappings.get_mut(&device_id) else {
            return Ok(None);
        };
        mapping.unmap_all()?;
        let domain_id = self
            .mapping
            .endpoints
            .read()
            .unwrap()
            .get(&device_id)
            .copied();
        if let Some(domain_id) = domain_id {
            remove_endpoint_from_domain(device_id, domain_id, &self.mapping);
        }
        Ok(mappings.remove(&device_id).map(|mapping| mapping.backend))
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
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
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "bypass" field is the only mutable field
        let bypass_offset =
            (&raw const self.config.bypass as u64) - (&raw const self.config as u64);
        if offset != bypass_offset || data.len() != size_of_val(&self.config.bypass) {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        // virtio spec says ignore bits 1-7 and that the device must
        // never present a value other than 0 or 1.
        self.config.bypass = data[0] & 1;

        self.update_bypass();
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.common.activate(&queues, Arc::clone(&interrupt_cb))?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds()?;

        let (_, request_queue, request_queue_evt) = queues.remove(0);
        let (_, _event_queue, _event_queue_evt) = queues.remove(0);

        let mut handler = IommuEpollHandler {
            mem,
            request_queue,
            _event_queue,
            interrupt_cb: Arc::clone(&interrupt_cb),
            request_queue_evt,
            _event_queue_evt,
            kill_evt,
            pause_evt,
            mapping: Arc::clone(&self.mapping),
            ext_mapping: Arc::clone(&self.ext_mapping),
            msi_iova_space: self.msi_iova_space,
            reserved_regions: self.reserved_regions.clone(),
            input_range: self.input_range,
        };

        self.common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioIommu,
            &self.exit_evt,
            Arc::clone(&device_status),
            Arc::clone(&interrupt_cb),
            move |pause_common| handler.run(pause_common),
        )?;

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
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

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Iommu {}
impl Migratable for Iommu {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex, RwLock, Weak};

    use seccompiler::SeccompAction;
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::QueueT;
    use vm_device::dma_mapping::{ExternalDmaMapping, ExternalDmaMappingError};
    use vm_memory::{ByteValued, Bytes, GuestAddress, GuestAddressSpace};
    use vm_virtio::AccessType;
    use vm_virtio::queue::testing::VirtQueue;
    use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

    use super::{
        Domain, Error, ExternalDmaRegistry, Iommu, IommuMapping, Mapping, Request,
        TrackedDmaMapping, VIRTIO_IOMMU_S_DEVERR, VIRTIO_IOMMU_S_INVAL, VIRTIO_IOMMU_S_NOENT,
        VIRTIO_IOMMU_S_OK, VIRTIO_IOMMU_S_RANGE, VIRTIO_IOMMU_T_ATTACH, VIRTIO_IOMMU_T_DETACH,
        VIRTIO_IOMMU_T_MAP, VIRTIO_IOMMU_T_UNMAP, VirtioIommuReqAttach, VirtioIommuReqDetach,
        VirtioIommuReqHead, VirtioIommuReqMap, VirtioIommuReqTail, VirtioIommuReqUnmap,
    };
    use crate::{DmaRemapping, GuestMemory};

    /// Test stub for VfioDmaMapping.
    struct MockMapping;

    impl ExternalDmaMapping for MockMapping {
        fn map(&self, _iova: u64, _gpa: u64, _size: u64) -> Result<(), ExternalDmaMappingError> {
            Ok(())
        }

        fn unmap(&self, _iova: u64, _size: u64) -> Result<(), ExternalDmaMappingError> {
            Ok(())
        }
    }

    fn new_iommu() -> Iommu {
        let (iommu, _mapping) = Iommu::new(
            "test-iommu".to_string(),
            SeccompAction::Allow,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            (0, 0),
            Vec::new(),
            64,
            false,
            None,
        )
        .unwrap();
        iommu
    }

    /// Tests removing a mapping works and releases the ref.
    #[test]
    fn remove_external_mapping() {
        let mut iommu = new_iommu();

        let mapping: Arc<dyn ExternalDmaMapping> = Arc::new(MockMapping);
        let weak: Weak<dyn ExternalDmaMapping> = Arc::downgrade(&mapping);

        iommu.add_external_mapping(0x100, mapping).unwrap();

        // Removing the mapping succeeds.
        let removed = iommu.remove_external_mapping(0x100).unwrap();
        assert!(removed.is_some());

        // Dropping the returned Arc drops the last reference.
        drop(removed);
        assert!(
            weak.upgrade().is_none(),
            "iommu must not retain a reference after removal"
        );

        // Removing the same id again is a nop.
        assert!(
            iommu.remove_external_mapping(0x100).unwrap().is_none(),
            "removal is idempotent"
        );

        // Removing a bogus ID doesn't crash.
        assert!(iommu.remove_external_mapping(0x999).unwrap().is_none());
    }

    /// Build an IommuMapping with endpoint 0 attached to a single domain whose
    /// mappings are the given `(iova, gpa, size)` tuples.
    fn iommu_mapping(entries: &[(u64, u64, u64)]) -> IommuMapping {
        let mut mappings = BTreeMap::new();
        for &(iova, gpa, size) in entries {
            let flags = Mapping::unrestricted_flags();
            mappings.insert(iova, Mapping { gpa, size, flags });
        }
        let mut domains = BTreeMap::new();
        domains.insert(
            0,
            Domain {
                mappings,
                bypass: false,
            },
        );
        let mut endpoints = BTreeMap::new();
        endpoints.insert(0, 0);
        IommuMapping {
            endpoints: Arc::new(RwLock::new(endpoints)),
            domains: Arc::new(RwLock::new(domains)),
            bypass: AtomicBool::new(false),
            msi_iova_space: (0, 0),
        }
    }

    #[test]
    fn translate_within_single_mapping() {
        let m = iommu_mapping(&[(0x1000, 0x4000, 0x1000)]);
        assert_eq!(
            m.translate_gva(0, 0x1200, 0x100, AccessType::Read).unwrap(),
            0x4200
        );
    }

    #[test]
    fn translate_spanning_contiguous_mappings() {
        // A buffer mapped with two adjacent mappings that resolve to a
        // contiguous physical range translates as one range.
        let m = iommu_mapping(&[(0x1000, 0x4000, 0x1000), (0x2000, 0x5000, 0x1000)]);
        assert_eq!(
            m.translate_gva(0, 0x1000, 0x2000, AccessType::Read)
                .unwrap(),
            0x4000
        );
        // A sub-range that straddles the boundary also resolves.
        assert_eq!(
            m.translate_gva(0, 0x1f00, 0x200, AccessType::Read).unwrap(),
            0x4f00
        );
    }

    #[test]
    fn reject_spanning_noncontiguous_mappings() {
        // Adjacent in IOVA but disjoint in GPA cannot be one range.
        let m = iommu_mapping(&[(0x1000, 0x4000, 0x1000), (0x2000, 0x9000, 0x1000)]);
        m.translate_gva(0, 0x1000, 0x2000, AccessType::Read)
            .unwrap_err();
    }

    #[test]
    fn reject_span_across_iova_gap() {
        // A hole between mappings leaves part of the span unmapped.
        let m = iommu_mapping(&[(0x1000, 0x4000, 0x1000), (0x3000, 0x6000, 0x1000)]);
        m.translate_gva(0, 0x1000, 0x2000, AccessType::Read)
            .unwrap_err();
    }

    #[test]
    fn reject_unmapped_base() {
        let m = iommu_mapping(&[(0x1000, 0x4000, 0x1000)]);
        m.translate_gva(0, 0x2500, 0x10, AccessType::Read)
            .unwrap_err();
    }

    #[test]
    fn device_writes_require_map_write_flag() {
        let mapping = Arc::new(iommu_mapping(&[]));
        for (virt_start, phys_start, flags) in [
            (
                0x1000,
                0x4000,
                super::VIRTIO_IOMMU_MAP_F_READ | super::VIRTIO_IOMMU_MAP_F_WRITE,
            ),
            (0x2000, 0x5000, super::VIRTIO_IOMMU_MAP_F_READ),
        ] {
            let request = VirtioIommuReqMap {
                domain: 0,
                virt_start,
                virt_end: virt_start + 0xfff,
                phys_start,
                flags,
            };
            let (_, status) =
                process_request(VIRTIO_IOMMU_T_MAP, request, &mapping, &BTreeMap::new());
            assert_eq!(status, VIRTIO_IOMMU_S_OK);
        }

        let write = |addr, size| mapping.translate_gva(0, addr, size, AccessType::Write);
        assert_eq!(write(0x1000, 0x100).unwrap(), 0x4000);
        write(0x2000, 0x100).unwrap_err();
        // A write spanning both mappings needs both to allow writes.
        write(0x1f00, 0x200).unwrap_err();
        // Both mappings allow reads.
        assert_eq!(
            mapping
                .translate_gva(0, 0x1f00, 0x200, AccessType::Read)
                .unwrap(),
            0x4f00
        );
    }

    const TAIL_LEN: usize = size_of::<VirtioIommuReqTail>();
    const INITIAL_STATUS: u8 = 0xa5;

    fn process_request<T: ByteValued>(
        type_: u8,
        body: T,
        mapping: &Arc<IommuMapping>,
        ext_mapping: &BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
    ) -> (Result<usize, Error>, u8) {
        let endpoints = mapping.endpoints.read().unwrap();
        let domains = mapping.domains.read().unwrap();
        let mut tracked = ext_mapping
            .iter()
            .map(|(&id, backend)| {
                let mut tracked = TrackedDmaMapping::new(Arc::clone(backend));
                if let Some(domain) = endpoints.get(&id).and_then(|id| domains.get(id)) {
                    tracked.ranges = domain
                        .mappings
                        .iter()
                        .map(|(&iova, m)| (iova, m.size))
                        .collect();
                }
                (id, tracked)
            })
            .collect();
        drop(domains);
        drop(endpoints);
        process_tracked_request(type_, body, mapping, &mut tracked)
    }

    fn process_tracked_request<T: ByteValued>(
        type_: u8,
        body: T,
        mapping: &Arc<IommuMapping>,
        ext_mapping: &mut ExternalDmaRegistry,
    ) -> (Result<usize, Error>, u8) {
        let guest_memory = GuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mem = guest_memory.memory();
        let vq = VirtQueue::new(GuestAddress(0x1000), &*mem, 2);
        let req_addr = GuestAddress(0x2000);
        let tail_addr = GuestAddress(0x3000);
        let head = VirtioIommuReqHead {
            type_,
            ..Default::default()
        };
        mem.write_obj(head, req_addr).unwrap();
        mem.write_obj(
            body,
            GuestAddress(req_addr.0 + size_of::<VirtioIommuReqHead>() as u64),
        )
        .unwrap();
        mem.write_obj(INITIAL_STATUS, tail_addr).unwrap();
        let req_len = (size_of::<VirtioIommuReqHead>() + size_of::<T>()) as u32;
        vq.dtable[0].set(req_addr.0, req_len, VRING_DESC_F_NEXT as u16, 1);
        vq.dtable[1].set(tail_addr.0, TAIL_LEN as u32, VRING_DESC_F_WRITE as u16, 0);
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);

        let mut queue = vq.create_queue();
        let mut desc_chain = queue.pop_descriptor_chain(guest_memory.memory()).unwrap();
        let result = Request::parse(&mut desc_chain, mapping, ext_mapping, (0, 0), &[], None);
        (result, mem.read_obj(tail_addr).unwrap())
    }

    #[test]
    fn request_status_and_reply_length() {
        let mapping = Arc::new(iommu_mapping(&[]));
        let detach = VirtioIommuReqDetach {
            domain: 1,
            endpoint: 0,
            ..Default::default()
        };
        let (len, status) =
            process_request(VIRTIO_IOMMU_T_DETACH, detach, &mapping, &BTreeMap::new());
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_INVAL);
        assert_eq!(mapping.endpoints.read().unwrap().get(&0), Some(&0));

        let valid_map = VirtioIommuReqMap {
            domain: 0,
            virt_start: 0x1000,
            virt_end: 0x1fff,
            phys_start: 0x4000,
            flags: super::VIRTIO_IOMMU_MAP_F_READ,
        };
        for (request, expected_status) in [
            (
                VirtioIommuReqMap {
                    flags: u32::MAX,
                    ..valid_map
                },
                VIRTIO_IOMMU_S_INVAL,
            ),
            (
                VirtioIommuReqMap {
                    virt_end: 0,
                    ..valid_map
                },
                VIRTIO_IOMMU_S_RANGE,
            ),
            (
                VirtioIommuReqMap {
                    domain: 1,
                    ..valid_map
                },
                VIRTIO_IOMMU_S_NOENT,
            ),
            (valid_map, VIRTIO_IOMMU_S_OK),
        ] {
            let (len, status) =
                process_request(VIRTIO_IOMMU_T_MAP, request, &mapping, &BTreeMap::new());
            assert_eq!(len.unwrap(), TAIL_LEN);
            assert_eq!(status, expected_status);
        }
    }

    #[test]
    fn unmap_rejections_report_invalid_or_range_status() {
        let mapping = Arc::new(iommu_mapping(&[(0x1000, 0x4000, 0x1000)]));
        let (len, status) = process_request(VIRTIO_IOMMU_T_UNMAP, 0u8, &mapping, &BTreeMap::new());
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_INVAL);

        for (virt_start, virt_end) in [(0x2000, 0x1000), (0x1000, 0x17ff)] {
            let request = VirtioIommuReqUnmap {
                domain: 0,
                virt_start,
                virt_end,
                ..Default::default()
            };
            let (len, status) =
                process_request(VIRTIO_IOMMU_T_UNMAP, request, &mapping, &BTreeMap::new());
            assert_eq!(len.unwrap(), TAIL_LEN);
            assert_eq!(status, VIRTIO_IOMMU_S_RANGE);
            assert_eq!(mapping.domains.read().unwrap()[&0].mappings.len(), 1);
        }
    }

    struct FailingMapping;

    impl ExternalDmaMapping for FailingMapping {
        fn map(&self, iova: u64, gpa: u64, size: u64) -> Result<(), ExternalDmaMappingError> {
            Err(ExternalDmaMappingError::Map {
                iova,
                gpa,
                size,
                source: io::Error::from_raw_os_error(libc::EIO).into(),
            })
        }

        fn unmap(&self, iova: u64, size: u64) -> Result<(), ExternalDmaMappingError> {
            Err(ExternalDmaMappingError::Unmap {
                iova,
                size,
                source: io::Error::from_raw_os_error(libc::EIO).into(),
            })
        }
    }

    #[test]
    fn external_mapping_failures_report_device_error() {
        let ext_mapping: BTreeMap<u32, Arc<dyn ExternalDmaMapping>> =
            BTreeMap::from([(0, Arc::new(FailingMapping) as Arc<dyn ExternalDmaMapping>)]);
        let mapping = Arc::new(iommu_mapping(&[]));
        let request = VirtioIommuReqMap {
            domain: 0,
            virt_start: 0x1000,
            virt_end: 0x1fff,
            phys_start: 0x4000,
            flags: super::VIRTIO_IOMMU_MAP_F_READ,
        };
        let (len, status) = process_request(VIRTIO_IOMMU_T_MAP, request, &mapping, &ext_mapping);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_DEVERR);
        assert!(mapping.domains.read().unwrap()[&0].mappings.is_empty());

        let mapping = Arc::new(iommu_mapping(&[(0x1000, 0x4000, 0x1000)]));
        let request = VirtioIommuReqUnmap {
            domain: 0,
            virt_start: 0x1000,
            virt_end: 0x1fff,
            ..Default::default()
        };
        let (len, status) = process_request(VIRTIO_IOMMU_T_UNMAP, request, &mapping, &ext_mapping);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_DEVERR);
        assert_eq!(mapping.domains.read().unwrap()[&0].mappings.len(), 1);
    }

    #[test]
    fn external_attach_and_detach_failures_report_device_error() {
        let ext_mapping: BTreeMap<u32, Arc<dyn ExternalDmaMapping>> =
            BTreeMap::from([(0, Arc::new(FailingMapping) as Arc<dyn ExternalDmaMapping>)]);
        // Attaching to domain 0 replays its mappings; moving to domain 1
        // first unmaps the old domain. Both failures must reach the driver.
        for domain in [0, 1] {
            let mapping = Arc::new(iommu_mapping(&[(0x1000, 0x4000, 0x1000)]));
            let request = VirtioIommuReqAttach {
                domain,
                endpoint: 0,
                ..Default::default()
            };
            let (len, status) =
                process_request(VIRTIO_IOMMU_T_ATTACH, request, &mapping, &ext_mapping);
            assert_eq!(len.unwrap(), TAIL_LEN);
            assert_eq!(status, VIRTIO_IOMMU_S_DEVERR);
        }

        let mapping = Arc::new(iommu_mapping(&[(0x1000, 0x4000, 0x1000)]));
        let request = VirtioIommuReqDetach::default();
        let (len, status) = process_request(VIRTIO_IOMMU_T_DETACH, request, &mapping, &ext_mapping);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_DEVERR);
    }

    #[test]
    fn unknown_request_leaves_reply_untouched() {
        let mapping = Arc::new(iommu_mapping(&[]));
        let (len, status) = process_request(
            0xff,
            VirtioIommuReqDetach::default(),
            &mapping,
            &BTreeMap::new(),
        );
        assert_eq!(len.unwrap(), 0);
        assert_eq!(status, INITIAL_STATUS);
        assert_eq!(mapping.endpoints.read().unwrap().get(&0), Some(&0));
    }

    #[test]
    fn restore_validates_domain_mappings() {
        let base_state = new_iommu().state();
        let entry = |iova, gpa, size| {
            (
                iova,
                Mapping {
                    gpa,
                    size,
                    flags: Mapping::unrestricted_flags(),
                },
            )
        };
        let restore_entries = |entries: Vec<(u64, Mapping)>| {
            let state = super::IommuState {
                avail_features: base_state.avail_features,
                acked_features: base_state.acked_features,
                endpoints: vec![(0, 0)],
                domains: vec![(0, (entries, false))],
                probe_size: base_state.probe_size,
            };
            Iommu::new(
                "test-iommu-restore".to_string(),
                SeccompAction::Allow,
                EventFd::new(EFD_NONBLOCK).unwrap(),
                (0, 0),
                Vec::new(),
                64,
                false,
                Some(state),
            )
        };

        // Disjoint mappings (even in unsorted order) restore cleanly.
        let (_, restored) = restore_entries(vec![
            entry(0x3000, 0x9000, 0x1000),
            entry(0x1000, 0x4000, 0x2000),
        ])
        .unwrap();
        assert_eq!(
            restored
                .translate_gva(0, 0x1000, 0x1000, AccessType::Read)
                .unwrap(),
            0x4000
        );
        assert_eq!(
            restored
                .translate_gva(0, 0x3000, 0x1000, AccessType::Read)
                .unwrap(),
            0x9000
        );

        // Zero size, u64 overflow, overlapping, and duplicate-start entries fail.
        for bad_entries in [
            vec![entry(0x1000, 0x4000, 0)],
            vec![entry(u64::MAX - 0xfff, 0x4000, 0x2000)],
            vec![entry(0x1000, 0x4000, 0x3000), entry(0x2000, 0x8000, 0x1000)],
            vec![entry(0x2000, 0x8000, 0x1000), entry(0x1000, 0x4000, 0x1001)],
            vec![entry(0x1000, 0x4000, 0x1000), entry(0x1000, 0x8000, 0x1000)],
        ] {
            let err = restore_entries(bad_entries).err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    struct UnmapRecorder {
        unmaps: Arc<Mutex<Vec<(u32, u64, u64)>>>,
        id: u32,
    }

    impl ExternalDmaMapping for UnmapRecorder {
        fn map(&self, _iova: u64, _gpa: u64, _size: u64) -> Result<(), ExternalDmaMappingError> {
            Ok(())
        }

        fn unmap(&self, iova: u64, size: u64) -> Result<(), ExternalDmaMappingError> {
            self.unmaps.lock().unwrap().push((self.id, iova, size));
            Ok(())
        }
    }

    #[test]
    fn eject_unmaps_only_remaining_backend_ranges() {
        let mut iommu = new_iommu();
        iommu.mapping = Arc::new(iommu_mapping(&[]));
        iommu.mapping.endpoints.write().unwrap().insert(7, 0);
        let calls = Arc::new(Mutex::new(Vec::new()));
        for id in [0, 7] {
            iommu
                .add_external_mapping(
                    id,
                    Arc::new(UnmapRecorder {
                        unmaps: Arc::clone(&calls),
                        id,
                    }),
                )
                .unwrap();
        }

        {
            let mut backends = iommu.ext_mapping.lock().unwrap();
            for virt_start in [0x1000, 0x3000] {
                let request = VirtioIommuReqMap {
                    domain: 0,
                    virt_start,
                    virt_end: virt_start + 0xfff,
                    phys_start: virt_start + 0x4000,
                    flags: Mapping::unrestricted_flags(),
                };
                let (len, status) = process_tracked_request(
                    VIRTIO_IOMMU_T_MAP,
                    request,
                    &iommu.mapping,
                    &mut backends,
                );
                len.unwrap();
                assert_eq!(status, VIRTIO_IOMMU_S_OK);
            }
            let request = VirtioIommuReqUnmap {
                domain: 0,
                virt_start: 0x1000,
                virt_end: 0x1fff,
                ..Default::default()
            };
            let (len, status) = process_tracked_request(
                VIRTIO_IOMMU_T_UNMAP,
                request,
                &iommu.mapping,
                &mut backends,
            );
            len.unwrap();
            assert_eq!(status, VIRTIO_IOMMU_S_OK);
        }
        assert!(iommu.remove_external_mapping(0).unwrap().is_some());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                (0, 0x1000, 0x1000),
                (7, 0x1000, 0x1000),
                (0, 0x3000, 0x1000)
            ]
        );
        assert_eq!(remaining_iovas(&iommu.mapping), vec![0x3000]);
        assert_eq!(
            *iommu.mapping.endpoints.read().unwrap(),
            BTreeMap::from([(7, 0)])
        );
    }

    #[test]
    fn failed_eject_retains_only_ranges_still_mapped() {
        struct RetryUnmap {
            calls: Arc<Mutex<Vec<(u64, u64)>>>,
        }

        impl ExternalDmaMapping for RetryUnmap {
            fn map(
                &self,
                _iova: u64,
                _gpa: u64,
                _size: u64,
            ) -> Result<(), ExternalDmaMappingError> {
                Ok(())
            }

            fn unmap(&self, iova: u64, size: u64) -> Result<(), ExternalDmaMappingError> {
                let mut calls = self.calls.lock().unwrap();
                calls.push((iova, size));
                if calls.len() == 2 {
                    FailingMapping.unmap(iova, size)
                } else {
                    Ok(())
                }
            }
        }

        let mut iommu = new_iommu();
        iommu.mapping = Arc::new(iommu_mapping(&[]));
        let calls = Arc::new(Mutex::new(Vec::new()));
        iommu
            .add_external_mapping(
                0,
                Arc::new(RetryUnmap {
                    calls: Arc::clone(&calls),
                }),
            )
            .unwrap();
        {
            let mut backends = iommu.ext_mapping.lock().unwrap();
            let backend = backends.get_mut(&0).unwrap();
            backend.map(0x1000, 0x4000, 0x1000).unwrap();
            backend.map(0x3000, 0x6000, 0x1000).unwrap();
        }

        assert!(iommu.remove_external_mapping(0).is_err());
        assert_eq!(iommu.mapping.endpoints.read().unwrap().get(&0), Some(&0));
        assert!(iommu.remove_external_mapping(0).unwrap().is_some());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(0x1000, 0x1000), (0x3000, 0x1000), (0x3000, 0x1000)]
        );
    }

    fn run_unmap(
        virt_start: u64,
        virt_end: u64,
        mapping: &Arc<IommuMapping>,
        ext_mapping: &BTreeMap<u32, Arc<dyn ExternalDmaMapping>>,
    ) -> (Result<usize, Error>, u8) {
        let request = VirtioIommuReqUnmap {
            domain: 0,
            virt_start,
            virt_end,
            ..Default::default()
        };
        process_request(VIRTIO_IOMMU_T_UNMAP, request, mapping, ext_mapping)
    }

    fn remaining_iovas(mapping: &IommuMapping) -> Vec<u64> {
        mapping.domains.read().unwrap()[&0]
            .mappings
            .keys()
            .copied()
            .collect()
    }

    #[test]
    fn unmap_exact_single_mapping() {
        let mapping = Arc::new(iommu_mapping(&[
            (0x1000, 0x4000, 0x1000),
            (0x2000, 0x5000, 0x2000),
            (0x5000, 0x8000, 0x1000),
        ]));
        mapping.endpoints.write().unwrap().insert(7, 0);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ext: BTreeMap<u32, Arc<dyn ExternalDmaMapping>> = BTreeMap::from([
            (
                0,
                Arc::new(UnmapRecorder {
                    unmaps: Arc::clone(&calls),
                    id: 0,
                }) as Arc<dyn ExternalDmaMapping>,
            ),
            (
                7,
                Arc::new(UnmapRecorder {
                    unmaps: Arc::clone(&calls),
                    id: 7,
                }) as Arc<dyn ExternalDmaMapping>,
            ),
        ]);

        let (len, status) = run_unmap(0x2000, 0x3fff, &mapping, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(remaining_iovas(&mapping), vec![0x1000, 0x5000]);
        mapping
            .translate_gva(0, 0x2000, 0x1000, AccessType::Read)
            .unwrap_err();
        assert_eq!(
            mapping
                .translate_gva(0, 0x1000, 0x1000, AccessType::Read)
                .unwrap(),
            0x4000
        );
        assert_eq!(
            mapping
                .translate_gva(0, 0x5000, 0x1000, AccessType::Read)
                .unwrap(),
            0x8000
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(0, 0x2000, 0x2000), (7, 0x2000, 0x2000)]
        );
    }

    #[test]
    fn unmap_covering_multiple_mappings() {
        let mapping = Arc::new(iommu_mapping(&[
            (0x1000, 0x4000, 0x1000),
            (0x2000, 0x5000, 0x1000),
            (0x4000, 0x6000, 0x1000),
            (0x6000, 0x7000, 0x1000),
        ]));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ext: BTreeMap<u32, Arc<dyn ExternalDmaMapping>> = BTreeMap::from([(
            0,
            Arc::new(UnmapRecorder {
                unmaps: Arc::clone(&calls),
                id: 0,
            }) as Arc<dyn ExternalDmaMapping>,
        )]);

        let (len, status) = run_unmap(0x2000, 0x4fff, &mapping, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(remaining_iovas(&mapping), vec![0x1000, 0x6000]);
        assert_eq!(*calls.lock().unwrap(), vec![(0, 0x2000, 0x3000)]);
    }

    #[test]
    fn unmap_rejects_partial_overlap_without_side_effects() {
        // Two disjoint mappings: [0x2000, 0x3fff] and [0x5000, 0x6fff].
        let mapping = Arc::new(iommu_mapping(&[
            (0x2000, 0x4000, 0x2000),
            (0x5000, 0x8000, 0x2000),
        ]));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ext: BTreeMap<u32, Arc<dyn ExternalDmaMapping>> = BTreeMap::from([(
            0,
            Arc::new(UnmapRecorder {
                unmaps: Arc::clone(&calls),
                id: 0,
            }) as Arc<dyn ExternalDmaMapping>,
        )]);

        for (virt_start, virt_end) in [
            (0x2000, 0x2fff), // first half of [0x2000, 0x3fff]
            (0x3000, 0x3fff), // second half of [0x2000, 0x3fff]
            (0x2400, 0x2bff), // strictly inside [0x2000, 0x3fff]
            (0x1000, 0x2fff), // overlaps start of [0x2000, 0x3fff]
            (0x3000, 0x4fff), // overlaps end of [0x2000, 0x3fff]
            (0x3fff, 0x4fff), // 1-byte overlap at inclusive end of [0x2000, 0x3fff]
            (0x4000, 0x5000), // 1-byte overlap at start of [0x5000, 0x6fff]
            (0x3000, 0x6fff), // splits [0x2000, 0x3fff] while fully covering [0x5000, 0x6fff]
            (0x2000, 0x5fff), // fully covers [0x2000, 0x3fff] while splitting [0x5000, 0x6fff]
            (0x3000, 0x5fff), // splits both mappings
        ] {
            let (len, status) = run_unmap(virt_start, virt_end, &mapping, &ext);
            assert_eq!(
                len.unwrap(),
                TAIL_LEN,
                "expected reply tail for [{virt_start:#x}, {virt_end:#x}]"
            );
            assert_eq!(status, VIRTIO_IOMMU_S_RANGE);
            assert_eq!(remaining_iovas(&mapping), vec![0x2000, 0x5000]);
            assert!(calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn unmap_range_with_no_mappings_is_noop() {
        let mapping = Arc::new(iommu_mapping(&[
            (0x2000, 0x4000, 0x1000),
            (0x5000, 0x8000, 0x1000),
        ]));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ext: BTreeMap<u32, Arc<dyn ExternalDmaMapping>> = BTreeMap::from([(
            0,
            Arc::new(UnmapRecorder {
                unmaps: Arc::clone(&calls),
                id: 0,
            }) as Arc<dyn ExternalDmaMapping>,
        )]);

        for (virt_start, virt_end) in [
            (0x0, 0xfff),     // before all mappings
            (0x1000, 0x1fff), // adjacent before 0x2000
            (0x3000, 0x4fff), // hole between 0x2000..=0x2fff and 0x5000..=0x5fff
            (0x6000, 0x6fff), // adjacent after 0x5000..=0x5fff
            (0x9000, 0x9fff), // after all mappings
        ] {
            let (len, status) = run_unmap(virt_start, virt_end, &mapping, &ext);
            assert_eq!(len.unwrap(), TAIL_LEN);
            assert_eq!(status, VIRTIO_IOMMU_S_OK);
            assert_eq!(remaining_iovas(&mapping), vec![0x2000, 0x5000]);
        }
        assert_eq!(calls.lock().unwrap().len(), 5);

        let empty = Arc::new(iommu_mapping(&[]));
        let (len, status) = run_unmap(0x0, 0xfff, &empty, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert!(remaining_iovas(&empty).is_empty());
    }

    #[test]
    fn unmap_boundary_cases_at_zero_and_u64_max() {
        let last_page = u64::MAX - 0xfff;
        let mapping = Arc::new(iommu_mapping(&[
            (0x0, 0x4000, 0x1000),
            (last_page, 0x8000, 0x1000),
        ]));
        let ext = BTreeMap::new();

        // Full 64-bit range [0, u64::MAX] overflows size calculation -> S_RANGE.
        let (len, status) = run_unmap(0, u64::MAX, &mapping, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_RANGE);

        // Reversed range virt_start > virt_end -> S_RANGE.
        let (len, status) = run_unmap(0x2000, 0x1000, &mapping, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_RANGE);

        // Partial overlaps at 0 and u64::MAX -> S_RANGE.
        for (virt_start, virt_end) in [
            (0x0, 0x7ff),
            (0x800, 0xfff),
            (last_page, u64::MAX - 0x800),
            (u64::MAX - 0x7ff, u64::MAX),
        ] {
            let (len, status) = run_unmap(virt_start, virt_end, &mapping, &ext);
            assert_eq!(len.unwrap(), TAIL_LEN);
            assert_eq!(status, VIRTIO_IOMMU_S_RANGE);
            assert_eq!(remaining_iovas(&mapping), vec![0x0, last_page]);
        }

        // Exact unmap at 0 succeeds and leaves last_page.
        let (len, status) = run_unmap(0x0, 0xfff, &mapping, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(remaining_iovas(&mapping), vec![last_page]);

        // Exact unmap at u64::MAX succeeds and leaves domain empty.
        let (len, status) = run_unmap(last_page, u64::MAX, &mapping, &ext);
        assert_eq!(len.unwrap(), TAIL_LEN);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert!(remaining_iovas(&mapping).is_empty());
    }
}
