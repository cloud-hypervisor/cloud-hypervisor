// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Define communication messages for the vhost-user protocol.
//!
//! For message definition, please refer to the [vhost-user spec](https://github.com/qemu/qemu/blob/f7526eece29cd2e36a63b6703508b24453095eb8/docs/interop/vhost-user.txt).

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::fmt::Debug;
use std::marker::PhantomData;

use VringConfigData;

/// The vhost-user specification uses a field of u32 to store message length.
/// On the other hand, preallocated buffers are needed to receive messages from the Unix domain
/// socket. To preallocating a 4GB buffer for each vhost-user message is really just an overhead.
/// Among all defined vhost-user messages, only the VhostUserConfig and VhostUserMemory has variable
/// message size. For the VhostUserConfig, a maximum size of 4K is enough because the user
/// configuration space for virtio devices is (4K - 0x100) bytes at most. For the VhostUserMemory,
/// 4K should be enough too because it can support 255 memory regions at most.
pub const MAX_MSG_SIZE: usize = 0x1000;

/// The VhostUserMemory message has variable message size and variable number of attached file
/// descriptors. Each user memory region entry in the message payload occupies 32 bytes,
/// so setting maximum number of attached file descriptors based on the maximum message size.
/// But rust only implements Default and AsMut traits for arrays with 0 - 32 entries, so further
/// reduce the maximum number...
// pub const MAX_ATTACHED_FD_ENTRIES: usize = (MAX_MSG_SIZE - 8) / 32;
pub const MAX_ATTACHED_FD_ENTRIES: usize = 32;

/// Starting position (inclusion) of the device configuration space in virtio devices.
pub const VHOST_USER_CONFIG_OFFSET: u32 = 0x100;

/// Ending position (exclusion) of the device configuration space in virtio devices.
pub const VHOST_USER_CONFIG_SIZE: u32 = 0x1000;

/// Maximum number of vrings supported.
pub const VHOST_USER_MAX_VRINGS: u64 = 0xFFu64;

pub(super) trait Req:
    Clone + Copy + Debug + PartialEq + Eq + PartialOrd + Ord + Into<u32>
{
    fn is_valid(&self) -> bool;
}

/// Type of requests sending from masters to slaves.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MasterReq {
    /// Null operation.
    NOOP = 0,
    /// Get from the underlying vhost implementation the features bit mask.
    GET_FEATURES = 1,
    /// Enable features in the underlying vhost implementation using a bit mask.
    SET_FEATURES = 2,
    /// Set the current Master as an owner of the session.
    SET_OWNER = 3,
    /// No longer used.
    RESET_OWNER = 4,
    /// Set the memory map regions on the slave so it can translate the vring addresses.
    SET_MEM_TABLE = 5,
    /// Set logging shared memory space.
    SET_LOG_BASE = 6,
    /// Set the logging file descriptor, which is passed as ancillary data.
    SET_LOG_FD = 7,
    /// Set the size of the queue.
    SET_VRING_NUM = 8,
    /// Set the addresses of the different aspects of the vring.
    SET_VRING_ADDR = 9,
    /// Set the base offset in the available vring.
    SET_VRING_BASE = 10,
    /// Get the available vring base offset.
    GET_VRING_BASE = 11,
    /// Set the event file descriptor for adding buffers to the vring.
    SET_VRING_KICK = 12,
    /// Set the event file descriptor to signal when buffers are used.
    SET_VRING_CALL = 13,
    /// Set the event file descriptor to signal when error occurs.
    SET_VRING_ERR = 14,
    /// Get the protocol feature bit mask from the underlying vhost implementation.
    GET_PROTOCOL_FEATURES = 15,
    /// Enable protocol features in the underlying vhost implementation.
    SET_PROTOCOL_FEATURES = 16,
    /// Query how many queues the backend supports.
    GET_QUEUE_NUM = 17,
    /// Signal slave to enable or disable corresponding vring.
    SET_VRING_ENABLE = 18,
    /// Ask vhost user backend to broadcast a fake RARP to notify the migration is terminated
    /// for guest that does not support GUEST_ANNOUNCE.
    SEND_RARP = 19,
    /// Set host MTU value exposed to the guest.
    NET_SET_MTU = 20,
    /// Set the socket file descriptor for slave initiated requests.
    SET_SLAVE_REQ_FD = 21,
    /// Send IOTLB messages with struct vhost_iotlb_msg as payload.
    IOTLB_MSG = 22,
    /// Set the endianness of a VQ for legacy devices.
    SET_VRING_ENDIAN = 23,
    /// Fetch the contents of the virtio device configuration space.
    GET_CONFIG = 24,
    /// Change the contents of the virtio device configuration space.
    SET_CONFIG = 25,
    /// Create a session for crypto operation.
    CREATE_CRYPTO_SESSION = 26,
    /// Close a session for crypto operation.
    CLOSE_CRYPTO_SESSION = 27,
    /// Advise slave that a migration with postcopy enabled is underway.
    POSTCOPY_ADVISE = 28,
    /// Advise slave that a transition to postcopy mode has happened.
    POSTCOPY_LISTEN = 29,
    /// Advise that postcopy migration has now completed.
    POSTCOPY_END = 30,
    /// Get a shared buffer from slave.
    GET_INFLIGHT_FD = 31,
    /// Send the shared inflight buffer back to slave
    SET_INFLIGHT_FD = 32,
    /// Upper bound of valid commands.
    MAX_CMD = 33,
}

impl Into<u32> for MasterReq {
    fn into(self) -> u32 {
        self as u32
    }
}

impl Req for MasterReq {
    fn is_valid(&self) -> bool {
        (*self > MasterReq::NOOP) && (*self < MasterReq::MAX_CMD)
    }
}

/// Type of requests sending from slaves to masters.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlaveReq {
    /// Null operation.
    NOOP = 0,
    /// Send IOTLB messages with struct vhost_iotlb_msg as payload.
    IOTLB_MSG = 1,
    /// Notify that the virtio device's configuration space has changed.
    CONFIG_CHANGE_MSG = 2,
    /// Set host notifier for a specified queue.
    VRING_HOST_NOTIFIER_MSG = 3,
    /// Virtio-fs draft: map file content into the window.
    FS_MAP = 4,
    /// Virtio-fs draft: unmap file content from the window.
    FS_UNMAP = 5,
    /// Virtio-fs draft: sync file content.
    FS_SYNC = 6,
    /// Upper bound of valid commands.
    MAX_CMD = 7,
}

impl Into<u32> for SlaveReq {
    fn into(self) -> u32 {
        self as u32
    }
}

impl Req for SlaveReq {
    fn is_valid(&self) -> bool {
        (*self > SlaveReq::NOOP) && (*self < SlaveReq::MAX_CMD)
    }
}

/// Vhost message Validator.
pub trait VhostUserMsgValidator {
    /// Validate message syntax only.
    /// It doesn't validate message semantics such as protocol version number and dependency
    /// on feature flags etc.
    fn is_valid(&self) -> bool {
        true
    }
}

bitflags! {
    /// Common message flags for vhost-user requests and replies.
    pub struct VhostUserHeaderFlag: u32 {
        /// Bits[0..2] is message version number.
        const VERSION = 0x3;
        /// Mark message as reply.
        const REPLY = 0x4;
        /// Sender anticipates a reply message from the peer.
        const NEED_REPLY = 0x8;
        /// All valid bits.
        const ALL_FLAGS = 0xc;
        /// All reserved bits.
        const RESERVED_BITS = !0xf;
    }
}

/// Common message header for vhost-user requests and replies.
/// A vhost-user message consists of 3 header fields and an optional payload. All numbers are in the
/// machine native byte order.
#[allow(safe_packed_borrows)]
#[repr(packed)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct VhostUserMsgHeader<R: Req> {
    request: u32,
    flags: u32,
    size: u32,
    _r: PhantomData<R>,
}

impl<R: Req> VhostUserMsgHeader<R> {
    /// Create a new instance of `VhostUserMsgHeader`.
    pub fn new(request: R, flags: u32, size: u32) -> Self {
        // Default to protocol version 1
        let fl = (flags & VhostUserHeaderFlag::ALL_FLAGS.bits()) | 0x1;
        VhostUserMsgHeader {
            request: request.into(),
            flags: fl,
            size,
            _r: PhantomData,
        }
    }

    /// Get message type.
    pub fn get_code(&self) -> R {
        // It's safe because R is marked as repr(u32).
        unsafe { std::mem::transmute_copy::<u32, R>(&self.request) }
    }

    /// Set message type.
    pub fn set_code(&mut self, request: R) {
        self.request = request.into();
    }

    /// Get message version number.
    pub fn get_version(&self) -> u32 {
        self.flags & 0x3
    }

    /// Set message version number.
    pub fn set_version(&mut self, ver: u32) {
        self.flags &= !0x3;
        self.flags |= ver & 0x3;
    }

    /// Check whether it's a reply message.
    pub fn is_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::REPLY.bits()) != 0
    }

    /// Mark message as reply.
    pub fn set_reply(&mut self, is_reply: bool) {
        if is_reply {
            self.flags |= VhostUserHeaderFlag::REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::REPLY.bits();
        }
    }

    /// Check whether reply for this message is requested.
    pub fn is_need_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::NEED_REPLY.bits()) != 0
    }

    /// Mark that reply for this message is needed.
    pub fn set_need_reply(&mut self, need_reply: bool) {
        if need_reply {
            self.flags |= VhostUserHeaderFlag::NEED_REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::NEED_REPLY.bits();
        }
    }

    /// Check whether it's the reply message for the request `req`.
    pub fn is_reply_for(&self, req: &VhostUserMsgHeader<R>) -> bool {
        self.is_reply() && !req.is_reply() && self.get_code() == req.get_code()
    }

    /// Get message size.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    /// Set message size.
    pub fn set_size(&mut self, size: u32) {
        self.size = size;
    }
}

impl<R: Req> Default for VhostUserMsgHeader<R> {
    fn default() -> Self {
        VhostUserMsgHeader {
            request: 0,
            flags: 0x1,
            size: 0,
            _r: PhantomData,
        }
    }
}

impl<T: Req> VhostUserMsgValidator for VhostUserMsgHeader<T> {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if !self.get_code().is_valid() {
            return false;
        } else if self.size as usize > MAX_MSG_SIZE {
            return false;
        } else if self.get_version() != 0x1 {
            return false;
        } else if (self.flags & VhostUserHeaderFlag::RESERVED_BITS.bits()) != 0 {
            return false;
        }
        true
    }
}

bitflags! {
    /// Transport specific flags in VirtIO feature set defined by vhost-user.
    pub struct VhostUserVirtioFeatures: u64 {
        /// Feature flag for the protocol feature.
        const PROTOCOL_FEATURES = 0x4000_0000;
    }
}

bitflags! {
    /// Vhost-user protocol feature flags.
    pub struct VhostUserProtocolFeatures: u64 {
        /// Support multiple queues.
        const MQ = 0x0000_0001;
        /// Support logging through shared memory fd.
        const LOG_SHMFD = 0x0000_0002;
        /// Support broadcasting fake RARP packet.
        const RARP = 0x0000_0004;
        /// Support sending reply messages for requests with NEED_REPLY flag set.
        const REPLY_ACK = 0x0000_0008;
        /// Support setting MTU for virtio-net devices.
        const MTU = 0x0000_0010;
        /// Allow the slave to send requests to the master by an optional communication channel.
        const SLAVE_REQ = 0x0000_0020;
        /// Support setting slave endian by SET_VRING_ENDIAN.
        const CROSS_ENDIAN = 0x0000_0040;
        /// Support crypto operations.
        const CRYPTO_SESSION = 0x0000_0080;
        /// Support sending userfault_fd from slaves to masters.
        const PAGEFAULT = 0x0000_0100;
        /// Support Virtio device configuration.
        const CONFIG = 0x0000_0200;
        /// Allow the slave to send fds (at most 8 descriptors in each message) to the master.
        const SLAVE_SEND_FD = 0x0000_0400;
        /// Allow the slave to register a host notifier.
        const HOST_NOTIFIER = 0x0000_0800;
    }
}

/// A generic message to encapsulate a 64-bit value.
#[repr(packed)]
#[derive(Default)]
pub struct VhostUserU64 {
    /// The encapsulated 64-bit common value.
    pub value: u64,
}

impl VhostUserU64 {
    /// Create a new instance.
    pub fn new(value: u64) -> Self {
        VhostUserU64 { value }
    }
}

impl VhostUserMsgValidator for VhostUserU64 {}

/// Memory region descriptor for the SET_MEM_TABLE request.
#[repr(packed)]
#[derive(Default)]
pub struct VhostUserMemory {
    /// Number of memory regions in the payload.
    pub num_regions: u32,
    /// Padding for alignment.
    pub padding1: u32,
}

impl VhostUserMemory {
    /// Create a new instance.
    pub fn new(cnt: u32) -> Self {
        VhostUserMemory {
            num_regions: cnt,
            padding1: 0,
        }
    }
}

impl VhostUserMsgValidator for VhostUserMemory {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if self.padding1 != 0 {
            return false;
        } else if self.num_regions == 0 || self.num_regions > MAX_ATTACHED_FD_ENTRIES as u32 {
            return false;
        }
        true
    }
}

/// Memory region descriptors as payload for the SET_MEM_TABLE request.
#[repr(packed)]
#[derive(Default, Clone, Copy)]
pub struct VhostUserMemoryRegion {
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub user_addr: u64,
    /// Offset where region starts in the mapped memory.
    pub mmap_offset: u64,
}

impl VhostUserMemoryRegion {
    /// Create a new instance.
    pub fn new(guest_phys_addr: u64, memory_size: u64, user_addr: u64, mmap_offset: u64) -> Self {
        VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            user_addr,
            mmap_offset,
        }
    }
}

impl VhostUserMsgValidator for VhostUserMemoryRegion {
    fn is_valid(&self) -> bool {
        if self.memory_size == 0
            || self.guest_phys_addr.checked_add(self.memory_size).is_none()
            || self.user_addr.checked_add(self.memory_size).is_none()
            || self.mmap_offset.checked_add(self.memory_size).is_none()
        {
            return false;
        }
        true
    }
}

/// Payload of the VhostUserMemory message.
pub type VhostUserMemoryPayload = Vec<VhostUserMemoryRegion>;

/// Vring state descriptor.
#[repr(packed)]
#[derive(Default)]
pub struct VhostUserVringState {
    /// Vring index.
    pub index: u32,
    /// A common 32bit value to encapsulate vring state etc.
    pub num: u32,
}

impl VhostUserVringState {
    /// Create a new instance.
    pub fn new(index: u32, num: u32) -> Self {
        VhostUserVringState { index, num }
    }
}

impl VhostUserMsgValidator for VhostUserVringState {}

bitflags! {
    /// Flags for vring address.
    pub struct VhostUserVringAddrFlags: u32 {
        /// Support log of vring operations.
        /// Modifications to "used" vring should be logged.
        const VHOST_VRING_F_LOG = 0x1;
    }
}

/// Vring address descriptor.
#[repr(packed)]
#[derive(Default)]
pub struct VhostUserVringAddr {
    /// Vring index.
    pub index: u32,
    /// Vring flags defined by VhostUserVringAddrFlags.
    pub flags: u32,
    /// Ring address of the vring descriptor table.
    pub descriptor: u64,
    /// Ring address of the vring used ring.
    pub used: u64,
    /// Ring address of the vring available ring.
    pub available: u64,
    /// Guest address for logging.
    pub log: u64,
}

impl VhostUserVringAddr {
    /// Create a new instance.
    pub fn new(
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Self {
        VhostUserVringAddr {
            index,
            flags: flags.bits(),
            descriptor,
            used,
            available,
            log,
        }
    }

    /// Create a new instance from `VringConfigData`.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::identity_conversion))]
    pub fn from_config_data(index: u32, config_data: &VringConfigData) -> Self {
        let log_addr = config_data.log_addr.unwrap_or(0);
        VhostUserVringAddr {
            index,
            flags: config_data.flags,
            descriptor: config_data.desc_table_addr,
            used: config_data.used_ring_addr,
            available: config_data.avail_ring_addr,
            log: log_addr,
        }
    }
}

impl VhostUserMsgValidator for VhostUserVringAddr {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if (self.flags & !VhostUserVringAddrFlags::all().bits()) != 0 {
            return false;
        } else if self.descriptor & 0xf != 0 {
            return false;
        } else if self.available & 0x1 != 0 {
            return false;
        } else if self.used & 0x3 != 0 {
            return false;
        }
        true
    }
}

bitflags! {
    /// Flags for the device configuration message.
    pub struct VhostUserConfigFlags: u32 {
        /// TODO: seems the vhost-user spec has refined the definition, EMPTY is removed.
        const EMPTY = 0x0;
        /// Vhost master messages used for writable fields
        const WRITABLE = 0x1;
        /// Mark that message is part of an ongoing live-migration operation.
        const LIVE_MIGRATION = 0x2;
    }
}

/// Message to read/write device configuration space.
#[repr(packed)]
#[derive(Default)]
pub struct VhostUserConfig {
    /// Offset of virtio device's configuration space.
    pub offset: u32,
    /// Configuration space access size in bytes.
    pub size: u32,
    /// Flags for the device configuration operation.
    pub flags: u32,
}

impl VhostUserConfig {
    /// Create a new instance.
    pub fn new(offset: u32, size: u32, flags: VhostUserConfigFlags) -> Self {
        VhostUserConfig {
            offset,
            size,
            flags: flags.bits(),
        }
    }
}

impl VhostUserMsgValidator for VhostUserConfig {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if (self.flags & !VhostUserConfigFlags::all().bits()) != 0 {
            return false;
        } else if self.offset < VHOST_USER_CONFIG_OFFSET
            || self.offset >= VHOST_USER_CONFIG_SIZE
            || self.size == 0
            || self.size > (VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET)
            || self.size + self.offset > VHOST_USER_CONFIG_SIZE
        {
            return false;
        }
        true
    }
}

/// Payload for the VhostUserConfig message.
pub type VhostUserConfigPayload = Vec<u8>;

/*
 * TODO: support dirty log, live migration and IOTLB operations.
#[repr(packed)]
pub struct VhostUserVringArea {
    pub index: u32,
    pub flags: u32,
    pub size: u64,
    pub offset: u64,
}

#[repr(packed)]
pub struct VhostUserLog {
    pub size: u64,
    pub offset: u64,
}

#[repr(packed)]
pub struct VhostUserIotlb {
    pub iova: u64,
    pub size: u64,
    pub user_addr: u64,
    pub permission: u8,
    pub optype: u8,
}
*/

bitflags! {
    #[derive(Default)]
    /// Flags for virtio-fs slave messages.
    pub struct VhostUserFSSlaveMsgFlags: u64 {
        /// Empty permission.
        const EMPTY = 0x0;
        /// Read permission.
        const MAP_R = 0x1;
        /// Write permission.
        const MAP_W = 0x2;
    }
}

/// Max entries in one virtio-fs slave request.
const VHOST_USER_FS_SLAVE_ENTRIES: usize = 8;

/// Slave request message to update the MMIO window.
#[repr(packed)]
#[derive(Default)]
pub struct VhostUserFSSlaveMsg {
    /// TODO:
    pub fd_offset: [u64; VHOST_USER_FS_SLAVE_ENTRIES],
    /// TODO:
    pub cache_offset: [u64; VHOST_USER_FS_SLAVE_ENTRIES],
    /// Size of region to map.
    pub len: [u64; VHOST_USER_FS_SLAVE_ENTRIES],
    /// Flags for the mmap operation
    pub flags: [VhostUserFSSlaveMsgFlags; VHOST_USER_FS_SLAVE_ENTRIES],
}

impl VhostUserMsgValidator for VhostUserFSSlaveMsg {
    fn is_valid(&self) -> bool {
        for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
            if ({ self.flags[i] }.bits() & !VhostUserFSSlaveMsgFlags::all().bits()) != 0
                || self.fd_offset[i].checked_add(self.len[i]).is_none()
                || self.cache_offset[i].checked_add(self.len[i]).is_none()
            {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn check_request_code() {
        let code = MasterReq::NOOP;
        assert!(!code.is_valid());
        let code = MasterReq::MAX_CMD;
        assert!(!code.is_valid());
        let code = MasterReq::GET_FEATURES;
        assert!(code.is_valid());
    }

    #[test]
    fn msg_header_ops() {
        let mut hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, 0x100);
        assert_eq!(hdr.get_code(), MasterReq::GET_FEATURES);
        hdr.set_code(MasterReq::SET_FEATURES);
        assert_eq!(hdr.get_code(), MasterReq::SET_FEATURES);

        assert_eq!(hdr.get_version(), 0x1);

        assert_eq!(hdr.is_reply(), false);
        hdr.set_reply(true);
        assert_eq!(hdr.is_reply(), true);
        hdr.set_reply(false);

        assert_eq!(hdr.is_need_reply(), false);
        hdr.set_need_reply(true);
        assert_eq!(hdr.is_need_reply(), true);
        hdr.set_need_reply(false);

        assert_eq!(hdr.get_size(), 0x100);
        hdr.set_size(0x200);
        assert_eq!(hdr.get_size(), 0x200);

        assert_eq!(hdr.is_need_reply(), false);
        assert_eq!(hdr.is_reply(), false);
        assert_eq!(hdr.get_version(), 0x1);

        // Check message length
        assert!(hdr.is_valid());
        hdr.set_size(0x2000);
        assert!(!hdr.is_valid());
        hdr.set_size(0x100);
        assert_eq!(hdr.get_size(), 0x100);
        assert!(hdr.is_valid());
        hdr.set_size((MAX_MSG_SIZE - mem::size_of::<VhostUserMsgHeader<MasterReq>>()) as u32);
        assert!(hdr.is_valid());
        hdr.set_size(0x0);
        assert!(hdr.is_valid());

        // Check version
        hdr.set_version(0x0);
        assert!(!hdr.is_valid());
        hdr.set_version(0x2);
        assert!(!hdr.is_valid());
        hdr.set_version(0x1);
        assert!(hdr.is_valid());
    }

    #[test]
    fn check_user_memory() {
        let mut msg = VhostUserMemory::new(1);
        assert!(msg.is_valid());
        msg.num_regions = MAX_ATTACHED_FD_ENTRIES as u32;
        assert!(msg.is_valid());

        msg.num_regions += 1;
        assert!(!msg.is_valid());
        msg.num_regions = 0xFFFFFFFF;
        assert!(!msg.is_valid());
        msg.num_regions = MAX_ATTACHED_FD_ENTRIES as u32;
        msg.padding1 = 1;
        assert!(!msg.is_valid());
    }

    #[test]
    fn check_user_memory_region() {
        let mut msg = VhostUserMemoryRegion {
            guest_phys_addr: 0,
            memory_size: 0x1000,
            user_addr: 0,
            mmap_offset: 0,
        };
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFEFFF;
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFF000;
        assert!(!msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFF0000;
        msg.memory_size = 0;
        assert!(!msg.is_valid());
    }

    #[test]
    fn check_user_vring_addr() {
        let mut msg =
            VhostUserVringAddr::new(0, VhostUserVringAddrFlags::all(), 0x0, 0x0, 0x0, 0x0);
        assert!(msg.is_valid());

        msg.descriptor = 1;
        assert!(!msg.is_valid());
        msg.descriptor = 0;

        msg.available = 1;
        assert!(!msg.is_valid());
        msg.available = 0;

        msg.used = 1;
        assert!(!msg.is_valid());
        msg.used = 0;

        msg.flags |= 0x80000000;
        assert!(!msg.is_valid());
        msg.flags &= !0x80000000;
    }

    #[test]
    fn check_user_config_msg() {
        let mut msg = VhostUserConfig::new(
            VHOST_USER_CONFIG_OFFSET,
            VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET,
            VhostUserConfigFlags::EMPTY,
        );

        assert!(msg.is_valid());
        msg.size = 0;
        assert!(!msg.is_valid());
        msg.size = 1;
        assert!(msg.is_valid());
        msg.offset = 0;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE - 1;
        assert!(msg.is_valid());
        msg.size = 2;
        assert!(!msg.is_valid());
        msg.size = 1;
        msg.flags |= VhostUserConfigFlags::WRITABLE.bits();
        assert!(msg.is_valid());
        msg.flags |= 0x4;
        assert!(!msg.is_valid());
    }
}
