// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Struct for vhost-user master.

use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use super::connection::Endpoint;
use super::message::*;
use super::{Error as VhostUserError, Result as VhostUserResult};
use crate::backend::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use crate::{Error, Result};

/// Trait for vhost-user master to provide extra methods not covered by the VhostBackend yet.
pub trait VhostUserMaster: VhostBackend {
    /// Get the protocol feature bitmask from the underlying vhost implementation.
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;

    /// Enable protocol features in the underlying vhost implementation.
    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()>;

    /// Query how many queues the backend supports.
    fn get_queue_num(&mut self) -> Result<u64>;

    /// Signal slave to enable or disable corresponding vring.
    ///
    /// Slave must not pass data to/from the backend until ring is enabled by
    /// VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
    /// disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<()>;

    /// Fetch the contents of the virtio device configuration space.
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)>;

    /// Change the virtio device configuration space. It also can be used for live migration on the
    /// destination host to set readonly configuration space fields.
    fn set_config(&mut self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()>;

    /// Setup slave communication channel.
    fn set_slave_request_fd(&mut self, fd: RawFd) -> Result<()>;
}

fn error_code<T>(err: VhostUserError) -> Result<T> {
    Err(Error::VhostUserProtocol(err))
}

/// Struct for the vhost-user master endpoint.
#[derive(Clone)]
pub struct Master {
    node: Arc<Mutex<MasterInternal>>,
}

impl Master {
    /// Create a new instance.
    fn new(ep: Endpoint<MasterReq>, max_queue_num: u64) -> Self {
        Master {
            node: Arc::new(Mutex::new(MasterInternal {
                main_sock: ep,
                virtio_features: 0,
                acked_virtio_features: 0,
                protocol_features: 0,
                acked_protocol_features: 0,
                protocol_features_ready: false,
                max_queue_num,
                error: None,
            })),
        }
    }

    /// Create a new instance from a Unix stream socket.
    pub fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
        Self::new(Endpoint::<MasterReq>::from_stream(sock), max_queue_num)
    }

    /// Create a new vhost-user master endpoint.
    ///
    /// # Arguments
    /// * `path` - path of Unix domain socket listener to connect to
    pub fn connect(path: &str, max_queue_num: u64) -> Result<Self> {
        Ok(Self::new(
            Endpoint::<MasterReq>::connect(path)?,
            max_queue_num,
        ))
    }
}

impl VhostBackend for Master {
    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&mut self) -> Result<u64> {
        let mut node = self.node.lock().unwrap();
        let hdr = node.send_request_header(MasterReq::GET_FEATURES, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        node.virtio_features = val.value;
        Ok(node.virtio_features)
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&mut self, features: u64) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let val = VhostUserU64::new(features);
        let _ = node.send_request_with_body(MasterReq::SET_FEATURES, &val, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        node.acked_virtio_features = features & node.virtio_features;
        Ok(())
    }

    /// Set the current Master as an owner of the session.
    fn set_owner(&mut self) -> Result<()> {
        // We unwrap() the return value to assert that we are not expecting threads to ever fail
        // while holding the lock.
        let mut node = self.node.lock().unwrap();
        let _ = node.send_request_header(MasterReq::SET_OWNER, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let _ = node.send_request_header(MasterReq::RESET_OWNER, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        Ok(())
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        if regions.is_empty() || regions.len() > MAX_ATTACHED_FD_ENTRIES {
            return error_code(VhostUserError::InvalidParam);
        }

        let mut ctx = VhostUserMemoryContext::new();
        for region in regions.iter() {
            if region.memory_size == 0 || region.mmap_handle < 0 {
                return error_code(VhostUserError::InvalidParam);
            }
            let reg = VhostUserMemoryRegion {
                guest_phys_addr: region.guest_phys_addr,
                memory_size: region.memory_size,
                user_addr: region.userspace_addr,
                mmap_offset: region.mmap_offset,
            };
            ctx.append(&reg, region.mmap_handle);
        }

        let mut node = self.node.lock().unwrap();
        let body = VhostUserMemory::new(ctx.regions.len() as u32);
        let hdr = node.send_request_with_payload(
            MasterReq::SET_MEM_TABLE,
            &body,
            ctx.regions.as_slice(),
            Some(ctx.fds.as_slice()),
        )?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    // Clippy doesn't seem to know that if let with && is still experimental
    #[allow(clippy::unnecessary_unwrap)]
    fn set_log_base(&mut self, base: u64, fd: Option<RawFd>) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let val = VhostUserU64::new(base);

        if node.acked_protocol_features & VhostUserProtocolFeatures::LOG_SHMFD.bits() != 0
            && fd.is_some()
        {
            let fds = [fd.unwrap()];
            let _ = node.send_request_with_body(MasterReq::SET_LOG_BASE, &val, Some(&fds))?;
        } else {
            let _ = node.send_request_with_body(MasterReq::SET_LOG_BASE, &val, None)?;
        }
        Ok(())
    }

    fn set_log_fd(&mut self, fd: RawFd) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let fds = [fd];
        node.send_request_header(MasterReq::SET_LOG_FD, Some(&fds))?;
        Ok(())
    }

    /// Set the size of the queue.
    fn set_vring_num(&mut self, queue_index: usize, num: u16) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, num.into());
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_NUM, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(&mut self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num
            || config_data.flags & !(VhostUserVringAddrFlags::all().bits()) != 0
        {
            return error_code(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringAddr::from_config_data(queue_index as u32, config_data);
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_ADDR, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&mut self, queue_index: usize, base: u16) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, base.into());
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_BASE, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_vring_base(&mut self, queue_index: usize) -> Result<u32> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let req = VhostUserVringState::new(queue_index as u32, 0);
        let hdr = node.send_request_with_body(MasterReq::GET_VRING_BASE, &req, None)?;
        let reply = node.recv_reply::<VhostUserVringState>(&hdr)?;
        Ok(reply.num)
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&mut self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }
        node.send_fd_for_vring(MasterReq::SET_VRING_CALL, queue_index, fd.as_raw_fd())?;
        Ok(())
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&mut self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }
        node.send_fd_for_vring(MasterReq::SET_VRING_KICK, queue_index, fd.as_raw_fd())?;
        Ok(())
    }

    /// Set the event file descriptor to signal when error occurs.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data.
    fn set_vring_err(&mut self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }
        node.send_fd_for_vring(MasterReq::SET_VRING_ERR, queue_index, fd.as_raw_fd())?;
        Ok(())
    }
}

impl VhostUserMaster for Master {
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        let mut node = self.node.lock().unwrap();
        let flag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if node.virtio_features & flag == 0 || node.acked_virtio_features & flag == 0 {
            return error_code(VhostUserError::InvalidOperation);
        }
        let hdr = node.send_request_header(MasterReq::GET_PROTOCOL_FEATURES, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        node.protocol_features = val.value;
        // Should we support forward compatibility?
        // If so just mask out unrecognized flags instead of return errors.
        match VhostUserProtocolFeatures::from_bits(node.protocol_features) {
            Some(val) => Ok(val),
            None => error_code(VhostUserError::InvalidMessage),
        }
    }

    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let flag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if node.virtio_features & flag == 0 || node.acked_virtio_features & flag == 0 {
            return error_code(VhostUserError::InvalidOperation);
        }
        let val = VhostUserU64::new(features.bits());
        let _ = node.send_request_with_body(MasterReq::SET_PROTOCOL_FEATURES, &val, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        node.acked_protocol_features = features.bits();
        node.protocol_features_ready = true;
        Ok(())
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        let mut node = self.node.lock().unwrap();
        if !node.is_feature_mq_available() {
            return error_code(VhostUserError::InvalidOperation);
        }

        let hdr = node.send_request_header(MasterReq::GET_QUEUE_NUM, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        if val.value > VHOST_USER_MAX_VRINGS {
            return error_code(VhostUserError::InvalidMessage);
        }
        node.max_queue_num = val.value;
        Ok(node.max_queue_num)
    }

    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        // set_vring_enable() is supported only when PROTOCOL_FEATURES has been enabled.
        if node.acked_virtio_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return error_code(VhostUserError::InvalidOperation);
        } else if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let flag = if enable { 1 } else { 0 };
        let val = VhostUserVringState::new(queue_index as u32, flag);
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_ENABLE, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)> {
        let body = VhostUserConfig::new(offset, size, flags);
        if !body.is_valid() {
            return error_code(VhostUserError::InvalidParam);
        }

        let mut node = self.node.lock().unwrap();
        // depends on VhostUserProtocolFeatures::CONFIG
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return error_code(VhostUserError::InvalidOperation);
        }

        // vhost-user spec states that:
        // "Master payload: virtio device config space"
        // "Slave payload: virtio device config space"
        let hdr = node.send_request_with_payload(MasterReq::GET_CONFIG, &body, buf, None)?;
        let (body_reply, buf_reply, rfds) =
            node.recv_reply_with_payload::<VhostUserConfig>(&hdr)?;
        if rfds.is_some() {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return error_code(VhostUserError::InvalidMessage);
        } else if body_reply.size == 0 {
            return error_code(VhostUserError::SlaveInternalError);
        } else if body_reply.size != body.size || body_reply.size as usize != buf.len() {
            return error_code(VhostUserError::InvalidMessage);
        }
        Ok((body_reply, buf_reply))
    }

    fn set_config(&mut self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()> {
        if buf.len() > MAX_MSG_SIZE {
            return error_code(VhostUserError::InvalidParam);
        }
        let body = VhostUserConfig::new(offset, buf.len() as u32, flags);
        if !body.is_valid() {
            return error_code(VhostUserError::InvalidParam);
        }

        let mut node = self.node.lock().unwrap();
        // depends on VhostUserProtocolFeatures::CONFIG
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return error_code(VhostUserError::InvalidOperation);
        }

        let hdr = node.send_request_with_payload(MasterReq::SET_CONFIG, &body, buf, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn set_slave_request_fd(&mut self, fd: RawFd) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if node.acked_protocol_features & VhostUserProtocolFeatures::SLAVE_REQ.bits() == 0 {
            return error_code(VhostUserError::InvalidOperation);
        }

        let fds = [fd];
        node.send_request_header(MasterReq::SET_SLAVE_REQ_FD, Some(&fds))?;
        Ok(())
    }
}

impl AsRawFd for Master {
    fn as_raw_fd(&self) -> RawFd {
        let node = self.node.lock().unwrap();
        node.main_sock.as_raw_fd()
    }
}

/// Context object to pass guest memory configuration to VhostUserMaster::set_mem_table().
struct VhostUserMemoryContext {
    regions: VhostUserMemoryPayload,
    fds: Vec<RawFd>,
}

impl VhostUserMemoryContext {
    /// Create a context object.
    pub fn new() -> Self {
        VhostUserMemoryContext {
            regions: VhostUserMemoryPayload::new(),
            fds: Vec::new(),
        }
    }

    /// Append a user memory region and corresponding RawFd into the context object.
    pub fn append(&mut self, region: &VhostUserMemoryRegion, fd: RawFd) {
        self.regions.push(*region);
        self.fds.push(fd);
    }
}

struct MasterInternal {
    // Used to send requests to the slave.
    main_sock: Endpoint<MasterReq>,
    // Cached virtio features from the slave.
    virtio_features: u64,
    // Cached acked virtio features from the driver.
    acked_virtio_features: u64,
    // Cached vhost-user protocol features from the slave.
    protocol_features: u64,
    // Cached vhost-user protocol features.
    acked_protocol_features: u64,
    // Cached vhost-user protocol features are ready to use.
    protocol_features_ready: bool,
    // Cached maxinum number of queues supported from the slave.
    max_queue_num: u64,
    // Internal flag to mark failure state.
    error: Option<i32>,
}

impl MasterInternal {
    fn send_request_header(
        &mut self,
        code: MasterReq,
        fds: Option<&[RawFd]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        self.check_state()?;
        let hdr = Self::new_request_header(code, 0);
        self.main_sock.send_header(&hdr, fds)?;
        Ok(hdr)
    }

    fn send_request_with_body<T: Sized>(
        &mut self,
        code: MasterReq,
        msg: &T,
        fds: Option<&[RawFd]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let hdr = Self::new_request_header(code, mem::size_of::<T>() as u32);
        self.main_sock.send_message(&hdr, msg, fds)?;
        Ok(hdr)
    }

    fn send_request_with_payload<T: Sized, P: Sized>(
        &mut self,
        code: MasterReq,
        msg: &T,
        payload: &[P],
        fds: Option<&[RawFd]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        let len = mem::size_of::<T>() + payload.len() * mem::size_of::<P>();
        if len > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        if let Some(ref fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(VhostUserError::InvalidParam);
            }
        }
        self.check_state()?;

        let hdr = Self::new_request_header(code, len as u32);
        self.main_sock
            .send_message_with_payload(&hdr, msg, payload, fds)?;
        Ok(hdr)
    }

    fn send_fd_for_vring(
        &mut self,
        code: MasterReq,
        queue_index: usize,
        fd: RawFd,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        if queue_index as u64 >= self.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
        // This flag is set when there is no file descriptor in the ancillary data. This signals
        // that polling will be used instead of waiting for the call.
        let msg = VhostUserU64::new(queue_index as u64);
        let hdr = Self::new_request_header(code, mem::size_of::<VhostUserU64>() as u32);
        self.main_sock.send_message(&hdr, &msg, Some(&[fd]))?;
        Ok(hdr)
    }

    fn recv_reply<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<T> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let (reply, body, rfds) = self.main_sock.recv_body::<T>()?;
        if !reply.is_reply_for(&hdr) || rfds.is_some() || !body.is_valid() {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return Err(VhostUserError::InvalidMessage);
        }
        Ok(body)
    }

    fn recv_reply_with_payload<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<(T, Vec<u8>, Option<Vec<RawFd>>)> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let mut buf: Vec<u8> = vec![0; hdr.get_size() as usize - mem::size_of::<T>()];
        let (reply, body, bytes, rfds) = self.main_sock.recv_payload_into_buf::<T>(&mut buf)?;
        if !reply.is_reply_for(hdr)
            || reply.get_size() as usize != mem::size_of::<T>() + bytes
            || rfds.is_some()
            || !body.is_valid()
        {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return Err(VhostUserError::InvalidMessage);
        } else if bytes > MAX_MSG_SIZE - mem::size_of::<T>() {
            return Err(VhostUserError::InvalidMessage);
        } else if bytes < buf.len() {
            // It's safe because we have checked the buffer size
            unsafe { buf.set_len(bytes) };
        }
        Ok((body, buf, rfds))
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<MasterReq>) -> VhostUserResult<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() == 0
            || !hdr.is_need_reply()
        {
            return Ok(());
        }
        self.check_state()?;

        let (reply, body, rfds) = self.main_sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(&hdr) || rfds.is_some() || !body.is_valid() {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return Err(VhostUserError::InvalidMessage);
        }
        if body.value != 0 {
            return Err(VhostUserError::SlaveInternalError);
        }
        Ok(())
    }

    fn is_feature_mq_available(&self) -> bool {
        self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0
    }

    fn check_state(&self) -> VhostUserResult<()> {
        match self.error {
            Some(e) => Err(VhostUserError::SocketBroken(
                std::io::Error::from_raw_os_error(e),
            )),
            None => Ok(()),
        }
    }

    #[inline]
    fn new_request_header(request: MasterReq, size: u32) -> VhostUserMsgHeader<MasterReq> {
        // TODO: handle NEED_REPLY flag
        VhostUserMsgHeader::new(request, 0x1, size)
    }
}

#[cfg(test)]
mod tests {
    use super::super::connection::Listener;
    use super::*;

    const UNIX_SOCKET_MASTER: &'static str = "/tmp/vhost_user_test_rust_master";
    const UNIX_SOCKET_MASTER2: &'static str = "/tmp/vhost_user_test_rust_master2";
    const UNIX_SOCKET_MASTER3: &'static str = "/tmp/vhost_user_test_rust_master3";
    const UNIX_SOCKET_MASTER4: &'static str = "/tmp/vhost_user_test_rust_master4";

    fn create_pair(path: &str) -> (Master, Endpoint<MasterReq>) {
        let listener = Listener::new(path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Master::connect(path, 2).unwrap();
        let slave = listener.accept().unwrap().unwrap();
        (master, Endpoint::from_stream(slave))
    }

    #[test]
    #[ignore]
    fn create_master() {
        let listener = Listener::new(UNIX_SOCKET_MASTER, true).unwrap();
        listener.set_nonblocking(true).unwrap();

        let mut master = Master::connect(UNIX_SOCKET_MASTER, 2).unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(listener.accept().unwrap().unwrap());

        // Send two messages continuously
        master.set_owner().unwrap();
        master.reset_owner().unwrap();

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::RESET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());
    }

    #[test]
    #[ignore]
    fn test_create_failure() {
        let _ = Listener::new(UNIX_SOCKET_MASTER2, true).unwrap();
        let _ = Listener::new(UNIX_SOCKET_MASTER2, false).is_err();
        assert!(Master::connect(UNIX_SOCKET_MASTER2, 2).is_err());

        let listener = Listener::new(UNIX_SOCKET_MASTER2, true).unwrap();
        assert!(Listener::new(UNIX_SOCKET_MASTER2, false).is_err());
        listener.set_nonblocking(true).unwrap();

        let _master = Master::connect(UNIX_SOCKET_MASTER2, 2).unwrap();
        let _slave = listener.accept().unwrap().unwrap();
    }

    #[test]
    #[ignore]
    fn test_features() {
        let (mut master, mut peer) = create_pair(UNIX_SOCKET_MASTER3);

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, 0x15u64);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_features(0x15).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, 0x15);

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = 0x15u32;
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_features().is_err());
    }

    #[test]
    #[ignore]
    fn test_protocol_features() {
        let (mut master, mut peer) = create_pair(UNIX_SOCKET_MASTER4);

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::SET_OWNER);
        assert!(rfds.is_none());

        assert!(master.get_protocol_features().is_err());
        assert!(master
            .set_protocol_features(VhostUserProtocolFeatures::all())
            .is_err());

        let vfeatures = 0x15 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(vfeatures);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, vfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_features(vfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, vfeatures);

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(MasterReq::GET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_protocol_features(pfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, pfeatures.bits());

        let hdr = VhostUserMsgHeader::new(MasterReq::SET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_protocol_features().is_err());
    }

    #[test]
    fn test_set_mem_table() {
        // TODO
    }

    #[test]
    fn test_get_ring_num() {
        // TODO
    }
}
