// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Structs to handle vhost-user requests from the slave to the master.

use libc;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use super::connection::Endpoint;
use super::message::*;
use super::{Error, HandlerResult, Result};

/// Trait to handle vhost-user requests from the slave to the master.
pub trait VhostUserMasterReqHandler {
    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: RawFd);

    /// Handle device configuration change notifications from the slave.
    fn handle_config_change(&mut self) -> HandlerResult<()> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs map file requests from the slave.
    fn fs_slave_map(&mut self, _fs: &VhostUserFSSlaveMsg, fd: RawFd) -> HandlerResult<()> {
        // Safe because we have just received the rawfd from kernel.
        unsafe { libc::close(fd) };
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs unmap file requests from the slave.
    fn fs_slave_unmap(&mut self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<()> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs sync file requests from the slave.
    fn fs_slave_sync(&mut self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<()> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }
}

/// A vhost-user master request endpoint which relays all received requests from the slave to the
/// provided request handler.
pub struct MasterReqHandler<S: VhostUserMasterReqHandler> {
    // underlying Unix domain socket for communication
    sub_sock: Endpoint<SlaveReq>,
    tx_sock: UnixStream,
    // the VirtIO backend device object
    backend: Arc<Mutex<S>>,
    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl<S: VhostUserMasterReqHandler> MasterReqHandler<S> {
    /// Create a vhost-user slave request handler.
    /// This opens a pair of connected anonymous sockets.
    /// Returns Self and the socket that must be sent to the slave via SET_SLAVE_REQ_FD.
    pub fn new(backend: Arc<Mutex<S>>) -> Result<Self> {
        let (tx, rx) = UnixStream::pair().map_err(Error::SocketError)?;

        Ok(MasterReqHandler {
            sub_sock: Endpoint::<SlaveReq>::from_stream(rx),
            tx_sock: tx,
            backend,
            error: None,
        })
    }

    /// Get the raw fd to send to the slave as slave communication channel.
    pub fn get_tx_raw_fd(&self) -> RawFd {
        self.tx_sock.as_raw_fd()
    }

    /// Mark endpoint as failed or normal state.
    pub fn set_failed(&mut self, error: i32) {
        self.error = Some(error);
    }

    /// Receive and handle one incoming request message from the slave.
    /// The caller needs to:
    /// . serialize calls to this function
    /// . decide what to do when errer happens
    /// . optional recover from failure
    pub fn handle_request(&mut self) -> Result<()> {
        // Return error if the endpoint is already in failed state.
        self.check_state()?;

        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, rfds) = self.sub_sock.recv_header()?;
        let rfds = self.check_attached_rfds(&hdr, rfds)?;
        let (size, buf) = match hdr.get_size() {
            0 => (0, vec![0u8; 0]),
            len => {
                let (size2, rbuf) = self.sub_sock.recv_data(len as usize)?;
                if size2 != len as usize {
                    return Err(Error::InvalidMessage);
                }
                (size2, rbuf)
            }
        };

        match hdr.get_code() {
            SlaveReq::CONFIG_CHANGE_MSG => {
                self.check_msg_size(&hdr, size, 0)?;
                self.backend
                    .lock()
                    .unwrap()
                    .handle_config_change()
                    .map_err(Error::ReqHandlerError)?;
            }
            SlaveReq::FS_MAP => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .fs_slave_map(msg, rfds.unwrap()[0])
                    .map_err(Error::ReqHandlerError)?;
            }
            SlaveReq::FS_UNMAP => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .fs_slave_unmap(msg)
                    .map_err(Error::ReqHandlerError)?;
            }
            SlaveReq::FS_SYNC => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .fs_slave_sync(msg)
                    .map_err(Error::ReqHandlerError)?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }

        Ok(())
    }

    fn check_state(&self) -> Result<()> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(()),
        }
    }

    fn check_msg_size(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        size: usize,
        expected: usize,
    ) -> Result<()> {
        if hdr.get_size() as usize != expected
            || hdr.is_reply()
            || hdr.get_version() != 0x1
            || size != expected
        {
            return Err(Error::InvalidMessage);
        }
        Ok(())
    }

    fn check_attached_rfds(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        rfds: Option<Vec<RawFd>>,
    ) -> Result<Option<Vec<RawFd>>> {
        match hdr.get_code() {
            SlaveReq::FS_MAP => {
                // Expect an fd set with a single fd.
                match rfds {
                    None => Err(Error::InvalidMessage),
                    Some(fds) => {
                        if fds.len() != 1 {
                            Endpoint::<SlaveReq>::close_rfds(Some(fds));
                            Err(Error::InvalidMessage)
                        } else {
                            Ok(Some(fds))
                        }
                    }
                }
            }
            _ => {
                if rfds.is_some() {
                    Endpoint::<SlaveReq>::close_rfds(rfds);
                    Err(Error::InvalidMessage)
                } else {
                    Ok(rfds)
                }
            }
        }
    }

    fn extract_msg_body<'a, T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        size: usize,
        buf: &'a [u8],
    ) -> Result<&'a T> {
        self.check_msg_size(hdr, size, mem::size_of::<T>())?;
        let msg = unsafe { &*(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }
}

impl<S: VhostUserMasterReqHandler> AsRawFd for MasterReqHandler<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.sub_sock.as_raw_fd()
    }
}
