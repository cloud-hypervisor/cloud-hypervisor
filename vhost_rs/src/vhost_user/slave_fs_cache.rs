// Copyright (C) 2020 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::connection::Endpoint;
use super::message::*;
use super::{Error, HandlerResult, Result, VhostUserMasterReqHandler};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

struct SlaveFsCacheReqInternal {
    sock: Endpoint<SlaveReq>,
}

/// A vhost-user slave endpoint which sends fs cache requests to the master
#[derive(Clone)]
pub struct SlaveFsCacheReq {
    // underlying Unix domain socket for communication
    node: Arc<Mutex<SlaveFsCacheReqInternal>>,

    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl SlaveFsCacheReq {
    fn new(ep: Endpoint<SlaveReq>) -> Self {
        SlaveFsCacheReq {
            node: Arc::new(Mutex::new(SlaveFsCacheReqInternal { sock: ep })),
            error: None,
        }
    }

    /// Create a new instance.
    pub fn from_stream(sock: UnixStream) -> Self {
        Self::new(Endpoint::<SlaveReq>::from_stream(sock))
    }

    fn send_message(
        &mut self,
        flags: SlaveReq,
        fs: &VhostUserFSSlaveMsg,
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        self.check_state()?;

        let len = mem::size_of::<VhostUserFSSlaveMsg>();
        let mut hdr = VhostUserMsgHeader::new(flags, 0, len as u32);
        hdr.set_need_reply(true);
        self.node.lock().unwrap().sock.send_message(&hdr, fs, fds)?;

        self.wait_for_ack(&hdr)
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<SlaveReq>) -> Result<()> {
        self.check_state()?;
        let (reply, body, rfds) = self.node.lock().unwrap().sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(&hdr) || rfds.is_some() || !body.is_valid() {
            Endpoint::<SlaveReq>::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::MasterInternalError);
        }
        Ok(())
    }

    fn check_state(&self) -> Result<()> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(()),
        }
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&mut self, error: i32) {
        self.error = Some(error);
    }
}

impl VhostUserMasterReqHandler for SlaveFsCacheReq {
    /// Handle virtio-fs map file requests from the slave.
    fn fs_slave_map(&mut self, fs: &VhostUserFSSlaveMsg, fd: RawFd) -> HandlerResult<()> {
        self.send_message(SlaveReq::FS_MAP, fs, Some(&[fd]))
            .or_else(|e| Err(io::Error::new(io::ErrorKind::Other, format!("{}", e))))
    }

    /// Handle virtio-fs unmap file requests from the slave.
    fn fs_slave_unmap(&mut self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<()> {
        self.send_message(SlaveReq::FS_UNMAP, fs, None)
            .or_else(|e| Err(io::Error::new(io::ErrorKind::Other, format!("{}", e))))
    }
}
