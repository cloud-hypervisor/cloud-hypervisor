// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Structs for vhost-user slave.

use std::sync::{Arc, Mutex};

use super::connection::{Endpoint, Listener};
use super::message::*;
use super::{Result, SlaveReqHandler, VhostUserSlaveReqHandler};

/// Vhost-user slave side connection listener.
pub struct SlaveListener<S: VhostUserSlaveReqHandler> {
    listener: Listener,
    backend: Option<Arc<Mutex<S>>>,
}

/// Sets up a listener for incoming master connections, and handles construction
/// of a Slave on success.
impl<S: VhostUserSlaveReqHandler> SlaveListener<S> {
    /// Create a unix domain socket for incoming master connections.
    ///
    /// Be careful, the file at `path` will be unlinked if unlink is true
    pub fn new(path: &str, unlink: bool, backend: Arc<Mutex<S>>) -> Result<Self> {
        Ok(SlaveListener {
            listener: Listener::new(path, unlink)?,
            backend: Some(backend),
        })
    }

    /// Accept an incoming connection from the master, returning Some(Slave) on
    /// success, or None if the socket is nonblocking and no incoming connection
    /// was detected
    pub fn accept(&mut self) -> Result<Option<SlaveReqHandler<S>>> {
        if let Some(fd) = self.listener.accept()? {
            return Ok(Some(SlaveReqHandler::new(
                Endpoint::<MasterReq>::from_stream(fd),
                self.backend.take().unwrap(),
            )));
        }
        Ok(None)
    }

    /// Change blocking status on the listener.
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.listener.set_nonblocking(block)
    }
}
