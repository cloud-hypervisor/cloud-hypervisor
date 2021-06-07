// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::super::{EpollHelper, EpollHelperError, EpollHelperHandler, EPOLL_HELPER_EVENT_LAST};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use vhost::vhost_user::{MasterReqHandler, VhostUserMasterReqHandler};
use vmm_sys_util::eventfd::EventFd;

/// Collection of common parameters required by vhost-user devices while
/// call Epoll handler.
///
/// # Arguments
/// * `interrupt_cb` interrupt for virtqueue change.
/// * `kill_evt` - EventFd used to kill the vhost-user device.
/// * `vu_interrupt_list` - virtqueue and EventFd to signal when buffer used.
pub struct VhostUserEpollConfig<S: VhostUserMasterReqHandler> {
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub slave_req_handler: Option<Arc<Mutex<MasterReqHandler<S>>>>,
    pub disconnect_evt: EventFd,
}

pub struct VhostUserEpollHandler<S: VhostUserMasterReqHandler> {
    vu_epoll_cfg: VhostUserEpollConfig<S>,
    slave_evt_idx: u16,
    disconnect_evt_idx: u16,
}

impl<S: VhostUserMasterReqHandler> VhostUserEpollHandler<S> {
    /// Construct a new event handler for vhost-user based devices.
    ///
    /// # Arguments
    /// * `vu_epoll_cfg` - collection of common parameters for vhost-user devices
    ///
    /// # Return
    /// * `VhostUserEpollHandler` - epoll handler for vhost-user based devices
    pub fn new(vu_epoll_cfg: VhostUserEpollConfig<S>) -> VhostUserEpollHandler<S> {
        VhostUserEpollHandler {
            vu_epoll_cfg,
            slave_evt_idx: EPOLL_HELPER_EVENT_LAST + 1,
            disconnect_evt_idx: EPOLL_HELPER_EVENT_LAST + 2,
        }
    }

    pub fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper =
            EpollHelper::new(&self.vu_epoll_cfg.kill_evt, &self.vu_epoll_cfg.pause_evt)?;

        if let Some(self_req_handler) = &self.vu_epoll_cfg.slave_req_handler {
            helper.add_event(
                self_req_handler.lock().unwrap().as_raw_fd(),
                self.slave_evt_idx,
            )?;
            helper.add_event(
                self.vu_epoll_cfg.disconnect_evt.as_raw_fd(),
                self.disconnect_evt_idx,
            )?;
        }

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl<S: VhostUserMasterReqHandler> EpollHelperHandler for VhostUserEpollHandler<S> {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            x if x == self.slave_evt_idx => {
                if let Some(slave_req_handler) = self.vu_epoll_cfg.slave_req_handler.as_mut() {
                    if let Err(e) = slave_req_handler.lock().unwrap().handle_request() {
                        error!("Failed to handle vhost-user request: {:?}", e);
                        return true;
                    }
                }
            }
            x if x == self.disconnect_evt_idx => {
                info!("Vhost-user socket disconnected, exiting the slave thread...");

                // Drain the disconnect_evt event before exiting
                let _ = self.vu_epoll_cfg.disconnect_evt.read();
                return true;
            }
            _ => {
                error!("Unknown event for vhost-user");
                return true;
            }
        }

        false
    }
}
