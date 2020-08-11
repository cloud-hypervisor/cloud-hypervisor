// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::super::{
    EpollHelper, EpollHelperError, EpollHelperHandler, Queue, VirtioInterruptType,
    EPOLL_HELPER_EVENT_LAST,
};
use super::{Error, Result};
use vmm_sys_util::eventfd::EventFd;

use crate::VirtioInterrupt;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use vhost_rs::vhost_user::{MasterReqHandler, VhostUserMasterReqHandler};

/// Collection of common parameters required by vhost-user devices while
/// call Epoll handler.
///
/// # Arguments
/// * `interrupt_cb` interrupt for virtqueue change.
/// * `kill_evt` - EventFd used to kill the vhost-user device.
/// * `vu_interrupt_list` - virtqueue and EventFd to signal when buffer used.
pub struct VhostUserEpollConfig<S: VhostUserMasterReqHandler> {
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub vu_interrupt_list: Vec<(Option<EventFd>, Queue)>,
    pub slave_req_handler: Option<MasterReqHandler<S>>,
}

pub struct VhostUserEpollHandler<S: VhostUserMasterReqHandler> {
    vu_epoll_cfg: VhostUserEpollConfig<S>,
    queue_evt_start_idx: u16,
    slave_evt_idx: u16,
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
        let queue_evt_start_idx = EPOLL_HELPER_EVENT_LAST + 1;
        let slave_evt_idx = queue_evt_start_idx + vu_epoll_cfg.vu_interrupt_list.len() as u16;

        VhostUserEpollHandler {
            vu_epoll_cfg,
            queue_evt_start_idx,
            slave_evt_idx,
        }
    }

    fn signal_used_queue(&self, queue: &Queue) -> Result<()> {
        self.vu_epoll_cfg
            .interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(queue))
            .map_err(Error::FailedSignalingUsedQueue)
    }

    pub fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper =
            EpollHelper::new(&self.vu_epoll_cfg.kill_evt, &self.vu_epoll_cfg.pause_evt)?;

        for (i, vhost_user_interrupt) in self.vu_epoll_cfg.vu_interrupt_list.iter().enumerate() {
            if let Some(eventfd) = &vhost_user_interrupt.0 {
                helper.add_event(eventfd.as_raw_fd(), self.queue_evt_start_idx + i as u16)?;
            }
        }

        if let Some(self_req_handler) = &self.vu_epoll_cfg.slave_req_handler {
            helper.add_event(self_req_handler.as_raw_fd(), self.slave_evt_idx)?;
        }

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl<S: VhostUserMasterReqHandler> EpollHelperHandler for VhostUserEpollHandler<S> {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            x if (x >= self.queue_evt_start_idx && x < self.slave_evt_idx) => {
                let idx = (x - self.queue_evt_start_idx) as usize;
                if let Some(eventfd) = &self.vu_epoll_cfg.vu_interrupt_list[idx].0 {
                    if let Err(e) = eventfd.read() {
                        error!("Failed to read queue: {:?}", e);
                        return true;
                    }
                    if let Err(e) =
                        self.signal_used_queue(&self.vu_epoll_cfg.vu_interrupt_list[idx].1)
                    {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            x if x == self.slave_evt_idx => {
                if let Some(slave_req_handler) = self.vu_epoll_cfg.slave_req_handler.as_mut() {
                    if let Err(e) = slave_req_handler.handle_request() {
                        error!("Failed to handle vhost-user request: {:?}", e);
                        return true;
                    }
                }
            }
            _ => {
                error!("Unknown event for vhost-user");
                return true;
            }
        }

        false
    }
}
