// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::super::{Queue, VirtioInterruptType};
use super::{Error, Result};
use epoll;
use vmm_sys_util::eventfd::EventFd;

use crate::VirtioInterrupt;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

/// Collection of common parameters required by vhost-user devices while
/// call Epoll handler.
///
/// # Arguments
/// * `interrupt_cb` interrupt for virtqueue change.
/// * `kill_evt` - EventFd used to kill the vhost-user device.
/// * `vu_interrupt_list` - virtqueue and EventFd to signal when buffer used.
pub struct VhostUserEpollConfig {
    pub interrupt_cb: Arc<VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub vu_interrupt_list: Vec<(EventFd, Queue)>,
}

pub struct VhostUserEpollHandler {
    pub vu_epoll_cfg: VhostUserEpollConfig,
}

impl VhostUserEpollHandler {
    /// Construct a new event handler for vhost-user based devices.
    ///
    /// # Arguments
    /// * `vu_epoll_cfg` - collection of common parameters for vhost-user devices
    ///
    /// # Return
    /// * `VhostUserEpollHandler` - epoll handler for vhost-user based devices
    pub fn new(vu_epoll_cfg: VhostUserEpollConfig) -> VhostUserEpollHandler {
        VhostUserEpollHandler { vu_epoll_cfg }
    }

    fn signal_used_queue(&self, queue: &Queue) -> Result<()> {
        (self.vu_epoll_cfg.interrupt_cb)(&VirtioInterruptType::Queue, Some(queue))
            .map_err(Error::FailedSignalingUsedQueue)?;
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let epoll_fd = epoll::create(true).map_err(Error::EpollCreateFd)?;

        for (index, vhost_user_interrupt) in self.vu_epoll_cfg.vu_interrupt_list.iter().enumerate()
        {
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                vhost_user_interrupt.0.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, index as u64),
            )
            .map_err(Error::EpollCtl)?;
        }

        let kill_evt_index = self.vu_epoll_cfg.vu_interrupt_list.len();

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.vu_epoll_cfg.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, kill_evt_index as u64),
        )
        .map_err(Error::EpollCtl)?;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); kill_evt_index + 1];

        'poll: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(Error::EpollWait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as usize;

                match ev_type {
                    x if x < kill_evt_index => {
                        let vhost_user_interrupt = &self.vu_epoll_cfg.vu_interrupt_list[x].0;
                        vhost_user_interrupt
                            .read()
                            .map_err(Error::FailedReadingQueue)?;
                        let result =
                            self.signal_used_queue(&self.vu_epoll_cfg.vu_interrupt_list[x].1);
                        if let Err(_e) = result {
                            error!("failed to signal used queue");
                        }
                    }
                    x if kill_evt_index == x => {
                        break 'poll;
                    }
                    _ => {
                        error!("Unknown event for vhost-user-net");
                    }
                }
            }
        }
        Ok(())
    }
}
