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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
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
        VhostUserEpollHandler { vu_epoll_cfg }
    }

    fn signal_used_queue(&self, queue: &Queue) -> Result<()> {
        self.vu_epoll_cfg
            .interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(queue))
            .map_err(Error::FailedSignalingUsedQueue)
    }

    pub fn run(&mut self, paused: Arc<AtomicBool>) -> Result<()> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(Error::EpollCreateFd)?;

        for (index, vhost_user_interrupt) in self.vu_epoll_cfg.vu_interrupt_list.iter().enumerate()
        {
            if let Some(eventfd) = &vhost_user_interrupt.0 {
                // Add events
                epoll::ctl(
                    epoll_fd,
                    epoll::ControlOptions::EPOLL_CTL_ADD,
                    eventfd.as_raw_fd(),
                    epoll::Event::new(epoll::Events::EPOLLIN, index as u64),
                )
                .map_err(Error::EpollCtl)?;
            }
        }

        let kill_evt_index = self.vu_epoll_cfg.vu_interrupt_list.len();

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.vu_epoll_cfg.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, kill_evt_index as u64),
        )
        .map_err(Error::EpollCtl)?;

        let pause_evt_index = kill_evt_index + 1;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.vu_epoll_cfg.pause_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, pause_evt_index as u64),
        )
        .map_err(Error::EpollCtl)?;

        let mut index = pause_evt_index;

        let slave_evt_index = if let Some(self_req_handler) = &self.vu_epoll_cfg.slave_req_handler {
            index = pause_evt_index + 1;
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                self_req_handler.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, index as u64),
            )
            .map_err(Error::EpollCtl)?;

            Some(index)
        } else {
            None
        };

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); index + 1];

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
                        if let Some(eventfd) = &self.vu_epoll_cfg.vu_interrupt_list[x].0 {
                            eventfd.read().map_err(Error::FailedReadingQueue)?;
                            if let Err(e) =
                                self.signal_used_queue(&self.vu_epoll_cfg.vu_interrupt_list[x].1)
                            {
                                error!("Failed to signal used queue: {:?}", e);
                                break 'poll;
                            }
                        }
                    }
                    x if kill_evt_index == x => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'poll;
                    }
                    x if pause_evt_index == x => {
                        debug!("PAUSE_EVENT received, pausing vhost-user epoll loop");
                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }
                    }
                    x if (slave_evt_index.is_some() && slave_evt_index.unwrap() == x) => {
                        if let Some(slave_req_handler) =
                            self.vu_epoll_cfg.slave_req_handler.as_mut()
                        {
                            slave_req_handler
                                .handle_request()
                                .map_err(Error::VhostUserSlaveRequest)?;
                        }
                    }
                    _ => {
                        error!("Unknown event for vhost-user");
                    }
                }
            }
        }
        Ok(())
    }
}
