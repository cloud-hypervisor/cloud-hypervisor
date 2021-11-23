// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use vmm_sys_util::eventfd::EventFd;

pub struct EpollHelper {
    pause_evt: EventFd,
    epoll_file: File,
}

#[derive(Debug)]
pub enum EpollHelperError {
    CreateFd(std::io::Error),
    Ctl(std::io::Error),
    IoError(std::io::Error),
    Wait(std::io::Error),
    QueueRingIndex(virtio_queue::Error),
}

pub const EPOLL_HELPER_EVENT_PAUSE: u16 = 0;
pub const EPOLL_HELPER_EVENT_KILL: u16 = 1;
pub const EPOLL_HELPER_EVENT_LAST: u16 = 15;

pub trait EpollHelperHandler {
    // Return true if the loop execution should be stopped
    fn handle_event(&mut self, helper: &mut EpollHelper, event: &epoll::Event) -> bool;
}

impl EpollHelper {
    pub fn new(
        kill_evt: &EventFd,
        pause_evt: &EventFd,
    ) -> std::result::Result<Self, EpollHelperError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(EpollHelperError::CreateFd)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let mut helper = Self {
            pause_evt: pause_evt.try_clone().unwrap(),
            epoll_file,
        };

        helper.add_event(kill_evt.as_raw_fd(), EPOLL_HELPER_EVENT_KILL)?;
        helper.add_event(pause_evt.as_raw_fd(), EPOLL_HELPER_EVENT_PAUSE)?;
        Ok(helper)
    }

    pub fn add_event(&mut self, fd: RawFd, id: u16) -> std::result::Result<(), EpollHelperError> {
        self.add_event_custom(fd, id, epoll::Events::EPOLLIN)
    }

    pub fn add_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> std::result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn del_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> std::result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
        handler: &mut dyn EpollHelperHandler,
    ) -> std::result::Result<(), EpollHelperError> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        // Before jumping into the epoll loop, check if the device is expected
        // to be in a paused state. This is helpful for the restore code path
        // as the device thread should not start processing anything before the
        // device has been resumed.
        while paused.load(Ordering::SeqCst) {
            thread::park();
        }

        loop {
            let num_events = match epoll::wait(self.epoll_file.as_raw_fd(), -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(EpollHelperError::Wait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    EPOLL_HELPER_EVENT_KILL => {
                        info!("KILL_EVENT received, stopping epoll loop");
                        return Ok(());
                    }
                    EPOLL_HELPER_EVENT_PAUSE => {
                        info!("PAUSE_EVENT received, pausing epoll loop");

                        // Acknowledge the pause is effective by using the
                        // paused_sync barrier.
                        paused_sync.wait();

                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }

                        // Drain pause event after the device has been resumed.
                        // This ensures the pause event has been seen by each
                        // thread related to this virtio device.
                        let _ = self.pause_evt.read();
                    }
                    _ => {
                        if handler.handle_event(self, event) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

impl AsRawFd for EpollHelper {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}
