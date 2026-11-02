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
#[cfg(not(fuzzing))]
use std::hint::spin_loop;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
#[cfg(not(fuzzing))]
use std::sync::TryLockError;
use std::sync::{Barrier, Mutex};
use std::{io, result, thread};

use log::debug;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

pub struct EpollHelper {
    pause_evt: EventFd,
    epoll_file: File,
}

#[derive(Error, Debug)]
pub enum EpollHelperError {
    #[error("Failed to create Fd")]
    CreateFd(#[source] io::Error),
    #[error("Failed to epoll_ctl")]
    Ctl(#[source] io::Error),
    #[error("IO error")]
    IoError(#[source] io::Error),
    #[error("Failed to epoll_wait")]
    Wait(#[source] io::Error),
    #[error("Failed to get virtio-queue index")]
    QueueRingIndex(#[source] virtio_queue::Error),
    #[error("Failed to handle virtio device events")]
    HandleEvent(#[source] anyhow::Error),
    #[error("Failed to handle timeout")]
    HandleTimeout(#[source] anyhow::Error),
}

pub const EPOLL_HELPER_EVENT_PAUSE: u16 = 0;
pub const EPOLL_HELPER_EVENT_KILL: u16 = 1;
pub const EPOLL_HELPER_EVENT_LAST: u16 = 15;

pub trait EpollHelperHandler {
    // Handle one event at a time. The EpollHelper iterates over a list of
    // events that have been returned by epoll_wait(). For each event, the
    // current method is invoked to let the implementation decide how to process
    // the incoming event.
    fn handle_event(
        &mut self,
        helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> Result<(), EpollHelperError>;

    // This method is only invoked if the EpollHelper was configured to call
    // epoll_wait() with a valid timeout (different from -1), meaning the call
    // won't block forever. When the timeout is reached, and if no even has been
    // triggered, this function will be called to let the implementation decide
    // how to interpret such situation. By default, it provides a no-op
    // implementation.
    fn handle_timeout(&mut self, _helper: &mut EpollHelper) -> Result<(), EpollHelperError> {
        Ok(())
    }

    // In some situations, it might be useful to know the full list of events
    // triggered while waiting on epoll_wait(). And having this list provided
    // prior to the iterations over each event might help make some informed
    // decisions. This function should not replace handle_event(), otherwise it
    // would completely defeat the purpose of having the loop being factorized
    // through the EpollHelper structure.
    fn event_list(
        &mut self,
        _helper: &mut EpollHelper,
        _events: &[epoll::Event],
    ) -> Result<(), EpollHelperError> {
        Ok(())
    }
}

impl EpollHelper {
    pub fn new(kill_evt: &EventFd, pause_evt: &EventFd) -> result::Result<Self, EpollHelperError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(EpollHelperError::CreateFd)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: epoll_fd is a valid fd
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let mut helper = Self {
            pause_evt: pause_evt.try_clone().unwrap(),
            epoll_file,
        };

        helper.add_event(kill_evt.as_raw_fd(), EPOLL_HELPER_EVENT_KILL)?;
        helper.add_event(pause_evt.as_raw_fd(), EPOLL_HELPER_EVENT_PAUSE)?;
        Ok(helper)
    }

    pub fn add_event(&mut self, fd: RawFd, id: u16) -> result::Result<(), EpollHelperError> {
        self.add_event_custom(fd, id, epoll::Events::EPOLLIN)
    }

    pub fn add_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn mod_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_MOD,
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
    ) -> result::Result<(), EpollHelperError> {
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
        paused: &Mutex<bool>,
        paused_sync: &Barrier,
        handler: &mut dyn EpollHelperHandler,
    ) -> result::Result<(), EpollHelperError> {
        self.run_with_timeout(paused, paused_sync, handler, -1, false)
    }

    #[cfg(not(fuzzing))]
    pub fn run_with_timeout(
        &mut self,
        paused: &Mutex<bool>,
        paused_sync: &Barrier,
        handler: &mut dyn EpollHelperHandler,
        timeout: i32,
        enable_event_list: bool,
    ) -> result::Result<(), EpollHelperError> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        // Before jumping into the epoll loop, check if the device is expected
        // to be in a paused state. This is helpful for the restore code path
        // as the device thread should not start processing anything before the
        // device has been resumed.
        let mut acked = false;
        let paused_guard = loop {
            match paused.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    if acked {
                        spin_loop();
                    } else {
                        // Only pause() holds this lock across a barrier wait;
                        // spawn_worker() does not hold it while starting a thread.
                        acked = true;
                        paused_sync.wait();
                    }
                }
                Err(TryLockError::Poisoned(e)) => break e.into_inner(),
            }
        };
        let initially_paused = *paused_guard;
        drop(paused_guard);
        if initially_paused {
            // Consume the pause event paired with the barrier above.
            let _ = self.pause_evt.read();
            loop {
                let guard = paused.lock().unwrap();
                if !*guard {
                    break;
                }
                drop(guard);
                thread::park();
            }
        }

        loop {
            let num_events =
                match epoll::wait(self.epoll_file.as_raw_fd(), timeout, &mut events[..]) {
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
                        return Err(EpollHelperError::Wait(e));
                    }
                };

            if num_events == 0 {
                // This case happens when the timeout is reached before any of
                // the registered events is triggered.
                handler.handle_timeout(self)?;
                continue;
            }

            if enable_event_list {
                handler.event_list(self, &events[..num_events])?;
            }

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    EPOLL_HELPER_EVENT_KILL => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        return Ok(());
                    }
                    EPOLL_HELPER_EVENT_PAUSE => {
                        debug!("PAUSE_EVENT received, pausing epoll loop");

                        paused_sync.wait();

                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        loop {
                            let guard = paused.lock().unwrap();
                            if !*guard {
                                break;
                            }
                            drop(guard);
                            thread::park();
                        }

                        // Drain pause event after the device has been resumed.
                        // This ensures the pause event has been seen by each
                        // thread related to this virtio device.
                        let _ = self.pause_evt.read();
                    }
                    _ => {
                        handler.handle_event(self, event)?;
                    }
                }
            }
        }
    }

    #[cfg(fuzzing)]
    // Require to have a 'queue_evt' being kicked before calling
    // and return when no epoll events are active
    pub fn run_with_timeout(
        &mut self,
        paused: &Mutex<bool>,
        paused_sync: &Barrier,
        handler: &mut dyn EpollHelperHandler,
        _timeout: i32,
        _enable_event_list: bool,
    ) -> result::Result<(), EpollHelperError> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        loop {
            let num_events = match epoll::wait(self.epoll_file.as_raw_fd(), 0, &mut events[..]) {
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
                    return Err(EpollHelperError::Wait(e));
                }
            };

            // Return when no epoll events are active
            if num_events == 0 {
                return Ok(());
            }

            // Unlike the regular loop, do not return as soon as the kill
            // event is seen: the fuzz targets drop the device (and thus
            // write the kill event) right after kicking the queue, so the
            // kill event is typically ready in the very same batch as the
            // queue event. Returning immediately would race the queue event
            // away and leave the device handler unexercised. Drain the whole
            // batch first, then stop.
            let mut killed = false;

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    EPOLL_HELPER_EVENT_KILL => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        killed = true;
                    }
                    EPOLL_HELPER_EVENT_PAUSE => {
                        debug!("PAUSE_EVENT received, pausing epoll loop");

                        paused_sync.wait();

                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        loop {
                            let guard = paused.lock().unwrap();
                            if !*guard {
                                break;
                            }
                            drop(guard);
                            thread::park();
                        }

                        // Drain pause event after the device has been resumed.
                        // This ensures the pause event has been seen by each
                        // thread related to this virtio device.
                        let _ = self.pause_evt.read();
                    }
                    _ => {
                        handler.handle_event(self, event)?;
                    }
                }
            }

            if killed {
                return Ok(());
            }
        }
    }
}

impl AsRawFd for EpollHelper {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

    use super::*;

    struct Dummy;

    impl EpollHelperHandler for Dummy {
        fn handle_event(
            &mut self,
            _helper: &mut EpollHelper,
            _event: &epoll::Event,
        ) -> Result<(), EpollHelperError> {
            Ok(())
        }
    }

    fn spawn_worker(
        paused: &Arc<Mutex<bool>>,
        pause_evt: &EventFd,
        kill_evt: &EventFd,
        barrier: Arc<Barrier>,
        finished: Option<Arc<AtomicBool>>,
    ) -> thread::JoinHandle<()> {
        let paused_worker = Arc::clone(paused);
        let pause_worker = pause_evt.try_clone().unwrap();
        let kill_worker = kill_evt.try_clone().unwrap();
        thread::spawn(move || {
            let mut helper = EpollHelper::new(&kill_worker, &pause_worker).unwrap();
            helper.run(&paused_worker, &barrier, &mut Dummy).unwrap();
            if let Some(finished) = finished {
                finished.store(true, Ordering::SeqCst);
            }
        })
    }

    fn stop_workers(
        paused: &Arc<Mutex<bool>>,
        kill_evt: &EventFd,
        workers: Vec<thread::JoinHandle<()>>,
    ) {
        *paused.lock().unwrap() = false;
        for worker in &workers {
            worker.thread().unpark();
        }
        kill_evt.write(1).unwrap();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn paused_start_parks_until_resume() {
        let paused = Arc::new(Mutex::new(true));
        let pause_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let kill_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let finished = Arc::new(AtomicBool::new(false));
        let worker = spawn_worker(
            &paused,
            &pause_evt,
            &kill_evt,
            Arc::clone(&barrier),
            Some(Arc::clone(&finished)),
        );

        thread::sleep(Duration::from_millis(100));
        assert!(!finished.load(Ordering::SeqCst));
        stop_workers(&paused, &kill_evt, vec![worker]);
    }

    #[test]
    fn pause_while_workers_start_acknowledges_barrier() {
        let paused = Arc::new(Mutex::new(false));
        let pause_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let kill_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let (locked_tx, locked_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let pause_paused = Arc::clone(&paused);
        let pause_evt_pause = pause_evt.try_clone().unwrap();
        let pause_barrier = Arc::clone(&barrier);
        let pause = thread::spawn(move || {
            let guard = {
                let mut guard = pause_paused.lock().unwrap();
                *guard = true;
                guard
            };
            locked_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            pause_evt_pause.write(1).unwrap();
            pause_barrier.wait();
            drop(guard);
            done_tx.send(()).unwrap();
        });

        locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let workers = (0..2)
            .map(|_| spawn_worker(&paused, &pause_evt, &kill_evt, Arc::clone(&barrier), None))
            .collect::<Vec<_>>();
        go_tx.send(()).unwrap();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("starting workers did not acknowledge the barrier");

        stop_workers(&paused, &kill_evt, workers);
        pause.join().unwrap();
    }
}
