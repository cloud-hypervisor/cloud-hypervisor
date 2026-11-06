// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::{panic, result};

use log::error;
use seccompiler::{SeccompAction, apply_filter};
use vmm_sys_util::eventfd::EventFd;

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::{ActivateError, VirtioInterrupt, mark_device_needs_reset};

#[derive(Default)]
struct PauseState {
    paused: bool,
    active_workers: usize,
}

#[derive(Default)]
pub struct PauseControl {
    state: Mutex<PauseState>,
    changed: Condvar,
}

#[expect(dead_code)]
impl PauseControl {
    pub fn new(paused: bool) -> Self {
        Self {
            state: Mutex::new(PauseState {
                paused,
                ..Default::default()
            }),
            changed: Condvar::new(),
        }
    }

    pub fn is_paused(&self) -> bool {
        self.state.lock().unwrap().paused
    }

    fn activate_worker(self: &Arc<Self>) -> ActiveWorker {
        let mut state = self.state.lock().unwrap();
        while state.paused {
            state = self.changed.wait(state).unwrap();
        }
        state.active_workers += 1;
        ActiveWorker {
            pause_control: Arc::clone(self),
        }
    }

    pub(crate) fn pause(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused = true;
        while state.active_workers != 0 {
            state = self.changed.wait(state).unwrap();
        }
    }

    pub(crate) fn resume(&self) {
        self.state.lock().unwrap().paused = false;
        self.changed.notify_all();
    }

    pub(crate) fn wait_if_paused(&self) {
        let mut state = self.state.lock().unwrap();
        if state.paused {
            state.active_workers -= 1;
            self.changed.notify_all();
            while state.paused {
                state = self.changed.wait(state).unwrap();
            }
            state.active_workers += 1;
        }
    }
}

struct ActiveWorker {
    pause_control: Arc<PauseControl>,
}

impl Drop for ActiveWorker {
    fn drop(&mut self) {
        let mut state = self.pause_control.state.lock().unwrap();
        state.active_workers -= 1;
        self.pause_control.changed.notify_all();
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn spawn_virtio_thread<F>(
    name: &str,
    seccomp_action: &SeccompAction,
    thread_type: Thread,
    epoll_threads: &mut Vec<JoinHandle<()>>,
    exit_evt: &EventFd,
    device_status: Arc<AtomicU8>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    f: F,
) -> Result<(), ActivateError>
where
    F: FnOnce() -> result::Result<(), EpollHelperError>,
    F: Send + 'static,
{
    let seccomp_filter = get_seccomp_filter(seccomp_action, thread_type)
        .map_err(ActivateError::CreateSeccompFilter)?;

    let thread_exit_evt = exit_evt.try_clone().map_err(ActivateError::CloneEventFd)?;
    let thread_name = name.to_string();

    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            if !seccomp_filter.is_empty()
                && let Err(e) = apply_filter(&seccomp_filter)
            {
                error!("Error applying seccomp filter: {e:?}");
                thread_exit_evt.write(1).ok();
                return;
            }
            match panic::catch_unwind(AssertUnwindSafe(f)) {
                Err(_) => {
                    error!("{thread_name} thread panicked");
                    thread_exit_evt.write(1).ok();
                }
                Ok(Err(e)) => {
                    mark_device_needs_reset(
                        &device_status,
                        interrupt_cb.as_ref(),
                        format_args!("{thread_name}: worker exited with error: {e:?}"),
                    );
                }
                Ok(Ok(())) => {}
            }
        })
        .map(|thread| epoll_threads.push(thread))
        .map_err(|e| {
            error!("Failed to spawn thread for {name}: {e}");
            ActivateError::ThreadSpawn(e)
        })
}
