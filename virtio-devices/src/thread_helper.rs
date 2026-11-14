// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::{io, panic, result};

use log::error;
use seccompiler::{SeccompAction, apply_filter};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::{ActivateError, VirtioInterrupt, mark_device_needs_reset};

#[derive(Default)]
struct PauseState {
    pause_requested: bool,
    active_threads: usize,
}

pub struct PauseCommon {
    state: Mutex<PauseState>,
    changed: Condvar,
    pause_evt: EventFd,
}

impl PauseCommon {
    pub fn new(pause_requested: bool) -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(PauseState {
                pause_requested,
                ..Default::default()
            }),
            changed: Condvar::new(),
            pause_evt: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    pub fn is_pause_requested(&self) -> bool {
        self.state.lock().unwrap().pause_requested
    }

    pub(crate) fn pause_evt(&self) -> &EventFd {
        &self.pause_evt
    }

    fn run<F, H>(self: &Arc<Self>, f: F, on_exit: H)
    where
        F: FnOnce(&Self) -> result::Result<(), EpollHelperError>,
        H: FnOnce(thread::Result<result::Result<(), EpollHelperError>>),
    {
        let mut active_thread_guard = None;
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            {
                let mut state = self.state.lock().unwrap();
                while state.pause_requested {
                    state = self.changed.wait(state).unwrap();
                }
                state.active_threads += 1;
                active_thread_guard = Some(ActiveThreadGuard {
                    pause_common: Arc::clone(self),
                });
            }
            f(self)
        }));
        on_exit(result);
    }

    pub(crate) fn pause(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.pause_requested = true;
        self.pause_evt.write(1)?;
        let _state = self
            .changed
            .wait_while(state, |state| state.active_threads != 0)
            .unwrap();
        self.pause_evt.read()?;
        Ok(())
    }

    pub(crate) fn resume(&self) {
        self.state.lock().unwrap().pause_requested = false;
        self.changed.notify_all();
    }

    pub(crate) fn reset(&self) {
        let _ = self.pause_evt.read();
        self.resume();
    }

    pub(crate) fn wait_if_paused(&self) {
        let mut state = self.state.lock().unwrap();
        if state.pause_requested {
            state.active_threads -= 1;
            self.changed.notify_all();
            while state.pause_requested {
                state = self.changed.wait(state).unwrap();
            }
            state.active_threads += 1;
        }
    }
}

struct ActiveThreadGuard {
    pause_common: Arc<PauseCommon>,
}

impl Drop for ActiveThreadGuard {
    fn drop(&mut self) {
        let mut state = self.pause_common.state.lock().unwrap();
        state.active_threads -= 1;
        self.pause_common.changed.notify_all();
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
    pause_common: Arc<PauseCommon>,
    f: F,
) -> Result<(), ActivateError>
where
    F: FnOnce(&PauseCommon) -> result::Result<(), EpollHelperError>,
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
            pause_common.run(f, |result| match result {
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
            });
        })
        .map(|thread| epoll_threads.push(thread))
        .map_err(|e| {
            error!("Failed to spawn thread for {name}: {e}");
            ActivateError::ThreadSpawn(e)
        })
}
