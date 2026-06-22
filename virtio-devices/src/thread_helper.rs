// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::thread::{self, JoinHandle};
use std::{panic, result};

use log::error;
use seccompiler::{SeccompAction, apply_filter};
use vmm_sys_util::eventfd::EventFd;

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::{ActivateError, VirtioInterrupt, mark_device_needs_reset};

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
