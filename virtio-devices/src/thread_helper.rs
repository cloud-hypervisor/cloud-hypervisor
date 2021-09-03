// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    seccomp_filters::{get_seccomp_filter, Thread},
    ActivateError,
};
use seccompiler::{apply_filter, SeccompAction};
use std::thread::{self, JoinHandle};

pub(crate) fn spawn_virtio_thread<F>(
    name: &str,
    seccomp_action: &SeccompAction,
    thread_type: Thread,
    epoll_threads: &mut Vec<JoinHandle<()>>,
    f: F,
) -> Result<(), ActivateError>
where
    F: FnOnce(),
    F: Send + 'static,
{
    let seccomp_filter = get_seccomp_filter(seccomp_action, thread_type)
        .map_err(ActivateError::CreateSeccompFilter)?;

    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            if !seccomp_filter.is_empty() {
                if let Err(e) = apply_filter(&seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                    return;
                }
            }
            f()
        })
        .map(|thread| epoll_threads.push(thread))
        .map_err(|e| {
            error!("Failed to spawn thread for {}: {}", name, e);
            ActivateError::BadActivate
        })
}
