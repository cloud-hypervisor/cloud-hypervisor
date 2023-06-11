// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

static mut MONITOR: Option<Monitor> = None;

struct Monitor {
    broadcaster: Option<flume::Sender<String>>,
    file: Option<File>,
    start: Instant,
}

/// This function must only be called once from the main process before any threads
/// are created to avoid race conditions
pub fn set_monitor(
    file: Option<File>,
    broadcast: bool,
) -> Result<Option<flume::Receiver<String>>, std::io::Error> {
    // SAFETY: there is only one caller of this function, so MONITOR is written to only once
    assert!(unsafe { MONITOR.is_none() });

    // return early if we do not want to write
    // events to a file or broadcast them
    if file.is_none() && !broadcast {
        return Ok(None);
    }

    if let Some(ref file) = file {
        let fd = file.as_raw_fd();
        // SAFETY: FFI call to configure the fd
        let ret = unsafe {
            let mut flags = libc::fcntl(fd, libc::F_GETFL);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(fd, libc::F_SETFL, flags)
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // `event_monitor` uses an unbounded MPMC channel for event
    // publication. Despite being `unbounded`, the actual limitation is the
    // available memory. Since each subscriber must receive the message,
    // a value transmitted will not be dropped until all receivers have
    // acknowledged it. This could potentially use up a lot of memory
    // over time, so use this carefully.
    let (broadcast_tx, broadcast_rx) = broadcast
        .then(flume::unbounded)
        .map_or((None, None), |(tx, rx)| (Some(tx), Some(rx)));

    let monitor = Monitor {
        broadcaster: broadcast_tx,
        file,
        start: Instant::now(),
    };

    // SAFETY: MONITOR is None. Nobody else can hold a reference to it.
    unsafe {
        MONITOR = Some(monitor);
    };

    Ok(broadcast_rx)
}

#[derive(Serialize)]
struct Event<'a> {
    timestamp: Duration,
    source: &'a str,
    event: &'a str,
    properties: Option<&'a HashMap<Cow<'a, str>, Cow<'a, str>>>,
}

pub fn event_log(source: &str, event: &str, properties: Option<&HashMap<Cow<str>, Cow<str>>>) {
    // SAFETY: MONITOR is always in a valid state (None or Some).
    if let Some(monitor) = unsafe { MONITOR.as_ref() } {
        let e = Event {
            timestamp: monitor.start.elapsed(),
            source,
            event,
            properties,
        };

        if let Ok(event_json) = serde_json::to_string_pretty(&e) {
            if let Some(ref file) = monitor.file {
                let mut file = file;
                file.write_all(event_json.as_bytes()).ok();
                file.write_all(b"\n\n").ok();
            }

            if let Some(ref broadcaster) = monitor.broadcaster {
                broadcaster.send(event_json).ok();
            }
        }
    }
}

/*
    Through the use of Cow<'a, str> it is possible to use String as well as
    &str as the parameters:
    e.g.
    event!("cpu_manager", "create_vcpu", "id", cpu_id.to_string());
*/
#[macro_export]
macro_rules! event {
    ($source:expr, $event:expr) => {
        $crate::event_log($source, $event, None)
    };
    ($source:expr, $event:expr, $($key:expr, $value:expr),*) => {
        {
            let mut properties = ::std::collections::HashMap::new();
            $(
                properties.insert($key.into(), $value.into());
            )+
            $crate::event_log($source, $event, Some(&properties))
        }
     };

}
