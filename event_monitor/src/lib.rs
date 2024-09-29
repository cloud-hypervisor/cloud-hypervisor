// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::OnceCell;
use serde::Serialize;

static MONITOR: OnceCell<MonitorHandle> = OnceCell::new();

#[derive(Serialize)]
struct Event<'a> {
    timestamp: Duration,
    source: &'a str,
    event: &'a str,
    properties: Option<&'a HashMap<Cow<'a, str>, Cow<'a, str>>>,
}

pub struct Monitor {
    pub rx: flume::Receiver<String>,
    pub file: Option<File>,
    pub broadcast: Vec<flume::Sender<Arc<String>>>,
}

impl Monitor {
    pub fn new(rx: flume::Receiver<String>, file: Option<File>) -> Self {
        Self {
            rx,
            file,
            broadcast: vec![],
        }
    }

    pub fn subscribe(&mut self) -> flume::Receiver<Arc<String>> {
        let (tx, rx) = flume::unbounded();
        self.broadcast.push(tx);
        rx
    }
}

struct MonitorHandle {
    tx: flume::Sender<String>,
    start: Instant,
}

fn set_file_nonblocking(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();

    // SAFETY: FFI call to configure the fd
    let ret = unsafe {
        let mut flags = libc::fcntl(fd, libc::F_GETFL);
        flags |= libc::O_NONBLOCK;
        libc::fcntl(fd, libc::F_SETFL, flags)
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// This function must only be called once from the main thread before any threads
/// are created to avoid race conditions.
pub fn set_monitor(file: Option<File>) -> io::Result<Monitor> {
    // There is only one caller of this function, so MONITOR is written to only once
    assert!(MONITOR.get().is_none());

    if let Some(ref file) = file {
        set_file_nonblocking(file)?;
    }

    let (tx, rx) = flume::unbounded();
    let monitor = Monitor::new(rx, file);

    MONITOR.get_or_init(|| MonitorHandle {
        tx,
        start: Instant::now(),
    });

    Ok(monitor)
}

pub fn event_log(source: &str, event: &str, properties: Option<&HashMap<Cow<str>, Cow<str>>>) {
    // `MONITOR` is always in a valid state (None or Some), because it is set
    // only once before any threads are spawned, and it's not mutated
    // afterwards. This function only creates immutable references to `MONITOR`.
    // Because `MONITOR.tx` is `Sync`, it's safe to share `MONITOR` across
    // threads, making this function thread-safe.
    if let Some(monitor_handle) = MONITOR.get().as_ref() {
        let event = Event {
            timestamp: monitor_handle.start.elapsed(),
            source,
            event,
            properties,
        };

        if let Ok(event) = serde_json::to_string_pretty(&event) {
            monitor_handle.tx.send(event).ok();
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
