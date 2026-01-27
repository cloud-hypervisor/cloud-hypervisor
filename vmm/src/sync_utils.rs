// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{Condvar, Mutex};

/// A single use abortable gate. The main thread will create the gate and pass
/// it to the memory sending threads. The main thread can always open the gate.
/// That way the main thread can also open the gate before all workers arrive
/// there, e.g. if one worker signals that an error occurred and thus cannot
/// continue.
#[derive(Debug)]
pub struct Gate {
    /// True if the gate is open, false otherwise.
    open: Mutex<bool>,
    /// Used to notify waiting threads.
    cv: Condvar,
}

impl Gate {
    pub fn new() -> Self {
        Self {
            open: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    /// Wait at the gate. Only blocks if the gate is not opened.
    pub fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.cv.wait(open).unwrap();
        }
    }

    /// Open the gate, releasing all waiting threads.
    pub fn open(&self) {
        let mut open = self.open.lock().unwrap();
        *open = true;
        self.cv.notify_all();
    }
}
