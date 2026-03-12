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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::Gate;

    #[test]
    fn gate_blocks_until_open() {
        let gate = Arc::new(Gate::new());
        let (tx, rx) = mpsc::channel();

        let gate_clone = gate.clone();
        thread::spawn(move || {
            gate_clone.wait();
            tx.send(()).unwrap();
        });

        // Give the thread time to block.
        thread::sleep(Duration::from_millis(50));
        assert!(rx.try_recv().is_err());

        gate.open();
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn gate_open_before_wait_is_non_blocking() {
        let gate = Arc::new(Gate::new());
        gate.open();

        let (tx, rx) = mpsc::channel();
        let gate_clone = gate.clone();
        thread::spawn(move || {
            gate_clone.wait();
            tx.send(()).unwrap();
        });

        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn gate_releases_multiple_waiters() {
        let gate = Arc::new(Gate::new());
        let (tx, rx) = mpsc::channel();

        for _ in 0..4 {
            let gate_clone = gate.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                gate_clone.wait();
                tx.send(()).unwrap();
            });
        }

        // Ensure nobody passed before open.
        thread::sleep(Duration::from_millis(50));
        assert!(rx.try_recv().is_err());

        gate.open();

        for _ in 0..4 {
            rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
    }

    #[test]
    fn gate_open_is_idempotent() {
        let gate = Arc::new(Gate::new());
        gate.open();
        gate.open();

        let (tx, rx) = mpsc::channel();
        let gate_clone = gate.clone();
        thread::spawn(move || {
            gate_clone.wait();
            tx.send(()).unwrap();
        });

        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
