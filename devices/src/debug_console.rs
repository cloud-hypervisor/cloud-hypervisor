// Copyright © 2023 Cyberus Technology
//
// SPDX-License-Identifier: Apache-2.0
//

//! Module for [`DebugconState`].

use std::io;
use std::io::Write;
use std::sync::{Arc, Barrier};

use vm_device::BusDevice;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

/// I/O-port.
pub const DEFAULT_PORT: u64 = 0xe9;

#[derive(Default)]
pub struct DebugconState {}

/// Emulates a debug console similar to the QEMU debugcon device. This device
/// is stateless and only prints the bytes (usually text) that are written to
/// it.
///
/// This device is only available on x86.
///
/// Reference:
/// - https://github.com/qemu/qemu/blob/master/hw/char/debugcon.c
/// - https://phip1611.de/blog/how-to-use-qemus-debugcon-feature-and-write-to-a-file/
pub struct DebugConsole {
    id: String,
    out: Box<dyn io::Write + Send>,
}

impl DebugConsole {
    pub fn new(id: String, out: Box<dyn io::Write + Send>) -> Self {
        Self { id, out }
    }
}

impl BusDevice for DebugConsole {
    fn read(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {}

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if let Err(e) = self.out.write_all(data) {
            // unlikely
            error!("debug-console: failed writing data: {e:?}");
        }
        None
    }
}

impl Snapshottable for DebugConsole {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&())
    }
}

impl Pausable for DebugConsole {}
impl Transportable for DebugConsole {}
impl Migratable for DebugConsole {}
