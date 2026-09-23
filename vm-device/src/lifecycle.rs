// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Reboot and shutdown requests that originate inside the VM.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use log::info;
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum PendingVmAction {
    Reboot,
    Shutdown,
}

/// Signals guest reboot and shutdown requests to the VMM, or records them
/// for the migration worker while the VM is being migrated.
pub struct GuestLifecycle {
    migrating: AtomicBool,
    pending: Mutex<Option<PendingVmAction>>,
    reset_evt: EventFd,
    guest_exit_evt: EventFd,
}

impl GuestLifecycle {
    pub fn new(reset_evt: EventFd, guest_exit_evt: EventFd) -> Self {
        Self {
            migrating: AtomicBool::new(false),
            pending: Mutex::new(None),
            reset_evt,
            guest_exit_evt,
        }
    }

    /// Must be called before the requesting thread waits for the vCPUs to be killed.
    pub fn request(&self, action: PendingVmAction) -> io::Result<()> {
        if self.migrating.load(Ordering::Acquire) {
            info!("Deferring pending VM {action:?} until migration finishes");
            self.record(action);
            return Ok(());
        }
        match action {
            PendingVmAction::Reboot => self.reset_evt.write(1),
            PendingVmAction::Shutdown => self.guest_exit_evt.write(1),
        }
    }

    pub fn record(&self, action: PendingVmAction) {
        *self.pending.lock().unwrap() = Some(action);
    }

    // Record guest's reboot and shutdown instead of signaling the VMM.
    pub fn set_migrating(&self, migrating: bool) {
        self.migrating.store(migrating, Ordering::Release);
    }

    pub fn pending(&self) -> Option<PendingVmAction> {
        *self.pending.lock().unwrap()
    }
}
