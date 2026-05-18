// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Asynchronous Migration Worker
//!
//! This module runs outgoing VM migration on a dedicated worker thread managing
//! the migration.
//!
//! The VMM starts a worker through [`MigrationWorker::spawn`], receives a
//! [`MigrationWorkerHandle`], and later joins it to recover the
//! [`MigrationThreadOut`]. The thread output contains the VM, the migration
//! result, and the migration configuration that was used.
//!
//! ## VM ownership
//!
//! The migration worker needs ownership of the [`Vm`] while migration is in
//! progress. While the thread holds the VM (and the VMM doesn't), lifecycle
//! events, such as adding a device, are not possible - this is intentional.
//!
//! However, spawning the worker thread can fail, for example because the host
//! cannot allocate another thread. In that case, the VM must be returned to
//! the VMM.
//!
//! To keep the VM recoverable, the worker thread is spawned without capturing
//! the VM directly. Once thread creation succeeds, the VM is transferred to the
//! worker through a zero-capacity channel. This channel acts as a rendezvous:
//! `spawn()` only returns after the worker has received the VM.
//!
//! If thread creation fails, the VM is still owned by the caller and is returned
//! in [`MigrationWorkerSpawnError`]. If it succeeds, migration continues
//! asynchronously on the worker thread.
//!
//! ## Completion & Migration Cleanup
//!
//! When migration finishes, fails, or is cancelled, the worker writes to the
//! migration eventfd. The VMM can then join the [`MigrationWorkerHandle`] and
//! inspect the returned [`MigrationThreadOut`].
//!
//! It is part of the VMM to clean up, e.g., resume a VM after a failed
//! migration.

use std::fmt::{Debug, Formatter};
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;

use event_monitor::event;
use log::{debug, error, warn};
use vm_migration::MigratableError;
use vmm_sys_util::eventfd::EventFd;

use crate::Vmm;
use crate::api::VmSendMigrationData;
use crate::vm::{Vm, VmState};

#[derive(thiserror::Error)]
#[error("Migration worker could not be spawned: {spawn_error}")]
pub struct MigrationWorkerSpawnError {
    pub spawn_error: std::io::Error,
    /// VM to return to the VMM.
    pub vm: Vm,
}

impl Debug for MigrationWorkerSpawnError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationWorkerSpawnError")
            .field("spawn_error", &self.spawn_error)
            .field("vm", &"<VM>")
            .finish()
    }
}

/// Handle to a [`MigrationWorker`] thread.
pub struct MigrationWorkerHandle {
    // Option to take the inner handle
    handle: Option<JoinHandle<MigrationThreadOut>>,
}

impl MigrationWorkerHandle {
    /// Joins the thread and returns the result.
    pub fn join(mut self) -> MigrationThreadOut {
        self.handle
            .take()
            .expect("should have thread")
            .join()
            .expect("should join migration thread gracefully")
    }
}

impl Drop for MigrationWorkerHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            warn!("Migration thread wasn't cleaned up explicitly via join()");
            handle.join().expect("should not be joined already");
        }
    }
}

/// Context of the thread controlling and performing the live migration.
pub struct MigrationWorker {
    /// Receiver used once after successfully spawning the thread to receive
    /// the VM.
    // We use this over directly owning the VM to avoid losing the VM when
    // spawning the thread fails.
    vm_receiver: Receiver<Vm>,
    check_migration_evt: EventFd,
    config: VmSendMigrationData,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    initial_vm_state: VmState,
}

impl MigrationWorker {
    /// Migration thread run logic.
    ///
    /// This drives a migration from its start either to its success,
    /// cancellation, or failure. In the end, it notifies the VMM's event loop
    /// to check the result.
    fn run(self) -> MigrationThreadOut {
        debug!("migration thread starting");
        let mut vm = self.vm_receiver.recv().expect("VMM should send VM");

        debug!("migration thread received VM from VMM");
        event!("vm", "migration-started");
        let res = Vmm::send_migration(
            &mut vm,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            self.hypervisor.as_ref(),
            &self.config,
        )
        .inspect(|_| event!("vm", "migration-finished"))
        .inspect_err(|e| {
            event!("vm", "migration-failed");
            error!("migrate error: {e}");
        });

        // Notify VMM thread to check migration result.
        self.check_migration_evt.write(1).unwrap();

        debug!("migration thread finished");
        MigrationThreadOut {
            vm,
            migration_res: res,
            initial_vm_state: self.initial_vm_state,
        }
    }

    /// Spawns a new worker and returns a handle to it.
    ///
    /// Makes sure that on error (e.g., VM thread can't be spawned because the
    /// system is OOM) the VM is handed safely back to the VMM.
    ///
    /// # Migration Cleanup
    ///
    /// Cleanup should be done by the VMM.
    ///
    /// See [module documentation](super::worker).
    #[expect(clippy::result_large_err)]
    // TODO seccomp?
    pub fn spawn(
        vm: Vm,
        check_migration_evt: EventFd,
        config: VmSendMigrationData,
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))] hypervisor: Arc<
            dyn hypervisor::Hypervisor,
        >,
        initial_vm_state: VmState,
    ) -> Result<MigrationWorkerHandle, MigrationWorkerSpawnError> {
        let (vm_sender, vm_receiver) = std::sync::mpsc::sync_channel(0);
        let worker = MigrationWorker {
            vm_receiver,
            check_migration_evt,
            config,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            hypervisor,
            initial_vm_state,
        };

        let inner_handle = match thread::Builder::new()
            .name("migration-worker".into())
            .spawn(move || worker.run())
        {
            Ok(inner_handle) => {
                // Transfer the VM to the spawned thread. This synchronizes the
                // VMM thread with the migration thread (rendevouz channel).
                // After that, the worker thread starts its async work. Panic is
                // unlikely as at this point the thread spawned and immediately
                // waits on the channel for the Vm.
                vm_sender
                    .send(vm)
                    .expect("thread should be waiting to receive VM");
                inner_handle
            }
            Err(e) => return Err(MigrationWorkerSpawnError { spawn_error: e, vm }),
        };

        Ok(MigrationWorkerHandle {
            handle: Some(inner_handle),
        })
    }
}

/// Return value of [`MigrationWorker`].
pub struct MigrationThreadOut {
    /// The VM that was migrated.
    ///
    /// If `migration_res` is `Ok`, the VM is paused and can be deleted.
    /// If `migration_res` is `Err`, the VM can be resumed and given back to
    /// the VMM.
    pub vm: Vm,
    /// The result of [`Vmm::send_migration`].
    pub migration_res: Result<(), MigratableError>,
    /// The initial VM state (paused or running).
    pub initial_vm_state: VmState,
}
