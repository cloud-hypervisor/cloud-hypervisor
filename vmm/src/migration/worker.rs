// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Asynchronous migration worker.
//!
//! The migration worker owns the [`Vm`] while migration is in progress, so the
//! VMM cannot run VM lifecycle operations concurrently. To keep the VM
//! recoverable when thread creation fails, [`MigrationWorker::spawn`] creates
//! the thread before transferring the VM through a zero-capacity
//! (rendezvous-channel). If spawning fails, the VM is returned to the caller in
//! [`MigrationWorkerSpawnError`].

use std::fmt::{Debug, Formatter};
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;

use event_monitor::event;
use log::warn;
use vm_migration::MigratableError;
use vmm_sys_util::eventfd::EventFd;

use crate::Vmm;
use crate::api::VmSendMigrationData;
use crate::vm::{Vm, VmState};

#[derive(thiserror::Error)]
#[error("Migration worker could not be spawned: {spawn_error}")]
pub struct MigrationWorkerSpawnError {
    pub spawn_error: std::io::Error,
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

pub struct MigrationWorkerHandle {
    handle: Option<JoinHandle<MigrationThreadOut>>,
}

impl MigrationWorkerHandle {
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

pub struct MigrationWorker {
    // Keep the VM out of the thread closure until spawning succeeds.
    vm_receiver: Receiver<Vm>,
    check_migration_evt: EventFd,
    config: VmSendMigrationData,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    initial_vm_state: VmState,
}

impl MigrationWorker {
    /// Drives the migration from its start to its end (success, cancellation,
    /// failure)
    fn run(self) -> MigrationThreadOut {
        let mut vm = self.vm_receiver.recv().expect("VMM should send VM");

        event!("vm", "migration-started");
        let res = Vmm::send_migration(
            &mut vm,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            self.hypervisor.as_ref(),
            &self.config,
            self.initial_vm_state,
        )
        .inspect(|_| event!("vm", "migration-finished"))
        .inspect_err(|_| event!("vm", "migration-failed"));

        // Notify VMM thread to check migration result.
        self.check_migration_evt.write(1).unwrap();

        MigrationThreadOut {
            vm,
            migration_res: res,
            initial_vm_state: self.initial_vm_state,
        }
    }

    /// Spawns a worker without losing VM ownership when thread creation fails.
    ///
    /// See [module documentation](super::worker).
    #[expect(clippy::result_large_err)]
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
                // The zero-capacity (rendezvous-channel) confirms the worker
                // has taken VM ownership.
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
    pub initial_vm_state: VmState,
}
