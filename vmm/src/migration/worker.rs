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

use std::fmt::{self, Debug, Formatter};
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::{io, thread};

use anyhow::anyhow;
use event_monitor::event;
use log::warn;
use seccompiler::{BpfProgram, apply_filter};
use vm_migration::MigratableError;
use vmm_sys_util::eventfd::EventFd;

use crate::Vmm;
use crate::api::VmSendMigrationData;
use crate::vm::{Vm, VmState};

#[derive(thiserror::Error)]
#[error("Migration worker could not be spawned: {spawn_error}")]
pub struct MigrationWorkerSpawnError {
    pub spawn_error: io::Error,
    pub vm: Vm,
}

impl Debug for MigrationWorkerSpawnError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationWorkerSpawnError")
            .field("spawn_error", &self.spawn_error)
            .field("vm", &"<VM>")
            .finish()
    }
}

pub struct MigrationWorkerHandle {
    handle: Option<JoinHandle<MigrationWorkerResult>>,
}

impl MigrationWorkerHandle {
    pub fn join(mut self) -> MigrationWorkerResult {
        self.handle
            .take()
            .expect("should have thread")
            .join()
            .expect("should join migration worker gracefully")
    }
}

impl Drop for MigrationWorkerHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            warn!("Migration worker wasn't cleaned up explicitly via join()");
            handle.join().expect("should not be joined already");
        }
    }
}

#[derive(Clone, Debug)]
pub struct MigrationSeccompFilters {
    pub worker: BpfProgram,
    pub tcp_worker: BpfProgram,
    pub postcopy_server: BpfProgram,
}

pub struct MigrationWorker {
    // Keep the VM out of the thread closure until spawning succeeds.
    vm_receiver: Receiver<Vm>,
    check_migration_evt: EventFd,
    config: VmSendMigrationData,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    initial_vm_state: VmState,
    seccomp_filters: MigrationSeccompFilters,
}

impl MigrationWorker {
    /// Drives the migration from its start to its end (success, cancellation,
    /// failure)
    fn run(self) -> MigrationWorkerResult {
        let seccomp_res = if self.seccomp_filters.worker.is_empty() {
            Ok(())
        } else {
            apply_filter(&self.seccomp_filters.worker).map_err(|e| {
                MigratableError::MigrateSend(anyhow!(
                    "Error applying migration seccomp filter: {e}"
                ))
            })
        };

        let mut vm = self.vm_receiver.recv().expect("VMM should send VM");

        // We can't propagate errors early because of the complex return type,
        // therefore we chain the results together.
        let migration_result = seccomp_res
            .and_then(|()| {
                event!("vm", "migration-started");
                Vmm::send_migration(
                    &mut vm,
                    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
                    self.hypervisor.as_ref(),
                    &self.config,
                    self.initial_vm_state,
                    &self.seccomp_filters,
                )
            })
            .inspect(|_| event!("vm", "migration-finished"))
            .inspect_err(|_| event!("vm", "migration-failed"));

        // Notify VMM thread to check migration result.
        self.check_migration_evt.write(1).unwrap();

        MigrationWorkerResult {
            vm,
            migration_result,
            initial_vm_state: self.initial_vm_state,
            preserve_source: self.config.preserve_source,
        }
    }

    /// Spawns a worker to coordinate the migration.
    // All code paths need special care to prevent any panic and thus losing the
    // VM in case of failure.
    #[expect(clippy::result_large_err)]
    pub fn spawn(
        vm: Vm,
        check_migration_evt: EventFd,
        config: VmSendMigrationData,
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))] hypervisor: Arc<
            dyn hypervisor::Hypervisor,
        >,
        initial_vm_state: VmState,
        seccomp_filters: MigrationSeccompFilters,
    ) -> Result<MigrationWorkerHandle, MigrationWorkerSpawnError> {
        let (vm_sender, vm_receiver) = mpsc::sync_channel(0);
        let worker = MigrationWorker {
            vm_receiver,
            check_migration_evt,
            config,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            hypervisor,
            initial_vm_state,
            seccomp_filters,
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
pub struct MigrationWorkerResult {
    /// The VM that was migrated.
    ///
    /// If `migration_result` is `Ok`, the VM is paused and can be deleted
    /// unless `preserve_source` is true, which means the VM is given back
    /// to the VMM in a paused state.
    /// If `Err`, the VM can be resumed and given back to the VMM.
    pub vm: Vm,
    /// The result of [`Vmm::send_migration`].
    pub migration_result: Result<(), MigratableError>,
    pub initial_vm_state: VmState,
    pub preserve_source: bool,
}
