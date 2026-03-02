// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! # Infrastructure for Migration Cancellation
//!
//! Cancellation is coordinated between the VMM thread and the migration worker.
//!
//! Migrations can be canceled as long as the VM wasn't moved to the destination
//! and also only if a cancellation request doesn't race with the final steps of
//! moving a VM to the destination.
//!
//! Migrations are actually canceled by checking a flag in selected code paths
//! exercised by the migration worker as a migration naturally progresses. Once
//! a cancellation request is seen, the migration worker will fail with
//! [`MigratableError::Canceled`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::info;
use vm_migration::MigratableError;
use vm_migration::protocol::Request;

use crate::migration::transport::SocketStream;

/// Cancellation context for the VMM side enabling cancellation of a migration.
///
/// Counterpart to [`CancelContextMigration`].
///
/// Notifies migration code about a cancellation and checks if the cancellation
/// was acknowledges.
pub struct CancelContextVmm {
    cancel: Arc<AtomicBool>,
    // In future we might add a "cancellation acknowledged?" mechanism. So far,
    // we rely on external visibility to handle this on the management layer.
}

impl CancelContextVmm {
    /// Tries to cancel the migration.
    pub fn try_cancel_migration(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

/// Cancellation context for the migration worker.
///
/// Counterpart to [`CancelContextVmm`].
///
/// Allows migration code to check whether cancellation was requested and to
/// acknowledge that cancellation has been observed.
pub struct CancelContextMigration {
    cancel: Arc<AtomicBool>,
}

impl CancelContextMigration {
    /// Returns [`MigratableError::Canceled`] if there is a pending cancellation
    /// and notifies the remote via a [`Request::abandon`] request.
    /// No-op otherwise.
    pub fn ok_or_cancelled(&self, socket: &mut SocketStream) -> Result<(), MigratableError> {
        if self.cancel.load(Ordering::Acquire) {
            info!("Cancelling migration now");
            Request::abandon().write_to(socket)?;
            Err(MigratableError::Canceled)
        } else {
            Ok(())
        }
    }
}

pub fn new_cancel_context() -> (CancelContextVmm, CancelContextMigration) {
    let cancel = Arc::new(AtomicBool::new(false));

    let ctx_vmm = CancelContextVmm {
        cancel: cancel.clone(),
    };
    let ctx_migration = CancelContextMigration { cancel };
    (ctx_vmm, ctx_migration)
}
