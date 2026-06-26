// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

//! # Infrastructure for Migration Cancellation
//!
//! Cancellation is coordinated between the VMM thread and the migration worker
//! at explicit checkpoints rather than through asynchronous thread
//! interruption. Once a cancellation request is seen, the migration worker will
//! fail with [`MigratableError::Cancelled`].
//!
//! Migrations can be cancelled as long as the VM wasn't moved to the destination
//! and also only if a cancellation request doesn't race with the final steps of
//! moving a VM to the destination.

#![expect(unused)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::info;
use vm_migration::MigratableError;

/// Cancellation context for the VMM side enabling cancellation of a migration.
pub(crate) struct CancelContextSender {
    cancel: Arc<AtomicBool>,
}

impl CancelContextSender {
    pub(crate) fn try_cancel_migration(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

/// Cancellation context for the migration worker.
#[derive(Clone)]
pub(crate) struct CancelContextReceiver {
    cancel: Arc<AtomicBool>,
}

impl CancelContextReceiver {
    pub(crate) fn ok_or_cancelled(&self) -> Result<(), MigratableError> {
        if self.cancel.load(Ordering::Acquire) {
            info!("Migration cancelled");
            Err(MigratableError::Cancelled)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn new_cancel_context() -> (CancelContextSender, CancelContextReceiver) {
    let cancel = Arc::new(AtomicBool::new(false));

    let ctx_vmm = CancelContextSender {
        cancel: cancel.clone(),
    };
    let ctx_migration = CancelContextReceiver { cancel };
    (ctx_vmm, ctx_migration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_can_be_cancelled() {
        let (ctx_vmm, ctx_migration) = new_cancel_context();

        assert!(matches!(ctx_migration.ok_or_cancelled(), Ok(())));
        ctx_vmm.try_cancel_migration();
        assert!(matches!(
            ctx_migration.ok_or_cancelled(),
            Err(MigratableError::Cancelled)
        ));
    }
}
