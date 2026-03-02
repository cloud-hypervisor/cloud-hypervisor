// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! # Infrastructure for Migration Cancellation
//!
//! Cancellation is coordinated between the VMM thread and the migration worker.
//! The VMM side requests cancellation by setting a shared atomic flag and then
//! waits for the migration side to report the final outcome.
//!
//! The migration side polls the flag at cancellation points. Once it observes a
//! pending cancellation, it sends an abandon request to the peer, reports
//! [`CancelChannelMessage::CancellationSucceeded`], and returns
//! [`MigratableError::Cancelled`].
//!
//! Cancellation is best effort: the migration may complete or fail before the
//! worker observes the cancellation request. In that case, the worker reports the
//! actual terminal outcome instead.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use log::{error, info};
use vm_migration::MigratableError;
use vm_migration::protocol::Request;

use crate::migration::transport::SocketStream;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CancelChannelMessage {
    /// The cancellation successfully stopped the migration.
    CancellationSucceeded,
    /// The migration succeeded before it could be cancelled.
    MigrationSucceeded,
    /// Before the migration could either be cancelled or succeeded, it failed.
    MigrationFailed,
}

/// Cancellation context for the VMM side enabling cancellation of a migration.
///
/// Counterpart to [`CancelContextMigration`].
///
/// Notifies migration code about a cancellation and checks if the cancellation
/// was acknowledges.
pub struct CancelContextVmm {
    cancel: Arc<AtomicBool>, /* cancel on true */
    cancel_ack_rx: Receiver<CancelChannelMessage>,
}

impl CancelContextVmm {
    /// Tries to cancel the migration.
    pub fn try_cancel_migration(&self) -> CancelChannelMessage {
        self.cancel.store(true, Ordering::Release);
        // Rendezvous point: the migration thread waits for the cancellation.
        // Only fails if the thread finished already.
        self.cancel_ack_rx.recv().unwrap_or_else(|_| {
            error!("Migration thread died before acknowledging cancellation");
            CancelChannelMessage::MigrationSucceeded
        })
    }
}

/// Cancellation context for the migration worker.
///
/// Counterpart to [`CancelContextVmm`].
///
/// Allows migration code to check whether cancellation was requested and to
/// acknowledge that cancellation has been observed.
pub struct CancelContextMigration {
    cancel: Arc<AtomicBool>, /* cancel on true */
    cancel_ack_tx: SyncSender<CancelChannelMessage>,
}

impl CancelContextMigration {
    /// If needed, notifies the cancellation receiver about the outcome of a
    /// potential cancellation.
    pub fn notify(&self, message: CancelChannelMessage) {
        if self.cancel.load(Ordering::Acquire) {
            self.cancel_ack_tx.send(message).expect(
                "Receiver in worker handle should outlive the sender in the migration worker",
            );
        }
    }

    /// Checks if the migration should be cancelled and returns an error if so.
    ///
    /// In that case, it also writes [`Request::abandon`] to the socket.
    pub fn ok_or_cancelled(&self, socket: &mut SocketStream) -> Result<(), MigratableError> {
        if self.cancel.load(Ordering::Acquire) {
            info!("Cancelling migration now");
            Request::abandon().write_to(socket)?;
            Err(MigratableError::Cancelled)
        } else {
            Ok(())
        }
    }
}

pub fn new_cancel_context() -> (CancelContextVmm, CancelContextMigration) {
    // In the lifetime of this channel, we sent exactly one message.
    // Capacity of zero so that the sender never outlives the receiver.
    let (cancel_ack_tx, cancel_ack_rx) = sync_channel::<CancelChannelMessage>(0);
    let cancel = Arc::new(AtomicBool::new(false));

    let ctx_vmm = CancelContextVmm {
        cancel: cancel.clone(),
        cancel_ack_rx,
    };
    let ctx_migration = CancelContextMigration {
        cancel,
        cancel_ack_tx,
    };
    (ctx_vmm, ctx_migration)
}
