// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{io, result};
use std::sync::{Arc, Mutex};
use crate::api::ApiResponse;
use crate::migration::state::{MigrationState, MigrationStateError, Migratable};

pub mod state;
pub mod device_states;

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot spawn a new migration thread.
    MigrationSpawn(io::Error),

    /// Response send error
    ResponseSend(MigrationStateError),

    /// Request receive error
    RequestRecv(MigrationStateError),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone)]
pub struct Migration {
    state: MigrationState,
}

impl Migration {
    pub fn new() -> Result<Self> {
        Ok(Migration {
            state: MigrationState::new(),
        })
    }

    pub fn insert(&self, idstr: String, comp: Arc<Mutex<dyn Migratable>>) -> ApiResponse {
        self.state.insert(idstr, comp)
    }

    pub fn take_snapshot(&self) -> Result<()> {
        self.state.get_states().expect("Get states fail");
        Ok(())
    }

    pub fn restore_snapshot(&self) -> Result<()> {
        /* TODO in next phase */
        Ok(())
    }
}
