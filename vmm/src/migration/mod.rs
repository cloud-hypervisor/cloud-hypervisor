// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{io, result, thread};
use std::sync::mpsc::{channel, Sender, SendError, RecvError};
use crate::api::ApiResponse;
use crate::migration::state::MigrationState;

pub mod state;

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot spawn a new migration thread.
    MigrationSpawn(io::Error),

    /// Request send error
    RequestSend(SendError<MigrationRequest>),

    /// Request receive error
    RequestRecv(RecvError),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum MigrationRequest {
    /// Start to take snapshot, i.e. save Vm states
    TakeSnapshot,

    /// Start to restore snapshot, i.e. restore Vm states
    RestoreSnapshot,
}

#[derive(Clone)]
pub struct Migration {
    state: MigrationState,
    sender: Sender<MigrationRequest>,
}

impl Migration {
    pub fn new() -> Result<Self> {
        let (sender, receiver) = channel();
        let state = MigrationState::new();
        let state1 = state.clone();

        thread::Builder::new()
            .name(format!("migration"))
            .spawn(move || {
                let request = receiver.recv().map_err(Error::RequestRecv);

                match request {
                    Ok(req) => {
                        match req {
                            MigrationRequest::TakeSnapshot => {
                                state1.get_iter().expect("Fail to get migration states");
                            }
                            MigrationRequest::RestoreSnapshot => {
                                /* TODO: call state's restore interface */
                            }
                        }
                    },
                    Err(e) => println!("Receive bad MigrationRequest {:?}", e),
                }
            })
            .map_err(Error::MigrationSpawn)?;

        Ok(Migration {
            state,
            sender,
        })
    }

    pub fn insert(&self, idstr: String, sender: Sender<ApiResponse>) -> ApiResponse {
        self.state.insert(idstr, sender)
    }

    pub fn take_snapshot(&self) -> Result<()> {
        self.sender.send(MigrationRequest::TakeSnapshot).map_err(Error::RequestSend)?;
        Ok(())
    }

    pub fn restore_snapshot(&self) -> Result<()> {
        self.sender.send(MigrationRequest::RestoreSnapshot).map_err(Error::RequestSend)?;
        Ok(())
    }
}
