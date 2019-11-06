// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::result;
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, SendError, RecvError};
use crate::api::{ApiResponsePayload, ApiResponse};

/// MigrationState errors are sent back from the receiver through the ApiResponse.
#[derive(Debug)]
pub enum MigrationStateError {
    /// API request receive error
    ApiRequestRecv(RecvError),

    /// API response send error
    ApiResponseSend(SendError<ApiResponse>),

    /// Cannot handle migration state load request.
    MigrationStateLoad,
}
pub type MigrationStateResult<T> = result::Result<T, MigrationStateError>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationStateData {
    pub state: Vec<u8>,
}

#[derive(Debug)]
pub enum MigrationResponsePayload {
    /// No data is sent on the channel.
    Empty,

    /// Migration state content
    MigrationState(MigrationStateData),
}

/// This is the response sent by the VMM API server through the mpsc channel.
pub type MigrationStateResponse = std::result::Result<MigrationResponsePayload, MigrationStateError>;

#[derive(Clone)]
pub struct MigrationState {
    state_owners: Arc<RwLock<HashMap<String, Mutex<Sender<ApiResponse>>>>>,
}

impl MigrationState {
    pub fn new() -> Self {
        MigrationState {
            state_owners: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, idstr: String, sender: Sender<ApiResponse>) -> ApiResponse {
        println!("Insert migration sender from {}", idstr);
        let mut map = self.state_owners.write().unwrap();
        map.insert(idstr, Mutex::new(sender));

        /* TODO: check if there is available data in MigrationDataFile. If yes,
         * it is target VM so return received states as ApiResponsePayload. If
         * no, it is source VM so return None.
         */
        let response = Ok(ApiResponsePayload::Empty);

        response
    }

    pub fn get_iter(&self) -> MigrationStateResult<()> {
        let map = self.state_owners.read().expect("RwLock poisoned");
        let (response_sender, response_receiver) = channel();

        for (idstr, sender) in map.iter() {
            println!("Get migration states from {}", idstr);
            let sender = sender.lock().unwrap();
            let response = Ok(ApiResponsePayload::MigrationStateGet(response_sender.clone()));

            sender
                .send(response)
                .map_err(MigrationStateError::ApiResponseSend)?;
        }

        let mut iter = response_receiver.iter();
        loop {
            let response = match iter.next() {
                None => {
                    println!("No more response, break the loop.");
                    break
                },
                Some(data) => data,
            };

            match response {
                Ok(resp) => {
                    match resp {
                        MigrationResponsePayload::Empty => {},
                        MigrationResponsePayload::MigrationState(data) => {
                            /* TODO: Put received state into MigrateDataFile buffer */
                            let s = String::from_utf8(data.state).expect("Invalid utf8");
                            println!("Received state is {}", s);
                        }
                    }
                },
                Err(e) => println!("Receive bad migration response {:?}", e),
            }
        }

        Ok(())
    }
}
