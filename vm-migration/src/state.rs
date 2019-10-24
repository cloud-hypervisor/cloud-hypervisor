// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, SendError, RecvError};

/// MigrationState errors are sent back from the receiver through the ApiResponse.
#[derive(Debug)]
pub enum MigrationStateError {
    /// MigrationRequest send error
    RequestSend(SendError<MigrationRequest>),

    /// Reponse receive error
    ResponseRecv(RecvError),

    /// Cannot handle migration state load request.
    MigrationStateLoad,
}
pub type MigrationStateResult<T> = std::result::Result<T, MigrationStateError>;

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

#[allow(clippy::large_enum_variant)]
pub enum MigrationRequest {
    /// Request to get migratble states. The response payload is a json which
    /// contains serialized states.
    /// If the receiver could not correctly handle this request, it will send a
    /// MigrationStateGet error back.
    MigrationStateGet(Sender<MigrationStateResponse>),

    /// Request to load migratble states. The request payload is a json which
    /// contains serialized states.
    /// If the receiver could not correctly handle this request, it will send a
    /// MigrationStateLoad error back.
    MigrationStateLoad(Arc<MigrationStateData>),
}

lazy_static! {
    static ref MIGRATION_STATE_ROUTES: Arc<RwLock<HashMap<String, Mutex<Sender<MigrationRequest>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

pub fn migration_state_insert(idstr: String, sender: Sender<MigrationRequest>) {
    println!("Insert migration sender from {}", idstr);
    let mut map = MIGRATION_STATE_ROUTES.write().unwrap();
    map.insert(idstr, Mutex::new(sender));
}

pub fn migration_state_iter_get() -> MigrationStateResult<()> {
    let map = MIGRATION_STATE_ROUTES.read().expect("RwLock poisoned");
    let (response_sender, response_receiver) = channel();

    for (idstr, sender) in map.iter() {
        println!("Get migration states from {}", idstr);
        let sender = sender.lock().unwrap();

        sender
            .send(MigrationRequest::MigrationStateGet(response_sender.clone()))
            .map_err(MigrationStateError::RequestSend)?;
    }

    let mut iter = response_receiver.iter();
    loop {
        let state = match iter.next() {
            None => {
                println!("No more response, break the loop.");
                break
            },
            Some(data) => data,
        };

        println!("Received state is {:?}", state);

        /* TODO: Put state into MigrateDataFile buffer */
    }

    Ok(())
}
