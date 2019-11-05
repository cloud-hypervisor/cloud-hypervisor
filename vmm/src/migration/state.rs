// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::result;
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use crate::api::{ApiResponsePayload, ApiResponse};

/// MigrationState errors are sent back from the receiver through the ApiResponse.
#[derive(Debug)]
pub enum MigrationStateError {
    /// Fail to get migration state.
    MigrationStateGet,

    /// Fail to load migration state.
    MigrationStateLoad,
}
pub type MigrationStateResult<T> = result::Result<T, MigrationStateError>;

pub struct MigrationComp {
    comp: Arc<Mutex<dyn Migratable>>,
    states: Vec<u8>,
}

#[derive(Clone)]
pub struct MigrationState {
    components: Arc<RwLock<HashMap<String, Mutex<MigrationComp>>>>,
}

impl MigrationState {
    pub fn new() -> Self {
        MigrationState {
            components: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, idstr: String, comp: Arc<Mutex<dyn Migratable>>) -> ApiResponse {
        println!("Insert migration sender from {}", idstr);
        let mut map = self.components.write().unwrap();
        let comp = MigrationComp {
            comp,
            states: Vec::new(),
        };

        map.insert(idstr, Mutex::new(comp));

        /* TODO: check if there is available data in MigrationComp::states. If yes,
         * it is target VM so return received states as ApiResponsePayload. If
         * no, it is source VM so return None.
         */
        let response = Ok(ApiResponsePayload::Empty);

        response
    }

    pub fn get_states(&self) -> MigrationStateResult<()> {
        let map = self.components.read().expect("RwLock poisoned");

        for (idstr, comp) in map.iter() {
            println!("Get migration states from {}", idstr);
            let guard = comp.lock().unwrap();
            let comp = guard.comp.lock().unwrap();
            let mut states = guard.states.clone();

            if let Some(data) = comp.snapshot() {
                println!("snapshot result is {}", data);
                let mut v = data.into_bytes();
                states.append(&mut v);
            }
        }

        Ok(())
    }
}

pub trait Migratable: Send + Sync {
    fn snapshot(&self) -> Option<String>;
}
