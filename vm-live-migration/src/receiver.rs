use std::{io, thread};
use std::time::Duration;

use crate::base::MigrationBase;
use crate::state:: MigrationState;

pub enum Error {
    MigrationSpawn(io::Error),
}

pub struct MigrationReceiver {
    base: MigrationBase,
    state: MigrationState,
}

impl MigrationReceiver {
    pub fn new(addr: String, state: MigrationState) -> Self {
        MigrationReceiver {
            base: MigrationBase::new(addr),
            state: state,
        }
    }

    pub fn bind(&self) {
        self.base.bind();
    }

    pub fn handle_state(&self) {
        let data = self.base.data.clone();

        thread::Builder::new()
            .name(format!("migration_server state"))
            .spawn(move || {
                loop {
                    if data.data_avail() {
                        let mut entry = vec![];
                        data.read(&mut entry);

                        // TODO: test Vm load_state
                        let mut vec = vec![0u8; 5];

                        for i in 0..5 {
                            vec[i] = entry[i];
                        }

                        let mut vm_state: MigrationState = crate::state::migration_state_pop();
                        vm_state.d_send(vec);
                    }
                    thread::sleep(Duration::from_millis(4000));
                }
            })
            .map_err(Error::MigrationSpawn);
    }

    pub fn data_avail(&self) -> bool {
        self.base.data.data_avail()
    }
}
