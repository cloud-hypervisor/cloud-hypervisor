use crate::base::MigrationBase;
use crate::state::MigrationState;

pub struct MigrationSender {
    base: MigrationBase,
    state: MigrationState,
}

impl MigrationSender {
    pub fn new(addr: String, state: MigrationState) -> Self {
        MigrationSender {
            base: MigrationBase::new(addr),
            state: state,
        }
    }

    pub fn connect(&self) {
        self.base.connect();
    }

    pub fn handle_state(&mut self) {
        // TODO: test Vm state.
        let state = crate::state::migration_state_pop();
        let msg = vec![1]; //OK
        state.m_send(msg);
        state.d_recv(self.base.data.clone());
    }
}
