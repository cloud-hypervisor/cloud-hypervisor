use crate::base::MigrationBase;

pub struct MigrationReceiver {
    base: MigrationBase,
}

impl MigrationReceiver {
    pub fn new(addr: String) -> Self {
        MigrationReceiver { base: MigrationBase::new(addr) }
    }

    pub fn bind(&self) {
        self.base.bind();
    }
}
