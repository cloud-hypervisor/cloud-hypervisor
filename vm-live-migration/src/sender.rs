use crate::base::MigrationBase;

pub struct MigrationSender {
    base: MigrationBase,
}

impl MigrationSender {
    pub fn new(addr: String) -> Self {
        MigrationSender { base: MigrationBase::new(addr) }
    }

    pub fn connect(&self) {
        self.base.connect();
    }
}
