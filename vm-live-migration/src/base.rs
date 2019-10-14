use std::boxed::Box;

use crate::transport::MigrationTransport;
use crate::tcp::MigrationTCP;

pub struct MigrationBase {
    trans: Box<dyn MigrationTransport>,
}

impl MigrationBase {
    pub fn new(addr: String) -> Self {
        MigrationBase { trans: Box::new(MigrationTCP::new(addr)) }
    }

    pub fn bind(&self) {
        self.trans.bind()
    }

    pub fn connect(&self) {
        self.trans.connect()
    }
}
