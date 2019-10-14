use std::boxed::Box;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::transport::MigrationTransport;
use crate::tcp::MigrationTCP;
use crate::data::MigrationDataFile;

pub struct MigrationBase {
    trans: Box<dyn MigrationTransport>,
    pub data: Arc<MigrationDataFile>,
}

impl MigrationBase {
    pub fn new(addr: String) -> Self {
        let trans = Box::new(MigrationTCP::new(addr));
        let data = MigrationDataFile::new();
        MigrationBase { trans: trans, data: Arc::new(data) }
    }

    pub fn bind(&self) {
        self.trans.bind(self.data.clone())
    }

    pub fn connect(&self) {
        let mut ver = vec![1, 2, 3, 4, 5];
        self.data.write(&mut ver, false);
        loop {
            if self.data.data_valid() == true {
                self.trans.connect(self.data.clone())
            } else {
                let sleep_duration = Duration::from_millis(1000);
                thread::sleep(sleep_duration);
            }
        }
    }
}
