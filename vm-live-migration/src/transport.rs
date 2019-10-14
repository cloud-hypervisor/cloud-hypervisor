use std::sync::Arc;

use crate::data::MigrationDataFile;

pub trait MigrationTransport {
    fn bind(&self, data: Arc<MigrationDataFile>);
    fn connect(&self, data: Arc<MigrationDataFile>);
}
