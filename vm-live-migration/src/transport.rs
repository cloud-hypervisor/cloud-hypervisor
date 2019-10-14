pub trait MigrationTransport {
    fn bind(&self);
    fn connect(&self);
}
