extern crate serde;
extern crate thiserror;

use thiserror::Error;

/// Trait meant for triggering the DMA mapping update related to an external
/// device not managed fully through virtio. It is dedicated to virtio-iommu
/// in order to trigger the map update anytime the mapping is updated from the
/// guest.
pub trait ExternalDmaMapping: Send + Sync {
    /// Map a memory range
    fn map(&self, iova: u64, gpa: u64, size: u64) -> std::result::Result<(), std::io::Error>;

    /// Unmap a memory range
    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), std::io::Error>;
}

#[derive(Error, Debug)]
pub enum MigratableError {
    #[error("Failed to pause migratable component: {0}")]
    Pause(#[source] anyhow::Error),

    #[error("Failed to resume migratable component: {0}")]
    Resume(#[source] anyhow::Error),
}

/// A Pausable component can be paused and resumed.
pub trait Pausable {
    /// Pause the component.
    fn pause(&mut self) -> std::result::Result<(), MigratableError>;

    /// Resume the component.
    fn resume(&mut self) -> std::result::Result<(), MigratableError>;
}

/// A snapshotable component can be snapshoted.
pub trait Snapshotable {}

/// Trait to be implemented by any component (device, CPU, RAM, etc) that
/// can be migrated.
/// All migratable components are paused before being snapshotted, and then
/// eventually resumed. Thus any Migratable component must be both Pausable
/// and Snapshotable.
pub trait Migratable: Pausable + Snapshotable {}
