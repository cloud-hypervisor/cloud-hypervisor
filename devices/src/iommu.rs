// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hardware IOMMU backend operation failed: {0}")]
    Backend(#[source] io::Error),
}

/// Table entry type related to a specific IOMMU
pub enum TableEntry {
    Smmuv3Ste([u64; 8]),
}

/// Invalidation command type related to a specific IOMMU
pub enum Invalidation {
    Smmuv3Cmd([u64; 2]),
}

/// Abstraction of the common mechanisms shared across hardware IOMMUs
pub trait HwIommuBackend: Send + Sync {
    fn install_table_entry(&self, device_id: u32, entry: TableEntry) -> Result<(), Error>;

    fn set_passthrough(&self, device_id: u32) -> Result<(), Error>;

    fn set_blocking(&self, device_id: u32) -> Result<(), Error>;

    fn invalidate(&self, invalidation: Invalidation) -> Result<(), Error>;
}
