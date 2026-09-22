// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(target_arch = "aarch64")]
use pci::PciBdf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Hardware IOMMU backend operation failed")]
    Backend(#[source] io::Error),
}

/// Table entry type related to a specific IOMMU
pub enum TableEntry {
    #[cfg(target_arch = "aarch64")]
    Smmuv3Ste([u64; 8]),
}

/// Invalidation command type related to a specific IOMMU
pub enum Invalidation {
    #[cfg(target_arch = "aarch64")]
    Smmuv3Cmd([u64; 2]),
}

/// Information about a specific IOMMU, as reported by the host
pub enum HwInfo {
    #[cfg(target_arch = "aarch64")]
    Smmuv3 { idr: [u32; 6], ats_supported: bool },
}

/// Abstraction of the common mechanisms shared across physical IOMMUs
pub trait PhysicalIommu: Send + Sync {
    fn hw_info(&self) -> Result<HwInfo, Error>;

    fn install_table_entry(&self, device_id: u32, entry: TableEntry) -> Result<(), Error>;

    fn set_passthrough(&self, device_id: u32) -> Result<(), Error>;

    fn set_blocking(&self, device_id: u32) -> Result<(), Error>;

    fn invalidate(&self, invalidation: Invalidation) -> Result<(), Error>;
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Default)]
pub struct Smmuv3AcpiInfo {
    pub base: u64,
    pub event_gsiv: u32,
    pub gerror_gsiv: u32,
    pub pri_gsiv: u32,
    pub sync_gsiv: u32,
    pub coherent: bool,
    pub ats_supported: bool,
    pub attached_bdfs: Vec<PciBdf>,
}

#[derive(Clone, Debug)]
pub enum IommuAcpiInfo {
    #[cfg(target_arch = "aarch64")]
    Smmuv3(Smmuv3AcpiInfo),
}
