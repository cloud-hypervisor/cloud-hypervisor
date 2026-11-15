// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::error::Error as StdError;

use thiserror::Error;

/// A DMA mapping failure with its address context and original error source.
#[derive(Debug, Error)]
pub enum ExternalDmaMappingError {
    /// No guest memory region contains the address.
    #[error("Guest memory region not found: gpa={gpa:#x}")]
    RegionNotFound { gpa: u64 },
    /// The guest range cannot be accessed through a host mapping.
    #[error("Invalid guest range: gpa={gpa:#x}, size={size:#x}")]
    InvalidGuestRange { gpa: u64, size: u64 },
    /// The guest memory region has no backing file.
    #[error("Missing backing file: gpa={gpa:#x}")]
    MissingBackingFile { gpa: u64 },
    /// The offset within the backing file overflows.
    #[error("File offset overflow: file_offset={file_offset:#x}, region_offset={region_offset:#x}")]
    FileOffsetOverflow {
        file_offset: u64,
        region_offset: u64,
    },
    /// A memory range could not be mapped.
    #[error("Failed to map DMA range: iova={iova:#x}, gpa={gpa:#x}, size={size:#x}")]
    Map {
        iova: u64,
        gpa: u64,
        size: u64,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// A memory range could not be unmapped.
    #[error("Failed to unmap DMA range: iova={iova:#x}, size={size:#x}")]
    Unmap {
        iova: u64,
        size: u64,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
}

/// Trait to trigger DMA mapping updates for devices managed by virtio-iommu
///
/// Trait meant for triggering the DMA mapping update related to an external
/// device not managed fully through virtio. It is dedicated to virtio-iommu
/// in order to trigger the map update anytime the mapping is updated from the
/// guest.
pub trait ExternalDmaMapping: Send + Sync {
    /// Map a memory range
    fn map(&self, iova: u64, gpa: u64, size: u64) -> Result<(), ExternalDmaMappingError>;

    /// Unmap a memory range
    fn unmap(&self, iova: u64, size: u64) -> Result<(), ExternalDmaMappingError>;
}
