// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Traits for extracting file descriptors from structs.

use std::collections::HashMap;
use std::os::fd::OwnedFd;

use thiserror::Error;

use crate::deserialization_barrier::FdMap;

/// Errors that can occur in [`ExtractFdMap`].
#[derive(Error, Debug, Eq, PartialEq)]
pub enum ExtractFdMapError {
    #[error("Identifier collision for {0}")]
    IdCollision(String),
}

/// Trait for extracting a [`FdMap`] from a file descriptor containing struct.
///
/// # Usage
///
/// Users of the trait should only call [`ExtractFdMap::extract_fd_map`].
/// Implementors should use [`ExtractFdMap::extract_fd_map_inner`] instead.
pub trait ExtractFdMap {
    /// Extracts all file descriptors into an [`FdMap`].
    ///
    /// This takes ownership of the file descriptors and leaves the struct without file descriptors.
    fn extract_fd_map(&mut self) -> Result<FdMap, ExtractFdMapError> {
        let mut fd_map = HashMap::new();
        self.extract_fd_map_inner(&mut fd_map)?;
        Ok(fd_map)
    }

    /// Extracts all file descriptors into `fd_map`.
    ///
    /// Only used by implementors of the trait.
    /// To use this trait, call [`ExtractFdMap::extract_fd_map`].
    /// Call this method instead of [`ExtractFdMap::extract_fd_map`] when implementing [`ExtractFdMap::extract_fd_map_inner`] for parent structs.
    fn extract_fd_map_inner(&mut self, fd_map: &mut FdMap) -> Result<(), ExtractFdMapError>;
}

/// Trait for exporting all file descriptors for use in `SCM_RIGHTS`.
///
/// # Usage
///
/// Users of the trait should only call [`ExportScmRights::fd_map`].
/// Implementors should use [`ExportScmRights::fd_map_inner`] instead.
pub trait ExportScmRights {
    /// The [`Deserialized`][super::Deserialized] version of the implementor of this trait.
    type Inactive;

    /// Exports all file descriptors for use in `SCM_RIGHTS` and turns `Self` in its [`Deserialized`][super::Deserialized] version.
    fn export_fd_list(self) -> (Self::Inactive, Vec<OwnedFd>)
    where
        Self: Sized,
    {
        let mut fd_list = Vec::new();
        let inactive = self.export_fd_list_inner(&mut fd_list);
        (inactive, fd_list)
    }

    /// Exports all file descriptors for use in `SCM_RIGHTS` and turns `Self` in its [`Deserialized`][super::Deserialized] version.
    ///
    /// Only used by implementors of the trait.
    /// To use this trait, call [`ExportScmRights::export_fd_list`].
    /// Call this method instead of [`ExportScmRights::export_fd_list`] when implementing [`ExportScmRights::export_fd_list_inner`] for parent structs.
    fn export_fd_list_inner(self, fds: &mut Vec<OwnedFd>) -> Self::Inactive;
}
