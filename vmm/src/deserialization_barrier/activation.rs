// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Traits for activating structs with file descriptors.

use std::fs::File;

use thiserror::Error;

use crate::deserialization_barrier::{Active, Fd, FdIdent, FdMap};

/// Errors that can occur in [`UpdateFds`].
#[derive(Error, Debug, Eq, PartialEq)]
pub enum FdUpdateError {
    #[error("Less file descriptors provided than expected for: {0:?}")]
    TooLittleFds(FdIdent),
    #[error("More file descriptors provided than expected for: {0:?}")]
    TooManyFds(FdIdent),
    #[error("Device without id expected file descriptors")]
    MissingId,
    #[error("Missing file descriptors for device: {0:?}")]
    MissingFds(FdIdent),
    #[error("File descriptors for the following devices were unused: {0:?}")]
    SuperfluousFds(Vec<FdIdent>),
}

/// Trait for updating all deserialized file descriptors to active.
///
/// # Usage
///
/// Users of the trait should only call [`UpdateFds::update_fds`].
/// Implementors should use [`UpdateFds::update_fds_inner`] instead.
pub trait UpdateFds {
    /// The [`Active`][super::Active] version of the implementor of this trait.
    type Activated;

    /// Updates all file descriptors within the implementor.
    fn update_fds(self, mut fd_map: FdMap) -> Result<Self::Activated, FdUpdateError>
    where
        Self: Sized,
    {
        let result = self.update_fds_inner(&mut fd_map)?;
        if fd_map.is_empty() {
            Ok(result)
        } else {
            Err(FdUpdateError::SuperfluousFds(
                fd_map.keys().cloned().collect(),
            ))
        }
    }

    /// Updates all file descriptors within the implementor.
    ///
    /// Only used by implementors of the trait.
    /// To use this trait, call [`UpdateFds::update_fds`].
    /// Call this method instead of [`UpdateFds::update_fds`] when implementing [`UpdateFds::update_fds_inner`] for parent structs.
    fn update_fds_inner(self, fd_map: &mut FdMap) -> Result<Self::Activated, FdUpdateError>;
}

/// Errors that can occur in [`IngestScmRights`].
#[derive(Error, Debug, Eq, PartialEq)]
pub enum IngestScmRightsError {
    #[error("Less file descriptors provided than expected")]
    TooLittleFds,
    #[error("More file descriptors provided than expected")]
    TooManyFds,
    #[error("SCM_RIGHTS is not supported")]
    Unsupported,
}

/// Trait for ingesting `SCM_RIGHTS` provided file descriptors.
///
/// # Usage
///
/// Users of the trait should only call [`IngestScmRights::ingest_scm_rights`].
/// Implementors should use [`IngestScmRights::ingest_scm_rights_inner`] instead.
pub trait IngestScmRights {
    /// The [`Active`][super::Active] version of the implementor of this trait.
    type Activated;

    /// Ingests a `SCM_RIGHTS` provided file descriptor list, updating all file descriptors.
    fn ingest_scm_rights(self, files: Vec<File>) -> Result<Self::Activated, IngestScmRightsError>
    where
        Self: Sized,
    {
        let mut files = files.into_iter().map(Into::into).collect();
        let result = self.ingest_scm_rights_inner(&mut files)?;
        if files.is_empty() {
            Ok(result)
        } else {
            Err(IngestScmRightsError::TooManyFds)
        }
    }

    /// Ingests a `SCM_RIGHTS` provided file descriptor list, updating all file descriptors.
    ///
    /// Only used by implementors of the trait.
    /// To use this trait, call [`IngestScmRights::ingest_scm_rights`].
    /// Call this method instead of [`IngestScmRights::ingest_scm_rights`] when implementing [`IngestScmRights::ingest_scm_rights_inner`] for parent structs.
    fn ingest_scm_rights_inner(
        self,
        fds: &mut Vec<Fd<Active>>,
    ) -> Result<Self::Activated, IngestScmRightsError>;
}
