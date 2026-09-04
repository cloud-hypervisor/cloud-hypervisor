// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! External file descriptor handling.

use std::collections::BTreeSet;
use std::fs::File;
use std::mem;
use std::os::fd::{IntoRawFd, RawFd};
use std::str::FromStr;

use option_parser::{Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::VmReceiveMigrationData;
use crate::config::{RestoreConfig, RestoredNetConfig, RestoredVfioConfig};
use crate::vm_config::{DeviceConfig, NetConfig, PlatformConfig, VmConfig};

/// Defines which operation caused the external file descriptor processing.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialOrd, PartialEq)]
pub(crate) enum ExternalFdOperation {
    Restore,
    ReceiveMigration,
    VmCreate,
}

/// A resource that can be backed by one or more file descriptors.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ExternalFdTarget {
    Net { id: String },
    Vfio { id: String },
    Iommu,
}

/// Errors parsing [`ExternalFdTarget`].
#[derive(Debug, Eq, PartialEq)]
pub enum ParseExternalFdTargetError {
    InvalidValue(String),
    EmptyIdent(String),
}

impl FromStr for ExternalFdTarget {
    type Err = ParseExternalFdTargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ident, rest) = s.split_once("(").unwrap_or((s, ""));

        fn parse_id(
            input: &str,
            constructor: fn(String) -> ExternalFdTarget,
            original: &str,
        ) -> Result<ExternalFdTarget, <ExternalFdTarget as FromStr>::Err> {
            if let Some((id, "")) = input.split_once(")") {
                if id.is_empty() {
                    Err(ParseExternalFdTargetError::EmptyIdent(original.to_owned()))
                } else {
                    Ok(constructor(id.to_owned()))
                }
            } else {
                Err(ParseExternalFdTargetError::InvalidValue(
                    original.to_owned(),
                ))
            }
        }

        match ident {
            "net" => parse_id(rest, |id| ExternalFdTarget::Net { id }, s),
            "vfio" => parse_id(rest, |id| ExternalFdTarget::Vfio { id }, s),
            "iommu" => {
                if rest.is_empty() {
                    Ok(ExternalFdTarget::Iommu)
                } else {
                    Err(ParseExternalFdTargetError::InvalidValue(s.to_owned()))
                }
            }
            _ => Err(ParseExternalFdTargetError::InvalidValue(s.to_owned())),
        }
    }
}

/// Metadata and file descriptors for one [`ExternalFdTarget`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ExternalFdsEntry {
    target: ExternalFdTarget,
    expected_fds: usize,
    #[serde(skip)]
    received_fds: Vec<RawFd>,
}

impl ExternalFdsEntry {
    /// Updates all file descriptors from the provided `files` list.
    ///
    /// Consumes only as many file descriptors as necessary and leaves remaining file descriptors untouched.
    fn update_from_scm_rights(&mut self, files: &mut Vec<File>) -> Result<(), ScmRightsError> {
        if self.expected_fds <= files.len() {
            self.received_fds = files
                .drain(..self.expected_fds)
                .map(IntoRawFd::into_raw_fd)
                .collect();
            Ok(())
        } else {
            Err(ScmRightsError::TooFewFds)
        }
    }

    /// Takes all file descriptors out of `Self`.
    fn take_fds(&mut self) -> Vec<RawFd> {
        mem::take(&mut self.received_fds)
    }

    /// Returns a reference to the contained file descriptors.
    fn fds(&self) -> &[RawFd] {
        &self.received_fds
    }

    /// Creates a new entry.
    fn new(target: ExternalFdTarget, files: Vec<RawFd>) -> Self {
        Self {
            target,
            expected_fds: files.len(),
            received_fds: files.into_iter().map(IntoRawFd::into_raw_fd).collect(),
        }
    }

    /// Returns the number of expected file descriptors.
    fn expected_fds(&self) -> usize {
        self.expected_fds
    }
}

// TODO(fd): Remove after `RestoredNetConfig` is deprecated and removed.
impl From<RestoredNetConfig> for ExternalFdsEntry {
    fn from(value: RestoredNetConfig) -> Self {
        ExternalFdsEntry {
            target: ExternalFdTarget::Net { id: value.id },
            expected_fds: value.num_fds,
            // `RestoredNetConfig` may contain valid file descriptors if passed via CLI.
            received_fds: value
                .fds
                .map(|fds| fds.iter().filter(|fd| **fd != -1).copied().collect())
                .unwrap_or_default(),
        }
    }
}

// TODO(fd): Remove after `RestoredVfioConfig` is deprecated and removed.
impl From<RestoredVfioConfig> for ExternalFdsEntry {
    fn from(value: RestoredVfioConfig) -> Self {
        ExternalFdsEntry {
            target: ExternalFdTarget::Vfio { id: value.id },
            expected_fds: 1,
            // `RestoredVfioConfig` may contain valid file descriptors if passed via CLI.
            received_fds: value
                .fd
                .filter(|fd: &RawFd| *fd != -1)
                .map(|fd| vec![fd])
                .unwrap_or_default(),
        }
    }
}

impl Clone for ExternalFdsEntry {
    fn clone(&self) -> Self {
        // In tests, we're often not using actual file descriptors, so duplicating can either fail or
        // duplicate an existing, unrelated file descriptor.
        let received_fds = if cfg!(test) {
            self.received_fds.clone()
        } else {
            self.received_fds
                .iter()
                .map(|fd| {
                    // SAFETY: `dup` doesn't modify the parameter and the result is checked.
                    let duplicated_fd = unsafe { libc::dup(*fd) };
                    if duplicated_fd == -1 && *fd != -1 {
                        panic!("Failed to duplicate file descriptor");
                    }
                    duplicated_fd
                })
                .collect()
        };

        Self {
            target: self.target.clone(),
            expected_fds: self.expected_fds,
            received_fds,
        }
    }
}

// In tests, we're not using actual file descriptors, so closing them may close unrelated file descriptors.
#[cfg(not(test))]
impl Drop for ExternalFdsEntry {
    fn drop(&mut self) {
        self.received_fds
            .iter()
            .filter(|fd| **fd != -1)
            .for_each(|fd| {
                // SAFETY: Since this is a `RawFd`, there aren't any safety requirements to uphold.
                unsafe { libc::close(*fd) };
            });
    }
}

/// External file descriptors provided by API or CLI.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct ExternalFds {
    #[serde(default)]
    external_fds: Vec<ExternalFdsEntry>,
}

impl ExternalFds {
    /// Takes the entry associated with `target` out of `Self`, if present.
    ///
    /// This does not preserve the order of entries.
    fn take_entry(&mut self, target: &ExternalFdTarget) -> Option<ExternalFdsEntry> {
        let position = self
            .external_fds
            .iter()
            .position(|entry| &entry.target == target)?;
        Some(self.external_fds.swap_remove(position))
    }

    /// Returns a reference to the entry associated with `target`, if present.
    fn entry(&self, target: &ExternalFdTarget) -> Option<&ExternalFdsEntry> {
        self.external_fds
            .iter()
            .find(|entry| &entry.target == target)
    }

    #[cfg(test)]
    /// Returns all entries as tuples.
    pub(crate) fn entries(&self) -> Vec<(&ExternalFdTarget, usize, &Vec<RawFd>)> {
        self.external_fds
            .iter()
            .map(|entry| (&entry.target, entry.expected_fds, &entry.received_fds))
            .collect()
    }

    /// Takes all file descriptors out of `Self`.
    ///
    /// Preserves the order to allow ingesting the file descriptors again.
    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        self.external_fds
            .iter_mut()
            .flat_map(|fd| mem::take(&mut fd.received_fds))
            .collect()
    }

    /// Returns true if `Self` contains no entries.
    pub(crate) fn is_empty(&self) -> bool {
        self.external_fds.is_empty()
    }

    /// Returns the number of expected file descriptors.
    fn expected_fds(&self) -> usize {
        self.external_fds.iter().fold(0, |mut acc, entry| {
            acc += entry.expected_fds();
            acc
        })
    }

    // TODO(fd): Remove after `RestoredNetConfig` is deprecated and removed.
    /// Imports [`RestoredNetConfig`] into `Self`.
    pub(crate) fn import_restored_net_configs(
        &mut self,
        restored_net_configs: &mut Option<Vec<RestoredNetConfig>>,
    ) {
        if let Some(restored_net_configs) = mem::take(restored_net_configs) {
            self.external_fds
                .splice(0..0, restored_net_configs.into_iter().map(Into::into));
        }
    }

    // TODO(fd): Remove after `RestoredVfioConfig` is deprecated and removed.
    /// Imports [`RestoredVfioConfig`] into `Self`.
    pub(crate) fn import_restored_vfio_configs(
        &mut self,
        restored_vfio_configs: &mut Option<Vec<RestoredVfioConfig>>,
    ) {
        if let Some(restored_vfio_configs) = mem::take(restored_vfio_configs) {
            self.external_fds
                .splice(0..0, restored_vfio_configs.into_iter().map(Into::into));
        }
    }

    // TODO(fd): Remove after `RestoreConfig::iommufd_fd` is deprecated and removed.
    /// Imports [`RestoreConfig::iommufd_fd`] into `Self`.
    pub(crate) fn import_restored_iommufd_fd(&mut self, iommufd_fd: &mut Option<i32>) {
        if let Some(iommufd_fd) = mem::take(iommufd_fd) {
            let entry = ExternalFdsEntry {
                target: ExternalFdTarget::Iommu,
                expected_fds: 1,
                // May contain valid file descriptors if passed via CLI.
                received_fds: if iommufd_fd == -1 {
                    vec![]
                } else {
                    vec![iommufd_fd]
                },
            };
            self.external_fds.insert(0, entry);
        }
    }
}

#[cfg(test)]
impl From<Vec<(ExternalFdTarget, Vec<RawFd>)>> for ExternalFds {
    fn from(value: Vec<(ExternalFdTarget, Vec<RawFd>)>) -> Self {
        Self {
            external_fds: value
                .into_iter()
                .map(|(target, fds)| ExternalFdsEntry::new(target, fds))
                .collect(),
        }
    }
}

impl From<TupleList<ExternalFdTarget, Vec<u64>>> for ExternalFds {
    fn from(value: TupleList<ExternalFdTarget, Vec<u64>>) -> Self {
        Self {
            external_fds: value
                .0
                .into_iter()
                .map(|Tuple(target, fds)| {
                    ExternalFdsEntry::new(target, fds.iter().map(|fd| *fd as RawFd).collect())
                })
                .collect(),
        }
    }
}

/// Errors that can occur when processing `SCM_RIGHTS` provided file descriptors.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum ScmRightsError {
    /// Less file descriptors provided than expected.
    #[error("Less file descriptors provided than expected")]
    TooFewFds,
    /// More file descriptors provided than expected.
    #[error("More file descriptors provided than expected")]
    TooManyFds,
    /// `SCM_RIGHTS` is not supported.
    #[error("SCM_RIGHTS is not supported")]
    Unsupported,
}

/// Trait to process file descriptors provided by `SCM_RIGHTS`.
///
/// After deserialization in the API, internal file descriptors are invalid.
/// The trait allows updating those stale file descriptors with valid ones provided by `SCM_RIGHTS`.
pub trait ScmRights {
    /// Consumes `files` and updates all internal file descriptors.
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError>;

    /// Takes all file descriptors out of `Self`.
    ///
    /// Preserves the order to allow ingesting the file descriptors again.
    fn take_raw_fds(&mut self) -> Vec<RawFd>;
}

impl ScmRights for NetConfig {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        let fds: Vec<_> = files.into_iter().map(IntoRawFd::into_raw_fd).collect();

        if fds.is_empty() {
            self.fds = None;
        } else {
            self.fds = Some(fds);
        }

        Ok(())
    }

    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        self.fds.take().unwrap_or_default()
    }
}

impl ScmRights for DeviceConfig {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        if files.len() > 1 {
            Err(ScmRightsError::TooManyFds)
        } else {
            self.fd = files.into_iter().map(IntoRawFd::into_raw_fd).next();
            Ok(())
        }
    }
    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        self.fd.take().map(|fd| vec![fd]).unwrap_or_default()
    }
}

impl ScmRights for VmReceiveMigrationData {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        // TODO(fd): Remove after `vfio_fds` is deprecated and removed.
        self.external_fds
            .import_restored_iommufd_fd(&mut self.iommufd_fd);

        // TODO(fd): Remove after `vfio_fds` is deprecated and removed.
        self.external_fds
            .import_restored_vfio_configs(&mut self.vfio_fds);

        self.external_fds.consume_fds(files)
    }

    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        self.external_fds.take_raw_fds()
    }
}

impl ScmRights for RestoreConfig {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        // TODO(fd): Remove after `iommufd_fd` is deprecated and removed.
        self.external_fds
            .import_restored_iommufd_fd(&mut self.iommufd_fd);

        // TODO(fd): Remove after `vfio_fds` is deprecated and removed.
        self.external_fds
            .import_restored_vfio_configs(&mut self.vfio_fds);

        // TODO(fd): Remove after `net_fds` is deprecated and removed.
        self.external_fds
            .import_restored_net_configs(&mut self.net_fds);

        self.external_fds.consume_fds(files)
    }

    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        self.external_fds.take_raw_fds()
    }
}

impl ScmRights for VmConfig {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        if files.is_empty() {
            Ok(())
        } else {
            Err(ScmRightsError::Unsupported)
        }
    }

    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        Vec::new()
    }
}

impl ScmRights for ExternalFds {
    fn consume_fds(&mut self, mut files: Vec<File>) -> Result<(), ScmRightsError> {
        // Check supplied and expected FD amount match before applying to prevent leaking FDs on failure.
        let expected_fds = self.expected_fds();
        let supplied_fds = files.len();

        if expected_fds < supplied_fds {
            return Err(ScmRightsError::TooManyFds);
        }

        if expected_fds > supplied_fds {
            return Err(ScmRightsError::TooFewFds);
        }

        self.external_fds
            .iter_mut()
            .try_for_each(|entry| entry.update_from_scm_rights(&mut files))
    }

    fn take_raw_fds(&mut self) -> Vec<RawFd> {
        self.take_raw_fds()
    }
}

/// Errors that can occur when updating file descriptors via [`UpdateFds`].
#[derive(Error, Debug, Eq, PartialEq)]
pub enum UpdateFdsError {
    /// Mismatch between number of expected and actual file descriptor.
    #[error(
        "Mismatch between number of expected and actual file descriptor for \"{target:?}\": actual: {actual}, expected: {expected}"
    )]
    FdAmountMismatch {
        target: ExternalFdTarget,
        expected: usize,
        actual: usize,
    },
    /// Target didn't expect file descriptors.
    #[error("{0:?} didn't expect file descriptors")]
    UnexpectedFds(ExternalFdTarget),
    /// Target without id expected file descriptors.
    #[error("Target without id expected file descriptors")]
    MissingId,
    /// Missing file descriptors for target.
    #[error("Missing file descriptors for {0:?}")]
    MissingFds(ExternalFdTarget),
    /// Unused file descriptors.
    #[error("File descriptors were unused for: {0:?}")]
    SuperfluousFds(Vec<ExternalFdTarget>),
    /// Duplicate entry.
    #[error("Duplicate entry for {0:?}")]
    DuplicatedTargetEntry(ExternalFdTarget),
    /// VFIO file descriptors require an IOMMU file descriptor.
    #[error("VFIO file descriptors require an IOMMU file descriptor")]
    VfioFdsWithoutIommuFd,
    /// IOMMU file descriptor requires VFIO file descriptors.
    #[error("IOMMU file descriptor requires VFIO file descriptors")]
    IommuFdWithoutVfioFds,
    /// `iommufd_fd` was provided without also enabling the iommufd backend.
    #[error("IOMMU file descriptor was provided without enalbing the iommufd backend")]
    IommufdFdRequiresIommufd,
}

/// Trait to update file descriptors after restore/migration.
///
/// During restore or migration, previously used file descriptors become invalid.
/// The trait allows updating those file descriptors with valid ones.
pub(crate) trait UpdateFds {
    /// Checks whether all required file descriptors are present and no more.
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError>;

    /// Updates all file descriptors.
    fn update_fds(
        &mut self,
        external_fds: ExternalFds,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError>;
}

impl UpdateFds for VmConfig {
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        let mut to_validate = BTreeSet::new();
        external_fds.external_fds.iter().try_for_each(|entry| {
            if to_validate.insert(entry.target.clone()) {
                Ok(())
            } else {
                Err(UpdateFdsError::DuplicatedTargetEntry(entry.target.clone()))
            }
        })?;

        let iommu_fd = to_validate.contains(&ExternalFdTarget::Iommu);
        let vfio_fd = to_validate
            .iter()
            .any(|target| matches!(target, ExternalFdTarget::Vfio { .. }));

        self.net.iter().try_for_each(|net_configs| {
            net_configs.iter().try_for_each(|net_config| {
                net_config.validate_fds(external_fds, &mut to_validate, operation)
            })
        })?;

        self.devices.iter().try_for_each(|device_configs| {
            device_configs.iter().try_for_each(|device_config| {
                device_config.validate_fds(external_fds, &mut to_validate, operation)
            })
        })?;

        self.platform.iter().try_for_each(|platform_config| {
            platform_config.validate_fds(external_fds, &mut to_validate, operation)
        })?;

        if vfio_fd && !iommu_fd {
            return Err(UpdateFdsError::VfioFdsWithoutIommuFd);
        }

        if iommu_fd && !vfio_fd {
            return Err(UpdateFdsError::IommuFdWithoutVfioFds);
        }

        if to_validate.is_empty() {
            Ok(())
        } else {
            Err(UpdateFdsError::SuperfluousFds(
                to_validate.into_iter().collect(),
            ))
        }
    }

    fn update_fds(
        &mut self,
        mut external_fds: ExternalFds,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        // Validate before updating to avoid TOCTOU issues.
        self.validate_fds(&external_fds, operation)?;

        self.net.iter_mut().try_for_each(|net_configs| {
            net_configs
                .iter_mut()
                .try_for_each(|net_config| net_config.update_fds(&mut external_fds, operation))
        })?;

        self.devices.iter_mut().try_for_each(|device_configs| {
            device_configs.iter_mut().try_for_each(|device_config| {
                device_config.update_fds(&mut external_fds, operation)
            })
        })?;

        self.platform.iter_mut().try_for_each(|platform_config| {
            platform_config.update_fds(&mut external_fds, operation)
        })
    }
}

/// Helper trait for [`UpdateFds`].
///
/// Should be implemented for members of [`VmConfig`] that carry file descriptors.
trait UpdateFdsComponent {
    /// Checks whether all required file descriptors for this component are present and no more.
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<ExternalFdTarget>,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError>;

    /// Updates all file descriptors of this component.
    fn update_fds(
        &mut self,
        external_fds: &mut ExternalFds,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError>;
}

impl UpdateFdsComponent for NetConfig {
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<ExternalFdTarget>,
        _operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        let Some(id) = &self.pci_common.id else {
            return if self.fds.is_some() {
                Err(UpdateFdsError::MissingId)
            } else {
                Ok(())
            };
        };

        let target = ExternalFdTarget::Net { id: id.clone() };

        let Some(net_fds) = &self.fds else {
            return if external_fds.entry(&target).is_some() {
                Err(UpdateFdsError::UnexpectedFds(target))
            } else {
                Ok(())
            };
        };

        let Some(received_fds) = external_fds.entry(&target) else {
            return Err(UpdateFdsError::MissingFds(target));
        };

        if net_fds.len() != received_fds.fds().len() {
            return Err(UpdateFdsError::FdAmountMismatch {
                target,
                expected: net_fds.len(),
                actual: received_fds.fds().len(),
            });
        }

        to_validate.remove(&target);

        Ok(())
    }

    fn update_fds(
        &mut self,
        external_fds: &mut ExternalFds,
        _operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        let Some(id) = self.pci_common.id.as_ref() else {
            return Ok(());
        };

        let target = ExternalFdTarget::Net { id: id.clone() };

        let Some(mut received_fds) = external_fds.take_entry(&target) else {
            return Ok(());
        };

        self.fds = Some(received_fds.take_fds());

        Ok(())
    }
}

impl UpdateFdsComponent for DeviceConfig {
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<ExternalFdTarget>,
        operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        let Some(id) = &self.pci_common.id else {
            return if self.fd.is_some() {
                Err(UpdateFdsError::MissingId)
            } else {
                Ok(())
            };
        };

        let target = ExternalFdTarget::Vfio { id: id.clone() };

        let received_fds = match operation {
            ExternalFdOperation::Restore => {
                match (self.fd.is_some(), external_fds.entry(&target)) {
                    (true | false, Some(received_fds)) => received_fds,
                    (true, None) => return Err(UpdateFdsError::MissingFds(target)),
                    (false, None) => return Ok(()),
                }
            }
            ExternalFdOperation::ReceiveMigration => {
                let Some(received_fds) = external_fds.entry(&target) else {
                    return Err(UpdateFdsError::MissingFds(target));
                };
                received_fds
            }
            ExternalFdOperation::VmCreate => {
                match (self.fd.is_some(), external_fds.entry(&target)) {
                    (true, Some(received_fds)) => received_fds,
                    (false, Some(_)) => {
                        return Err(UpdateFdsError::SuperfluousFds(vec![target]));
                    }
                    (true, None) => return Err(UpdateFdsError::MissingFds(target)),
                    (false, None) => return Ok(()),
                }
            }
        };

        if received_fds.fds().len() != 1 {
            return Err(UpdateFdsError::FdAmountMismatch {
                target,
                expected: 1,
                actual: received_fds.fds().len(),
            });
        }

        to_validate.remove(&target);

        Ok(())
    }

    fn update_fds(
        &mut self,
        external_fds: &mut ExternalFds,
        _operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        let Some(id) = self.pci_common.id.as_ref() else {
            return Ok(());
        };

        let target = ExternalFdTarget::Vfio { id: id.clone() };

        let Some(mut received_fds) = external_fds.take_entry(&target) else {
            return Ok(());
        };

        self.fd = Some(
            received_fds
                .take_fds()
                .pop()
                .expect("Should be checked during validation"),
        );
        self.path = None;

        Ok(())
    }
}

impl UpdateFdsComponent for PlatformConfig {
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<ExternalFdTarget>,
        _operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        let target = ExternalFdTarget::Iommu;
        let Some(received_fds) = external_fds.entry(&target) else {
            return Ok(());
        };

        if !self.iommufd {
            return Err(UpdateFdsError::IommufdFdRequiresIommufd);
        }

        match received_fds.fds().len() {
            1 => {
                to_validate.remove(&target);
            }
            len => {
                return Err(UpdateFdsError::FdAmountMismatch {
                    target,
                    expected: 1,
                    actual: len,
                });
            }
        }

        Ok(())
    }

    fn update_fds(
        &mut self,
        external_fds: &mut ExternalFds,
        _operation: ExternalFdOperation,
    ) -> Result<(), UpdateFdsError> {
        if let Some(mut received_fds) = external_fds.take_entry(&ExternalFdTarget::Iommu) {
            self.iommufd_fd = Some(
                received_fds
                    .take_fds()
                    .pop()
                    .expect("Should be checked during validation"),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::os::fd::{AsRawFd, RawFd};
    use std::str::FromStr;

    use option_parser::{OptionParser, TupleList};
    use serde::{Deserialize, Serialize};

    use crate::api::VmReceiveMigrationData;
    use crate::config::tests::{net_fixture, platform_fixture};
    use crate::config::{RestoreConfig, RestoredNetConfig, RestoredVfioConfig};
    use crate::external_fds::{
        ExternalFdOperation, ExternalFdTarget, ExternalFds, ExternalFdsEntry,
        ParseExternalFdTargetError, ScmRights, ScmRightsError, UpdateFds, UpdateFdsError,
    };
    use crate::tests::create_dummy_vm_config;
    use crate::vm_config::{
        DeviceConfig, NetConfig, PciDeviceCommonConfig, PlatformConfig, VmConfig,
    };

    pub(crate) fn net_target(id: &str) -> ExternalFdTarget {
        ExternalFdTarget::Net { id: id.to_owned() }
    }

    pub(crate) fn vfio_target(id: &str) -> ExternalFdTarget {
        ExternalFdTarget::Vfio { id: id.to_owned() }
    }

    /// Closes all provided file descriptors.
    ///
    /// # Safety
    ///
    /// The provided file descriptors must not be owned by any other type.
    /// The provided file descriptors are not required to be valid.
    unsafe fn drop_fds(fds: Vec<RawFd>) {
        fds.into_iter().for_each(|fd| {
            //SAFETY: Caller guarantees that no `RawFd`s is owned by any other type.
            unsafe { libc::close(fd) };
        });
    }

    fn dev_null_file() -> File {
        File::open("/dev/null").unwrap()
    }

    fn vfio_vm_config(device_config_fd: Option<RawFd>, iommufd: bool) -> Box<VmConfig> {
        let mut vm_config = create_dummy_vm_config();
        vm_config.devices = Some(vec![DeviceConfig {
            pci_common: PciDeviceCommonConfig {
                id: Some("vfio1".to_owned()),
                ..Default::default()
            },
            path: Some("/dev/vfio/1".into()),
            fd: device_config_fd,
            x_nv_gpudirect_clique: None,
            x_exclude_mmap_bars: vec![],
        }]);
        vm_config.platform = Some(PlatformConfig {
            iommufd,
            ..platform_fixture()
        });
        vm_config
    }

    #[test]
    fn test_parse_external_fd_target_net() {
        assert_eq!(
            net_target("foo"),
            ExternalFdTarget::from_str("net(foo)").unwrap()
        );

        assert_eq!(
            ParseExternalFdTargetError::EmptyIdent("net()".to_owned()),
            ExternalFdTarget::from_str("net()").unwrap_err()
        );

        assert_eq!(
            ParseExternalFdTargetError::InvalidValue("net((".to_owned()),
            ExternalFdTarget::from_str("net((").unwrap_err()
        );

        assert_eq!(
            ParseExternalFdTargetError::InvalidValue("net".to_owned()),
            ExternalFdTarget::from_str("net").unwrap_err()
        );
    }

    #[test]
    fn test_parse_external_fd_target_vfio() {
        assert_eq!(
            vfio_target("foo"),
            ExternalFdTarget::from_str("vfio(foo)").unwrap()
        );

        assert_eq!(
            ParseExternalFdTargetError::EmptyIdent("vfio()".to_owned()),
            ExternalFdTarget::from_str("vfio()").unwrap_err()
        );

        assert_eq!(
            ParseExternalFdTargetError::InvalidValue("vfio((".to_owned()),
            ExternalFdTarget::from_str("vfio((").unwrap_err()
        );

        assert_eq!(
            ParseExternalFdTargetError::InvalidValue("vfio".to_owned()),
            ExternalFdTarget::from_str("vfio").unwrap_err()
        );
    }

    #[test]
    fn test_parse_external_fd_target_iommu() {
        assert_eq!(
            ExternalFdTarget::Iommu,
            ExternalFdTarget::from_str("iommu").unwrap()
        );

        assert_eq!(
            ParseExternalFdTargetError::InvalidValue("iommu(foo)".to_owned()),
            ExternalFdTarget::from_str("iommu(foo)").unwrap_err()
        );
    }

    #[test]
    fn test_parse_external_fd_target_invalid() {
        assert_eq!(
            ExternalFdTarget::Iommu,
            ExternalFdTarget::from_str("iommu").unwrap()
        );
        assert_eq!(
            ParseExternalFdTargetError::InvalidValue("foo".to_owned()),
            ExternalFdTarget::from_str("foo").unwrap_err()
        );
    }

    #[test]
    fn parse_external_fds() {
        let mut parser = OptionParser::new();
        parser.add("external_fds");
        parser
            .parse("external_fds=[net(1)@[1,2],net(2)@[3,4]]")
            .unwrap();

        let external_fds: ExternalFds = parser
            .convert::<TupleList<ExternalFdTarget, Vec<u64>>>("external_fds")
            .unwrap()
            .unwrap()
            .into();

        assert_eq!(
            external_fds,
            ExternalFds {
                external_fds: vec![
                    ExternalFdsEntry::new(net_target("1"), vec![1, 2],),
                    ExternalFdsEntry::new(net_target("2"), vec![3, 4],),
                ]
            }
        );
    }

    #[test]
    fn parse_external_fds_json() {
        #[derive(Serialize, Deserialize)]
        struct Dummy {
            #[serde(default, flatten)]
            external_fds: ExternalFds,
        }

        let serialized = serde_json::to_string(&Dummy {
            external_fds: ExternalFds {
                external_fds: vec![
                    ExternalFdsEntry::new(net_target("1"), vec![1, 2]),
                    ExternalFdsEntry::new(net_target("2"), vec![3, 4]),
                ],
            },
        })
        .unwrap();

        assert_eq!(
            serialized,
            r#"{"external_fds":[{"target":{"Net":{"id":"1"}},"expected_fds":2},{"target":{"Net":{"id":"2"}},"expected_fds":2}]}"#
        );

        let external_fds: Dummy = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            external_fds.external_fds,
            ExternalFds {
                external_fds: vec![
                    ExternalFdsEntry {
                        target: net_target("1"),
                        expected_fds: 2,
                        received_fds: vec![],
                    },
                    ExternalFdsEntry {
                        target: net_target("2"),
                        expected_fds: 2,
                        received_fds: vec![],
                    },
                ]
            }
        );
    }

    #[test]
    fn external_fds_entry_update() {
        let mut entry = ExternalFdsEntry::new(ExternalFdTarget::Iommu, vec![0]);
        let mut files = vec![dev_null_file(), dev_null_file()];
        let file_raw = files[0].as_raw_fd();
        let trailing_file_raw = files[1].as_raw_fd();
        entry.update_from_scm_rights(&mut files).unwrap();
        assert_eq!(entry.received_fds[0], file_raw);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].as_raw_fd(), trailing_file_raw);
        // SAFETY: The FDs in `entry` are not owned by any other type and moved out of `entry`.
        unsafe { drop_fds(entry.take_fds()) };

        let mut entry = ExternalFdsEntry::new(
            ExternalFdTarget::Net {
                id: "net1".to_owned(),
            },
            vec![0, 1, 2, 3, 4, 5],
        );
        let file = dev_null_file();

        let mut files = vec![file];
        assert_eq!(
            entry.update_from_scm_rights(&mut files),
            Err(ScmRightsError::TooFewFds)
        );
        assert_eq!(entry.received_fds, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn external_fds_entry_take_fds() {
        let mut entry = ExternalFdsEntry {
            target: ExternalFdTarget::Iommu,
            expected_fds: 1,
            received_fds: vec![1],
        };

        assert_eq!(entry.take_fds(), vec![1]);
    }

    #[test]
    fn external_fds_entry_fds() {
        let entry = ExternalFdsEntry {
            target: ExternalFdTarget::Iommu,
            expected_fds: 1,
            received_fds: vec![1],
        };

        assert_eq!(entry.fds(), &[1]);
    }

    #[test]
    fn restored_net_config_to_external_fds_entry() {
        assert_eq!(
            ExternalFdsEntry::from(RestoredNetConfig {
                id: "net1".to_string(),
                num_fds: 3,
                fds: Some(vec![-1, 2, 3]),
            }),
            ExternalFdsEntry {
                target: ExternalFdTarget::Net {
                    id: "net1".to_owned()
                },
                expected_fds: 3,
                received_fds: vec![2, 3],
            }
        );

        assert_eq!(
            ExternalFdsEntry::from(RestoredNetConfig {
                id: "net1".to_string(),
                num_fds: 3,
                fds: None,
            }),
            ExternalFdsEntry {
                target: ExternalFdTarget::Net {
                    id: "net1".to_owned()
                },
                expected_fds: 3,
                received_fds: vec![],
            }
        );

        assert_eq!(
            ExternalFdsEntry::from(RestoredNetConfig {
                id: "net1".to_string(),
                num_fds: 0,
                fds: None,
            }),
            ExternalFdsEntry {
                target: ExternalFdTarget::Net {
                    id: "net1".to_owned()
                },
                expected_fds: 0,
                received_fds: vec![],
            }
        );
    }

    #[test]
    fn restored_vfio_config_to_external_fds_entry() {
        assert_eq!(
            ExternalFdsEntry::from(RestoredVfioConfig {
                id: "vfio1".to_string(),
                fd: Some(1),
            }),
            ExternalFdsEntry {
                target: ExternalFdTarget::Vfio {
                    id: "vfio1".to_owned()
                },
                expected_fds: 1,
                received_fds: vec![1],
            }
        );

        assert_eq!(
            ExternalFdsEntry::from(RestoredVfioConfig {
                id: "vfio1".to_string(),
                fd: Some(-1),
            }),
            ExternalFdsEntry {
                target: ExternalFdTarget::Vfio {
                    id: "vfio1".to_owned()
                },
                expected_fds: 1,
                received_fds: vec![],
            }
        );

        assert_eq!(
            ExternalFdsEntry::from(RestoredVfioConfig {
                id: "vfio1".to_string(),
                fd: None,
            }),
            ExternalFdsEntry {
                target: ExternalFdTarget::Vfio {
                    id: "vfio1".to_owned()
                },
                expected_fds: 1,
                received_fds: vec![],
            }
        );
    }

    #[test]
    fn external_fds_take_entry() {
        let target = net_target("net1");
        let mut external_fds: ExternalFds = vec![(target.clone(), vec![1, 2, 3])].into();

        assert_eq!(
            external_fds.take_entry(&target),
            Some(ExternalFdsEntry {
                target: target.clone(),
                expected_fds: 3,
                received_fds: vec![1, 2, 3],
            })
        );

        assert_eq!(external_fds.take_entry(&target), None);
    }

    #[test]
    fn external_fds_entry() {
        let target = net_target("net1");
        let external_fds: ExternalFds = vec![(target.clone(), vec![1, 2, 3])].into();

        assert_eq!(
            external_fds.entry(&target),
            Some(&ExternalFdsEntry {
                target: target.clone(),
                expected_fds: 3,
                received_fds: vec![1, 2, 3],
            })
        );
    }

    #[test]
    fn external_fds_entries() {
        let target = net_target("net1");
        let raw_fds = vec![1, 2, 3];
        let external_fds: ExternalFds = vec![
            (target.clone(), raw_fds.clone()),
            (target.clone(), raw_fds.clone()),
        ]
        .into();

        assert_eq!(
            external_fds.entries(),
            vec![(&target, 3, &raw_fds), (&target, 3, &raw_fds),]
        );
    }

    #[test]
    fn external_fds_take_raw_fds() {
        let target = net_target("net1");
        let mut external_fds: ExternalFds =
            vec![(target.clone(), vec![1, 2, 3]), (target, vec![4, 5, 6])].into();

        assert_eq!(external_fds.take_raw_fds(), vec![1, 2, 3, 4, 5, 6]);
        assert!(
            external_fds
                .external_fds
                .iter()
                .all(|entry| entry.received_fds.is_empty())
        );
    }

    #[test]
    fn external_fds_is_empty() {
        let target = net_target("net1");
        let mut external_fds: ExternalFds = vec![(target.clone(), vec![1, 2, 3])].into();

        assert!(!external_fds.is_empty());
        let _ = external_fds.take_entry(&target);
        assert!(external_fds.is_empty());
    }

    #[test]
    fn scm_rights_external_fds() {
        let mut external_fds = ExternalFds {
            external_fds: vec![
                ExternalFdsEntry::new(ExternalFdTarget::Iommu, vec![0]),
                ExternalFdsEntry::new(net_target("net1"), vec![0, 0]),
            ],
        };
        let files = vec![dev_null_file(), dev_null_file(), dev_null_file()];
        let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();

        external_fds.consume_fds(files).unwrap();
        assert_eq!(
            external_fds.entries(),
            vec![
                (&ExternalFdTarget::Iommu, 1, &vec![raw_fds[0]]),
                (&net_target("net1"), 2, &vec![raw_fds[1], raw_fds[2]]),
            ]
        );
        // SAFETY: FDs in `ExternalFds` are not dropped in tests.
        unsafe { drop_fds(raw_fds) };

        let mut external_fds = ExternalFds {
            external_fds: vec![
                ExternalFdsEntry::new(net_target("net1"), vec![0, 0, 0]),
                ExternalFdsEntry::new(net_target("net2"), vec![]),
                ExternalFdsEntry::new(net_target("net3"), vec![0, 0]),
            ],
        };
        let files = vec![
            dev_null_file(),
            dev_null_file(),
            dev_null_file(),
            dev_null_file(),
            dev_null_file(),
        ];
        let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();

        external_fds.consume_fds(files).unwrap();
        assert_eq!(
            external_fds.entries(),
            vec![
                (
                    &net_target("net1"),
                    3,
                    &vec![raw_fds[0], raw_fds[1], raw_fds[2]]
                ),
                (&net_target("net2"), 0, &vec![]),
                (&net_target("net3"), 2, &vec![raw_fds[3], raw_fds[4]]),
            ]
        );
        // SAFETY: FDs in `ExternalFds` are not dropped in tests.
        unsafe { drop_fds(raw_fds) };

        let mut external_fds = ExternalFds {
            external_fds: vec![ExternalFdsEntry::new(ExternalFdTarget::Iommu, vec![0])],
        };
        let files = vec![dev_null_file(), dev_null_file()];
        assert_eq!(
            external_fds.consume_fds(files),
            Err(ScmRightsError::TooManyFds)
        );
    }

    #[test]
    fn external_fds_import_restored_net_configs() {
        let restored_net_config1 = RestoredNetConfig {
            id: "net1".to_owned(),
            num_fds: 1,
            fds: None,
        };
        let restored_net_config2 = RestoredNetConfig {
            id: "net2".to_owned(),
            num_fds: 1,
            fds: Some(vec![-1, 1]),
        };
        let restored_net_config3 = RestoredNetConfig {
            id: "net3".to_owned(),
            num_fds: 10,
            fds: Some(vec![1, -1]),
        };
        let mut external_fds = ExternalFds::default();
        external_fds.import_restored_net_configs(&mut Some(vec![
            restored_net_config1,
            restored_net_config2,
            restored_net_config3,
        ]));
        assert_eq!(
            external_fds.entries(),
            vec![
                (&net_target("net1"), 1, &vec![]),
                (&net_target("net2"), 1, &vec![1]),
                (&net_target("net3"), 10, &vec![1]),
            ]
        );
    }

    #[test]
    fn external_fds_import_restored_vfio_configs() {
        let restored_vfio_config1 = RestoredVfioConfig {
            id: "vfio1".to_owned(),
            fd: None,
        };
        let restored_vfio_config2 = RestoredVfioConfig {
            id: "vfio2".to_owned(),
            fd: Some(1),
        };
        let restored_vfio_config3 = RestoredVfioConfig {
            id: "vfio3".to_owned(),
            fd: Some(-1),
        };
        let mut external_fds = ExternalFds::default();
        external_fds.import_restored_vfio_configs(&mut Some(vec![
            restored_vfio_config1,
            restored_vfio_config2,
            restored_vfio_config3,
        ]));
        assert_eq!(
            external_fds.entries(),
            vec![
                (&vfio_target("vfio1"), 1, &vec![]),
                (&vfio_target("vfio2"), 1, &vec![1]),
                (&vfio_target("vfio3"), 1, &vec![]),
            ]
        );
    }

    #[test]
    fn external_fds_import_restored_iommufd_fd() {
        let mut external_fds = ExternalFds::default();
        external_fds.import_restored_iommufd_fd(&mut None);
        assert_eq!(external_fds.entries(), vec![]);
        let mut external_fds = ExternalFds::default();
        external_fds.import_restored_iommufd_fd(&mut Some(-1));
        assert_eq!(
            external_fds.entries(),
            vec![(&ExternalFdTarget::Iommu, 1, &vec![]),]
        );

        let mut external_fds = ExternalFds::default();
        external_fds.import_restored_iommufd_fd(&mut Some(1));
        assert_eq!(
            external_fds.entries(),
            vec![(&ExternalFdTarget::Iommu, 1, &vec![1]),]
        );
    }

    #[test]
    fn scm_rights_net_config() {
        let net_config = NetConfig {
            pci_common: Default::default(),
            tap: None,
            ip: None,
            mask: None,
            mac: None,
            host_mac: None,
            mtu: None,
            num_queues: 0,
            queue_size: 0,
            vhost_user: false,
            vhost_socket: None,
            vhost_mode: Default::default(),
            fds: None,
            rate_limiter_config: None,
            offload_tso: false,
            offload_ufo: false,
            offload_csum: false,
        };
        {
            let mut net_config = net_config.clone();
            let files = vec![dev_null_file(), dev_null_file(), dev_null_file()];
            let raw_fds = files.iter().map(AsRawFd::as_raw_fd).collect();
            net_config.consume_fds(files).unwrap();
            assert_eq!(net_config.fds.as_ref(), Some(&raw_fds));
            //SAFETY: FDs in `ExternalFds` are not dropped in tests.
            unsafe { drop_fds(raw_fds) };
        }
        {
            let mut net_config = net_config.clone();
            net_config.consume_fds(vec![]).unwrap();
            assert_eq!(net_config.fds, None);
        }
    }

    #[test]
    fn scm_rights_device_config() {
        let device_config = DeviceConfig {
            pci_common: Default::default(),
            path: None,
            fd: None,
            x_nv_gpudirect_clique: None,
            x_exclude_mmap_bars: vec![],
        };

        {
            let mut device_config = device_config.clone();
            let files = vec![dev_null_file()];
            let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
            device_config.consume_fds(files).unwrap();
            assert_eq!(device_config.fd.as_ref(), Some(&raw_fds[0]));
            //SAFETY: FDs in `ExternalFds` are not dropped in tests.
            unsafe { drop_fds(raw_fds) };
        }
        {
            let mut device_config = device_config.clone();
            let files = vec![dev_null_file(), dev_null_file(), dev_null_file()];
            assert_eq!(
                device_config.consume_fds(files),
                Err(ScmRightsError::TooManyFds)
            );
        }
        {
            let mut device_config = device_config.clone();
            device_config.consume_fds(vec![]).unwrap();
            assert_eq!(device_config.fd, None);
        }
    }

    #[test]
    fn scm_rights_vm_receive_migration_data() {
        {
            let mut vm_receive_migration_data = VmReceiveMigrationData::default();
            let files = vec![dev_null_file()];
            assert_eq!(
                vm_receive_migration_data.consume_fds(files),
                Err(ScmRightsError::TooManyFds)
            );
        }

        let vm_receive_migration_data = VmReceiveMigrationData {
            vfio_fds: Some(vec![
                RestoredVfioConfig {
                    id: "vfio1".to_owned(),
                    fd: Some(1),
                },
                RestoredVfioConfig {
                    id: "vfio2".to_owned(),
                    fd: Some(1),
                },
            ]),
            iommufd_fd: Some(-1),
            ..Default::default()
        };

        {
            let mut vm_receive_migration_data = vm_receive_migration_data.clone();
            let files = vec![dev_null_file()];
            assert_eq!(
                vm_receive_migration_data.consume_fds(files),
                Err(ScmRightsError::TooFewFds)
            );
        }

        {
            let mut vm_receive_migration_data = vm_receive_migration_data.clone();
            let files = vec![dev_null_file(), dev_null_file(), dev_null_file()];
            let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();

            vm_receive_migration_data.consume_fds(files).unwrap();
            assert_eq!(
                vm_receive_migration_data.external_fds.entries(),
                vec![
                    (&vfio_target("vfio1"), 1, &vec![raw_fds[0]]),
                    (&vfio_target("vfio2"), 1, &vec![raw_fds[1]]),
                    (&ExternalFdTarget::Iommu, 1, &vec![raw_fds[2]]),
                ],
            );

            //SAFETY: FDs in `ExternalFds` are not dropped in tests.
            unsafe { drop_fds(raw_fds) };
        }

        {
            let mut vm_receive_migration_data = vm_receive_migration_data.clone();
            let files = vec![
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
            ];
            assert_eq!(
                vm_receive_migration_data.consume_fds(files),
                Err(ScmRightsError::TooManyFds)
            );
        }
    }

    #[test]
    fn scm_rights_restore_config() {
        {
            let mut restore_config = RestoreConfig::default();
            let files = vec![dev_null_file()];
            assert_eq!(
                restore_config.consume_fds(files),
                Err(ScmRightsError::TooManyFds)
            );
        }

        let restore_config = RestoreConfig {
            net_fds: Some(vec![
                RestoredNetConfig {
                    id: "net1".to_string(),
                    num_fds: 1,
                    fds: Some(vec![-1]),
                },
                RestoredNetConfig {
                    id: "net2".to_string(),
                    num_fds: 5,
                    fds: Some(vec![1]),
                },
            ]),
            vfio_fds: Some(vec![
                RestoredVfioConfig {
                    id: "vfio1".to_owned(),
                    fd: Some(1),
                },
                RestoredVfioConfig {
                    id: "vfio2".to_owned(),
                    fd: Some(1),
                },
            ]),
            iommufd_fd: Some(-1),
            ..Default::default()
        };

        {
            let mut restore_config = restore_config.clone();
            let files = vec![dev_null_file()];
            assert_eq!(
                restore_config.consume_fds(files),
                Err(ScmRightsError::TooFewFds)
            );
        }

        {
            let mut restore_config = restore_config.clone();
            let files = vec![
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
            ];
            let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();

            restore_config.consume_fds(files).unwrap();
            assert_eq!(
                restore_config.external_fds.entries(),
                vec![
                    (&net_target("net1"), 1, &vec![raw_fds[0]]),
                    (
                        &net_target("net2"),
                        5,
                        &vec![raw_fds[1], raw_fds[2], raw_fds[3], raw_fds[4], raw_fds[5]]
                    ),
                    (&vfio_target("vfio1"), 1, &vec![raw_fds[6]]),
                    (&vfio_target("vfio2"), 1, &vec![raw_fds[7]]),
                    (&ExternalFdTarget::Iommu, 1, &vec![raw_fds[8]]),
                ],
            );

            //SAFETY: FDs in `ExternalFds` are not dropped in tests.
            unsafe { drop_fds(raw_fds) };
        }

        {
            let mut restore_config = restore_config.clone();
            let files = vec![
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
                dev_null_file(),
            ];
            assert_eq!(
                restore_config.consume_fds(files),
                Err(ScmRightsError::TooManyFds)
            );
        }
    }

    #[test]
    fn scm_rights_vm_config() {
        let mut vm_config = create_dummy_vm_config();

        let files = vec![dev_null_file()];
        assert_eq!(
            vm_config.consume_fds(files),
            Err(ScmRightsError::Unsupported)
        );
        let files = vec![];
        assert_eq!(vm_config.consume_fds(files), Ok(()));
    }

    #[test]
    fn update_fds_vm_config() {
        {
            let mut vm_config = create_dummy_vm_config();
            let external_fds = ExternalFds::default();
            vm_config
                .update_fds(external_fds, ExternalFdOperation::VmCreate)
                .unwrap();
            assert_eq!(vm_config, create_dummy_vm_config());
            let external_fds = ExternalFds::default();
            vm_config
                .update_fds(external_fds, ExternalFdOperation::ReceiveMigration)
                .unwrap();
            assert_eq!(vm_config, create_dummy_vm_config());
            let external_fds = ExternalFds::default();
            vm_config
                .update_fds(external_fds, ExternalFdOperation::Restore)
                .unwrap();
            assert_eq!(vm_config, create_dummy_vm_config());
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: Some(vec![-1]),
                ..net_fixture()
            }]);

            let external_fds = vec![(net_target("net1"), vec![1])].into();
            vm_config
                .update_fds(external_fds, ExternalFdOperation::VmCreate)
                .unwrap();
            assert_eq!(
                vm_config
                    .net
                    .as_ref()
                    .unwrap()
                    .first()
                    .as_ref()
                    .unwrap()
                    .fds
                    .as_ref()
                    .unwrap(),
                &[1]
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: Some(vec![-1]),
                ..net_fixture()
            }]);

            let external_fds =
                vec![(net_target("net1"), vec![1]), (net_target("net1"), vec![1])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::DuplicatedTargetEntry(net_target("net1")))
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: None,
                    ..Default::default()
                },
                fds: Some(vec![-1]),
                ..net_fixture()
            }]);

            let external_fds = vec![(net_target("net1"), vec![1])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::MissingId)
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: None,
                ..net_fixture()
            }]);

            let external_fds = vec![(net_target("net1"), vec![1])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::UnexpectedFds(net_target("net1")))
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: None,
                ..net_fixture()
            }]);

            let external_fds = ExternalFds::default();
            let vm_config_expected = vm_config.clone();

            vm_config
                .update_fds(external_fds, ExternalFdOperation::VmCreate)
                .unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: Some(vec![-1, -1]),
                ..net_fixture()
            }]);
            let vm_config_expected = vm_config.clone();

            assert_eq!(
                vm_config.update_fds(ExternalFds::default(), ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::MissingFds(net_target("net1")))
            );
            assert_eq!(vm_config, vm_config_expected);

            let external_fds = vec![(net_target("net1"), vec![1])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::FdAmountMismatch {
                    target: net_target("net1"),
                    expected: 2,
                    actual: 1,
                })
            );
            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: None,
                    ..Default::default()
                },
                fds: None,
                ..net_fixture()
            }]);
            let vm_config_expected = vm_config.clone();

            vm_config
                .update_fds(ExternalFds::default(), ExternalFdOperation::VmCreate)
                .unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = create_dummy_vm_config();
            let external_fds = vec![(net_target("net1"), vec![1])].into();

            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::SuperfluousFds(vec![net_target("net1")]))
            );
        }
    }

    #[test]
    fn update_fds_vm_config_vfio_and_iommu() {
        {
            for operation in [
                ExternalFdOperation::Restore,
                ExternalFdOperation::ReceiveMigration,
                ExternalFdOperation::VmCreate,
            ] {
                let mut vm_config = vfio_vm_config(
                    (operation == ExternalFdOperation::VmCreate).then_some(-1),
                    true,
                );
                let external_fds = vec![
                    (vfio_target("vfio1"), vec![1]),
                    (ExternalFdTarget::Iommu, vec![2]),
                ]
                .into();

                vm_config.update_fds(external_fds, operation).unwrap();
                let device_config = &vm_config.devices.as_ref().unwrap()[0];
                assert_eq!(device_config.fd, Some(1));
                assert_eq!(device_config.path, None);
                assert_eq!(vm_config.platform.as_ref().unwrap().iommufd_fd, Some(2));
            }
        }

        {
            let mut vm_config = vfio_vm_config(None, true);
            vm_config.devices.as_mut().unwrap().insert(
                0,
                DeviceConfig {
                    pci_common: PciDeviceCommonConfig {
                        id: Some("vfio0".to_owned()),
                        ..Default::default()
                    },
                    path: Some("/dev/vfio/0".into()),
                    fd: None,
                    x_nv_gpudirect_clique: None,
                    x_exclude_mmap_bars: vec![],
                },
            );
            let external_fds = vec![
                (vfio_target("vfio1"), vec![1]),
                (ExternalFdTarget::Iommu, vec![2]),
            ]
            .into();

            vm_config
                .update_fds(external_fds, ExternalFdOperation::Restore)
                .unwrap();
            let devices = vm_config.devices.as_ref().unwrap();
            assert_eq!(devices[0].path, Some("/dev/vfio/0".into()));
            assert_eq!(devices[0].fd, None);
            assert_eq!(devices[1].path, None);
            assert_eq!(devices[1].fd, Some(1));
            assert_eq!(vm_config.platform.as_ref().unwrap().iommufd_fd, Some(2));
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), true);
            vm_config.devices.as_mut().unwrap()[0].pci_common.id = None;
            assert_eq!(
                vm_config.update_fds(ExternalFds::default(), ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::MissingId)
            );
        }

        {
            let mut vm_config = vfio_vm_config(None, true);
            vm_config.devices.as_mut().unwrap()[0].pci_common.id = None;
            let vm_config_expected = vm_config.clone();

            vm_config
                .update_fds(ExternalFds::default(), ExternalFdOperation::VmCreate)
                .unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), true);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![1, 2]),
                (ExternalFdTarget::Iommu, vec![3]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::FdAmountMismatch {
                    target: vfio_target("vfio1"),
                    expected: 1,
                    actual: 2,
                })
            );
        }

        {
            let mut vm_config = vfio_vm_config(None, true);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![1]),
                (ExternalFdTarget::Iommu, vec![2]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::SuperfluousFds(vec![vfio_target("vfio1")]))
            );
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), true);
            assert_eq!(
                vm_config.update_fds(ExternalFds::default(), ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::MissingFds(vfio_target("vfio1")))
            );
        }

        {
            let mut vm_config = vfio_vm_config(None, true);
            let vm_config_expected = vm_config.clone();

            vm_config
                .update_fds(ExternalFds::default(), ExternalFdOperation::VmCreate)
                .unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = vfio_vm_config(None, true);
            let vm_config_expected = vm_config.clone();

            vm_config
                .update_fds(ExternalFds::default(), ExternalFdOperation::Restore)
                .unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), true);
            let external_fds = vec![(ExternalFdTarget::Iommu, vec![2])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::Restore),
                Err(UpdateFdsError::MissingFds(vfio_target("vfio1")))
            );
        }

        {
            let mut vm_config = vfio_vm_config(None, true);
            let external_fds = vec![(ExternalFdTarget::Iommu, vec![2])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::ReceiveMigration),
                Err(UpdateFdsError::MissingFds(vfio_target("vfio1")))
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.platform = Some(PlatformConfig {
                iommufd: true,
                ..platform_fixture()
            });
            let external_fds = vec![(ExternalFdTarget::Iommu, vec![1])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::IommuFdWithoutVfioFds)
            );
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), true);
            let external_fds = vec![(vfio_target("vfio1"), vec![1])].into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::VfioFdsWithoutIommuFd)
            );
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), false);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![1]),
                (ExternalFdTarget::Iommu, vec![2]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::IommufdFdRequiresIommufd)
            );
        }

        {
            let mut vm_config = vfio_vm_config(Some(-1), true);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![1]),
                (ExternalFdTarget::Iommu, vec![]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds, ExternalFdOperation::VmCreate),
                Err(UpdateFdsError::FdAmountMismatch {
                    target: ExternalFdTarget::Iommu,
                    expected: 1,
                    actual: 0,
                })
            );
        }
    }
}
