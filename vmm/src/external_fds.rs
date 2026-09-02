// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! External file descriptor handling.

#![allow(unused, reason = "Will be used in later commits")]

use std::collections::BTreeSet;
use std::fs::File;
use std::mem;
use std::str::FromStr;

use option_parser::{Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;
use crate::vm_config::{DeviceConfig, ExternalFd, NetConfig, PlatformConfig, VmConfig};

/// A resource that can be backed by one or more file descriptors.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Target {
    Net { id: String },
    Vfio { id: String },
    Iommu,
}

/// Errors parsing [`Target`].
#[derive(Debug, Eq, PartialEq)]
pub enum ParseTargetError {
    InvalidValue(String),
    EmptyTarget(String),
}

impl FromStr for Target {
    type Err = ParseTargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let contains_parenthesis = s.contains("(");
        let (target, rest) = s.split_once("(").unwrap_or((s, ""));

        fn parse_id(
            input: &str,
            constructor: fn(String) -> Target,
            original: &str,
        ) -> Result<Target, <Target as FromStr>::Err> {
            if let Some((id, "")) = input.split_once(")") {
                if id.is_empty() {
                    Err(ParseTargetError::EmptyTarget(original.to_owned()))
                } else {
                    Ok(constructor(id.to_owned()))
                }
            } else {
                Err(ParseTargetError::InvalidValue(original.to_owned()))
            }
        }

        match target {
            "net" => parse_id(rest, |id| Target::Net { id }, s),
            "vfio" => parse_id(rest, |id| Target::Vfio { id }, s),
            "iommu" => {
                if rest.is_empty() && !contains_parenthesis {
                    Ok(Target::Iommu)
                } else {
                    Err(ParseTargetError::InvalidValue(s.to_owned()))
                }
            }
            _ => Err(ParseTargetError::InvalidValue(s.to_owned())),
        }
    }
}

/// Metadata and file descriptors for one [`Target`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    target: Target,
    expected_fds: usize,
    #[serde(skip)]
    received_fds: Vec<ExternalFd>,
}

impl Entry {
    /// Updates all file descriptors from the provided `files` list.
    ///
    /// Consumes only as many file descriptors as necessary and leaves remaining file descriptors untouched.
    fn update_from_scm_rights(&mut self, files: &mut Vec<File>) -> Result<(), ScmRightsError> {
        if self.expected_fds <= files.len() {
            self.received_fds = files.drain(..self.expected_fds).map(From::from).collect();
            Ok(())
        } else {
            Err(ScmRightsError::TooFewFds)
        }
    }

    fn take_fds(&mut self) -> Vec<ExternalFd> {
        mem::take(&mut self.received_fds)
    }

    fn fds(&self) -> &[ExternalFd] {
        &self.received_fds
    }

    fn new(target: Target, files: Vec<ExternalFd>) -> Self {
        Self {
            target,
            expected_fds: files.len(),
            received_fds: files,
        }
    }

    /// Returns the number of expected file descriptors.
    fn expected_fds(&self) -> usize {
        self.expected_fds
    }
}

impl Clone for Entry {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            expected_fds: self.expected_fds,
            received_fds: self.received_fds.clone(),
        }
    }
}

/// External file descriptors provided by API or CLI.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct ExternalFds {
    #[serde(default)]
    external_fds: Vec<Entry>,
}

impl ExternalFds {
    /// Takes the entry associated with `target` out of `Self`, if present.
    ///
    /// This does not preserve the order of entries.
    fn take_entry(&mut self, target: &Target) -> Option<Entry> {
        let position = self
            .external_fds
            .iter()
            .position(|entry| &entry.target == target)?;
        Some(self.external_fds.swap_remove(position))
    }

    fn entry(&self, target: &Target) -> Option<&Entry> {
        self.external_fds
            .iter()
            .find(|entry| &entry.target == target)
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> Vec<(&Target, usize, &Vec<ExternalFd>)> {
        self.external_fds
            .iter()
            .map(|entry| (&entry.target, entry.expected_fds, &entry.received_fds))
            .collect()
    }

    /// Takes all file descriptors out of `Self`.
    ///
    /// Preserves the order to allow ingesting the file descriptors again.
    fn take_fds(&mut self) -> Vec<ExternalFd> {
        self.external_fds
            .iter_mut()
            .flat_map(|fd| mem::take(&mut fd.received_fds))
            .collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.external_fds.is_empty()
    }

    /// Returns the number of expected file descriptors or `None` on overflow.
    fn expected_fds(&self) -> Option<usize> {
        self.external_fds
            .iter()
            .try_fold(0, |acc: usize, entry| acc.checked_add(entry.expected_fds()))
    }

    /// # Safety
    ///
    /// A live fd must be exclusively owned by the caller, which transfers it here.
    unsafe fn from_cli(value: TupleList<Target, Vec<u64>>) -> Result<Self, config::Error> {
        Ok(Self {
            external_fds: value
                .0
                .into_iter()
                .map(|Tuple(target, fds)| {
                    Ok(Entry::new(
                        target,
                        fds.into_iter()
                            .map(|fd| {
                                // SAFETY: The caller transfers ownership of the inherited CLI descriptors.
                                unsafe { config::take_inherited_fd(fd) }
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[cfg(test)]
impl From<Vec<(Target, Vec<ExternalFd>)>> for ExternalFds {
    fn from(value: Vec<(Target, Vec<ExternalFd>)>) -> Self {
        Self {
            external_fds: value
                .into_iter()
                .map(|(target, fds)| Entry::new(target, fds))
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
///
/// ## Implementation note
///
/// `ScmRights::take_fds` must provide file descriptors in the same order `ScmRights::consume_fds` expects them.
pub trait ScmRights {
    /// Consumes `files` and updates all internal file descriptors.
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError>;

    /// Takes all file descriptors out of `Self`.
    ///
    /// Preserves the order to allow ingesting the file descriptors again.
    fn take_fds(&mut self) -> Vec<ExternalFd>;
}

impl ScmRights for NetConfig {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        let fds: Vec<_> = files.into_iter().map(From::from).collect();

        if fds.is_empty() {
            self.fds = None;
        } else {
            self.fds = Some(fds);
        }

        Ok(())
    }

    fn take_fds(&mut self) -> Vec<ExternalFd> {
        self.fds.take().unwrap_or_default()
    }
}

impl ScmRights for DeviceConfig {
    fn consume_fds(&mut self, files: Vec<File>) -> Result<(), ScmRightsError> {
        if files.len() > 1 {
            Err(ScmRightsError::TooManyFds)
        } else {
            self.fd = files.into_iter().map(From::from).next().unwrap_or_default();
            Ok(())
        }
    }
    fn take_fds(&mut self) -> Vec<ExternalFd> {
        vec![mem::take(&mut self.fd)]
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

    fn take_fds(&mut self) -> Vec<ExternalFd> {
        Vec::new()
    }
}

impl ScmRights for ExternalFds {
    fn consume_fds(&mut self, mut files: Vec<File>) -> Result<(), ScmRightsError> {
        // Check supplied and expected FD amount match before applying to prevent leaking FDs on failure.
        let expected_fds = self.expected_fds().ok_or(ScmRightsError::TooManyFds)?;
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

    fn take_fds(&mut self) -> Vec<ExternalFd> {
        self.take_fds()
    }
}

/// Errors that can occur when updating file descriptors in a [`VmConfig`].
#[derive(Error, Debug, Eq, PartialEq)]
pub enum UpdateFdsError {
    /// Mismatch between number of expected and actual file descriptor.
    #[error(
        "Mismatch between number of expected and actual file descriptor for \"{target:?}\": actual: {actual}, expected: {expected}"
    )]
    FdAmountMismatch {
        target: Target,
        expected: usize,
        actual: usize,
    },
    /// Target didn't expect file descriptors.
    #[error("{0:?} didn't expect file descriptors")]
    UnexpectedFds(Target),
    /// Target without id expected file descriptors.
    #[error("Target without id expected file descriptors")]
    MissingId,
    /// Missing file descriptors for target.
    #[error("Missing file descriptors for {0:?}")]
    MissingFds(Target),
    /// Unused file descriptors.
    #[error("File descriptors were unused for: {0:?}")]
    SuperfluousFds(Vec<Target>),
    /// Duplicate entry.
    #[error("Duplicate entry for {0:?}")]
    DuplicatedTargetEntry(Target),
    /// VFIO file descriptors require an IOMMU file descriptor.
    #[error("VFIO file descriptors require an IOMMU file descriptor")]
    VfioFdsWithoutIommuFd,
    /// IOMMU file descriptor requires VFIO file descriptors.
    #[error("IOMMU file descriptor requires VFIO file descriptors")]
    IommuFdWithoutVfioFds,
    /// `iommufd_fd` was provided without also enabling the iommufd backend.
    #[error("IOMMU file descriptor was provided without enabling the iommufd backend")]
    IommufdFdRequiresIommufdBackend,
}

impl VmConfig {
    pub(crate) fn validate_fds(&self, external_fds: &ExternalFds) -> Result<(), UpdateFdsError> {
        let mut to_validate = BTreeSet::new();
        external_fds.external_fds.iter().try_for_each(|entry| {
            if to_validate.insert(entry.target.clone()) {
                Ok(())
            } else {
                Err(UpdateFdsError::DuplicatedTargetEntry(entry.target.clone()))
            }
        })?;

        let iommu_fd = to_validate.contains(&Target::Iommu);
        let vfio_fd = to_validate
            .iter()
            .any(|target| matches!(target, Target::Vfio { .. }));

        self.net.iter().try_for_each(|net_configs| {
            net_configs
                .iter()
                .try_for_each(|net_config| net_config.validate_fds(external_fds, &mut to_validate))
        })?;

        self.devices.iter().try_for_each(|device_configs| {
            device_configs.iter().try_for_each(|device_config| {
                device_config.validate_fds(external_fds, &mut to_validate)
            })
        })?;

        self.platform.iter().try_for_each(|platform_config| {
            platform_config.validate_fds(external_fds, &mut to_validate)
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

    pub(crate) fn update_fds(
        &mut self,
        mut external_fds: ExternalFds,
    ) -> Result<(), UpdateFdsError> {
        // Validate before updating to avoid TOCTOU issues.
        self.validate_fds(&external_fds)?;

        self.net.iter_mut().try_for_each(|net_configs| {
            net_configs
                .iter_mut()
                .try_for_each(|net_config| net_config.update_fds(&mut external_fds))
        })?;

        self.devices.iter_mut().try_for_each(|device_configs| {
            device_configs
                .iter_mut()
                .try_for_each(|device_config| device_config.update_fds(&mut external_fds))
        })?;

        self.platform
            .iter_mut()
            .try_for_each(|platform_config| platform_config.update_fds(&mut external_fds))
    }
}

/// Helper trait for updating file descriptors in [`VmConfig`].
///
/// Should be implemented for members of [`VmConfig`] that carry file descriptors.
trait UpdateFdsComponent {
    /// Checks whether all required file descriptors for this component are present and no more.
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<Target>,
    ) -> Result<(), UpdateFdsError>;

    /// Updates all file descriptors of this component.
    fn update_fds(&mut self, external_fds: &mut ExternalFds) -> Result<(), UpdateFdsError>;
}

impl UpdateFdsComponent for NetConfig {
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<Target>,
    ) -> Result<(), UpdateFdsError> {
        let Some(id) = &self.pci_common.id else {
            if self.fds.is_some() {
                return Err(UpdateFdsError::MissingId);
            }
            return Ok(());
        };

        let target = Target::Net { id: id.clone() };

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

    fn update_fds(&mut self, external_fds: &mut ExternalFds) -> Result<(), UpdateFdsError> {
        let Some(id) = self.pci_common.id.as_ref() else {
            if self.fds.is_some() {
                return Err(UpdateFdsError::MissingId);
            }
            return Ok(());
        };

        let target = Target::Net { id: id.clone() };

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
        to_validate: &mut BTreeSet<Target>,
    ) -> Result<(), UpdateFdsError> {
        let Some(id) = &self.pci_common.id else {
            if self.path.is_none() {
                return Err(UpdateFdsError::MissingId);
            }
            return Ok(());
        };

        let target = Target::Vfio { id: id.clone() };

        match (self.path.is_some(), external_fds.entry(&target)) {
            (true, None) => {
                // Path will be used, nothing to do.
            }
            (true, Some(_)) => {
                return Err(UpdateFdsError::SuperfluousFds(vec![target]));
            }
            (false, None) => {
                return Err(UpdateFdsError::MissingFds(target));
            }
            (false, Some(received_fds)) => {
                if received_fds.fds().len() != 1 {
                    return Err(UpdateFdsError::FdAmountMismatch {
                        target,
                        expected: 1,
                        actual: received_fds.fds().len(),
                    });
                }
            }
        }

        to_validate.remove(&target);

        Ok(())
    }

    fn update_fds(&mut self, external_fds: &mut ExternalFds) -> Result<(), UpdateFdsError> {
        let Some(id) = self.pci_common.id.as_ref() else {
            if self.path.is_none() {
                return Err(UpdateFdsError::MissingId);
            }
            return Ok(());
        };

        let target = Target::Vfio { id: id.clone() };

        let Some(mut received_fds) = external_fds.take_entry(&target) else {
            return Ok(());
        };

        self.fd = received_fds
            .take_fds()
            .pop()
            .expect("Should be checked during validation");
        self.path = None;

        Ok(())
    }
}

impl UpdateFdsComponent for PlatformConfig {
    fn validate_fds(
        &self,
        external_fds: &ExternalFds,
        to_validate: &mut BTreeSet<Target>,
    ) -> Result<(), UpdateFdsError> {
        let target = Target::Iommu;
        let Some(received_fds) = external_fds.entry(&target) else {
            return Ok(());
        };

        if !self.iommufd {
            return Err(UpdateFdsError::IommufdFdRequiresIommufdBackend);
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

    fn update_fds(&mut self, external_fds: &mut ExternalFds) -> Result<(), UpdateFdsError> {
        if let Some(mut received_fds) = external_fds.take_entry(&Target::Iommu) {
            self.iommufd_fd = received_fds
                .take_fds()
                .pop()
                .expect("Should be checked during validation");
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::slice;
    use std::str::FromStr;

    use option_parser::{OptionParser, TupleList};
    use serde::{Deserialize, Serialize};

    use crate::config::tests::{net_fixture, platform_fixture};
    use crate::external_fds::{
        Entry, ExternalFds, ParseTargetError, ScmRights, ScmRightsError, Target, UpdateFdsError,
    };
    use crate::tests::{create_dummy_vm_config, test_fd};
    use crate::vm_config::{
        DeviceConfig, ExternalFd, NetConfig, PciDeviceCommonConfig, PlatformConfig, VmConfig,
    };

    pub(crate) fn net_target(id: &str) -> Target {
        Target::Net { id: id.to_owned() }
    }

    pub(crate) fn vfio_target(id: &str) -> Target {
        Target::Vfio { id: id.to_owned() }
    }

    fn vfio_vm_config(device_config_fd: ExternalFd, iommufd: bool) -> Box<VmConfig> {
        let mut vm_config = create_dummy_vm_config();
        vm_config.devices = Some(vec![DeviceConfig {
            pci_common: PciDeviceCommonConfig {
                id: Some("vfio1".to_owned()),
                ..Default::default()
            },
            path: device_config_fd.is_none().then(|| "/dev/vfio/1".into()),
            fd: device_config_fd,
            x_nv_gpudirect_clique: None,
            x_exclude_mmap_bars: vec![],
            iommufd_dev_id: None,
        }]);
        vm_config.platform = Some(PlatformConfig {
            iommufd,
            ..platform_fixture()
        });
        vm_config
    }

    #[test]
    fn test_parse_external_fd_target() {
        for (input, expected) in [
            ("net(foo)", net_target("foo")),
            ("vfio(foo)", vfio_target("foo")),
            ("iommu", Target::Iommu),
        ] {
            assert_eq!(Target::from_str(input), Ok(expected), "{input}");
        }

        for input in ["net()", "vfio()"] {
            assert_eq!(
                Target::from_str(input),
                Err(ParseTargetError::EmptyTarget(input.to_owned())),
                "{input}"
            );
        }

        for input in [
            "net((",
            "net",
            "vfio((",
            "vfio",
            "iommu(foo)",
            "iommu(",
            "foo",
        ] {
            assert_eq!(
                Target::from_str(input),
                Err(ParseTargetError::InvalidValue(input.to_owned())),
                "{input}"
            );
        }
    }

    #[test]
    fn parse_external_fds() {
        let files: Vec<_> = (0..4).map(|_| test_fd()).collect();
        let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let mut parser = OptionParser::new();
        parser.add("external_fds");
        parser
            .parse(&format!(
                "external_fds=[net(1)@[{},{}],net(2)@[{},{}]]",
                raw_fds[0], raw_fds[1], raw_fds[2], raw_fds[3],
            ))
            .unwrap();

        // Transfer ownership to the parsed configuration.
        for file in files {
            file.into_raw_fd();
        }
        let external_fds =
            // SAFETY: We transferred ownership of the fds to the parsed config.
            unsafe{
            ExternalFds::from_cli(
                parser
                    .convert::<TupleList<Target, Vec<u64>>>("external_fds")
                    .unwrap()
                    .unwrap(),
            )}
                .unwrap();

        assert_eq!(external_fds.external_fds.len(), 2);
        for (entry, (target, fds)) in external_fds.external_fds.iter().zip([
            (net_target("1"), &raw_fds[..2]),
            (net_target("2"), &raw_fds[2..]),
        ]) {
            assert_eq!(entry.target, target);
            assert_eq!(entry.expected_fds(), 2);
            assert_eq!(
                entry
                    .fds()
                    .iter()
                    .map(|fd| fd.as_ref().unwrap().as_raw_fd())
                    .collect::<Vec<_>>(),
                fds,
            );
        }
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
                    Entry::new(net_target("1"), vec![test_fd().into(), test_fd().into()]),
                    Entry::new(net_target("2"), vec![test_fd().into(), test_fd().into()]),
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
                    Entry {
                        target: net_target("1"),
                        expected_fds: 2,
                        received_fds: vec![],
                    },
                    Entry {
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
        let mut entry = Entry::new(Target::Iommu, vec![test_fd().into()]);
        let mut files = vec![test_fd(), test_fd()];
        let file_raw = files[0].as_raw_fd();
        let trailing_file_raw = files[1].as_raw_fd();
        entry.update_from_scm_rights(&mut files).unwrap();
        assert_eq!(
            entry.received_fds[0].as_ref().unwrap().as_raw_fd(),
            file_raw
        );
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].as_raw_fd(), trailing_file_raw);

        let fds: Vec<ExternalFd> = (0..6).map(|_| test_fd().into()).collect();
        let mut entry = Entry::new(
            Target::Net {
                id: "net1".to_owned(),
            },
            fds.clone(),
        );
        let file = test_fd();

        let mut files = vec![file];
        assert_eq!(
            entry.update_from_scm_rights(&mut files),
            Err(ScmRightsError::TooFewFds)
        );
        assert_eq!(entry.received_fds, fds);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn external_fds_entry_take_fds() {
        let fd: ExternalFd = test_fd().into();
        let mut entry = Entry {
            target: Target::Iommu,
            expected_fds: 1,
            received_fds: vec![fd.clone()],
        };

        assert_eq!(entry.take_fds(), vec![fd]);
        assert!(entry.fds().is_empty());
        assert_eq!(entry.expected_fds(), 1);
    }

    #[test]
    fn external_fds_entry_lifecycle() {
        let target = net_target("net1");
        let fds: Vec<ExternalFd> = (0..3).map(|_| test_fd().into()).collect();
        let mut external_fds: ExternalFds = vec![(target.clone(), fds.clone())].into();

        let expected = Entry {
            target: target.clone(),
            expected_fds: 3,
            received_fds: fds,
        };

        assert!(!external_fds.is_empty());
        assert_eq!(external_fds.entry(&target), Some(&expected));
        assert_eq!(external_fds.take_entry(&target), Some(expected));
        assert_eq!(external_fds.entry(&target), None);
        assert_eq!(external_fds.take_entry(&target), None);
        assert!(external_fds.is_empty());
    }

    #[test]
    fn external_fds_take_raw_fds() {
        let trailing_fds: Vec<ExternalFd> = (0..3).map(|_| test_fd().into()).collect();
        let target = net_target("net1");
        let fds: Vec<ExternalFd> = (0..3).map(|_| test_fd().into()).collect();
        let mut external_fds: ExternalFds = vec![
            (target.clone(), fds.clone()),
            (target, trailing_fds.clone()),
        ]
        .into();

        assert_eq!(external_fds.take_fds(), [fds, trailing_fds].concat());
        assert!(
            external_fds
                .external_fds
                .iter()
                .all(|entry| entry.received_fds.is_empty())
        );
    }

    #[test]
    fn scm_rights_external_fds_count_overflow() {
        let mut external_fds: ExternalFds = serde_json::from_value(serde_json::json!({
            "external_fds": [
                {"target": {"Net": {"id": "net0"}}, "expected_fds": usize::MAX},
                {"target": "Iommu", "expected_fds": 1}
            ]
        }))
        .unwrap();

        assert_eq!(
            external_fds.consume_fds(Vec::new()),
            Err(ScmRightsError::TooManyFds)
        );
    }

    #[test]
    fn scm_rights_external_fds() {
        let mut external_fds = ExternalFds {
            external_fds: vec![
                Entry::new(Target::Iommu, vec![test_fd().into()]),
                Entry::new(net_target("net1"), vec![test_fd().into(), test_fd().into()]),
            ],
        };
        let files = vec![test_fd(), test_fd(), test_fd()];
        let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();

        external_fds.consume_fds(files).unwrap();
        assert_eq!(
            external_fds
                .entries()
                .into_iter()
                .map(|(target, count, fds)| (
                    target,
                    count,
                    fds.iter()
                        .map(|fd| fd.as_ref().unwrap().as_raw_fd())
                        .collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            vec![
                (&Target::Iommu, 1, vec![raw_fds[0]]),
                (&net_target("net1"), 2, vec![raw_fds[1], raw_fds[2]]),
            ]
        );

        let mut external_fds = ExternalFds {
            external_fds: vec![
                Entry::new(
                    net_target("net1"),
                    vec![test_fd().into(), test_fd().into(), test_fd().into()],
                ),
                Entry::new(net_target("net2"), vec![]),
                Entry::new(net_target("net3"), vec![test_fd().into(), test_fd().into()]),
            ],
        };
        let files = vec![test_fd(), test_fd(), test_fd(), test_fd(), test_fd()];
        let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();

        external_fds.consume_fds(files).unwrap();
        assert_eq!(
            external_fds
                .entries()
                .into_iter()
                .map(|(target, count, fds)| (
                    target,
                    count,
                    fds.iter()
                        .map(|fd| fd.as_ref().unwrap().as_raw_fd())
                        .collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    &net_target("net1"),
                    3,
                    vec![raw_fds[0], raw_fds[1], raw_fds[2]]
                ),
                (&net_target("net2"), 0, vec![]),
                (&net_target("net3"), 2, vec![raw_fds[3], raw_fds[4]]),
            ]
        );

        let mut external_fds = ExternalFds {
            external_fds: vec![Entry::new(Target::Iommu, vec![test_fd().into()])],
        };
        let files = vec![test_fd(), test_fd()];
        assert_eq!(
            external_fds.consume_fds(files),
            Err(ScmRightsError::TooManyFds)
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
            let files = vec![test_fd(), test_fd(), test_fd()];
            let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
            net_config.consume_fds(files).unwrap();
            assert_eq!(
                net_config
                    .fds
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|fd| fd.as_ref().unwrap().as_raw_fd())
                    .collect::<Vec<_>>(),
                raw_fds
            );
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
            fd: ExternalFd::default(),
            x_nv_gpudirect_clique: None,
            x_exclude_mmap_bars: vec![],
            iommufd_dev_id: None,
        };

        {
            let mut device_config = device_config.clone();
            let files = vec![test_fd()];
            let raw_fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
            device_config.consume_fds(files).unwrap();
            assert_eq!(device_config.fd.as_ref().unwrap().as_raw_fd(), raw_fds[0]);
        }
        {
            let mut device_config = device_config.clone();
            let files = vec![test_fd(), test_fd(), test_fd()];
            assert_eq!(
                device_config.consume_fds(files),
                Err(ScmRightsError::TooManyFds)
            );
        }
        {
            let mut device_config = device_config.clone();
            device_config.consume_fds(vec![]).unwrap();
            assert!(device_config.fd.is_none());
        }
    }

    #[test]
    fn scm_rights_vm_config() {
        let mut vm_config = create_dummy_vm_config();

        let files = vec![test_fd()];
        assert_eq!(
            vm_config.consume_fds(files),
            Err(ScmRightsError::Unsupported)
        );
        let files = vec![];
        assert_eq!(vm_config.consume_fds(files), Ok(()));
    }

    #[test]
    fn update_fds_vm_config() {
        let fd1: ExternalFd = test_fd().into();
        {
            let mut vm_config = create_dummy_vm_config();
            let external_fds = ExternalFds::default();
            vm_config.update_fds(external_fds).unwrap();
            assert_eq!(vm_config, create_dummy_vm_config());
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: Some(vec![ExternalFd::default()]),
                ..net_fixture()
            }]);

            let external_fds = vec![(net_target("net1"), vec![fd1.clone()])].into();
            vm_config.update_fds(external_fds).unwrap();
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
                slice::from_ref(&fd1)
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: Some(vec![ExternalFd::default()]),
                ..net_fixture()
            }]);

            let external_fds = vec![
                (net_target("net1"), vec![fd1.clone()]),
                (net_target("net1"), vec![fd1.clone()]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds),
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
                fds: Some(vec![ExternalFd::default()]),
                ..net_fixture()
            }]);

            let external_fds = vec![(net_target("net1"), vec![fd1.clone()])].into();
            assert_eq!(
                vm_config.update_fds(external_fds),
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

            let external_fds = vec![(net_target("net1"), vec![fd1.clone()])].into();
            assert_eq!(
                vm_config.update_fds(external_fds),
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

            vm_config.update_fds(external_fds).unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.net = Some(vec![NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("net1".to_owned()),
                    ..Default::default()
                },
                fds: Some(vec![ExternalFd::default(), ExternalFd::default()]),
                ..net_fixture()
            }]);
            let vm_config_expected = vm_config.clone();

            assert_eq!(
                vm_config.update_fds(ExternalFds::default()),
                Err(UpdateFdsError::MissingFds(net_target("net1")))
            );
            assert_eq!(vm_config, vm_config_expected);

            let external_fds = vec![(net_target("net1"), vec![fd1.clone()])].into();
            assert_eq!(
                vm_config.update_fds(external_fds),
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
                fds: Some(Default::default()),
                ..net_fixture()
            }]);
            let vm_config_expected = vm_config.clone();

            assert_eq!(
                vm_config.update_fds(ExternalFds::default()),
                Err(UpdateFdsError::MissingId)
            );

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = create_dummy_vm_config();
            let external_fds = vec![(net_target("net1"), vec![fd1.clone()])].into();

            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::SuperfluousFds(vec![net_target("net1")]))
            );
        }
    }

    #[test]
    fn update_fds_iommufd_without_external_fd() {
        for with_device in [false, true] {
            let mut vm_config = vfio_vm_config(ExternalFd::default(), true);
            if !with_device {
                vm_config.devices = None;
            }
            // Exercise the deserialization and update used by HTTP VM creation
            // and snapshots with an internally opened IOMMU FD.
            let mut vm_config: VmConfig =
                serde_json::from_value(serde_json::to_value(vm_config).unwrap()).unwrap();
            let expected = vm_config.clone();
            vm_config.update_fds(ExternalFds::default()).unwrap();
            assert_eq!(vm_config, expected);
        }
    }

    #[test]
    fn update_fds_vm_config_vfio_and_iommu() {
        let fd1: ExternalFd = test_fd().into();
        let fd2: ExternalFd = test_fd().into();
        let fd3: ExternalFd = test_fd().into();
        {
            // A pathless device requires an external FD with or without a saved FD.
            for saved_fd in [ExternalFd::default(), test_fd().into()] {
                let mut vm_config = vfio_vm_config(saved_fd, true);
                vm_config.devices.as_mut().unwrap()[0].path = None;
                let external_fds = vec![
                    (vfio_target("vfio1"), vec![fd1.clone()]),
                    (Target::Iommu, vec![fd2.clone()]),
                ]
                .into();

                vm_config.update_fds(external_fds).unwrap();
                let device_config = &vm_config.devices.as_ref().unwrap()[0];
                assert_eq!(device_config.fd, fd1);
                assert_eq!(device_config.path, None);
                assert_eq!(vm_config.platform.as_ref().unwrap().iommufd_fd, fd2);
            }
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            vm_config.devices.as_mut().unwrap().insert(
                0,
                DeviceConfig {
                    pci_common: PciDeviceCommonConfig {
                        id: Some("vfio0".to_owned()),
                        ..Default::default()
                    },
                    path: Some("/dev/vfio/0".into()),
                    fd: ExternalFd::default(),
                    x_nv_gpudirect_clique: None,
                    x_exclude_mmap_bars: vec![],
                    iommufd_dev_id: None,
                },
            );
            let external_fds = vec![
                (vfio_target("vfio1"), vec![fd1.clone()]),
                (Target::Iommu, vec![fd2.clone()]),
            ]
            .into();

            vm_config.update_fds(external_fds).unwrap();
            let devices = vm_config.devices.as_ref().unwrap();
            assert_eq!(devices[0].path, Some("/dev/vfio/0".into()));
            assert!(devices[0].fd.is_none());
            assert_eq!(devices[1].path, None);
            assert_eq!(devices[1].fd, fd1);
            assert_eq!(vm_config.platform.as_ref().unwrap().iommufd_fd, fd2);
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            vm_config.devices.as_mut().unwrap()[0].pci_common.id = None;
            assert_eq!(
                vm_config.update_fds(ExternalFds::default()),
                Err(UpdateFdsError::MissingId)
            );
        }

        {
            let mut vm_config = vfio_vm_config(ExternalFd::default(), true);
            vm_config.devices.as_mut().unwrap()[0].pci_common.id = None;
            vm_config.devices.as_mut().unwrap()[0].path = None;
            let vm_config_expected = vm_config.clone();

            assert_eq!(
                vm_config.update_fds(ExternalFds::default()),
                Err(UpdateFdsError::MissingId)
            );

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![fd1.clone(), fd2.clone()]),
                (Target::Iommu, vec![fd3.clone()]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::FdAmountMismatch {
                    target: vfio_target("vfio1"),
                    expected: 1,
                    actual: 2,
                })
            );
        }

        {
            let mut vm_config = vfio_vm_config(ExternalFd::default(), true);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![fd1.clone()]),
                (Target::Iommu, vec![fd2.clone()]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::SuperfluousFds(vec![vfio_target("vfio1")]))
            );
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            assert_eq!(
                vm_config.update_fds(ExternalFds::default()),
                Err(UpdateFdsError::MissingFds(vfio_target("vfio1")))
            );
        }

        {
            let mut vm_config = vfio_vm_config(ExternalFd::default(), false);
            let vm_config_expected = vm_config.clone();

            vm_config.update_fds(ExternalFds::default()).unwrap();

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = vfio_vm_config(ExternalFd::default(), true);
            // Restore and migration remove source paths before FD validation.
            vm_config.devices.as_mut().unwrap()[0].path = None;
            let vm_config_expected = vm_config.clone();

            assert_eq!(
                vm_config.update_fds(ExternalFds::default()),
                Err(UpdateFdsError::MissingFds(vfio_target("vfio1")))
            );

            assert_eq!(vm_config, vm_config_expected);
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            let external_fds = vec![(Target::Iommu, vec![fd2.clone()])].into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::MissingFds(vfio_target("vfio1")))
            );
        }

        {
            let mut vm_config = create_dummy_vm_config();
            vm_config.platform = Some(PlatformConfig {
                iommufd: true,
                ..platform_fixture()
            });
            let external_fds = vec![(Target::Iommu, vec![fd1.clone()])].into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::IommuFdWithoutVfioFds)
            );
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            let external_fds = vec![(vfio_target("vfio1"), vec![fd1.clone()])].into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::VfioFdsWithoutIommuFd)
            );
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), false);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![fd1.clone()]),
                (Target::Iommu, vec![fd2.clone()]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::IommufdFdRequiresIommufdBackend)
            );
        }

        {
            let mut vm_config = vfio_vm_config(test_fd().into(), true);
            let external_fds = vec![
                (vfio_target("vfio1"), vec![fd1.clone()]),
                (Target::Iommu, vec![]),
            ]
            .into();
            assert_eq!(
                vm_config.update_fds(external_fds),
                Err(UpdateFdsError::FdAmountMismatch {
                    target: Target::Iommu,
                    expected: 1,
                    actual: 0,
                })
            );
        }
    }
}
