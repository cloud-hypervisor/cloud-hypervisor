// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! External file descriptor handling.

#![allow(unused, reason = "Will be used in later commits")]

use std::fs::File;
use std::mem;
use std::os::fd::{IntoRawFd, RawFd};
use std::str::FromStr;

use option_parser::{Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::os::fd::{AsRawFd, RawFd};
    use std::str::FromStr;

    use option_parser::{OptionParser, TupleList};
    use serde::{Deserialize, Serialize};

    use crate::config::tests::platform_fixture;
    use crate::external_fds::{
        ExternalFdTarget, ExternalFds, ExternalFdsEntry, ParseExternalFdTargetError, ScmRightsError,
    };
    use crate::tests::create_dummy_vm_config;
    use crate::vm_config::{DeviceConfig, PciDeviceCommonConfig, PlatformConfig, VmConfig};

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
}
