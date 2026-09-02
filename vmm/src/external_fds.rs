// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! External file descriptor handling.

#![allow(unused, reason = "Will be used in later commits")]

use std::fs::File;
use std::mem;
use std::str::FromStr;

use option_parser::{Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;
use crate::vm_config::ExternalFd;

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
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::str::FromStr;

    use option_parser::{OptionParser, TupleList};
    use serde::{Deserialize, Serialize};

    use crate::config::tests::platform_fixture;
    use crate::external_fds::{Entry, ExternalFds, ParseTargetError, ScmRightsError, Target};
    use crate::tests::{create_dummy_vm_config, test_fd};
    use crate::vm_config::{
        DeviceConfig, ExternalFd, PciDeviceCommonConfig, PlatformConfig, VmConfig,
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
            path: Some("/dev/vfio/1".into()),
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
}
