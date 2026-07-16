// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;
use std::str::FromStr;

use log::debug;
use option_parser::{OptionParser, OptionParserError, Toggle, Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoredVfioConfig {
    pub id: String,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "crate::deserialize_restored_fd")]
    pub fd: Option<i32>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Eq, PartialEq)]
/// Data required for updating memory zone <-> host NUMA node mappings.
pub struct VmMemoryZoneUpdateData {
    /// Id of the MemoryZone to update
    pub id: String,
    /// Host NUMA node to relocate the MemoryZone to
    pub host_numa_node: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum MemoryRestoreMode {
    /// Restore by eagerly copying the snapshot into guest RAM before resume.
    #[default]
    Copy,
    /// Restore lazily by faulting snapshot pages into guest RAM on demand.
    OnDemand,
}

#[derive(Debug, Error)]
pub enum MemoryRestoreModeParseError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

impl FromStr for MemoryRestoreMode {
    type Err = MemoryRestoreModeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "copy" => Ok(Self::Copy),
            "ondemand" => Ok(Self::OnDemand),
            _ => Err(MemoryRestoreModeParseError::InvalidValue(s.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoredNetConfig {
    pub id: String,
    #[serde(default)]
    pub num_fds: usize,
    // Special deserialize handling:
    // A serialize-deserialize cycle typically happens across processes.
    // Therefore, we don't serialize FDs, and whatever value is here after
    // deserialization is invalid.
    //
    // Valid FDs are transmitted via a different channel (SCM_RIGHTS message)
    // and will be populated into this struct on the destination VMM eventually.
    #[serde(default, deserialize_with = "deserialize_restorednetconfig_fds")]
    pub fds: Option<Vec<i32>>,
}

fn deserialize_restorednetconfig_fds<'de, D>(d: D) -> Result<Option<Vec<i32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fds: Option<Vec<i32>> = Option::deserialize(d)?;
    if let Some(invalid_fds) = invalid_fds {
        // If the live-migration path is used properly, new FDs are passed as
        // SCM_RIGHTS message. So, we don't get them from the serialized JSON
        // anyway.
        debug!(
            "FDs in 'RestoredNetConfig' won't be deserialized as they are most likely invalid now. Deserializing them as -1."
        );
        Ok(Some(vec![-1; invalid_fds.len()]))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Error)]
pub enum RestoreConfigParseError {
    /// Missing restore source_url parameter.
    #[error("Error parsing --restore: source_url missing")]
    ParseRestoreSourceUrlMissing,
    /// Failed to parse config string.
    #[error("Failed to parse configuration string")]
    ParseRestore(#[from] OptionParserError),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoreConfig {
    pub source_url: PathBuf,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub memory_restore_mode: MemoryRestoreMode,
    #[serde(default)]
    pub net_fds: Option<Vec<RestoredNetConfig>>,
    #[serde(default)]
    pub vfio_fds: Option<Vec<RestoredVfioConfig>>,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "crate::deserialize_restored_fd")]
    pub iommufd_fd: Option<i32>,
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub zone_updates: Vec<VmMemoryZoneUpdateData>,
}

impl RestoreConfig {
    pub const SYNTAX: &'static str = "Restore from a VM snapshot. \
        \nRestore parameters \"source_url=<source_url>,prefault=on|off,memory_restore_mode=copy|ondemand,\
        net_fds=<list_of_net_ids_with_their_associated_fds>,\
        vfio_fds=<list_of_vfio_ids_with_their_associated_fd>,iommufd_fd=<fd>,resume=true|false,\
        zone_updates=<list_of_updates>\"
        \n`source_url` should be a valid URL (e.g file:///foo/bar or tcp://192.168.1.10/foo) \
        \n`prefault` controls eager prefaulting for the copy-based restore path (disabled by default) \
        \n`memory_restore_mode=copy` preserves the existing eager read-copy restore behavior, while `memory_restore_mode=ondemand` enables lazy demand paging and fails restore if userfaultfd support is unavailable \
        \n`net_fds` is a list of net ids with new file descriptors. \
        Only net devices backed by FDs directly are needed as input.\
        \n`vfio_fds` is a list of VFIO device ids each paired with a new cdev file descriptor, \
        e.g. vfio_fds=[vfio0@5,vfio1@6]. Use this to restore a VFIO device onto a different \
        sysfs path or host. Requires `iommufd_fd`.\
        \n`iommufd_fd` is a new iommufd file descriptor for the restored VM. \
        The one saved in the snapshot does not survive serialization.\
        \n `resume` controls whether the VM will be directly resumed after restore \
        \n `zone_updates` can be used to update NUMA memory zones. Expects a list of elements in the form `id@host_numa_node`";

    pub fn parse(restore: &str) -> Result<Self, RestoreConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("source_url")
            .add("prefault")
            .add("memory_restore_mode")
            .add("net_fds")
            .add("vfio_fds")
            .add("iommufd_fd")
            .add("resume")
            .add("zone_updates");
        parser.parse(restore)?;

        let source_url = parser
            .get("source_url")
            .map(PathBuf::from)
            .ok_or(RestoreConfigParseError::ParseRestoreSourceUrlMissing)?;
        let prefault = parser
            .convert::<Toggle>("prefault")?
            .unwrap_or(Toggle(false))
            .0;
        let memory_restore_mode = parser
            .convert::<MemoryRestoreMode>("memory_restore_mode")?
            .unwrap_or_default();
        let net_fds = parser
            .convert::<TupleList<String, Vec<u64>>>("net_fds")?
            .map(|v| {
                v.0.iter()
                    .map(|Tuple(id, fds)| RestoredNetConfig {
                        id: id.clone(),
                        num_fds: fds.len(),
                        fds: Some(fds.iter().map(|e| *e as i32).collect()),
                    })
                    .collect()
            });
        let vfio_fds = parser
            .convert::<TupleList<String, u64>>("vfio_fds")?
            .map(|v| {
                v.0.iter()
                    .map(|Tuple(id, fd)| RestoredVfioConfig {
                        id: id.clone(),
                        fd: Some(*fd as i32),
                    })
                    .collect()
            });
        let iommufd_fd = parser.convert::<i32>("iommufd_fd")?;
        let resume = parser
            .convert::<Toggle>("resume")?
            .unwrap_or(Toggle(false))
            .0;

        let zone_updates: Vec<VmMemoryZoneUpdateData> = parser
            .convert::<TupleList<String, u32>>("zone_updates")?
            .map_or(Vec::new(), |v| {
                v.0.iter()
                    .map(|Tuple(id, host_numa_node)| VmMemoryZoneUpdateData {
                        id: id.clone(),
                        host_numa_node: *host_numa_node,
                    })
                    .collect()
            });

        Ok(RestoreConfig {
            source_url,
            prefault,
            memory_restore_mode,
            net_fds,
            vfio_fds,
            iommufd_fd,
            resume,
            zone_updates,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        MemoryRestoreMode, RestoreConfig, RestoreConfigParseError, RestoredNetConfig,
        RestoredVfioConfig, VmMemoryZoneUpdateData,
    };

    #[test]
    fn test_restore_parsing() -> Result<(), RestoreConfigParseError> {
        assert_eq!(
            RestoreConfig::parse("source_url=/path/to/snapshot")?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                memory_restore_mode: MemoryRestoreMode::Copy,
                net_fds: None,
                vfio_fds: None,
                iommufd_fd: None,
                resume: false,
                zone_updates: vec![],
            }
        );
        assert_eq!(
            RestoreConfig::parse(
                "source_url=/path/to/snapshot,prefault=off,net_fds=[net0@[3,4],net1@[5,6,7,8]]"
            )?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                memory_restore_mode: MemoryRestoreMode::Copy,
                net_fds: Some(vec![
                    RestoredNetConfig {
                        id: "net0".to_string(),
                        num_fds: 2,
                        fds: Some(vec![3, 4]),
                    },
                    RestoredNetConfig {
                        id: "net1".to_string(),
                        num_fds: 4,
                        fds: Some(vec![5, 6, 7, 8]),
                    }
                ]),
                vfio_fds: None,
                iommufd_fd: None,
                resume: false,
                zone_updates: vec![],
            }
        );
        assert_eq!(
            RestoreConfig::parse("source_url=/path/to/snapshot,memory_restore_mode=ondemand")?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                memory_restore_mode: MemoryRestoreMode::OnDemand,
                net_fds: None,
                vfio_fds: None,
                iommufd_fd: None,
                resume: false,
                zone_updates: vec![],
            }
        );
        assert_eq!(
            RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=[zone1@1]")?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                memory_restore_mode: MemoryRestoreMode::Copy,
                net_fds: None,
                vfio_fds: None,
                iommufd_fd: None,
                resume: true,
                zone_updates: vec![VmMemoryZoneUpdateData {
                    host_numa_node: 1,
                    id: "zone1".to_string(),
                }],
            }
        );
        assert_eq!(
            RestoreConfig::parse(
                "source_url=/path/to/snapshot,vfio_fds=[vfio0@5,vfio1@6],iommufd_fd=7"
            )?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                memory_restore_mode: MemoryRestoreMode::Copy,
                net_fds: None,
                vfio_fds: Some(vec![
                    RestoredVfioConfig {
                        id: "vfio0".to_string(),
                        fd: Some(5),
                    },
                    RestoredVfioConfig {
                        id: "vfio1".to_string(),
                        fd: Some(6),
                    },
                ]),
                iommufd_fd: Some(7),
                resume: false,
                zone_updates: vec![],
            }
        );
        assert_eq!(
            RestoreConfig::parse(
                "source_url=/path/to/snapshot,vfio_fds=[vfio0@5,vfio1@6],iommufd_fd=7"
            )?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                memory_restore_mode: MemoryRestoreMode::Copy,
                net_fds: None,
                vfio_fds: Some(vec![
                    RestoredVfioConfig {
                        id: "vfio0".to_string(),
                        fd: Some(5),
                    },
                    RestoredVfioConfig {
                        id: "vfio1".to_string(),
                        fd: Some(6),
                    },
                ]),
                iommufd_fd: Some(7),
                resume: false,
                zone_updates: vec![],
            }
        );
        // Parsing should fail as source_url is a required field
        RestoreConfig::parse("prefault=off").unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,memory_restore_mode=bogus").unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=[@1]")
            .unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=[@]")
            .unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=[id1@]")
            .unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=[id1 1]")
            .unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=[[id1@1]]")
            .unwrap_err();
        RestoreConfig::parse("source_url=/path/to/snapshot,resume=on,zone_updates=id1@1")
            .unwrap_err();
        Ok(())
    }

    #[test]
    fn test_restore_config_serde() {
        assert_eq!(
            serde_json::from_str::<RestoreConfig>(r#"{"source_url":"/path/to/snapshot"}"#)
                .unwrap()
                .memory_restore_mode,
            MemoryRestoreMode::Copy
        );
        assert_eq!(
            serde_json::from_str::<RestoreConfig>(
                r#"{"source_url":"/path/to/snapshot","memory_restore_mode":"OnDemand"}"#
            )
            .unwrap()
            .memory_restore_mode,
            MemoryRestoreMode::OnDemand
        );
        assert_eq!(
            serde_json::from_str::<RestoreConfig>(
                r#"{"source_url":"/path/to/snapshot","zone_updates":[{"id": "zone1", "host_numa_node": 1}]}"#
            )
            .unwrap()
            .zone_updates,
            vec![VmMemoryZoneUpdateData {
                    host_numa_node: 1,
                    id: "zone1".to_string(),
                }],
        );
    }
}
