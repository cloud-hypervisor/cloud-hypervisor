// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;
use std::str::FromStr;

use option_parser::{OptionParser, OptionParserError, Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{RestoredVfioConfig, VmMemoryZoneUpdateData};

/// Memory transfer mode for a migration.
#[derive(Copy, Clone, Default, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum MigrationMode {
    /// Transfer all guest memory before the destination resumes.
    #[default]
    Precopy,
    /// Resume the destination first and fault guest pages in on demand.
    /// This is an experimental mode. It uses a single connection even
    /// when parallel connections are configured. Pages are served on
    /// demand, but a background faulting mechanism also pulls in the
    /// remaining pages to speed up completion.
    Postcopy,
}

impl FromStr for MigrationMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "precopy" => Ok(MigrationMode::Precopy),
            "postcopy" => Ok(MigrationMode::Postcopy),
            _ => Err(format!("Invalid migration mode: {s}")),
        }
    }
}

#[derive(Copy, Clone, Default, Deserialize, Serialize, Debug, PartialEq, Eq)]
/// The migration timeout strategy.
///
/// This strategy describes the behavior of the migration when the target
/// downtime can't be reached in the given timeout.
pub enum TimeoutStrategy {
    #[default]
    /// Cancel the migration and keep the VM running on the source.
    Cancel,
    /// Ignore the timeout and migrate anyway.
    Ignore,
}

impl FromStr for TimeoutStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cancel" => Ok(TimeoutStrategy::Cancel),
            "ignore" => Ok(TimeoutStrategy::Ignore),
            _ => Err(format!("Invalid timeout strategy: {s}")),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct VmReceiveMigrationData {
    /// URL for the reception of migration state
    pub receiver_url: String,
    /// Directory containing the TLS server certificate (`server-cert.pem`),
    /// the TLS server key (`server-key.pem`), and the server's TLS root CA
    /// certificate (`ca-cert.pem`).
    ///
    /// If this is `Some`, the migration is instructed to use mTLS.
    #[serde(default)]
    pub tls_dir: Option<PathBuf>,
    /// Memory transfer mode.
    #[serde(default)]
    pub memory_mode: MigrationMode,
    /// Optional VFIO device id to cdev FD pairs, used to substitute each
    /// device's saved path or stale FD in the received VmConfig.
    #[serde(default)]
    pub vfio_fds: Option<Vec<RestoredVfioConfig>>,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "crate::deserialize_restored_fd")]
    pub iommufd_fd: Option<i32>,
    /// Optional memory zone update data
    #[serde(default)]
    pub zone_updates: Vec<VmMemoryZoneUpdateData>,
}

#[derive(Debug, Error)]
pub enum VmReceiveMigrationDataParseError {
    #[error("Failed to parse vm receive migration configuration")]
    Parse(#[from] OptionParserError),
}

impl VmReceiveMigrationData {
    pub const SYNTAX: &'static str = "VM receive migration parameters \
        \"<receiver_url>\" or \"receiver_url=<url>[,tls_dir=<path>][,memory_mode=precopy|postcopy]\
        [,vfio_fds=<list_of_vfio_ids_with_their_associated_fd>][,iommufd_fd=<fd>]\
        [,zone_updates=[<id@host_numa_node>]]\"";

    pub fn parse(migration: &str) -> Result<Self, VmReceiveMigrationDataParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("receiver_url")
            .add("tls_dir")
            .add("memory_mode")
            .add("vfio_fds")
            .add("iommufd_fd")
            .add("zone_updates");
        parser.parse(migration)?;

        let receiver_url = parser.get("receiver_url").ok_or_else(|| {
            OptionParserError::InvalidSyntax("receiver_url is required".to_string())
        })?;
        let tls_dir = parser
            .convert::<String>("tls_dir")?
            .map(|path| PathBuf::from(&path));
        let memory_mode = parser
            .convert::<MigrationMode>("memory_mode")?
            .unwrap_or_default();
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

        let data = Self {
            receiver_url,
            tls_dir,
            memory_mode,
            vfio_fds,
            iommufd_fd,
            zone_updates,
        };

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::{MigrationMode, VmReceiveMigrationData, VmReceiveMigrationDataParseError};

    #[test]
    fn test_vm_receive_migration_data_parse() {
        let data = VmReceiveMigrationData::parse("receiver_url=tcp:192.168.1.1:8080").unwrap();
        assert_eq!(
            data,
            VmReceiveMigrationData {
                receiver_url: "tcp:192.168.1.1:8080".to_string(),
                tls_dir: None,
                memory_mode: MigrationMode::Precopy,
                vfio_fds: None,
                iommufd_fd: None,
                zone_updates: vec![],
            }
        );

        let data = VmReceiveMigrationData::parse("receiver_url=tcp:[2001:db8::1]:8080").unwrap();
        assert_eq!(data.receiver_url, "tcp:[2001:db8::1]:8080");

        let data =
            VmReceiveMigrationData::parse("receiver_url=tcp:destination.example:8080").unwrap();
        assert_eq!(data.receiver_url, "tcp:destination.example:8080");

        let data = VmReceiveMigrationData::parse("receiver_url=unix:/tmp/ch=migrate.sock").unwrap();
        assert_eq!(data.receiver_url, "unix:/tmp/ch=migrate.sock");

        // memory_mode defaults to precopy when not specified.
        let data = VmReceiveMigrationData::parse("receiver_url=tcp:127.0.0.1:1234").unwrap();
        assert_eq!(
            data,
            VmReceiveMigrationData {
                receiver_url: "tcp:127.0.0.1:1234".to_string(),
                tls_dir: None,
                memory_mode: MigrationMode::Precopy,
                vfio_fds: None,
                iommufd_fd: None,
                ..Default::default()
            }
        );

        // Explicit receiver_url with memory_mode=postcopy.
        let data =
            VmReceiveMigrationData::parse("receiver_url=unix:/tmp/sock,memory_mode=postcopy")
                .unwrap();
        assert_eq!(
            data,
            VmReceiveMigrationData {
                receiver_url: "unix:/tmp/sock".to_string(),
                tls_dir: None,
                memory_mode: MigrationMode::Postcopy,
                vfio_fds: None,
                iommufd_fd: None,
                ..Default::default()
            }
        );

        // Missing receiver_url in keyed form must fail.
        let e = VmReceiveMigrationData::parse("memory_mode=postcopy").unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationDataParseError::Parse(_)),
            "Expected \"ParseError\"; got \"{e:?}\"",
        );

        // vfio_fds without iommufd_fd parses fine now, the pairing is checked
        // later against the received VmConfig by validate_vfio_fds.
        let data =
            VmReceiveMigrationData::parse("receiver_url=tcp:127.0.0.1:1234,vfio_fds=[vfio0@5]")
                .unwrap();
        assert!(data.iommufd_fd.is_none());

        // vfio_fds entries with the iommufd FD.
        let data = VmReceiveMigrationData::parse(
            "receiver_url=tcp:127.0.0.1:1234,vfio_fds=[vfio0@5,vfio1@7],iommufd_fd=9",
        )
        .unwrap();
        let fds = data.vfio_fds.expect("vfio_fds populated");
        assert_eq!(fds.len(), 2);
        assert_eq!(fds[0].id, "vfio0");
        assert_eq!(fds[0].fd, Some(5));
        assert_eq!(fds[1].id, "vfio1");
        assert_eq!(fds[1].fd, Some(7));
        assert_eq!(data.iommufd_fd, Some(9));

        // zone update tests
        let e = VmReceiveMigrationData::parse("receiver_url=unix:/tmp/sock,zone_updates=[]")
            .unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationDataParseError::Parse(_)),
            "Expected \"ParseError\"; got \"{e:?}\"",
        );
        let e = VmReceiveMigrationData::parse("receiver_url=unix:/tmp/sock,zone_updates=[zone1 3]")
            .unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationDataParseError::Parse(_)),
            "Expected \"ParseError\"; got \"{e:?}\"",
        );

        // zone update tests
        // Mind the space before the second zone. If the whitespace isn't trimmed, we end up with two
        // different ID.
        let data = VmReceiveMigrationData::parse(
            "receiver_url=unix:/tmp/sock,zone_updates=[zone1@1,  zone1@1]",
        )
        .unwrap();
        assert_eq!(data.zone_updates[0], data.zone_updates[1]);
    }
}
