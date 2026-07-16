// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::result;

use anyhow::{Context, anyhow};
use api_types::{MigrationMode, RestoredVfioConfig, VmMemoryZoneUpdateData};
use thiserror::Error;
use vm_migration::tls::{TlsConfigError, TlsEndpoint, validate_tls_dir};
use vm_migration::{MigratableError, Snapshot};

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::GuestDebuggableError;
use crate::migration::transport::{TcpAddressParseError, tcp_address_to_server_name};
use crate::vm::VmSnapshot;
use crate::vm_config::VmConfig;

pub(crate) mod transport;
pub(crate) mod worker;

pub const SNAPSHOT_STATE_FILE: &str = "state.json";
pub const SNAPSHOT_CONFIG_FILE: &str = "config.json";

pub fn url_to_path(url: &str) -> result::Result<PathBuf, MigratableError> {
    let path: PathBuf = url
        .strip_prefix("file://")
        .ok_or_else(|| {
            MigratableError::MigrateSend(anyhow!("Could not extract path from URL: {url}"))
        })
        .map(|s| s.into())?;

    if !path.is_dir() {
        return Err(MigratableError::MigrateSend(anyhow!(
            "Destination is not a directory: {path:?}"
        )));
    }

    Ok(path)
}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
pub fn url_to_file(url: &str) -> result::Result<PathBuf, GuestDebuggableError> {
    let file: PathBuf = url
        .strip_prefix("file://")
        .ok_or_else(|| {
            GuestDebuggableError::Coredump(anyhow!("Could not extract file from URL: {url}"))
        })
        .map(|s| s.into())?;

    Ok(file)
}

pub fn recv_vm_config(source_url: &str) -> result::Result<VmConfig, MigratableError> {
    let mut vm_config_path = url_to_path(source_url)?;

    vm_config_path.push(SNAPSHOT_CONFIG_FILE);

    // Try opening the snapshot file
    let mut vm_config_file = File::open(&vm_config_path)
        .with_context(|| format!("Error opening VM config snapshot file {vm_config_path:?}"))
        .map_err(MigratableError::MigrateReceive)?;
    let mut bytes = Vec::new();
    vm_config_file
        .read_to_end(&mut bytes)
        .with_context(|| format!("Error reading VM config snapshot file {vm_config_path:?}"))
        .map_err(MigratableError::MigrateReceive)?;

    serde_json::from_slice(&bytes)
        .context("Error deserialising VM config snapshot")
        .map_err(MigratableError::MigrateReceive)
}

pub fn recv_vm_state(source_url: &str) -> result::Result<Snapshot, MigratableError> {
    let mut vm_state_path = url_to_path(source_url)?;

    vm_state_path.push(SNAPSHOT_STATE_FILE);

    // Try opening the snapshot file
    let mut vm_state_file = File::open(&vm_state_path)
        .with_context(|| format!("Error opening VM state snapshot file {vm_state_path:?}"))
        .map_err(MigratableError::MigrateReceive)?;
    let mut bytes = Vec::new();
    vm_state_file
        .read_to_end(&mut bytes)
        .with_context(|| format!("Error reading VM state snapshot file {vm_state_path:?}"))
        .map_err(MigratableError::MigrateReceive)?;

    serde_json::from_slice(&bytes)
        .context("Error deserialising VM state snapshot")
        .map_err(MigratableError::MigrateReceive)
}

pub fn get_vm_snapshot(snapshot: &Snapshot) -> result::Result<VmSnapshot, MigratableError> {
    if let Some(snapshot_data) = snapshot.snapshot_data.as_ref() {
        return snapshot_data.to_state();
    }

    Err(MigratableError::Restore(anyhow!(
        "Could not find VM config snapshot section"
    )))
}

#[derive(Clone, Default, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct VmReceiveMigrationData {
    /// URL for the reception of migration state
    pub receiver_url: String,
    /// Directory containing the TLS server certificate (`server-cert.pem`),
    /// the TLS server key (`server-key.pem`), and the server's TLS root CA
    /// certificate (`ca-cert.pem`).
    ///
    /// If this is `Some`, the migration is instructed to use mTLS.
    pub tls_dir: Option<PathBuf>,
    /// Memory transfer mode.
    pub memory_mode: MigrationMode,
    /// Optional VFIO device id to cdev FD pairs, used to substitute each
    /// device's saved path or stale FD in the received VmConfig.
    pub vfio_fds: Option<Vec<RestoredVfioConfig>>,
    pub iommufd_fd: Option<i32>,
    /// Optional memory zone update data
    pub zone_updates: Vec<VmMemoryZoneUpdateData>,
}

#[derive(Debug, Error)]
pub enum VmReceiveMigrationConfigError {
    /// Variant returned of validation of `receiver_url` failed.
    #[error("Expected receiver_url in the form of either `tcp:<host>:<port>` or `unix:<path>:`")]
    MalformedReceiverUrl(#[source] TcpAddressParseError),
    /// TLS encryption cannot be used for UNIX sockets. It is therefore
    /// forbidden to use TLS encryption with UNIX sockets.
    #[error("UNIX sockets and TLS encryption cannot be used at the same time")]
    TlsEncryptionUsedForUnixSocket,
    /// The `receiver_url` does not contain one of the supported
    /// prefixes. Supported prefixes are "tcp" and "unix".
    #[error("Expected receiver_url to either use `tcp` or `unix` prefix")]
    InvalidSocketPrefix,
    /// The TLS configuration is invalid.
    #[error("Invalid TLS configuration for receive-migration")]
    InvalidTlsConfiguration(#[source] TlsConfigError),
    /// Every VFIO device needs a replacement in vfio_fds and none was found for the respective
    /// device
    #[error(
        "VFIO device '{0}' has no replacement in vfio_fds, its source path or fd is not usable on the destination"
    )]
    VfioDeviceNoReplacementFd(String),
    /// The `vfio_fds` option was used without supplying `iommufd_fd`
    #[error("Usage of `vfio_fds` requires `iommufd_fd` to be specified")]
    VfioFdRequiresIommufdFd,
    /// `iommufd_fd` was provided without also enabling the iommufd backend.
    #[error("Platform `iommufd_fd=<fd>` requires `iommufd=on`")]
    IommufdFdRequiresIommufd,
    /// Identified duplicate fd replacements for the FD with the given ID.
    #[error("Multiple replacements defined for fd with ID {0}")]
    VfioFdMultipleReplacements(String),
    /// Identified a fd replacements for a FD not present in the VmConfig.
    #[error("Replacement ID {0} in vfio_fds id does not match any device in the received VmConfig")]
    VfioFdReplacementWithoutTarget(String),
    /// Multiple updates for the same memory zone were defined.
    #[error("More than one update was defined for at least one memory zone")]
    MultipleMemoryZoneUpdates,
    /// An update with an empty memory zone ID was specified.
    #[error("One or more memory zone updates contained an empty ID")]
    MemoryZoneUpdatesEmptyId,
}

impl VmReceiveMigrationData {
    pub fn validate(&self) -> Result<(), VmReceiveMigrationConfigError> {
        if let Some(addr) = self.receiver_url.strip_prefix("tcp:") {
            tcp_address_to_server_name(addr)
                .map_err(VmReceiveMigrationConfigError::MalformedReceiverUrl)?;
        } else if self
            .receiver_url
            .strip_prefix("unix:")
            .is_some_and(|path| !path.is_empty())
        {
            if self.tls_dir.is_some() {
                return Err(VmReceiveMigrationConfigError::TlsEncryptionUsedForUnixSocket);
            }
        } else {
            return Err(VmReceiveMigrationConfigError::InvalidSocketPrefix);
        }

        if let Some(tls_dir) = &self.tls_dir {
            validate_tls_dir(tls_dir, TlsEndpoint::Server)
                .map_err(VmReceiveMigrationConfigError::InvalidTlsConfiguration)?;
        }

        let unique_zones = self
            .zone_updates
            .iter()
            .map(|update| update.id.as_str())
            .collect::<HashSet<_>>();
        if self.zone_updates.len() != unique_zones.len() {
            return Err(VmReceiveMigrationConfigError::MultipleMemoryZoneUpdates);
        }
        if unique_zones.contains("") {
            return Err(VmReceiveMigrationConfigError::MemoryZoneUpdatesEmptyId);
        }

        Ok(())
    }

    pub fn validate_vfio_fds(
        &self,
        vm_config: &VmConfig,
    ) -> Result<(), VmReceiveMigrationConfigError> {
        let vfio_fds = self.vfio_fds.as_deref().unwrap_or_default();

        // A migrated VFIO device cannot reuse its source handle. Its fd is
        // invalid across the migration and its path names the source host's
        // topology, so every device needs a replacement in vfio_fds. This
        // holds even when no vfio_fds are supplied at all.
        let substituted: HashSet<&str> = vfio_fds.iter().map(|v| v.id.as_str()).collect();
        for d in vm_config.devices.iter().flatten() {
            if !d
                .pci_common
                .id
                .as_deref()
                .is_some_and(|id| substituted.contains(id))
            {
                return Err(VmReceiveMigrationConfigError::VfioDeviceNoReplacementFd(
                    d.pci_common.id.as_deref().unwrap_or_default().to_owned(),
                ));
            }
        }

        if vfio_fds.is_empty() {
            return Ok(());
        }

        // The supplied vfio_fds must be usable against the received VmConfig.
        if self.iommufd_fd.is_none() {
            return Err(VmReceiveMigrationConfigError::VfioFdRequiresIommufdFd);
        }
        if !vm_config.platform.as_ref().is_some_and(|p| p.iommufd) {
            return Err(VmReceiveMigrationConfigError::IommufdFdRequiresIommufd);
        }

        let mut seen = HashSet::new();
        for v in vfio_fds {
            if !seen.insert(v.id.as_str()) {
                return Err(VmReceiveMigrationConfigError::VfioFdMultipleReplacements(
                    v.id.to_owned(),
                ));
            }
        }

        let known_ids: HashSet<&str> = vm_config
            .devices
            .iter()
            .flatten()
            .filter_map(|d| d.pci_common.id.as_deref())
            .collect();
        for v in vfio_fds {
            if !known_ids.contains(v.id.as_str()) {
                return Err(
                    VmReceiveMigrationConfigError::VfioFdReplacementWithoutTarget(v.id.to_owned()),
                );
            }
        }

        Ok(())
    }
}

impl TryFrom<api_types::VmReceiveMigrationData> for VmReceiveMigrationData {
    type Error = VmReceiveMigrationConfigError;

    fn try_from(value: api_types::VmReceiveMigrationData) -> Result<Self, Self::Error> {
        let result = Self {
            receiver_url: value.receiver_url,
            tls_dir: value.tls_dir,
            memory_mode: value.memory_mode,
            vfio_fds: value.vfio_fds,
            iommufd_fd: value.iommufd_fd,
            zone_updates: value.zone_updates,
        };

        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs, process};

    use super::*;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "cloud-hypervisor-api-{name}-{}-{unique}",
                process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn add_file(&self, file_name: &str) {
            fs::write(self.path.join(file_name), b"test").unwrap();
        }

        fn add_receive_tls_files(&self) {
            self.add_file("ca-cert.pem");
            self.add_file("server-cert.pem");
            self.add_file("server-key.pem");
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_vm_receive_migration_data_validate() {
        let tls_dir = TestDir::new("receive-tls");
        tls_dir.add_receive_tls_files();
        VmReceiveMigrationData {
            receiver_url: "tcp:192.168.1.1:8080".to_owned(),
            tls_dir: Some(tls_dir.path.clone()),
            ..Default::default()
        }
        .validate()
        .unwrap();

        let tls_dir = TestDir::new("receive-empty-tls");
        let e = VmReceiveMigrationData {
            receiver_url: "tcp:192.168.1.1:8080".to_owned(),
            tls_dir: Some(tls_dir.path.clone()),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationConfigError::InvalidTlsConfiguration(_)),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::InvalidTlsConfiguration(TlsConfigError::MissingFile {
                endpoint: "",
                path: Default::default()
            }),
        );

        let e = VmReceiveMigrationData {
            receiver_url: "file:///tmp/migration".to_owned(),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationConfigError::InvalidSocketPrefix),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::InvalidSocketPrefix,
        );
        let e = VmReceiveMigrationData {
            receiver_url: "tcp:192.168.1.1".to_owned(),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(
                e,
                VmReceiveMigrationConfigError::MalformedReceiverUrl(
                    TcpAddressParseError::MissingPort
                )
            ),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::MalformedReceiverUrl(TcpAddressParseError::MissingPort),
        );

        let e = VmReceiveMigrationData {
            receiver_url: "tcp:[2001:db8::1]".to_owned(),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(
                e,
                VmReceiveMigrationConfigError::MalformedReceiverUrl(
                    TcpAddressParseError::MissingPortSeparatorAfterBracketedHost
                )
            ),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::MalformedReceiverUrl(
                TcpAddressParseError::MissingPortSeparatorAfterBracketedHost
            ),
        );

        let e = VmReceiveMigrationData {
            receiver_url: "unix:/tmp/sock".to_owned(),
            tls_dir: Some(PathBuf::from("/tmp".to_owned())),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(
                e,
                VmReceiveMigrationConfigError::TlsEncryptionUsedForUnixSocket
            ),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::TlsEncryptionUsedForUnixSocket,
        );

        // zone update tests
        let e = VmReceiveMigrationData {
            receiver_url: "unix:/tmp/sock".to_string(),
            zone_updates: vec![
                VmMemoryZoneUpdateData {
                    id: "zone1".to_owned(),
                    host_numa_node: 1,
                },
                VmMemoryZoneUpdateData {
                    id: "zone1".to_owned(),
                    host_numa_node: 2,
                },
            ],
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationConfigError::MultipleMemoryZoneUpdates),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::MultipleMemoryZoneUpdates,
        );

        let e = VmReceiveMigrationData {
            receiver_url: "unix:/tmp/sock".to_string(),
            zone_updates: vec![
                VmMemoryZoneUpdateData {
                    id: "zone1".to_owned(),
                    host_numa_node: 1,
                },
                VmMemoryZoneUpdateData {
                    id: "zone1".to_owned(),
                    host_numa_node: 2,
                },
            ],
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(e, VmReceiveMigrationConfigError::MultipleMemoryZoneUpdates),
            "Expected \"{:?}\"; got \"{e:?}\"",
            VmReceiveMigrationConfigError::MultipleMemoryZoneUpdates,
        );
    }
}
