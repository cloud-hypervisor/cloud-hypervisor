// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::result;

use anyhow::{Context, anyhow};
use vm_migration::{MigratableError, Snapshot};

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::GuestDebuggableError;
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

    let mut config: VmConfig = serde_json::from_slice(&bytes)
        .context("Error deserialising VM config snapshot")
        .map_err(MigratableError::MigrateReceive)?;
    // Device paths are invalid on the target host.
    if let Some(devices) = config.devices.as_mut() {
        devices.iter_mut().for_each(|device| device.path = None);
    }
    Ok(config)
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

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::tests::create_dummy_vm_config;
    use crate::vm_config::{DeviceConfig, PciDeviceCommonConfig};

    #[test]
    fn recv_vm_config_removes_vfio_paths() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = create_dummy_vm_config();
        config.devices = Some(
            ["vfio0", "vfio1"]
                .into_iter()
                .map(|id| DeviceConfig {
                    pci_common: PciDeviceCommonConfig {
                        id: Some(id.to_owned()),
                        ..Default::default()
                    },
                    path: Some(format!("/sys/bus/pci/devices/{id}").into()),
                    fd: Default::default(),
                    x_nv_gpudirect_clique: None,
                    x_exclude_mmap_bars: vec![],
                    iommufd_dev_id: None,
                })
                .collect(),
        );
        fs::write(
            directory.path().join(super::SNAPSHOT_CONFIG_FILE),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();

        let received =
            super::recv_vm_config(&format!("file://{}", directory.path().display())).unwrap();
        let devices = received.devices.as_ref().unwrap();
        assert_eq!(devices.len(), 2);
        for (device, original) in devices.iter().zip(config.devices.as_ref().unwrap()) {
            let mut expected = original.clone();
            expected.path = None;
            assert_eq!(device, &expected);
        }
    }
}
