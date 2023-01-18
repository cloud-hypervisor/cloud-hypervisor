// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "guest_debug")]
use crate::coredump::GuestDebuggableError;
use crate::{
    config::VmConfig,
    vm::{VmSnapshot, VM_SNAPSHOT_ID},
};
use anyhow::anyhow;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use vm_migration::{MigratableError, Snapshot};

pub const SNAPSHOT_STATE_FILE: &str = "state.json";
pub const SNAPSHOT_CONFIG_FILE: &str = "config.json";

pub fn url_to_path(url: &str) -> std::result::Result<PathBuf, MigratableError> {
    let path: PathBuf = url
        .strip_prefix("file://")
        .ok_or_else(|| {
            MigratableError::MigrateSend(anyhow!("Could not extract path from URL: {}", url))
        })
        .map(|s| s.into())?;

    if !path.is_dir() {
        return Err(MigratableError::MigrateSend(anyhow!(
            "Destination is not a directory"
        )));
    }

    Ok(path)
}

#[cfg(feature = "guest_debug")]
pub fn url_to_file(url: &str) -> std::result::Result<PathBuf, GuestDebuggableError> {
    let file: PathBuf = url
        .strip_prefix("file://")
        .ok_or_else(|| {
            GuestDebuggableError::Coredump(anyhow!("Could not extract file from URL: {}", url))
        })
        .map(|s| s.into())?;

    Ok(file)
}

pub fn recv_vm_config(source_url: &str) -> std::result::Result<VmConfig, MigratableError> {
    let mut vm_config_path = url_to_path(source_url)?;

    vm_config_path.push(SNAPSHOT_CONFIG_FILE);

    // Try opening the snapshot file
    let vm_config_file =
        File::open(vm_config_path).map_err(|e| MigratableError::MigrateSend(e.into()))?;
    let vm_config_reader = BufReader::new(vm_config_file);
    serde_json::from_reader(vm_config_reader).map_err(|e| MigratableError::MigrateReceive(e.into()))
}

pub fn recv_vm_state(source_url: &str) -> std::result::Result<Snapshot, MigratableError> {
    let mut vm_state_path = url_to_path(source_url)?;

    vm_state_path.push(SNAPSHOT_STATE_FILE);

    // Try opening the snapshot file
    let vm_state_file =
        File::open(vm_state_path).map_err(|e| MigratableError::MigrateSend(e.into()))?;
    let vm_state_reader = BufReader::new(vm_state_file);
    serde_json::from_reader(vm_state_reader).map_err(|e| MigratableError::MigrateReceive(e.into()))
}

pub fn get_vm_snapshot(snapshot: &Snapshot) -> std::result::Result<VmSnapshot, MigratableError> {
    if let Some(vm_section) = snapshot
        .snapshot_data
        .get(&format!("{VM_SNAPSHOT_ID}-section"))
    {
        return serde_json::from_slice(&vm_section.snapshot).map_err(|e| {
            MigratableError::Restore(anyhow!("Could not deserialize VM snapshot {}", e))
        });
    }

    Err(MigratableError::Restore(anyhow!(
        "Could not find VM config snapshot section"
    )))
}
