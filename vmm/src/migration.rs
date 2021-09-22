// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::vm::{VmSnapshot, VM_SNAPSHOT_ID};
use anyhow::anyhow;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use vm_migration::{MigratableError, Snapshot};

pub(crate) const VM_SNAPSHOT_FILE: &str = "vm.json";

pub(crate) fn url_to_path(url: &str) -> std::result::Result<PathBuf, MigratableError> {
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

pub(crate) fn recv_vm_snapshot(source_url: &str) -> std::result::Result<Snapshot, MigratableError> {
    let mut vm_snapshot_path = url_to_path(source_url)?;

    vm_snapshot_path.push(VM_SNAPSHOT_FILE);

    // Try opening the snapshot file
    let vm_snapshot_file =
        File::open(vm_snapshot_path).map_err(|e| MigratableError::MigrateSend(e.into()))?;
    let vm_snapshot_reader = BufReader::new(vm_snapshot_file);
    let vm_snapshot = serde_json::from_reader(vm_snapshot_reader)
        .map_err(|e| MigratableError::MigrateReceive(e.into()))?;

    Ok(vm_snapshot)
}

pub(crate) fn get_vm_snapshot(
    snapshot: &Snapshot,
) -> std::result::Result<VmSnapshot, MigratableError> {
    if let Some(vm_section) = snapshot
        .snapshot_data
        .get(&format!("{}-section", VM_SNAPSHOT_ID))
    {
        return serde_json::from_slice(&vm_section.snapshot).map_err(|e| {
            MigratableError::Restore(anyhow!("Could not deserialize VM snapshot {}", e))
        });
    }

    Err(MigratableError::Restore(anyhow!(
        "Could not find VM config snapshot section"
    )))
}
