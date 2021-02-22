// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::vm::{VmSnapshot, VM_SNAPSHOT_ID};
use anyhow::anyhow;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use url::Url;
use vm_migration::{MigratableError, Snapshot};

pub const VM_SNAPSHOT_FILE: &str = "vm.json";

pub fn url_to_path(url: &Url) -> std::result::Result<PathBuf, MigratableError> {
    match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|_| {
                MigratableError::MigrateSend(anyhow!(
                    "Could not convert file URL to a file path: {}",
                    url.as_str()
                ))
            })
            .and_then(|path| {
                if !path.is_dir() {
                    return Err(MigratableError::MigrateSend(anyhow!(
                        "Destination is not a directory"
                    )));
                }
                Ok(path)
            }),

        _ => Err(MigratableError::MigrateSend(anyhow!(
            "URL scheme is not file: {}",
            url.scheme()
        ))),
    }
}

pub fn recv_vm_snapshot(source_url: &str) -> std::result::Result<Snapshot, MigratableError> {
    let url = Url::parse(source_url).map_err(|e| {
        MigratableError::MigrateSend(anyhow!("Could not parse destination URL: {}", e))
    })?;

    match url.scheme() {
        "file" => {
            let mut vm_snapshot_path = url_to_path(&url)?;
            vm_snapshot_path.push(VM_SNAPSHOT_FILE);

            // Try opening the snapshot file
            let vm_snapshot_file =
                File::open(vm_snapshot_path).map_err(|e| MigratableError::MigrateSend(e.into()))?;
            let vm_snapshot_reader = BufReader::new(vm_snapshot_file);
            let vm_snapshot = serde_json::from_reader(vm_snapshot_reader)
                .map_err(|e| MigratableError::MigrateReceive(e.into()))?;

            Ok(vm_snapshot)
        }
        _ => Err(MigratableError::MigrateSend(anyhow!(
            "Unsupported VM transport URL scheme: {}",
            url.scheme()
        ))),
    }
}

pub fn get_vm_snapshot(snapshot: &Snapshot) -> std::result::Result<VmSnapshot, MigratableError> {
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
