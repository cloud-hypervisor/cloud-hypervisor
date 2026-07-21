// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoredVfioConfig {
    pub id: String,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "deserialize_restored_fd")]
    pub fd: Option<i32>,
}

fn deserialize_restored_fd<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fd: Option<i32> = Option::deserialize(d)?;
    if invalid_fd.is_some() {
        Ok(Some(-1))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Deserialize, Serialize, Debug, Eq, PartialEq)]
/// Data required for updating memory zone <-> host NUMA node mappings.
pub struct VmMemoryZoneUpdateData {
    /// Id of the MemoryZone to update
    pub id: String,
    /// Host NUMA node to relocate the MemoryZone to
    pub host_numa_node: u32,
}
