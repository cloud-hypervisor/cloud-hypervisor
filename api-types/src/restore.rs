// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

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
