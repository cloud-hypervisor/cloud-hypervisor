// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

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
