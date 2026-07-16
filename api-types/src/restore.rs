// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use log::debug;
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
