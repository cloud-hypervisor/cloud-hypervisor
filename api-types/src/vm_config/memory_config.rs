// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum HotplugMethod {
    #[default]
    Acpi,
    VirtioMem,
}

#[derive(Debug)]
pub enum ParseHotplugMethodError {
    InvalidValue(String),
}

impl FromStr for HotplugMethod {
    type Err = ParseHotplugMethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "acpi" => Ok(HotplugMethod::Acpi),
            "virtio-mem" => Ok(HotplugMethod::VirtioMem),
            _ => Err(ParseHotplugMethodError::InvalidValue(s.to_owned())),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct MemoryZoneConfig {
    pub id: String,
    pub size: u64,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub host_numa_node: Option<u32>,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub reserve: bool,
    #[serde(default)]
    pub mergeable: bool,
}
