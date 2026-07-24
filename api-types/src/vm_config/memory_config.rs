// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;
use std::str::FromStr;

use option_parser::{ByteSized, OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

fn default_memoryconfig_thp() -> bool {
    true
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MemoryConfig {
    pub size: u64,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub hotplug_method: HotplugMethod,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub reserve: bool,
    #[serde(default)]
    pub zones: Option<Vec<MemoryZoneConfig>>,
    #[serde(default = "default_memoryconfig_thp")]
    pub thp: bool,
}

pub const DEFAULT_MEMORY_MB: u64 = 512;

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            size: DEFAULT_MEMORY_MB << 20,
            mergeable: false,
            hotplug_method: HotplugMethod::Acpi,
            hotplug_size: None,
            hotplugged_size: None,
            shared: false,
            hugepages: false,
            hugepage_size: None,
            prefault: false,
            reserve: false,
            zones: None,
            thp: true,
        }
    }
}

#[derive(Debug, Error)]
pub enum MemoryConfigParseError {
    #[error("Failed to parse memory configuration")]
    Parse(#[source] OptionParserError),
    #[error("Failed to parse memory-zone configuration")]
    ParseZone(#[source] OptionParserError),
    #[error("Memory-zone configuration is missing id")]
    MissingZoneId,
}

impl MemoryConfig {
    #[expect(clippy::needless_pass_by_value)]
    pub fn parse(
        memory: &str,
        memory_zones: Option<Vec<&str>>,
    ) -> Result<Self, MemoryConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size")
            .add("hotplugged_size")
            .add("shared")
            .add("hugepages")
            .add("hugepage_size")
            .add("prefault")
            .add("reserve")
            .add("thp");
        parser
            .parse(memory)
            .map_err(MemoryConfigParseError::Parse)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
            .0;
        let mergeable = parser
            .convert::<Toggle>("mergeable")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let hotplug_method = parser
            .convert("hotplug_method")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or_default();
        let hotplug_size = parser
            .convert::<ByteSized>("hotplug_size")
            .map_err(MemoryConfigParseError::Parse)?
            .map(|v| v.0);
        let hotplugged_size = parser
            .convert::<ByteSized>("hotplugged_size")
            .map_err(MemoryConfigParseError::Parse)?
            .map(|v| v.0);
        let shared = parser
            .convert::<Toggle>("shared")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let hugepages = parser
            .convert::<Toggle>("hugepages")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let hugepage_size = parser
            .convert::<ByteSized>("hugepage_size")
            .map_err(MemoryConfigParseError::Parse)?
            .map(|v| v.0);
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let reserve = parser
            .convert::<Toggle>("reserve")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let thp = parser
            .convert::<Toggle>("thp")
            .map_err(MemoryConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;

        let zones: Option<Vec<MemoryZoneConfig>> = if let Some(memory_zones) = &memory_zones {
            let mut zones = Vec::new();
            for memory_zone in memory_zones.iter() {
                let mut parser = OptionParser::new();
                parser
                    .add("id")
                    .add("size")
                    .add("file")
                    .add("shared")
                    .add("hugepages")
                    .add("hugepage_size")
                    .add("host_numa_node")
                    .add("hotplug_size")
                    .add("hotplugged_size")
                    .add("prefault")
                    .add("reserve")
                    .add("mergeable");
                parser
                    .parse(memory_zone)
                    .map_err(MemoryConfigParseError::ParseZone)?;

                let id = parser
                    .get("id")
                    .ok_or(MemoryConfigParseError::MissingZoneId)?;
                let size = parser
                    .convert::<ByteSized>("size")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
                    .0;
                let file = parser.get("file").map(PathBuf::from);
                let shared = parser
                    .convert::<Toggle>("shared")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let hugepages = parser
                    .convert::<Toggle>("hugepages")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let hugepage_size = parser
                    .convert::<ByteSized>("hugepage_size")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .map(|v| v.0);

                let host_numa_node = parser
                    .convert::<u32>("host_numa_node")
                    .map_err(MemoryConfigParseError::ParseZone)?;
                let hotplug_size = parser
                    .convert::<ByteSized>("hotplug_size")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .map(|v| v.0);
                let hotplugged_size = parser
                    .convert::<ByteSized>("hotplugged_size")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .map(|v| v.0);
                let prefault = parser
                    .convert::<Toggle>("prefault")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let reserve = parser
                    .convert::<Toggle>("reserve")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let mergeable = parser
                    .convert::<Toggle>("mergeable")
                    .map_err(MemoryConfigParseError::ParseZone)?
                    .unwrap_or(Toggle(mergeable))
                    .0;

                zones.push(MemoryZoneConfig {
                    id,
                    size,
                    file,
                    shared,
                    hugepages,
                    hugepage_size,
                    host_numa_node,
                    hotplug_size,
                    hotplugged_size,
                    prefault,
                    reserve,
                    mergeable,
                });
            }
            Some(zones)
        } else {
            None
        };

        Ok(MemoryConfig {
            size,
            mergeable,
            hotplug_method,
            hotplug_size,
            hotplugged_size,
            shared,
            hugepages,
            hugepage_size,
            prefault,
            reserve,
            zones,
            thp,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{HotplugMethod, MemoryConfig, MemoryConfigParseError, MemoryZoneConfig};

    #[test]
    fn test_mem_zone_parsing() -> Result<(), MemoryConfigParseError> {
        // mergeable defaults to false
        assert_eq!(
            MemoryConfig::parse("size=0", Some(vec!["id=mem0,size=1G"]))?,
            MemoryConfig {
                size: 0,
                zones: Some(vec![MemoryZoneConfig {
                    id: "mem0".to_string(),
                    size: 1 << 30,
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );
        // mergeable=on
        assert_eq!(
            MemoryConfig::parse("size=0", Some(vec!["id=mem0,size=1G,mergeable=on"]))?,
            MemoryConfig {
                size: 0,
                zones: Some(vec![MemoryZoneConfig {
                    id: "mem0".to_string(),
                    size: 1 << 30,
                    mergeable: true,
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );
        // mergeable=off is explicit false
        assert_eq!(
            MemoryConfig::parse("size=0", Some(vec!["id=mem0,size=1G,mergeable=off"]))?,
            MemoryConfig {
                size: 0,
                zones: Some(vec![MemoryZoneConfig {
                    id: "mem0".to_string(),
                    size: 1 << 30,
                    mergeable: false,
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );
        // per-zone mergeable independent of global mergeable
        assert_eq!(
            MemoryConfig::parse(
                "size=1G,mergeable=off",
                Some(vec!["id=hotplug,size=0,hotplug_size=4G,mergeable=on"])
            )?,
            MemoryConfig {
                size: 1 << 30,
                mergeable: false,
                hotplug_method: HotplugMethod::Acpi,
                zones: Some(vec![MemoryZoneConfig {
                    id: "hotplug".to_string(),
                    size: 0,
                    hotplug_size: Some(4 << 30),
                    mergeable: true,
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );
        // global mergeable=on inherited by zone with no explicit mergeable
        assert_eq!(
            MemoryConfig::parse("size=0,mergeable=on", Some(vec!["id=mem0,size=1G"]))?,
            MemoryConfig {
                size: 0,
                mergeable: true,
                zones: Some(vec![MemoryZoneConfig {
                    id: "mem0".to_string(),
                    size: 1 << 30,
                    mergeable: true,
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );
        // reserve=on on a zone
        assert_eq!(
            MemoryConfig::parse("size=0", Some(vec!["id=mem0,size=1G,reserve=on"]))?,
            MemoryConfig {
                size: 0,
                zones: Some(vec![MemoryZoneConfig {
                    id: "mem0".to_string(),
                    size: 1 << 30,
                    reserve: true,
                    ..Default::default()
                }]),
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_mem_parsing() -> Result<(), MemoryConfigParseError> {
        assert_eq!(MemoryConfig::parse("", None)?, MemoryConfig::default());
        // Default string
        assert_eq!(
            MemoryConfig::parse("size=512M", None)?,
            MemoryConfig::default()
        );
        assert_eq!(
            MemoryConfig::parse("size=512M,mergeable=on", None)?,
            MemoryConfig {
                size: 512 << 20,
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("mergeable=on", None)?,
            MemoryConfig {
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("size=1G,mergeable=off", None)?,
            MemoryConfig {
                size: 1 << 30,
                mergeable: false,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi", None)?,
            MemoryConfig {
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi,hotplug_size=512M", None)?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=virtio-mem,hotplug_size=512M", None)?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                hotplug_method: HotplugMethod::VirtioMem,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hugepages=on,size=1G,hugepage_size=2M", None)?,
            MemoryConfig {
                hugepage_size: Some(2 << 20),
                size: 1 << 30,
                hugepages: true,
                ..Default::default()
            }
        );
        // reserve=on opts out of MAP_NORESERVE
        assert_eq!(
            MemoryConfig::parse("size=1G,hugepages=on,reserve=on", None)?,
            MemoryConfig {
                size: 1 << 30,
                hugepages: true,
                reserve: true,
                ..Default::default()
            }
        );
        Ok(())
    }
}
