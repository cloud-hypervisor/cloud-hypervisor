// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use option_parser::{IntegerList, OptionParser, OptionParserError, StringList, Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NumaDistance {
    #[serde(default)]
    pub destination: u32,
    #[serde(default)]
    pub distance: u8,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NumaConfig {
    pub guest_numa_id: u32,
    #[serde(default)]
    pub cpus: Option<Box<[u32]>>,
    #[serde(default)]
    pub distances: Option<Box<[NumaDistance]>>,
    #[serde(default)]
    pub memory_zones: Option<Box<[String]>>,
    #[serde(default)]
    pub pci_segments: Option<Box<[u16]>>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum NumaConfigParseError {
    #[error("Failed to parse NUMA configuration")]
    Parse(#[from] OptionParserError),
}

impl NumaConfig {
    pub const SYNTAX: &'static str = "Settings related to a given NUMA node \
        \"guest_numa_id=<node_id>,cpus=<cpus_id>,distances=<list_of_distances_to_destination_nodes>,\
        device_id=<device_id>,\
        memory_zones=<list_of_memory_zones>,\
        pci_segments=<list_of_pci_segments>\"";

    pub fn parse(numa: &str) -> Result<Self, NumaConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("guest_numa_id")
            .add("cpus")
            .add("distances")
            .add("device_id")
            .add("memory_zones")
            .add("pci_segments");

        parser.parse(numa)?;

        let guest_numa_id = parser.convert::<u32>("guest_numa_id")?.ok_or_else(|| {
            OptionParserError::InvalidValue(
                "guest_numa_id is required for all NUMA nodes".to_string(),
            )
        })?;
        let cpus = parser
            .convert::<IntegerList>("cpus")?
            .map(|v| v.0.iter().map(|e| *e as u32).collect());
        let distances = parser
            .convert::<TupleList<u64, u64>>("distances")?
            .map(|v| {
                v.0.iter()
                    .map(|Tuple(e1, e2)| NumaDistance {
                        destination: *e1 as u32,
                        distance: *e2 as u8,
                    })
                    .collect()
            });
        let device_id = parser.get("device_id");
        let memory_zones = parser
            .convert::<StringList>("memory_zones")?
            .map(|v| v.0.into_boxed_slice());
        let pci_segments = parser
            .convert::<IntegerList>("pci_segments")?
            .map(|v| v.0.iter().map(|e| *e as u16).collect());
        if device_id.is_some() && (cpus.is_some() || memory_zones.is_some()) {
            return Err(NumaConfigParseError::Parse(
                OptionParserError::InvalidValue(
                    "device_id in numa config cannot be used with cpus or memory zones".to_string(),
                ),
            ));
        }
        Ok(NumaConfig {
            guest_numa_id,
            cpus,
            distances,
            device_id,
            memory_zones,
            pci_segments,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::vm_config::numa_config::NumaConfigParseError;
    use crate::{NumaConfig, NumaDistance};

    #[test]
    fn test_numa_config_parsing() -> Result<(), NumaConfigParseError> {
        // Error when device_id and cpu/memory are present
        let invalid_input = "guest_numa_id=0,cpus=[0,1],distances=[0@25,1@20],\
                                device_id=vfio0,memory_zones=[mem1],pci_segments=[0]";
        NumaConfig::parse(invalid_input).unwrap_err();
        // Successful numa config parsing
        let standard_input = "guest_numa_id=1,cpus=[2,3],distances=[0@20],\
                                memory_zones=[mem0],pci_segments=[0]";
        let expected_standard = NumaConfig {
            guest_numa_id: 1,
            cpus: Some(Box::new([2, 3])),
            distances: Some(Box::new([NumaDistance {
                destination: 0,
                distance: 20,
            }])),
            device_id: None,
            memory_zones: Some(Box::new(["mem0".to_string()])),
            pci_segments: Some(Box::new([0])),
        };
        assert_eq!(NumaConfig::parse(standard_input)?, expected_standard);
        // Successful generic initiator config parse
        let gi_input = "guest_numa_id=2,device_id=vfio1,distances=[0@30],pci_segments=[1]";
        let expected_gi = NumaConfig {
            guest_numa_id: 2,
            cpus: None,
            distances: Some(Box::new([NumaDistance {
                destination: 0,
                distance: 30,
            }])),
            device_id: Some("vfio1".to_string()),
            memory_zones: None,
            pci_segments: Some(Box::new([1])),
        };
        assert_eq!(NumaConfig::parse(gi_input)?, expected_gi);
        Ok(())
    }
}
