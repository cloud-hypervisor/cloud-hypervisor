// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{ByteSized, OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

pub const DEFAULT_IVSHMEM_SIZE: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IvshmemConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub path: PathBuf,
    pub size: usize,
}

impl Default for IvshmemConfig {
    fn default() -> Self {
        Self {
            pci_common: PciDeviceCommonConfig::default(),
            path: PathBuf::new(),
            size: DEFAULT_IVSHMEM_SIZE << 20,
        }
    }
}

#[derive(Debug, Error)]
pub enum IvshmemConfigParseError {
    #[error("Failed to parse ivshmem configuration")]
    Parse(#[source] OptionParserError),
    #[error("Ivshmem path is missing")]
    PathMissing,
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl IvshmemConfig {
    pub const SYNTAX: &'static str = "Ivshmem device. Specify the backend file path and size \
    for the shared memory: \"path=</path/to/a/file>,size=<file_size>,id=<device_id>,\
    pci_segment=<segment_id>,pci_device_id=<pci_slot>\" \
    \nThe <file_size> must be a power of 2 (e.g., 2M, 4M, etc.), as it represents the size \
    of the memory region mapped to the guest. Default size is 128M.";

    pub fn parse(ivshmem: &str) -> Result<Self, IvshmemConfigParseError> {
        let mut parser = OptionParser::new();
        parser.add("path").add("size");
        parser.add_all(PciDeviceCommonConfig::OPTIONS);
        parser
            .parse(ivshmem)
            .map_err(IvshmemConfigParseError::Parse)?;
        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(IvshmemConfigParseError::PathMissing)?;
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(IvshmemConfigParseError::Parse)?
            .unwrap_or(ByteSized((DEFAULT_IVSHMEM_SIZE << 20) as u64))
            .0;
        let pci_common = PciDeviceCommonConfig::parse(ivshmem)
            .map_err(IvshmemConfigParseError::PciDeviceCommon)?;
        Ok(IvshmemConfig {
            pci_common,
            path,
            size: size as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{IvshmemConfig, IvshmemConfigParseError, PciDeviceCommonConfig};

    #[test]
    #[cfg(feature = "ivshmem")]
    fn test_parse_ivshmem() -> Result<(), IvshmemConfigParseError> {
        assert_eq!(
            IvshmemConfig::parse("path=/tmp/ivshmem.data,size=2M,pci_segment=1,pci_device_id=7")?,
            IvshmemConfig {
                pci_common: PciDeviceCommonConfig {
                    pci_segment: 1,
                    pci_device_id: Some(7),
                    ..Default::default()
                },
                path: PathBuf::from("/tmp/ivshmem.data"),
                size: 2 << 20,
            }
        );

        Ok(())
    }
}
