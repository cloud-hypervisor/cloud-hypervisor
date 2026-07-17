// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{ByteSized, OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PmemConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub file: PathBuf,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub discard_writes: bool,
}

#[derive(Debug, Error)]
pub enum PmemConfigParseError {
    #[error("Failed to parse persistent memory configuration")]
    Parse(#[source] OptionParserError),
    #[error("Persistent memory file is missing")]
    FileMissing,
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl PmemConfig {
    pub const SYNTAX: &'static str = "Persistent memory parameters \
    \"file=<backing_file_path>,size=<persistent_memory_size>,iommu=on|off,\
    discard_writes=on|off,id=<device_id>,\
    pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(pmem: &str) -> Result<Self, PmemConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("discard_writes")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser.parse(pmem).map_err(PmemConfigParseError::Parse)?;

        let pci_common =
            PciDeviceCommonConfig::parse(pmem).map_err(PmemConfigParseError::PciDeviceCommon)?;
        let file = PathBuf::from(
            parser
                .get("file")
                .ok_or(PmemConfigParseError::FileMissing)?,
        );
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(PmemConfigParseError::Parse)?
            .map(|v| v.0);
        let discard_writes = parser
            .convert::<Toggle>("discard_writes")
            .map_err(PmemConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(Self {
            pci_common,
            file,
            size,
            discard_writes,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{PciDeviceCommonConfig, PmemConfig, PmemConfigParseError};

    fn pmem_fixture() -> PmemConfig {
        PmemConfig {
            pci_common: PciDeviceCommonConfig::default(),
            file: PathBuf::from("/tmp/pmem"),
            size: Some(128 << 20),
            discard_writes: false,
        }
    }

    #[test]
    fn test_pmem_parsing() -> Result<(), PmemConfigParseError> {
        // Must always give a file and size
        PmemConfig::parse("").unwrap_err();
        PmemConfig::parse("size=128M").unwrap_err();
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M")?,
            pmem_fixture()
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,id=mypmem0")?,
            PmemConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("mypmem0".to_owned()),
                    ..Default::default()
                },
                ..pmem_fixture()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,iommu=on,discard_writes=on")?,
            PmemConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                discard_writes: true,
                ..pmem_fixture()
            }
        );

        Ok(())
    }
}
