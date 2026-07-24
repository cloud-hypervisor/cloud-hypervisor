// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RngConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub src: PathBuf,
}

#[derive(Debug, Error)]
pub enum RngConfigParseError {
    #[error("Failed to parse RNG configuration")]
    Parse(#[source] OptionParserError),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl RngConfig {
    pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";

    pub const SYNTAX: &'static str = "Random number generator parameters \"\
        src=<entropy_source_path>,iommu=on|off,pci_segment=<segment_id>,\
        pci_device_id=<pci_slot>\"";

    pub fn parse(rng: &str) -> Result<Self, RngConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("src")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser.parse(rng).map_err(RngConfigParseError::Parse)?;

        let src = PathBuf::from(
            parser
                .get("src")
                .unwrap_or_else(|| Self::DEFAULT_RNG_SOURCE.to_owned()),
        );
        let pci_common =
            PciDeviceCommonConfig::parse(rng).map_err(RngConfigParseError::PciDeviceCommon)?;

        Ok(Self { src, pci_common })
    }
}

impl Default for RngConfig {
    fn default() -> Self {
        Self {
            src: PathBuf::from(Self::DEFAULT_RNG_SOURCE),
            pci_common: PciDeviceCommonConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{PciDeviceCommonConfig, RngConfig, RngConfigParseError};

    #[test]
    fn test_parse_rng() -> Result<(), RngConfigParseError> {
        assert_eq!(RngConfig::parse("")?, RngConfig::default());
        assert_eq!(
            RngConfig::parse("src=/dev/random")?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                ..Default::default()
            }
        );
        assert_eq!(
            RngConfig::parse("src=/dev/random,iommu=on,pci_segment=1,pci_device_id=7")?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                pci_common: PciDeviceCommonConfig {
                    id: None,
                    iommu: true,
                    pci_segment: 1,
                    pci_device_id: Some(7),
                },
            }
        );
        assert_eq!(
            RngConfig::parse("iommu=on")?,
            RngConfig {
                pci_common: PciDeviceCommonConfig {
                    id: None,
                    iommu: true,
                    pci_segment: 0,
                    pci_device_id: None,
                },
                ..Default::default()
            }
        );
        Ok(())
    }
}
