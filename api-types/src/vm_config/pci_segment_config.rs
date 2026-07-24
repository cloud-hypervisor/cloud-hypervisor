// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT: u32 = 1;

fn default_pci_segment_aperture_weight() -> u32 {
    DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PciSegmentConfig {
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default = "default_pci_segment_aperture_weight")]
    pub mmio32_aperture_weight: u32,
    #[serde(default = "default_pci_segment_aperture_weight")]
    pub mmio64_aperture_weight: u32,
}

#[derive(Debug, Error)]
pub enum PciSegmentConfigParseError {
    #[error("Failed to parse PCI segment configuration")]
    Parse(#[source] OptionParserError),
}

impl PciSegmentConfig {
    pub const SYNTAX: &'static str = "PCI Segment parameters \
         \"pci_segment=<segment_id>,mmio32_aperture_weight=<scale>,mmio64_aperture_weight=<scale>\"";

    pub fn parse(disk: &str) -> Result<Self, PciSegmentConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("mmio32_aperture_weight")
            .add("mmio64_aperture_weight")
            .add("pci_segment");
        parser
            .parse(disk)
            .map_err(PciSegmentConfigParseError::Parse)?;

        let pci_segment = parser
            .convert("pci_segment")
            .map_err(PciSegmentConfigParseError::Parse)?
            .unwrap_or_default();
        let mmio32_aperture_weight = parser
            .convert("mmio32_aperture_weight")
            .map_err(PciSegmentConfigParseError::Parse)?
            .unwrap_or(DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT);
        let mmio64_aperture_weight = parser
            .convert("mmio64_aperture_weight")
            .map_err(PciSegmentConfigParseError::Parse)?
            .unwrap_or(DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT);

        Ok(PciSegmentConfig {
            pci_segment,
            mmio32_aperture_weight,
            mmio64_aperture_weight,
        })
    }
}

#[test]
fn test_pci_segment_parsing() -> Result<(), PciSegmentConfigParseError> {
    assert_eq!(
        PciSegmentConfig::parse("pci_segment=0")?,
        PciSegmentConfig {
            pci_segment: 0,
            mmio32_aperture_weight: 1,
            mmio64_aperture_weight: 1,
        }
    );
    assert_eq!(
        PciSegmentConfig::parse("pci_segment=0,mmio32_aperture_weight=1,mmio64_aperture_weight=1")?,
        PciSegmentConfig {
            pci_segment: 0,
            mmio32_aperture_weight: 1,
            mmio64_aperture_weight: 1,
        }
    );
    assert_eq!(
        PciSegmentConfig::parse("pci_segment=0,mmio32_aperture_weight=2")?,
        PciSegmentConfig {
            pci_segment: 0,
            mmio32_aperture_weight: 2,
            mmio64_aperture_weight: 1,
        }
    );
    assert_eq!(
        PciSegmentConfig::parse("pci_segment=0,mmio64_aperture_weight=2")?,
        PciSegmentConfig {
            pci_segment: 0,
            mmio32_aperture_weight: 1,
            mmio64_aperture_weight: 2,
        }
    );

    Ok(())
}
