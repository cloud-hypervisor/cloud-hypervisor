// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use option_parser::{OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct PciDeviceCommonConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "<&bool as std::ops::Not>::not")]
    pub iommu: bool,
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default)]
    pub pci_device_id: Option<u8>,
}

#[derive(Debug, Error)]
pub enum PciDeviceCommonConfigParseError {
    #[error("Failed to parse PCI device configuration")]
    Parse(#[source] OptionParserError),
}

impl PciDeviceCommonConfig {
    pub const OPTIONS: &[&str] = &["id", "pci_segment", "pci_device_id"];
    pub const OPTIONS_IOMMU: &[&str] = &["id", "iommu", "pci_segment", "pci_device_id"];

    pub fn parse(input: &str) -> Result<Self, PciDeviceCommonConfigParseError> {
        let mut parser = OptionParser::new();

        parser.add_all(Self::OPTIONS_IOMMU);

        parser
            .parse_subset(input)
            .map_err(PciDeviceCommonConfigParseError::Parse)?;

        let id = parser.get("id");
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(PciDeviceCommonConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(PciDeviceCommonConfigParseError::Parse)?
            .unwrap_or_default();
        let pci_device_id = parser
            .convert::<u8>("pci_device_id")
            .map_err(PciDeviceCommonConfigParseError::Parse)?;

        Ok(Self {
            id,
            iommu,
            pci_segment,
            pci_device_id,
        })
    }
}
