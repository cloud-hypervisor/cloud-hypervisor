// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RtcConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
}

#[derive(Debug, Error)]
pub enum RtcConfigParseError {
    #[error("Failed to parse RTC configuration")]
    Parse(#[source] OptionParserError),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl RtcConfig {
    pub const SYNTAX: &'static str = "Virtio RTC parameters \"\
        iommu=on|off,id=<device_id>,\
        pci_segment=<segment_id>,pci_device_id=<pci_slot>\". \
        Passing --rtc with no arguments enables the device with default \
        settings.";

    pub fn parse(rtc: &str) -> Result<Self, RtcConfigParseError> {
        let mut parser = OptionParser::new();
        parser.add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser.parse(rtc).map_err(RtcConfigParseError::Parse)?;

        let pci_common =
            PciDeviceCommonConfig::parse(rtc).map_err(RtcConfigParseError::PciDeviceCommon)?;

        Ok(Self { pci_common })
    }
}
