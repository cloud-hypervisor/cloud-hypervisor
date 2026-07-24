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
pub struct UserDeviceConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub socket: PathBuf,
}

#[derive(Debug, Error)]
pub enum UserDeviceConfigParseError {
    #[error("Failed to parse userspace device configuration")]
    Parse(#[source] OptionParserError),
    #[error("Userspace device socket is missing")]
    SocketMissing,
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl UserDeviceConfig {
    pub const SYNTAX: &'static str = "Userspace device socket=<socket_path>,id=<device_id>,\
        pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(user_device: &str) -> Result<Self, UserDeviceConfigParseError> {
        let mut parser = OptionParser::new();
        parser.add("socket").add_all(PciDeviceCommonConfig::OPTIONS);
        parser
            .parse(user_device)
            .map_err(UserDeviceConfigParseError::Parse)?;

        let pci_common = PciDeviceCommonConfig::parse(user_device)
            .map_err(UserDeviceConfigParseError::PciDeviceCommon)?;
        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(UserDeviceConfigParseError::SocketMissing)?;

        Ok(UserDeviceConfig { pci_common, socket })
    }
}
