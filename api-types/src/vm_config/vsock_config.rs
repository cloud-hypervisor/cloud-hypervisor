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
pub struct VsockConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub cid: u32,
    pub socket: PathBuf,
}

#[derive(Debug, Error)]
pub enum VsockConfigParseError {
    #[error("Failed to parse vsock configuration")]
    Parse(#[source] OptionParserError),
    #[error("Vsock socket is missing")]
    SocketMissing,
    #[error("Vsock CID is missing")]
    CidMissing,
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl VsockConfig {
    pub const SYNTAX: &'static str = "Virtio VSOCK parameters \
        \"cid=<context_id>,socket=<socket_path>,iommu=on|off,id=<device_id>,\
        pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(vsock: &str) -> Result<Self, VsockConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("socket")
            .add("cid")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser.parse(vsock).map_err(VsockConfigParseError::Parse)?;

        let pci_common =
            PciDeviceCommonConfig::parse(vsock).map_err(VsockConfigParseError::PciDeviceCommon)?;
        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(VsockConfigParseError::SocketMissing)?;
        let cid = parser
            .convert("cid")
            .map_err(VsockConfigParseError::Parse)?
            .ok_or(VsockConfigParseError::CidMissing)?;

        Ok(VsockConfig {
            pci_common,
            cid,
            socket,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{PciDeviceCommonConfig, VsockConfig, VsockConfigParseError};

    #[test]
    fn test_vsock_parsing() -> Result<(), VsockConfigParseError> {
        // socket and cid is required
        VsockConfig::parse("").unwrap_err();
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=3")?,
            VsockConfig {
                pci_common: PciDeviceCommonConfig::default(),
                cid: 3,
                socket: PathBuf::from("/tmp/sock"),
            }
        );
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=3,iommu=on")?,
            VsockConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                cid: 3,
                socket: PathBuf::from("/tmp/sock"),
            }
        );
        Ok(())
    }
}
