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
pub struct VdpaConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub path: PathBuf,
    #[serde(default = "default_vdpaconfig_num_queues")]
    pub num_queues: usize,
}

pub fn default_vdpaconfig_num_queues() -> usize {
    1
}

#[derive(Debug, Error)]
pub enum VdpaConfigParseError {
    #[error("Failed to parse vDPA configuration")]
    Parse(#[source] OptionParserError),
    #[error("vDPA path is missing")]
    PathMissing,
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl VdpaConfig {
    pub const SYNTAX: &'static str = "vDPA device \
        \"path=<device_path>,num_queues=<number_of_queues>,iommu=on|off,\
        id=<device_id>,pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(vdpa: &str) -> Result<Self, VdpaConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("num_queues")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser.parse(vdpa).map_err(VdpaConfigParseError::Parse)?;

        let pci_common =
            PciDeviceCommonConfig::parse(vdpa).map_err(VdpaConfigParseError::PciDeviceCommon)?;
        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(VdpaConfigParseError::PathMissing)?;
        let num_queues = parser
            .convert("num_queues")
            .map_err(VdpaConfigParseError::Parse)?
            .unwrap_or_else(default_vdpaconfig_num_queues);

        Ok(VdpaConfig {
            pci_common,
            path,
            num_queues,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{PciDeviceCommonConfig, VdpaConfig, VdpaConfigParseError};

    fn vdpa_fixture() -> VdpaConfig {
        VdpaConfig {
            pci_common: PciDeviceCommonConfig::default(),
            path: PathBuf::from("/dev/vhost-vdpa"),
            num_queues: 1,
        }
    }

    #[test]
    fn test_vdpa_parsing() -> Result<(), VdpaConfigParseError> {
        // path is required
        VdpaConfig::parse("").unwrap_err();
        assert_eq!(VdpaConfig::parse("path=/dev/vhost-vdpa")?, vdpa_fixture());
        assert_eq!(
            VdpaConfig::parse("path=/dev/vhost-vdpa,num_queues=2,id=my_vdpa")?,
            VdpaConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("my_vdpa".to_owned()),
                    ..Default::default()
                },
                num_queues: 2,
                ..vdpa_fixture()
            }
        );
        Ok(())
    }
}
