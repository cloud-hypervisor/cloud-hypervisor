// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use log::debug;
use option_parser::{IntegerList, OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    #[serde(default)]
    pub path: Option<PathBuf>,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "deserialize_deviceconfig_fd")]
    pub fd: Option<i32>,
    #[serde(default)]
    pub x_nv_gpudirect_clique: Option<u8>,
    #[serde(default)]
    pub x_exclude_mmap_bars: Vec<u64>,
}

fn deserialize_deviceconfig_fd<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fd: Option<i32> = Option::deserialize(d)?;
    if invalid_fd.is_some() {
        debug!(
            "FD in 'DeviceConfig' won't be deserialized as it is most likely invalid now. Deserializing it as -1."
        );
        Ok(Some(-1))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Error)]
pub enum DeviceConfigParseError {
    #[error("Failed to parse device configuration")]
    Parse(#[source] OptionParserError),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl DeviceConfig {
    pub const SYNTAX: &'static str = "Direct device assignment parameters \
    \"path=<device_path>,fd=<vfio_cdev_fd>,iommu=on|off,id=<device_id>,\
    pci_segment=<segment_id>,pci_device_id=<pci_slot>,\
    x_nv_gpudirect_clique=<clique_id>,\
    x_exclude_mmap_bars=[<bar>...]\"";

    pub fn parse(device: &str) -> Result<Self, DeviceConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("fd")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU)
            .add("x_nv_gpudirect_clique")
            .add("x_exclude_mmap_bars");
        parser
            .parse(device)
            .map_err(DeviceConfigParseError::Parse)?;

        let pci_common = PciDeviceCommonConfig::parse(device)
            .map_err(DeviceConfigParseError::PciDeviceCommon)?;
        let path = parser.get("path").map(PathBuf::from);
        let fd = parser
            .convert::<i32>("fd")
            .map_err(DeviceConfigParseError::Parse)?;
        let x_nv_gpudirect_clique = parser
            .convert::<u8>("x_nv_gpudirect_clique")
            .map_err(DeviceConfigParseError::Parse)?;
        let x_exclude_mmap_bars = parser
            .convert::<IntegerList>("x_exclude_mmap_bars")
            .map_err(DeviceConfigParseError::Parse)?
            .map(|bars| bars.0)
            .unwrap_or_default();

        Ok(DeviceConfig {
            pci_common,
            path,
            fd,
            x_nv_gpudirect_clique,
            x_exclude_mmap_bars,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{DeviceConfig, DeviceConfigParseError, PciDeviceCommonConfig};

    fn device_fixture() -> DeviceConfig {
        DeviceConfig {
            pci_common: PciDeviceCommonConfig::default(),
            path: Some(PathBuf::from("/path/to/device")),
            fd: None,
            x_nv_gpudirect_clique: None,
            x_exclude_mmap_bars: Vec::new(),
        }
    }

    #[test]
    fn test_device_parsing() -> Result<(), DeviceConfigParseError> {
        // The parser itself is purely syntactic; the "path or fd is
        // required" rule is enforced by VmConfig::validate instead.
        assert_eq!(
            DeviceConfig::parse("")?,
            DeviceConfig {
                path: None,
                ..device_fixture()
            }
        );
        assert_eq!(
            DeviceConfig::parse("path=/path/to/device")?,
            device_fixture()
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on")?,
            DeviceConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                ..device_fixture()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on,id=mydevice0")?,
            DeviceConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("mydevice0".to_owned()),
                    iommu: true,
                    ..Default::default()
                },
                ..device_fixture()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,x_exclude_mmap_bars=[2]")?,
            DeviceConfig {
                x_exclude_mmap_bars: vec![2],
                ..device_fixture()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,x_exclude_mmap_bars=[0,2,5]")?,
            DeviceConfig {
                x_exclude_mmap_bars: vec![0, 2, 5],
                ..device_fixture()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,x_exclude_mmap_bars=[6]")?,
            DeviceConfig {
                x_exclude_mmap_bars: vec![6],
                ..device_fixture()
            }
        );

        // `fd=` is accepted alongside or in place of `path=`; exclusivity
        // is enforced by DeviceConfig::validate, not by the parser.
        assert_eq!(
            DeviceConfig::parse("fd=7")?,
            DeviceConfig {
                path: None,
                fd: Some(7),
                ..device_fixture()
            }
        );
        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,fd=7")?,
            DeviceConfig {
                fd: Some(7),
                ..device_fixture()
            }
        );
        // Non-integer fd fails at parse time.
        DeviceConfig::parse("fd=notanint").unwrap_err();

        Ok(())
    }
}
