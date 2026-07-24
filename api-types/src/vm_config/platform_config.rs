// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::LazyLock;

use log::{debug, warn};
use option_parser::{IntegerList, OptionParser, OptionParserError, StringList, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_NUM_PCI_SEGMENTS: u16 = 1;
pub fn default_platformconfig_num_pci_segments() -> u16 {
    DEFAULT_NUM_PCI_SEGMENTS
}
pub const DEFAULT_IOMMU_ADDRESS_WIDTH_BITS: u8 = 64;
pub fn default_platformconfig_iommu_address_width_bits() -> u8 {
    DEFAULT_IOMMU_ADDRESS_WIDTH_BITS
}
pub fn default_platformconfig_vfio_p2p_dma() -> bool {
    true
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PlatformConfig {
    #[serde(default = "default_platformconfig_num_pci_segments")]
    pub num_pci_segments: u16,
    #[serde(default)]
    pub iommu_segments: Option<Box<[u16]>>,
    #[serde(default = "default_platformconfig_iommu_address_width_bits")]
    pub iommu_address_width_bits: u8,
    #[serde(default, alias = "serial_number")]
    pub system_serial_number: Option<String>,
    #[serde(default, alias = "uuid")]
    pub system_uuid: Option<String>,
    #[serde(default)]
    pub oem_strings: Option<Box<[String]>>,
    #[serde(default)]
    pub system_manufacturer: Option<String>,
    #[serde(default)]
    pub system_product_name: Option<String>,
    #[serde(default)]
    pub system_version: Option<String>,
    #[serde(default)]
    pub system_family: Option<String>,
    #[serde(default)]
    pub system_sku_number: Option<String>,
    #[serde(default)]
    pub chassis_asset_tag: Option<String>,
    #[cfg(feature = "tdx")]
    #[serde(default)]
    pub tdx: bool,
    #[cfg(feature = "sev_snp")]
    #[serde(default)]
    pub sev_snp: bool,
    #[serde(default)]
    pub iommufd: bool,
    #[serde(default, deserialize_with = "deserialize_platformconfig_iommufd_fd")]
    pub iommufd_fd: Option<i32>,
    #[serde(default = "default_platformconfig_vfio_p2p_dma")]
    pub vfio_p2p_dma: bool,
}

fn deserialize_platformconfig_iommufd_fd<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fd: Option<i32> = Option::deserialize(d)?;
    if invalid_fd.is_some() {
        debug!(
            "FD in 'PlatformConfig::iommufd_fd' won't be deserialized as it is most likely invalid now. Deserializing it as -1."
        );
        Ok(Some(-1))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Error)]
pub enum PlatformConfigParseError {
    #[error("Failed to parse platform configuration")]
    Parse(#[source] OptionParserError),
}

impl PlatformConfig {
    pub fn syntax() -> &'static str {
        static SYNTAX: LazyLock<String> = LazyLock::new(|| {
            let mut syntax = "Platform configuration parameters \"num_pci_segments=<num_pci_segments>,iommu_segments=<list_of_segments>,iommu_address_width=<bits>,iommufd=on|off,iommufd_fd=<fd>,vfio_p2p_dma=on|off,system_manufacturer=<dmi_system_manufacturer>,system_product_name=<dmi_system_product_name>,system_version=<dmi_system_version>,system_serial_number=<dmi_system_serial_number>,system_uuid=<dmi_system_uuid>,system_sku_number=<dmi_system_sku_number>,system_family=<dmi_system_family>,oem_strings=<list_of_strings>,chassis_asset_tag=<dmi_chassis_asset_tag>".to_string();
            if cfg!(feature = "tdx") {
                syntax.push_str(",tdx=on|off");
            }
            if cfg!(feature = "sev_snp") {
                syntax.push_str(",sev_snp=on|off");
            }
            syntax.push('"');
            syntax
        });
        &SYNTAX
    }
    pub fn parse(platform: &str) -> Result<Self, PlatformConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("num_pci_segments")
            .add("iommu_segments")
            .add("iommu_address_width")
            .add("serial_number")
            .add("uuid")
            .add("oem_strings")
            .add("iommufd")
            .add("iommufd_fd")
            .add("vfio_p2p_dma")
            .add("system_manufacturer")
            .add("system_product_name")
            .add("system_version")
            .add("system_serial_number")
            .add("system_uuid")
            .add("system_sku_number")
            .add("system_family")
            .add("chassis_asset_tag");
        #[cfg(feature = "tdx")]
        parser.add("tdx");
        #[cfg(feature = "sev_snp")]
        parser.add("sev_snp");
        parser
            .parse(platform)
            .map_err(PlatformConfigParseError::Parse)?;
        let mut config = Self {
            num_pci_segments: parser
                .convert("num_pci_segments")
                .map_err(PlatformConfigParseError::Parse)?
                .unwrap_or(DEFAULT_NUM_PCI_SEGMENTS),
            iommu_segments: parser
                .convert::<IntegerList>("iommu_segments")
                .map_err(PlatformConfigParseError::Parse)?
                .map(|v| v.0.iter().map(|e| *e as u16).collect()),
            iommu_address_width_bits: parser
                .convert("iommu_address_width")
                .map_err(PlatformConfigParseError::Parse)?
                .unwrap_or(DEFAULT_IOMMU_ADDRESS_WIDTH_BITS),
            system_serial_number: parser
                .convert("system_serial_number")
                .map_err(PlatformConfigParseError::Parse)?,
            system_uuid: parser
                .convert("system_uuid")
                .map_err(PlatformConfigParseError::Parse)?,
            oem_strings: parser
                .convert::<StringList>("oem_strings")
                .map_err(PlatformConfigParseError::Parse)?
                .map(|v| v.0.into_boxed_slice()),
            system_manufacturer: parser
                .convert("system_manufacturer")
                .map_err(PlatformConfigParseError::Parse)?,
            system_product_name: parser
                .convert("system_product_name")
                .map_err(PlatformConfigParseError::Parse)?,
            system_version: parser
                .convert("system_version")
                .map_err(PlatformConfigParseError::Parse)?,
            system_family: parser
                .convert("system_family")
                .map_err(PlatformConfigParseError::Parse)?,
            system_sku_number: parser
                .convert("system_sku_number")
                .map_err(PlatformConfigParseError::Parse)?,
            chassis_asset_tag: parser
                .convert("chassis_asset_tag")
                .map_err(PlatformConfigParseError::Parse)?,
            #[cfg(feature = "tdx")]
            tdx: parser
                .convert::<Toggle>("tdx")
                .map_err(PlatformConfigParseError::Parse)?
                .unwrap_or(Toggle(false))
                .0,
            #[cfg(feature = "sev_snp")]
            sev_snp: parser
                .convert::<Toggle>("sev_snp")
                .map_err(PlatformConfigParseError::Parse)?
                .unwrap_or(Toggle(false))
                .0,
            iommufd_fd: parser
                .convert("iommufd_fd")
                .map_err(PlatformConfigParseError::Parse)?,
            iommufd: false,
            vfio_p2p_dma: parser
                .convert::<Toggle>("vfio_p2p_dma")
                .map_err(PlatformConfigParseError::Parse)?
                .unwrap_or(Toggle(true))
                .0,
        };
        config.iommufd = parser
            .convert::<Toggle>("iommufd")
            .map_err(PlatformConfigParseError::Parse)?
            .map_or(config.iommufd_fd.is_some(), |Toggle(v)| v);
        let legacy_serial = parser
            .convert("serial_number")
            .map_err(PlatformConfigParseError::Parse)?;
        if legacy_serial.is_some() {
            warn!("'serial_number' in --platform is deprecated; use 'system_serial_number'.");
        }
        config.system_serial_number = config.system_serial_number.or(legacy_serial);
        let legacy_uuid = parser
            .convert("uuid")
            .map_err(PlatformConfigParseError::Parse)?;
        if legacy_uuid.is_some() {
            warn!("'uuid' in --platform is deprecated; use 'system_uuid'.");
        }
        config.system_uuid = config.system_uuid.or(legacy_uuid);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use crate::{PlatformConfig, PlatformConfigParseError};

    #[test]
    fn test_platform_iommufd_fd_parsing() -> Result<(), PlatformConfigParseError> {
        // `iommufd_fd=N` alone implies `iommufd=on`.
        let p = PlatformConfig::parse("iommufd_fd=42")?;
        assert!(p.iommufd);
        assert_eq!(p.iommufd_fd, Some(42));

        // Explicit `iommufd=on,iommufd_fd=N` is the same.
        let p = PlatformConfig::parse("iommufd=on,iommufd_fd=42")?;
        assert!(p.iommufd);
        assert_eq!(p.iommufd_fd, Some(42));

        // No flags → both default to off.
        let p = PlatformConfig::parse("")?;
        assert!(!p.iommufd);
        assert_eq!(p.iommufd_fd, None);

        Ok(())
    }
}
