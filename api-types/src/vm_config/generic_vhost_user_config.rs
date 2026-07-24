// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use log::warn;
use option_parser::{IntegerList, OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_ids::*;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GenericVhostUserConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub socket: PathBuf,
    pub queue_sizes: Vec<u16>,
    pub device_type: u32,
}

#[derive(Debug, Error)]
pub enum GenericVhostUserConfigParseError {
    #[error("Failed to parse generic vhost-user configuration")]
    Parse(#[source] OptionParserError),
    #[error("Generic vhost-user socket is missing")]
    SocketMissing,
    #[error("Generic vhost-user queue sizes are missing")]
    QueueSizesMissing,
    #[error("Generic vhost-user device type is missing")]
    DeviceTypeMissing,
    #[error("Invalid generic vhost-user device type: {0}")]
    InvalidDeviceType(String),
    #[error("Unsupported generic vhost-user device type: {0}")]
    UnsupportedDeviceType(String),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl GenericVhostUserConfig {
    pub const SYNTAX: &'static str = "generic vhost-user parameters \
    \"device_type=<ID number for virtio device type (FS, block, net, etc) or symbolic name>,\
    socket=<socket_path>,\
    queue_sizes=<list of queue sizes>,\
    id=<device_id>,pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(vhost_user: &str) -> Result<Self, GenericVhostUserConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("device_type")
            // TODO: Remove 'virtio_id' as a deprecated alias for 'device_type'
            .add("virtio_id")
            .add("queue_sizes")
            .add("socket")
            .add_all(PciDeviceCommonConfig::OPTIONS);
        parser
            .parse(vhost_user)
            .map_err(GenericVhostUserConfigParseError::Parse)?;

        let socket = parser
            .get("socket")
            .ok_or(GenericVhostUserConfigParseError::SocketMissing)?;

        let IntegerList(queue_sizes) = parser
            .convert::<IntegerList<u16>>("queue_sizes")
            .map_err(GenericVhostUserConfigParseError::Parse)?
            .ok_or(GenericVhostUserConfigParseError::QueueSizesMissing)?;
        let legacy_virtio_id = parser
            .convert::<String>("virtio_id")
            .map_err(GenericVhostUserConfigParseError::Parse)?;
        if legacy_virtio_id.is_some() {
            warn!("'virtio_id' in --generic-vhost-user is deprecated; use 'device_type'.");
        }
        let device_type_str = parser
            .convert::<String>("device_type")
            .map_err(GenericVhostUserConfigParseError::Parse)?
            .or(legacy_virtio_id)
            .ok_or(GenericVhostUserConfigParseError::DeviceTypeMissing)?;
        let device_type = match device_type_str.as_bytes() {
            b"net" => VIRTIO_ID_NET,
            b"block" => VIRTIO_ID_BLOCK,
            b"console" => VIRTIO_ID_CONSOLE,
            b"rng" => VIRTIO_ID_RNG,
            b"balloon" => VIRTIO_ID_BALLOON,
            b"iomem" => VIRTIO_ID_IOMEM,
            b"rpmsg" => VIRTIO_ID_RPMSG,
            b"scsi" => VIRTIO_ID_SCSI,
            b"9p" => VIRTIO_ID_9P,
            b"mac80211_wlan" => VIRTIO_ID_MAC80211_WLAN,
            b"rproc_serial" => VIRTIO_ID_RPROC_SERIAL,
            b"caif" => VIRTIO_ID_CAIF,
            b"memory_balloon" => VIRTIO_ID_MEMORY_BALLOON,
            b"gpu" => VIRTIO_ID_GPU,
            b"clock" => VIRTIO_ID_CLOCK,
            b"input" => VIRTIO_ID_INPUT,
            b"vsock" => VIRTIO_ID_VSOCK,
            b"crypto" => VIRTIO_ID_CRYPTO,
            b"signal_dist" => VIRTIO_ID_SIGNAL_DIST,
            b"pstore" => VIRTIO_ID_PSTORE,
            b"iommu" => VIRTIO_ID_IOMMU,
            b"mem" => VIRTIO_ID_MEM,
            b"sound" => VIRTIO_ID_SOUND,
            b"fs" => VIRTIO_ID_FS,
            b"pmem" => VIRTIO_ID_PMEM,
            b"rpmb" => VIRTIO_ID_RPMB,
            b"mac80211_hwsim" => VIRTIO_ID_MAC80211_HWSIM,
            b"video_encoder" => VIRTIO_ID_VIDEO_ENCODER,
            b"video_decoder" => VIRTIO_ID_VIDEO_DECODER,
            b"scmi" => VIRTIO_ID_SCMI,
            b"nitro_sec_mod" => VIRTIO_ID_NITRO_SEC_MOD,
            b"i2c" => VIRTIO_ID_I2C_ADAPTER,
            b"watchdog" => VIRTIO_ID_WATCHDOG,
            b"can" => VIRTIO_ID_CAN,
            b"dmabuf" => VIRTIO_ID_DMABUF,
            b"param_serv" => VIRTIO_ID_PARAM_SERV,
            b"audio_policy" => VIRTIO_ID_AUDIO_POLICY,
            b"bt" => VIRTIO_ID_BT,
            b"gpio" => VIRTIO_ID_GPIO,
            b"rdma" => 42,
            b"camera" => 43,
            b"ism" => 44,
            b"spi" => 45,
            b"tee" => 46,
            b"cpu_balloon" => 47,
            b"media" => 48,
            b"usb" => 49,
            [b'1'..=b'9', ..] => match device_type_str.parse() {
                Ok(id) => id,
                Err(_) => {
                    return Err(GenericVhostUserConfigParseError::InvalidDeviceType(
                        device_type_str,
                    ));
                }
            },
            _ => {
                return Err(GenericVhostUserConfigParseError::InvalidDeviceType(
                    device_type_str,
                ));
            }
        };
        match device_type {
            VIRTIO_ID_WATCHDOG | VIRTIO_ID_IOMMU => {
                return Err(GenericVhostUserConfigParseError::UnsupportedDeviceType(
                    device_type_str,
                ));
            }
            _ => {}
        }
        let pci_common = PciDeviceCommonConfig::parse(vhost_user)
            .map_err(GenericVhostUserConfigParseError::PciDeviceCommon)?;

        Ok(GenericVhostUserConfig {
            pci_common,
            socket: socket.into(),
            device_type,
            queue_sizes,
        })
    }
}

#[cfg(test)]
mod tests {
    use option_parser::IntegerList;
    use virtio_bindings::virtio_ids::{VIRTIO_ID_BALLOON, VIRTIO_ID_IOMMU, VIRTIO_ID_WATCHDOG};

    use crate::{GenericVhostUserConfig, GenericVhostUserConfigParseError, PciDeviceCommonConfig};

    #[track_caller]
    fn make_vhost_user_config(
        socket: &str,
        virtio_id: u64,
        id: &str,
        pci_segment: u64,
        queue_sizes: &IntegerList,
    ) {
        assert!(!socket.contains(",[]\n\r\0\""));
        assert!(!id.contains(",[]\n\r\0\""));
        let config = GenericVhostUserConfig::parse(&format!(
            "device_type={virtio_id},socket=\"{socket}\",\
id=\"{id}\",pci_segment={pci_segment},queue_sizes={queue_sizes}"
        ));
        if pci_segment <= u16::MAX.into()
            && virtio_id <= u32::MAX.into()
            && virtio_id != u64::from(VIRTIO_ID_BALLOON)
            && virtio_id != u64::from(VIRTIO_ID_WATCHDOG)
            && virtio_id != u64::from(VIRTIO_ID_IOMMU)
            && queue_sizes.0.iter().all(|&f| f <= u16::MAX.into())
        {
            assert_eq!(
                config.unwrap(),
                GenericVhostUserConfig {
                    pci_common: PciDeviceCommonConfig {
                        id: Some(id.to_owned()),
                        pci_segment: u16::try_from(pci_segment).unwrap(),
                        ..Default::default()
                    },
                    socket: socket.into(),
                    device_type: u32::try_from(virtio_id).unwrap(),
                    queue_sizes: queue_sizes
                        .0
                        .iter()
                        .map(|&f| u16::try_from(f).unwrap())
                        .collect(),
                }
            );
        } else {
            config.unwrap_err();
        }
    }

    #[test]
    fn test_parse_vhost_user() -> Result<(), GenericVhostUserConfigParseError> {
        // all parameters must be supplied, except pci_segment
        GenericVhostUserConfig::parse("").unwrap_err();
        GenericVhostUserConfig::parse("virtio_id=1").unwrap_err();
        GenericVhostUserConfig::parse("queue_size=1").unwrap_err();
        GenericVhostUserConfig::parse("socket=/tmp/sock").unwrap_err();
        GenericVhostUserConfig::parse("id=1").unwrap_err();
        make_vhost_user_config(
            "/dev/null/doesnotexist",
            100,
            "Something",
            10,
            &IntegerList(vec![u16::MAX.into(), 20u16.into()]),
        );
        make_vhost_user_config(
            "/dev/null/doesnotexist",
            100,
            "Something",
            10,
            &IntegerList(vec![u16::MAX.into()]),
        );
        make_vhost_user_config(
            "/dev/null/doesnotexist",
            u64::from(u32::MAX) + 1,
            "Something",
            10,
            &IntegerList(vec![20u64]),
        );
        make_vhost_user_config(
            "/dev/null/doesnotexist",
            u64::from(u32::MAX) + 1,
            "Something",
            10,
            &IntegerList(vec![20u64]),
        );
        make_vhost_user_config(
            "/dev/null/doesnotexist",
            u64::from(u32::MAX) + 1,
            "Something",
            10,
            &IntegerList(vec![20u64]),
        );

        // The deprecated 'virtio_id' key is an alias for 'device_type' and must
        // parse to an identical configuration.
        assert_eq!(
            GenericVhostUserConfig::parse("virtio_id=26,socket=/tmp/sock,queue_sizes=[1024]")
                .unwrap(),
            GenericVhostUserConfig::parse("device_type=26,socket=/tmp/sock,queue_sizes=[1024]")
                .unwrap(),
        );
        Ok(())
    }
}
