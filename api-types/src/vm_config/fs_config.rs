// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_devices::vhost_user::VIRTIO_FS_TAG_LEN;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FsConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub tag: String,
    pub socket: PathBuf,
    #[serde(default = "default_fsconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_fsconfig_queue_size")]
    pub queue_size: u16,
}

#[derive(Debug, Error)]
pub enum FsConfigParseError {
    #[error("Failed to parse filesystem configuration")]
    Parse(#[source] OptionParserError),
    #[error("Filesystem tag is missing")]
    TagMissing,
    #[error("Filesystem tag is too long")]
    TagTooLong,
    #[error("Filesystem socket is missing")]
    SocketMissing,
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl FsConfig {
    pub const SYNTAX: &'static str = "virtio-fs parameters \
    \"tag=<tag_name>,socket=<socket_path>,num_queues=<number_of_queues>,\
    queue_size=<size_of_each_queue>,id=<device_id>,\
    pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(fs: &str) -> Result<Self, FsConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("tag")
            .add("queue_size")
            .add("num_queues")
            .add("socket")
            .add_all(PciDeviceCommonConfig::OPTIONS);
        parser.parse(fs).map_err(FsConfigParseError::Parse)?;

        let tag = parser.get("tag").ok_or(FsConfigParseError::TagMissing)?;
        if tag.len() > VIRTIO_FS_TAG_LEN {
            return Err(FsConfigParseError::TagTooLong);
        }
        let socket = PathBuf::from(
            parser
                .get("socket")
                .ok_or(FsConfigParseError::SocketMissing)?,
        );
        let queue_size = parser
            .convert("queue_size")
            .map_err(FsConfigParseError::Parse)?
            .unwrap_or_else(default_fsconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(FsConfigParseError::Parse)?
            .unwrap_or_else(default_fsconfig_num_queues);
        let pci_common =
            PciDeviceCommonConfig::parse(fs).map_err(FsConfigParseError::PciDeviceCommon)?;

        Ok(Self {
            pci_common,
            tag,
            socket,
            num_queues,
            queue_size,
        })
    }
}

pub fn default_fsconfig_num_queues() -> usize {
    1
}

pub fn default_fsconfig_queue_size() -> u16 {
    1024
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{FsConfig, FsConfigParseError, PciDeviceCommonConfig};

    fn fs_fixture() -> FsConfig {
        FsConfig {
            pci_common: PciDeviceCommonConfig::default(),
            socket: PathBuf::from("/tmp/sock"),
            tag: "mytag".to_owned(),
            num_queues: 1,
            queue_size: 1024,
        }
    }

    #[test]
    fn test_parse_fs() -> Result<(), FsConfigParseError> {
        // "tag" and "socket" must be supplied
        FsConfig::parse("").unwrap_err();
        FsConfig::parse("tag=mytag").unwrap_err();
        FsConfig::parse("socket=/tmp/sock").unwrap_err();
        assert_eq!(FsConfig::parse("tag=mytag,socket=/tmp/sock")?, fs_fixture());
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock,num_queues=4,queue_size=1024")?,
            FsConfig {
                num_queues: 4,
                queue_size: 1024,
                ..fs_fixture()
            }
        );

        Ok(())
    }
}
