// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{OptionParser, OptionParserError, Toggle, Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_devices::{RateLimiterConfig, TokenBucketConfig};

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};
use crate::{ImageType, LockGranularityChoice};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VirtQueueAffinity {
    pub queue_index: u16,
    pub host_cpus: Box<[usize]>,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DiskConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub direct: bool,
    #[serde(default = "default_diskconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_diskconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub rate_limit_group: Option<String>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_io_uring: bool,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_aio: bool,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub queue_affinity: Option<Box<[VirtQueueAffinity]>>,
    #[serde(default)]
    pub backing_files: bool,
    #[serde(default = "default_diskconfig_sparse")]
    pub sparse: bool,
    #[serde(default)]
    pub image_type: ImageType,
    #[serde(default)]
    pub lock_granularity: LockGranularityChoice,
}

pub const DEFAULT_DISK_NUM_QUEUES: usize = 1;

pub fn default_diskconfig_num_queues() -> usize {
    DEFAULT_DISK_NUM_QUEUES
}

pub const DEFAULT_DISK_QUEUE_SIZE: u16 = 128;

pub fn default_diskconfig_queue_size() -> u16 {
    DEFAULT_DISK_QUEUE_SIZE
}

pub fn default_diskconfig_sparse() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum DiskConfigParseError {
    #[error("Failed to parse disk configuration")]
    Parse(#[source] OptionParserError),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl DiskConfig {
    pub const SYNTAX: &'static str = "Disk parameters \\
         \"path=<disk_image_path>,readonly=on|off,direct=on|off,iommu=on|off,\\
         num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\\
         vhost_user=on|off,socket=<vhost_user_socket_path>,\\
         bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\\
         ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,\\
         id=<device_id>,pci_segment=<segment_id>,pci_device_id=<pci_slot>,\\
         rate_limit_group=<group_id>,\\
         queue_affinity=<list_of_queue_indices_with_their_associated_cpuset>,\\
         serial=<serial_number>,backing_files=on|off,sparse=on|off,\\
         image_type=<raw,qcow2,vhd,vhdx>,lock_granularity=byte-range|full";

    pub fn parse(disk: &str) -> Result<Self, DiskConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("readonly")
            .add("direct")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("_disable_io_uring")
            .add("_disable_aio")
            .add("serial")
            .add("rate_limit_group")
            .add("queue_affinity")
            .add("backing_files")
            .add("sparse")
            .add("image_type")
            .add("lock_granularity")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);

        parser.parse(disk).map_err(DiskConfigParseError::Parse)?;

        let path = parser.get("path").map(PathBuf::from);
        let readonly = parser
            .convert::<Toggle>("readonly")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let direct = parser
            .convert::<Toggle>("direct")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let queue_size = parser
            .convert("queue_size")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_else(default_diskconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_else(default_diskconfig_num_queues);
        let vhost_user = parser
            .convert::<Toggle>("vhost_user")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let vhost_socket = parser.get("socket");
        let disable_io_uring = parser
            .convert::<Toggle>("_disable_io_uring")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let disable_aio = parser
            .convert::<Toggle>("_disable_aio")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let rate_limit_group = parser.get("rate_limit_group");
        let bw_size = parser
            .convert("bw_size")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();
        let serial = parser.get("serial");
        let queue_affinity = parser
            .convert::<TupleList<u16, Vec<usize>>>("queue_affinity")
            .map_err(DiskConfigParseError::Parse)?
            .map(|v| {
                v.0.iter()
                    .map(|Tuple(e1, e2)| VirtQueueAffinity {
                        queue_index: *e1,
                        host_cpus: e2.clone().into_boxed_slice(),
                    })
                    .collect()
            });

        let backing_files = parser
            .convert::<Toggle>("backing_files")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;

        let image_type = if vhost_socket.is_none() {
            parser
                .convert::<ImageType>("image_type")
                .map_err(DiskConfigParseError::Parse)?
                .unwrap_or(ImageType::Unknown)
        } else {
            ImageType::Unknown
        };

        let lock_granularity = parser
            .convert::<LockGranularityChoice>("lock_granularity")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_default();

        let bw_tb_config = if bw_size != 0 && bw_refill_time != 0 {
            Some(TokenBucketConfig {
                size: bw_size,
                one_time_burst: Some(bw_one_time_burst),
                refill_time: bw_refill_time,
            })
        } else {
            None
        };
        let ops_tb_config = if ops_size != 0 && ops_refill_time != 0 {
            Some(TokenBucketConfig {
                size: ops_size,
                one_time_burst: Some(ops_one_time_burst),
                refill_time: ops_refill_time,
            })
        } else {
            None
        };
        let rate_limiter_config = if bw_tb_config.is_some() || ops_tb_config.is_some() {
            Some(RateLimiterConfig {
                bandwidth: bw_tb_config,
                ops: ops_tb_config,
            })
        } else {
            None
        };
        let sparse = parser
            .convert::<Toggle>("sparse")
            .map_err(DiskConfigParseError::Parse)?
            .unwrap_or_else(|| Toggle(default_diskconfig_sparse()))
            .0;

        let pci_common =
            PciDeviceCommonConfig::parse(disk).map_err(DiskConfigParseError::PciDeviceCommon)?;

        Ok(DiskConfig {
            pci_common,
            path,
            readonly,
            direct,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            rate_limit_group,
            rate_limiter_config,
            disable_io_uring,
            disable_aio,
            serial,
            queue_affinity,
            backing_files,
            sparse,
            image_type,
            lock_granularity,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use block::ImageType;
    use block::fcntl::LockGranularityChoice;

    use crate::{DiskConfig, DiskConfigParseError, PciDeviceCommonConfig, VirtQueueAffinity};

    fn disk_fixture() -> DiskConfig {
        DiskConfig {
            pci_common: PciDeviceCommonConfig::default(),
            path: Some(PathBuf::from("/path/to_file")),
            readonly: false,
            direct: false,
            num_queues: 1,
            queue_size: 128,
            vhost_user: false,
            vhost_socket: None,
            disable_io_uring: false,
            disable_aio: false,
            rate_limit_group: None,
            rate_limiter_config: None,
            serial: None,
            queue_affinity: None,
            backing_files: false,
            sparse: true,
            image_type: ImageType::Unknown,
            lock_granularity: LockGranularityChoice::default(),
        }
    }

    #[test]
    fn test_disk_parsing() -> Result<(), DiskConfigParseError> {
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig { ..disk_fixture() }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,id=mydisk0")?,
            DiskConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("mydisk0".to_owned()),
                    ..Default::default()
                },
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("vhost_user=true,socket=/tmp/sock")?,
            DiskConfig {
                path: None,
                vhost_socket: Some(String::from("/tmp/sock")),
                vhost_user: true,
                image_type: ImageType::Unknown,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on")?,
            DiskConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256")?,
            DiskConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                queue_size: 256,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256,num_queues=4")?,
            DiskConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                queue_size: 256,
                num_queues: 4,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,direct=on")?,
            DiskConfig {
                direct: true,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,serial=test")?,
            DiskConfig {
                serial: Some(String::from("test")),
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,rate_limit_group=group0")?,
            DiskConfig {
                rate_limit_group: Some("group0".to_string()),
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,lock_granularity=full")?,
            DiskConfig {
                lock_granularity: LockGranularityChoice::Full,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,lock_granularity=byte-range")?,
            DiskConfig {
                lock_granularity: LockGranularityChoice::ByteRange,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,queue_affinity=[0@[1],1@[2],2@[3,4],3@[5-8]]")?,
            DiskConfig {
                queue_affinity: Some(Box::new([
                    VirtQueueAffinity {
                        queue_index: 0,
                        host_cpus: Box::new([1]),
                    },
                    VirtQueueAffinity {
                        queue_index: 1,
                        host_cpus: Box::new([2]),
                    },
                    VirtQueueAffinity {
                        queue_index: 2,
                        host_cpus: Box::new([3, 4]),
                    },
                    VirtQueueAffinity {
                        queue_index: 3,
                        host_cpus: Box::new([5, 6, 7, 8]),
                    }
                ])),
                ..disk_fixture()
            }
        );
        Ok(())
    }
}
