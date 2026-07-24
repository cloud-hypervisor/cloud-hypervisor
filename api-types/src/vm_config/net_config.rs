// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::IpAddr;
use std::str::FromStr;

use log::debug;
use net_util::MacAddr;
use option_parser::{IntegerList, OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_devices::{RateLimiterConfig, TokenBucketConfig};

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum VhostMode {
    #[default]
    Client,
    Server,
}

#[derive(Debug)]
pub enum ParseVhostModeError {
    InvalidValue(String),
}

impl FromStr for VhostMode {
    type Err = ParseVhostModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "client" => Ok(VhostMode::Client),
            "server" => Ok(VhostMode::Server),
            _ => Err(ParseVhostModeError::InvalidValue(s.to_owned())),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NetConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    #[serde(default = "default_netconfig_tap")]
    pub tap: Option<String>,
    pub ip: Option<IpAddr>,
    pub mask: Option<IpAddr>,
    #[serde(default = "default_netconfig_mac")]
    pub mac: MacAddr,
    #[serde(default)]
    pub host_mac: Option<MacAddr>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default = "default_netconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_netconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub vhost_mode: VhostMode,
    // Special deserialize handling:
    // Therefore, we don't serialize FDs, and whatever value is here after
    // deserialization is invalid.
    //
    // Valid FDs are transmitted via a different channel (SCM_RIGHTS message)
    // and will be populated into this struct on the destination VMM eventually.
    #[serde(default, deserialize_with = "deserialize_netconfig_fds")]
    pub fds: Option<Vec<i32>>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default = "default_netconfig_true")]
    pub offload_tso: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_ufo: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_csum: bool,
}

#[derive(Debug, Error)]
pub enum NetConfigParseError {
    #[error("Failed to parse network configuration")]
    Parse(#[source] OptionParserError),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl NetConfig {
    pub const SYNTAX: &'static str = "Network parameters \
    \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,fd=<[fd1,fd2,...]>,iommu=on|off,\
    num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,id=<device_id>,\
    vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>,vhost_mode=client|server,\
    bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
    ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,\
    pci_segment=<segment_id>,pci_device_id=<pci_slot>,\
    offload_tso=on|off,offload_ufo=on|off,offload_csum=on|off\"";

    pub fn parse(net: &str) -> Result<Self, NetConfigParseError> {
        let mut parser = OptionParser::new();

        parser
            .add("tap")
            .add("ip")
            .add("mask")
            .add("mac")
            .add("host_mac")
            .add("offload_tso")
            .add("offload_ufo")
            .add("offload_csum")
            .add("mtu")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket")
            .add("vhost_mode")
            .add("fd")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser.parse(net).map_err(NetConfigParseError::Parse)?;

        let tap = parser.get("tap");
        let ip = parser.convert("ip").map_err(NetConfigParseError::Parse)?;
        let mask = parser.convert("mask").map_err(NetConfigParseError::Parse)?;

        let mac = parser
            .convert("mac")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_else(default_netconfig_mac);
        let host_mac = parser
            .convert("host_mac")
            .map_err(NetConfigParseError::Parse)?;
        let offload_tso = parser
            .convert::<Toggle>("offload_tso")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let offload_ufo = parser
            .convert::<Toggle>("offload_ufo")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let offload_csum = parser
            .convert::<Toggle>("offload_csum")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let mtu = parser.convert("mtu").map_err(NetConfigParseError::Parse)?;
        let queue_size = parser
            .convert("queue_size")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_else(default_netconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_else(default_netconfig_num_queues);
        let vhost_user = parser
            .convert::<Toggle>("vhost_user")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or(Toggle(false))
            .0;
        let vhost_socket = parser.get("socket");
        let vhost_mode = parser
            .convert("vhost_mode")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_default();
        let fds = parser
            .convert::<IntegerList>("fd")
            .map_err(NetConfigParseError::Parse)?
            .map(|v| v.0.iter().map(|e| *e as i32).collect());
        let bw_size = parser
            .convert("bw_size")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(NetConfigParseError::Parse)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(NetConfigParseError::Parse)?
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

        let pci_common =
            PciDeviceCommonConfig::parse(net).map_err(NetConfigParseError::PciDeviceCommon)?;

        Ok(Self {
            pci_common,
            tap,
            ip,
            mask,
            mac,
            host_mac,
            mtu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            vhost_mode,
            fds,
            rate_limiter_config,
            offload_tso,
            offload_ufo,
            offload_csum,
        })
    }
}

pub fn default_netconfig_true() -> bool {
    true
}

pub fn default_netconfig_tap() -> Option<String> {
    None
}

pub fn default_netconfig_mac() -> MacAddr {
    MacAddr::local_random()
}

pub const DEFAULT_NET_NUM_QUEUES: usize = 2;

pub fn default_netconfig_num_queues() -> usize {
    DEFAULT_NET_NUM_QUEUES
}

pub const DEFAULT_NET_QUEUE_SIZE: u16 = 256;

pub fn default_netconfig_queue_size() -> u16 {
    DEFAULT_NET_QUEUE_SIZE
}

fn deserialize_netconfig_fds<'de, D>(d: D) -> Result<Option<Vec<i32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fds: Option<Vec<i32>> = Option::deserialize(d)?;
    if let Some(invalid_fds) = invalid_fds {
        debug!(
            "FDs in 'NetConfig' won't be deserialized as they are most likely invalid now. Deserializing them as -1."
        );
        Ok(Some(vec![-1; invalid_fds.len()]))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use net_util::MacAddr;

    use crate::{NetConfig, NetConfigParseError, PciDeviceCommonConfig, VhostMode};

    fn net_fixture() -> NetConfig {
        NetConfig {
            pci_common: PciDeviceCommonConfig::default(),
            tap: None,
            ip: None,
            mask: None,
            mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
            host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
            mtu: None,
            num_queues: 2,
            queue_size: 256,
            vhost_user: false,
            vhost_socket: None,
            vhost_mode: VhostMode::Client,
            fds: None,
            rate_limiter_config: None,
            offload_tso: true,
            offload_ufo: true,
            offload_csum: true,
        }
    }

    #[test]
    fn test_net_parsing() -> Result<(), NetConfigParseError> {
        // mac address is random
        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef")?,
            net_fixture(),
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,id=mynet0")?,
            NetConfig {
                pci_common: PciDeviceCommonConfig {
                    id: Some("mynet0".to_owned()),
                    ..Default::default()
                },
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,tap=tap0,ip=192.168.100.1,mask=255.255.255.128"
            )?,
            NetConfig {
                tap: Some("tap0".to_owned()),
                ip: Some("192.168.100.1".parse().unwrap()),
                mask: Some("255.255.255.128".parse().unwrap()),
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,vhost_user=true,socket=/tmp/sock"
            )?,
            NetConfig {
                vhost_user: true,
                vhost_socket: Some("/tmp/sock".to_owned()),
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,num_queues=4,queue_size=1024,iommu=on"
            )?,
            NetConfig {
                pci_common: PciDeviceCommonConfig {
                    iommu: true,
                    ..Default::default()
                },
                num_queues: 4,
                queue_size: 1024,
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,fd=[3,7],num_queues=4")?,
            NetConfig {
                host_mac: None,
                fds: Some(vec![3, 7]),
                num_queues: 4,
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,mask=255.255.255.0")?,
            NetConfig {
                mask: Some("255.255.255.0".parse().unwrap()),
                host_mac: None,
                ..net_fixture()
            }
        );

        Ok(())
    }
}
