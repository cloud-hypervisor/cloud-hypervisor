// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{vnet_hdr_len, MacAddr, Tap, TapError};
use std::net::Ipv4Addr;
use std::path::Path;
use std::{fs, io};

#[derive(Debug)]
pub enum Error {
    /// Failed to convert an hexadecimal string into an integer.
    ConvertHexStringToInt(std::num::ParseIntError),
    /// Error related to the multiqueue support (no support TAP side).
    MultiQueueNoTapSupport,
    /// Error related to the multiqueue support (no support device side).
    MultiQueueNoDeviceSupport,
    /// Failed to read the TAP flags from sysfs.
    ReadSysfsTunFlags(io::Error),
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting MAC address failed
    TapSetMac(TapError),
    /// Getting MAC address failed
    TapGetMac(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
}

type Result<T> = std::result::Result<T, Error>;

fn check_mq_support(if_name: &Option<&str>, queue_pairs: usize) -> Result<()> {
    if let Some(tap_name) = if_name {
        let mq = queue_pairs > 1;
        let path = format!("/sys/class/net/{}/tun_flags", tap_name);
        // interface does not exist, check is not required
        if !Path::new(&path).exists() {
            return Ok(());
        }
        let tun_flags_str = fs::read_to_string(path).map_err(Error::ReadSysfsTunFlags)?;
        let tun_flags = u32::from_str_radix(tun_flags_str.trim().trim_start_matches("0x"), 16)
            .map_err(Error::ConvertHexStringToInt)?;
        if (tun_flags & net_gen::IFF_MULTI_QUEUE != 0) && !mq {
            return Err(Error::MultiQueueNoDeviceSupport);
        } else if (tun_flags & net_gen::IFF_MULTI_QUEUE == 0) && mq {
            return Err(Error::MultiQueueNoTapSupport);
        }
    }
    Ok(())
}

/// Create a new virtio network device with the given IP address and
/// netmask.
pub fn open_tap(
    if_name: Option<&str>,
    ip_addr: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    host_mac: &mut Option<MacAddr>,
    num_rx_q: usize,
    flags: Option<i32>,
) -> Result<Vec<Tap>> {
    let mut taps: Vec<Tap> = Vec::new();
    let mut ifname: String = String::new();
    let vnet_hdr_size = vnet_hdr_len() as i32;

    // In case the tap interface already exists, check if the number of
    // queues is appropriate. The tap might not support multiqueue while
    // the number of queues indicates the user expects multiple queues, or
    // on the contrary, the tap might support multiqueue while the number
    // of queues indicates the user doesn't expect multiple queues.
    check_mq_support(&if_name, num_rx_q)?;

    for i in 0..num_rx_q {
        let tap: Tap;
        if i == 0 {
            tap = match if_name {
                Some(name) => Tap::open_named(name, num_rx_q, flags).map_err(Error::TapOpen)?,
                None => Tap::new(num_rx_q).map_err(Error::TapOpen)?,
            };
            if let Some(ip) = ip_addr {
                tap.set_ip_addr(ip).map_err(Error::TapSetIp)?;
            }
            if let Some(mask) = netmask {
                tap.set_netmask(mask).map_err(Error::TapSetNetmask)?;
            }
            if let Some(mac) = host_mac {
                tap.set_mac_addr(*mac).map_err(Error::TapSetMac)?
            } else {
                *host_mac = Some(tap.get_mac_addr().map_err(Error::TapGetMac)?)
            }
            tap.enable().map_err(Error::TapEnable)?;

            tap.set_vnet_hdr_size(vnet_hdr_size)
                .map_err(Error::TapSetVnetHdrSize)?;

            ifname = String::from_utf8(tap.get_if_name()).unwrap();
        } else {
            tap = Tap::open_named(ifname.as_str(), num_rx_q, flags).map_err(Error::TapOpen)?;

            tap.set_vnet_hdr_size(vnet_hdr_size)
                .map_err(Error::TapSetVnetHdrSize)?;
        }
        taps.push(tap);
    }
    Ok(taps)
}
