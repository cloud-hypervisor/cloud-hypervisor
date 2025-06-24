// Copyright (c) 2020 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::net::IpAddr;
use std::path::Path;
use std::{fs, io};

use thiserror::Error;

use super::{vnet_hdr_len, MacAddr, Tap, TapError};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to convert an hexadecimal string into an integer")]
    ConvertHexStringToInt(#[source] std::num::ParseIntError),
    #[error("Error related to the multiqueue support (no support TAP side)")]
    MultiQueueNoTapSupport,
    #[error("Error related to the multiqueue support (no support device side)")]
    MultiQueueNoDeviceSupport,
    #[error("Failed to read the TAP flags from sysfs")]
    ReadSysfsTunFlags(#[source] io::Error),
    #[error("Open tap device failed")]
    TapOpen(#[source] TapError),
    #[error("Setting tap IP and/or netmask failed")]
    TapSetIpNetmask(#[source] TapError),
    #[error("Setting MAC address failed")]
    TapSetMac(#[source] TapError),
    #[error("Getting MAC address failed")]
    TapGetMac(#[source] TapError),
    #[error("Setting vnet header size failed")]
    TapSetVnetHdrSize(#[source] TapError),
    #[error("Setting MTU failed")]
    TapSetMtu(#[source] TapError),
    #[error("Enabling tap interface failed")]
    TapEnable(#[source] TapError),
}

type Result<T> = std::result::Result<T, Error>;

fn check_mq_support(if_name: &Option<&str>, queue_pairs: usize) -> Result<()> {
    if let Some(tap_name) = if_name {
        let mq = queue_pairs > 1;
        let path = format!("/sys/class/net/{tap_name}/tun_flags");
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

/// Opens a Tap device and configures it.
///
/// Afterward, further RX queues can be opened with a common config.
fn open_tap_rx_q_0(
    if_name: Option<&str>,
    ip_addr: Option<IpAddr>,
    netmask: Option<IpAddr>,
    host_mac: &mut Option<MacAddr>,
    mtu: Option<u16>,
    num_rx_q: usize,
    flags: Option<i32>,
) -> Result<Tap> {
    // Check if the given interface exists before we create it.
    let tap_exists = if_name.is_some_and(|n| Path::new(&format!("/sys/class/net/{n}")).exists());

    let tap = match if_name {
        Some(name) => Tap::open_named(name, num_rx_q, flags).map_err(Error::TapOpen)?,
        // Create a new Tap device in Linux, if none was specified.
        None => Tap::new(num_rx_q).map_err(Error::TapOpen)?,
    };
    // Don't overwrite ip configuration of existing interfaces:
    if !tap_exists {
        if let Some(ip) = ip_addr {
            tap.set_ip_addr(ip, netmask)
                .map_err(Error::TapSetIpNetmask)?;
        }
    } else {
        warn!(
            "Tap {} already exists. IP configuration will not be overwritten.",
            if_name.unwrap_or_default()
        );
    }
    if let Some(mac) = host_mac {
        tap.set_mac_addr(*mac).map_err(Error::TapSetMac)?
    } else {
        *host_mac = Some(tap.get_mac_addr().map_err(Error::TapGetMac)?)
    }
    if let Some(mtu) = mtu {
        tap.set_mtu(mtu as i32).map_err(Error::TapSetMtu)?;
    }
    tap.enable().map_err(Error::TapEnable)?;

    tap.set_vnet_hdr_size(vnet_hdr_len() as i32)
        .map_err(Error::TapSetVnetHdrSize)?;

    Ok(tap)
}

/// Create a new virtio network device with the given IP address and
/// netmask.
pub fn open_tap(
    if_name: Option<&str>,
    ip_addr: Option<IpAddr>,
    netmask: Option<IpAddr>,
    host_mac: &mut Option<MacAddr>,
    mtu: Option<u16>,
    num_rx_q: usize,
    flags: Option<i32>,
) -> Result<Vec<Tap>> {
    let mut taps: Vec<Tap> = Vec::new();
    let mut ifname: String = String::new();

    // In case the tap interface already exists, check if the number of
    // queues is appropriate. The tap might not support multiqueue while
    // the number of queues indicates the user expects multiple queues, or
    // on the contrary, the tap might support multiqueue while the number
    // of queues indicates the user doesn't expect multiple queues.
    check_mq_support(&if_name, num_rx_q)?;

    for i in 0..num_rx_q {
        let tap: Tap;
        if i == 0 {
            // Special handling is required for the first RX queue, such as
            // configuring the device. Subsequent iterations will then use the
            // same device.
            tap = open_tap_rx_q_0(if_name, ip_addr, netmask, host_mac, mtu, num_rx_q, flags)?;
            // Set the name of the tap device we open in subsequent iterations.
            ifname = String::from_utf8(tap.get_if_name()).unwrap();
        } else {
            tap = Tap::open_named(ifname.as_str(), num_rx_q, flags).map_err(Error::TapOpen)?;

            tap.set_vnet_hdr_size(vnet_hdr_len() as i32)
                .map_err(Error::TapSetVnetHdrSize)?;
        }
        taps.push(tap);
    }
    Ok(taps)
}
