// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use thiserror::Error;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};

use super::{
    create_inet_socket, create_sockaddr, create_unix_socket, vnet_hdr_len, Error as NetUtilError,
    MacAddr,
};
use crate::mac::MAC_ADDR_LEN;

/// Maximum length of a network interface name in Linux, excluding any NUL byte.
///
/// This corresponds to `IFNAMSIZ` in Linux [[0]].
///
/// [0]: https://elixir.bootlin.com/linux/v6.12/source/include/uapi/linux/if.h#L33
const MAX_INTERFACE_NAME_LEN: usize = 15;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Couldn't open /dev/net/tun")]
    OpenTun(#[source] IoError),
    #[error("Unable to configure tap interface")]
    ConfigureTap(#[source] IoError),
    #[error("Unable to retrieve features")]
    GetFeatures(#[source] IoError),
    #[error("Missing multiqueue support in the kernel")]
    MultiQueueKernelSupport,
    #[error("ioctl ({0}) failed: {1}")]
    IoctlError(c_ulong, #[source] IoError),
    #[error("Failed to create a socket")]
    NetUtil(#[source] NetUtilError),
    #[error("Interface name too long (max length is {MAX_INTERFACE_NAME_LEN}): {0}")]
    IfnameTooLong(String),
    #[error("Invalid interface name (does it exist?): {0}")]
    InvalidIfname(String),
    #[error("Error parsing MAC data")]
    MacParsing(#[source] IoError),
    #[error("Invalid netmask")]
    InvalidNetmask,
}

pub type Result<T> = ::std::result::Result<T, Error>;

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface
/// automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    if_name: Vec<u8>,
}

impl PartialEq for Tap {
    fn eq(&self, other: &Tap) -> bool {
        self.if_name == other.if_name
    }
}

impl std::clone::Clone for Tap {
    fn clone(&self) -> Self {
        Tap {
            tap_file: self.tap_file.try_clone().unwrap(),
            if_name: self.if_name.clone(),
        }
    }
}

// Returns a byte vector representing the contents of a null terminated C string which
// contains if_name.
fn build_terminated_if_name(if_name: &str) -> Result<Vec<u8>> {
    // Convert the string slice to bytes, and shadow the variable,
    // since we no longer need the &str version.
    let bytes = if_name.as_bytes();

    if bytes.len() > MAX_INTERFACE_NAME_LEN {
        return Err(Error::IfnameTooLong(if_name.to_string()));
    }

    let mut terminated_if_name = vec![b'\0'; bytes.len() + 1];
    terminated_if_name[..bytes.len()].copy_from_slice(bytes);

    Ok(terminated_if_name)
}

fn ipv6_mask_to_prefix(mask: Ipv6Addr) -> Result<u8> {
    let mask = mask.segments();
    let mut iter = mask.iter();

    let mut prefix = 0;
    for &segment in &mut iter {
        if segment == 0xffff {
            prefix += 16;
        } else if segment == 0 {
            break;
        } else {
            let prefix_bits = segment.leading_ones() as u8;
            if segment << prefix_bits != 0 {
                return Err(Error::InvalidNetmask);
            }

            prefix += prefix_bits;
            break;
        }
    }

    // Check that remaining bits are all unset
    for &segment in iter {
        if segment != 0 {
            return Err(Error::InvalidNetmask);
        }
    }

    Ok(prefix)
}

impl Tap {
    unsafe fn ioctl_with_mut_ref<F: AsRawFd, T>(fd: &F, req: c_ulong, arg: &mut T) -> Result<()> {
        let ret = ioctl_with_mut_ref(fd, req, arg);
        if ret < 0 {
            return Err(Error::IoctlError(req, IoError::last_os_error()));
        }

        Ok(())
    }

    unsafe fn ioctl_with_ref<F: AsRawFd, T>(fd: &F, req: c_ulong, arg: &T) -> Result<()> {
        let ret = ioctl_with_ref(fd, req, arg);
        if ret < 0 {
            return Err(Error::IoctlError(req, IoError::last_os_error()));
        }

        Ok(())
    }

    unsafe fn ioctl_with_val<F: AsRawFd>(fd: &F, req: c_ulong, arg: c_ulong) -> Result<()> {
        let ret = ioctl_with_val(fd, req, arg);
        if ret < 0 {
            return Err(Error::IoctlError(req, IoError::last_os_error()));
        }

        Ok(())
    }

    pub fn open_named(if_name: &str, num_queue_pairs: usize, flags: Option<i32>) -> Result<Tap> {
        let terminated_if_name = build_terminated_if_name(if_name)?;

        // SAFETY: FFI call
        let fd = unsafe {
            // Open calls are safe because we give a constant null-terminated
            // string and verify the result.
            libc::open(
                c"/dev/net/tun".as_ptr() as *const c_char,
                flags.unwrap_or(libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC),
            )
        };
        if fd < 0 {
            return Err(Error::OpenTun(IoError::last_os_error()));
        }

        // SAFETY: We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_fd(fd) };

        // Let's validate some features before going any further.
        // ioctl is safe since we call it with a valid tap fd and check the return
        // value.
        let mut features = 0;
        // SAFETY: IOCTL with correct arguments
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, net_gen::TUNGETFEATURES(), &mut features) };
        if ret < 0 {
            return Err(Error::GetFeatures(IoError::last_os_error()));
        }

        // Check if the user parameters match the kernel support for MQ
        if (features & net_gen::IFF_MULTI_QUEUE == 0) && num_queue_pairs > 1 {
            return Err(Error::MultiQueueKernelSupport);
        }

        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: net_gen::ifreq = Default::default();
        // SAFETY: see the comment above.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            let name_slice = &mut ifrn_name[..terminated_if_name.len()];
            name_slice.copy_from_slice(terminated_if_name.as_slice());
            ifreq.ifr_ifru.ifru_flags =
                (net_gen::IFF_TAP | net_gen::IFF_NO_PI | net_gen::IFF_VNET_HDR) as c_short;
            if num_queue_pairs > 1 {
                ifreq.ifr_ifru.ifru_flags |= net_gen::IFF_MULTI_QUEUE as c_short;
            }
        }

        // SAFETY: ioctl is safe since we call it with a valid tap fd and check the return
        // value.
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, net_gen::TUNSETIFF(), &mut ifreq) };
        if ret < 0 {
            return Err(Error::ConfigureTap(IoError::last_os_error()));
        }

        // SAFETY: only the name is accessed, and it's cloned out.
        let mut if_name = unsafe { ifreq.ifr_ifrn.ifrn_name }.to_vec();
        if_name.truncate(terminated_if_name.len() - 1);
        Ok(Tap {
            tap_file: tuntap,
            if_name,
        })
    }

    /// Create a new tap interface.
    pub fn new(num_queue_pairs: usize) -> Result<Tap> {
        Self::open_named("vmtap%d", num_queue_pairs, None)
    }

    pub fn from_tap_fd(fd: RawFd, num_queue_pairs: usize) -> Result<Tap> {
        // Ensure that the file is opened non-blocking, this is particularly
        // needed when opened via the shell for macvtap.
        // SAFETY: FFI call
        let ret = unsafe {
            let mut flags = libc::fcntl(fd, libc::F_GETFL);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(fd, libc::F_SETFL, flags)
        };
        if ret < 0 {
            return Err(Error::ConfigureTap(IoError::last_os_error()));
        }

        // SAFETY: fd is a tap fd
        let tap_file = unsafe { File::from_raw_fd(fd) };
        let mut ifreq: net_gen::ifreq = Default::default();

        // Get current config including name
        // SAFETY: IOCTL with correct arguments
        unsafe { Self::ioctl_with_mut_ref(&tap_file, net_gen::TUNGETIFF(), &mut ifreq)? };

        // SAFETY: We only access one field of the ifru union
        let if_name = unsafe { ifreq.ifr_ifrn.ifrn_name }.to_vec();

        // Try and update flags. Depending on how the tap was created (macvtap
        // or via open_named()) this might return -EEXIST so we just ignore that.
        // SAFETY: access union fields
        unsafe {
            ifreq.ifr_ifru.ifru_flags =
                (net_gen::IFF_TAP | net_gen::IFF_NO_PI | net_gen::IFF_VNET_HDR) as c_short;
            if num_queue_pairs > 1 {
                ifreq.ifr_ifru.ifru_flags |= net_gen::IFF_MULTI_QUEUE as c_short;
            }
        }
        // SAFETY: IOCTL with correct arguments
        let ret = unsafe { ioctl_with_mut_ref(&tap_file, net_gen::TUNSETIFF(), &mut ifreq) };
        if ret < 0 && IoError::last_os_error().raw_os_error().unwrap() != libc::EEXIST {
            return Err(Error::ConfigureTap(IoError::last_os_error()));
        }

        let tap = Tap { tap_file, if_name };
        let vnet_hdr_size = vnet_hdr_len() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)?;

        Ok(tap)
    }

    /// Set the host-side IP address for the tap interface.
    pub fn set_ip_addr(&self, ip_addr: IpAddr, netmask: Option<IpAddr>) -> Result<()> {
        let sock = create_inet_socket(ip_addr).map_err(Error::NetUtil)?;

        let mut ifreq = self.get_ifreq();

        match ip_addr {
            IpAddr::V4(addr) => {
                let addr = create_sockaddr(addr);

                ifreq.ifr_ifru.ifru_addr = addr;

                // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
                unsafe {
                    Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFADDR as c_ulong, &ifreq)?;
                }

                if let Some(IpAddr::V4(mask)) = netmask {
                    ifreq.ifr_ifru.ifru_netmask = create_sockaddr(mask);

                    // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
                    unsafe {
                        Self::ioctl_with_ref(
                            &sock,
                            net_gen::sockios::SIOCSIFNETMASK as c_ulong,
                            &ifreq,
                        )?;
                    }
                };

                Ok(())
            }
            IpAddr::V6(addr) => {
                let ifindex = {
                    // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
                    unsafe {
                        Self::ioctl_with_ref(
                            &sock,
                            net_gen::sockios::SIOCGIFINDEX as c_ulong,
                            &ifreq,
                        )?;
                    }

                    // SAFETY: ifru_ivalue contains the ifindex and is set by the previous ioctl
                    unsafe {
                        match ifreq.ifr_ifru.ifru_ivalue {
                            0 => {
                                let name = String::from_utf8_lossy(&self.if_name).to_string();
                                return Err(Error::InvalidIfname(name));
                            }
                            i => i,
                        }
                    }
                };

                let prefixlen = match netmask {
                    Some(IpAddr::V6(netmask)) => ipv6_mask_to_prefix(netmask)?,
                    Some(IpAddr::V4(_)) => return Err(Error::InvalidNetmask),
                    None => 0,
                };

                let ifreq = net_gen::in6_ifreq {
                    // SAFETY: addr can be safely transmuted to in6_addr
                    ifr6_addr: unsafe {
                        std::mem::transmute::<[u8; 16], net_gen::ipv6::in6_addr>(addr.octets())
                    },
                    ifr6_prefixlen: prefixlen as u32,
                    ifr6_ifindex: ifindex,
                };

                // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
                unsafe {
                    Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFADDR as c_ulong, &ifreq)
                }
            }
        }
    }

    /// Set mac addr for tap interface.
    pub fn set_mac_addr(&self, addr: MacAddr) -> Result<()> {
        // Checking if the mac address already matches the desired one
        // is useful to avoid making the "set ioctl" in the case where
        // the VMM is running without the privilege to do that.
        // In practice this comes from a reboot after the configuration
        // has been update with the kernel generated address.
        if self.get_mac_addr()? == addr {
            return Ok(());
        }

        let sock = create_unix_socket().map_err(Error::NetUtil)?;

        let mut ifreq = self.get_ifreq();

        // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCGIFHWADDR as c_ulong, &ifreq)? };

        // SAFETY: We only access one field of the ifru union
        unsafe {
            let ifru_hwaddr = &mut ifreq.ifr_ifru.ifru_hwaddr;
            for (i, v) in addr.get_bytes().iter().enumerate() {
                ifru_hwaddr.sa_data[i] = *v as c_uchar;
            }
        }

        // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFHWADDR as c_ulong, &ifreq) }
    }

    /// Get mac addr for tap interface.
    pub fn get_mac_addr(&self) -> Result<MacAddr> {
        let sock = create_unix_socket().map_err(Error::NetUtil)?;

        let ifreq = self.get_ifreq();

        // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCGIFHWADDR as c_ulong, &ifreq)? };

        // SAFETY: We only access one field of the ifru union
        let addr = unsafe {
            MacAddr::from_bytes(&ifreq.ifr_ifru.ifru_hwaddr.sa_data[0..MAC_ADDR_LEN])
                .map_err(Error::MacParsing)?
        };
        Ok(addr)
    }

    #[cfg(not(fuzzing))]
    pub fn mtu(&self) -> Result<i32> {
        let sock = create_unix_socket().map_err(Error::NetUtil)?;

        let ifreq = self.get_ifreq();

        // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCGIFMTU as c_ulong, &ifreq)? };

        // SAFETY: access a union field
        let mtu = unsafe { ifreq.ifr_ifru.ifru_mtu };

        Ok(mtu)
    }

    #[cfg(fuzzing)]
    pub fn mtu(&self) -> Result<i32> {
        // Consistent with the `virtio_devices::net::MIN_MTU`
        Ok(1280)
    }

    pub fn set_mtu(&self, mtu: i32) -> Result<()> {
        let sock = create_unix_socket().map_err(Error::NetUtil)?;

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_mtu = mtu;

        // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFMTU as c_ulong, &ifreq) }
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: c_uint) -> Result<()> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        unsafe { Self::ioctl_with_val(&self.tap_file, net_gen::TUNSETOFFLOAD(), flags as c_ulong) }
    }

    /// Enable the tap interface.
    pub fn enable(&self) -> Result<()> {
        let sock = create_unix_socket().map_err(Error::NetUtil)?;

        let mut ifreq = self.get_ifreq();

        // SAFETY: IOCTL with correct arguments
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCGIFFLAGS as c_ulong, &ifreq)? };

        // If TAP device is already up don't try and enable it
        // SAFETY: access a union field
        let ifru_flags = unsafe { ifreq.ifr_ifru.ifru_flags };
        if ifru_flags & net_gen::net_device_flags_IFF_UP as i16
            == net_gen::net_device_flags_IFF_UP as i16
        {
            return Ok(());
        }

        ifreq.ifr_ifru.ifru_flags = net_gen::net_device_flags_IFF_UP as i16;

        // SAFETY: ioctl is safe. Called with a valid sock fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFFLAGS as c_ulong, &ifreq) }
    }

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<()> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        unsafe { Self::ioctl_with_ref(&self.tap_file, net_gen::TUNSETVNETHDRSZ(), &size) }
    }

    fn get_ifreq(&self) -> net_gen::ifreq {
        let mut ifreq: net_gen::ifreq = Default::default();

        // This sets the name of the interface, which is the only entry
        // in a single-field union.
        // SAFETY: access union fields and we're sure the copy is okay.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            let name_slice = &mut ifrn_name[..self.if_name.len()];
            name_slice.copy_from_slice(&self.if_name);
        }

        ifreq
    }

    pub fn get_if_name(&self) -> Vec<u8> {
        self.if_name.clone()
    }

    #[cfg(fuzzing)]
    pub fn new_for_fuzzing(tap_file: File, if_name: Vec<u8>) -> Self {
        Tap { tap_file, if_name }
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tap_file.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tap_file.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{mpsc, LazyLock, Mutex};
    use std::time::Duration;
    use std::{str, thread};

    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
    use pnet::packet::{MutablePacket, Packet};
    use pnet::util::MacAddr;
    use pnet_datalink::Channel::Ethernet;
    use pnet_datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface};

    use super::*;

    static DATA_STRING: &str = "test for tap";
    static SUBNET_MASK: &str = "255.255.255.0";

    // We needed to have a mutex as a global variable, so we use a once cell for testing. The main
    // potential problem, caused by tests being run in parallel by cargo, is creating different
    // TAPs and trying to associate the same address, so we hide the IP address &str behind this
    // mutex, more as a convention to remember to lock it at the very beginning of each function
    // susceptible to this issue. Another variant is to use a different IP address per function,
    // but we must remember to pick an unique one each time.
    static TAP_IP_LOCK: LazyLock<Mutex<&'static str>> =
        LazyLock::new(|| Mutex::new("192.168.241.1"));

    // Describes the outcomes we are currently interested in when parsing a packet (we use
    // an UDP packet for testing).
    struct ParsedPkt<'a> {
        eth: EthernetPacket<'a>,
        ipv4: Option<Ipv4Packet<'a>>,
        udp: Option<UdpPacket<'a>>,
    }

    impl<'a> ParsedPkt<'a> {
        fn new(buf: &'a [u8]) -> Self {
            let eth = EthernetPacket::new(buf).unwrap();
            let mut ipv4 = None;
            let mut udp = None;

            if eth.get_ethertype() == EtherTypes::Ipv4 {
                let ipv4_start = 14;
                ipv4 = Some(Ipv4Packet::new(&buf[ipv4_start..]).unwrap());

                // Hiding the old ipv4 variable for the rest of this block.
                let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();

                if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    // The value in header_length indicates the number of 32 bit words
                    // that make up the header, not the actual length in bytes.
                    let udp_start = ipv4_start + ipv4.get_header_length() as usize * 4;
                    udp = Some(UdpPacket::new(&buf[udp_start..]).unwrap());
                }
            }

            ParsedPkt { eth, ipv4, udp }
        }

        fn print(&self) {
            print!(
                "{} {} {} ",
                self.eth.get_source(),
                self.eth.get_destination(),
                self.eth.get_ethertype()
            );
            if let Some(ref ipv4) = self.ipv4 {
                print!(
                    "{} {} {} ",
                    ipv4.get_source(),
                    ipv4.get_destination(),
                    ipv4.get_next_level_protocol()
                );
            }
            if let Some(ref udp) = self.udp {
                print!(
                    "{} {} {}",
                    udp.get_source(),
                    udp.get_destination(),
                    str::from_utf8(udp.payload()).unwrap()
                );
            }
            println!();
        }
    }

    fn tap_name_to_string(tap: &Tap) -> String {
        let null_pos = tap.if_name.iter().position(|x| *x == 0).unwrap();
        str::from_utf8(&tap.if_name[..null_pos])
            .unwrap()
            .to_string()
    }

    // Given a buffer of appropriate size, this fills in the relevant fields based on the
    // provided information. Payload refers to the UDP payload.
    fn pnet_build_packet(buf: &mut [u8], dst_mac: MacAddr, payload: &[u8]) {
        let mut eth = MutableEthernetPacket::new(buf).unwrap();
        eth.set_source(MacAddr::new(0x06, 0, 0, 0, 0, 0));
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);

        let mut ipv4 = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(20 + 8 + payload.len() as u16);
        ipv4.set_ttl(200);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4.set_source(Ipv4Addr::new(192, 168, 241, 1));
        ipv4.set_destination(Ipv4Addr::new(192, 168, 241, 2));

        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).unwrap();
        udp.set_source(1000);
        udp.set_destination(1001);
        udp.set_length(8 + payload.len() as u16);
        udp.set_payload(payload);
    }

    // Sends a test packet on the interface named "ifname".
    fn pnet_send_packet(ifname: String) {
        let payload = DATA_STRING.as_bytes();

        // eth hdr + ip hdr + udp hdr + payload len
        let buf_size = 14 + 20 + 8 + payload.len();

        let (mac, mut tx, _) = pnet_get_mac_tx_rx(ifname);

        let res = tx.build_and_send(1, buf_size, &mut |buf| {
            pnet_build_packet(buf, mac, payload);
        });
        // Make sure build_and_send() -> Option<io::Result<()>> succeeds.
        res.unwrap().unwrap();
    }

    // For a given interface name, this returns a tuple that contains the MAC address of the
    // interface, an object that can be used to send Ethernet frames, and a receiver of
    // Ethernet frames arriving at the specified interface.
    fn pnet_get_mac_tx_rx(
        ifname: String,
    ) -> (MacAddr, Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
        let interface_name_matches = |iface: &NetworkInterface| iface.name == ifname;

        // Find the network interface with the provided name.
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces.into_iter().find(interface_name_matches).unwrap();

        if let Ok(Ethernet(tx, rx)) = pnet_datalink::channel(&interface, Default::default()) {
            (interface.mac.unwrap(), tx, rx)
        } else {
            panic!("datalink channel error or unhandled channel type");
        }
    }

    #[test]
    fn test_tap_create() {
        let _tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let t = Tap::new(1).unwrap();
        println!("created tap: {t:?}");
    }

    #[test]
    fn test_tap_from_fd() {
        let _tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let orig_tap = Tap::new(1).unwrap();
        let fd = orig_tap.as_raw_fd();
        let _new_tap = Tap::from_tap_fd(fd, 1).unwrap();
    }

    #[test]
    fn test_tap_configure() {
        // This should be the first thing to be called inside the function, so everything else
        // is torn down by the time the mutex is automatically released. Also, we should
        // explicitly bind the MutexGuard to a variable via let, the make sure it lives until
        // the end of the function.
        let tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let tap = Tap::new(1).unwrap();
        let ip_addr = IpAddr::V4((*tap_ip_guard).parse().unwrap());
        let netmask = IpAddr::V4(SUBNET_MASK.parse().unwrap());

        tap.set_ip_addr(ip_addr, Some(netmask)).unwrap();
    }

    #[test]
    fn test_tap_configure_ipv6() {
        let tap_ip6_lock: Mutex<&'static str> = Mutex::new("2001:db8:85a3::8a2e:370:7334");
        let tap_ip6_guard = tap_ip6_lock.lock().unwrap();

        let tap = Tap::new(1).unwrap();
        let ip_addr = IpAddr::V6((*tap_ip6_guard).parse().unwrap());
        let netmask = IpAddr::V6("ffff:ffff::".parse().unwrap());

        tap.set_ip_addr(ip_addr, Some(netmask)).unwrap();
    }

    #[test]
    fn test_set_options() {
        let _tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        // This line will fail to provide an initialized FD if the test is not run as root.
        let tap = Tap::new(1).unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();
    }

    #[test]
    fn test_tap_enable() {
        let _tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let tap = Tap::new(1).unwrap();
        tap.enable().unwrap();
    }

    #[test]
    fn test_raw_fd() {
        let _tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let tap = Tap::new(1).unwrap();
        assert_eq!(tap.as_raw_fd(), tap.tap_file.as_raw_fd());
    }

    #[test]
    fn test_read() {
        let tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let mut tap = Tap::new(1).unwrap();
        let ip_addr = IpAddr::V4((*tap_ip_guard).parse().unwrap());
        let netmask = IpAddr::V4(SUBNET_MASK.parse().unwrap());
        tap.set_ip_addr(ip_addr, Some(netmask)).unwrap();
        tap.enable().unwrap();

        // Send a packet to the interface. We expect to be able to receive it on the associated fd.
        pnet_send_packet(tap_name_to_string(&tap));

        let mut buf = [0u8; 4096];

        let mut found_packet_sz = None;

        // In theory, this could actually loop forever if something keeps sending data through the
        // tap interface, but it's highly unlikely.
        while found_packet_sz.is_none() {
            let size = tap.read(&mut buf).unwrap();

            // We skip the first 10 bytes because the IFF_VNET_HDR flag is set when the interface
            // is created, and the legacy header is 10 bytes long without a certain flag which
            // is not set in Tap::new().
            let eth_bytes = &buf[10..size];

            let packet = EthernetPacket::new(eth_bytes).unwrap();
            if packet.get_ethertype() != EtherTypes::Ipv4 {
                // not an IPv4 packet
                continue;
            }

            let ipv4_bytes = &eth_bytes[14..];
            let packet = Ipv4Packet::new(ipv4_bytes).unwrap();

            // Our packet should carry an UDP payload, and not contain IP options.
            if packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp
                && packet.get_header_length() != 5
            {
                continue;
            }

            let udp_bytes = &ipv4_bytes[20..];

            let udp_len = UdpPacket::new(udp_bytes).unwrap().get_length() as usize;

            // Skip the header bytes.
            let inner_string = str::from_utf8(&udp_bytes[8..udp_len]).unwrap();

            if inner_string.eq(DATA_STRING) {
                found_packet_sz = Some(size);
                break;
            }
        }

        assert!(found_packet_sz.is_some());
    }

    #[test]
    fn test_write() {
        let tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let mut tap = Tap::new(1).unwrap();
        let ip_addr = IpAddr::V4((*tap_ip_guard).parse().unwrap());
        let netmask = IpAddr::V4(SUBNET_MASK.parse().unwrap());
        tap.set_ip_addr(ip_addr, Some(netmask)).unwrap();
        tap.enable().unwrap();

        let (mac, _, mut rx) = pnet_get_mac_tx_rx(tap_name_to_string(&tap));

        let payload = DATA_STRING.as_bytes();

        // vnet hdr + eth hdr + ip hdr + udp hdr + payload len
        let buf_size = 10 + 14 + 20 + 8 + payload.len();

        let mut buf = vec![0u8; buf_size];
        // leave the vnet hdr as is
        pnet_build_packet(&mut buf[10..], mac, payload);

        tap.write_all(&buf).unwrap();
        tap.flush().unwrap();

        let (channel_tx, channel_rx) = mpsc::channel();

        // We use a separate thread to wait for the test packet because the API exposed by pnet is
        // blocking. This thread will be killed when the main thread exits.
        let _handle = thread::spawn(move || loop {
            let buf = rx.next().unwrap();
            let p = ParsedPkt::new(buf);
            p.print();

            if let Some(ref udp) = p.udp {
                if payload == udp.payload() {
                    channel_tx.send(true).unwrap();
                    break;
                }
            }
        });

        // We wait for at most SLEEP_MILLIS * SLEEP_ITERS milliseconds for the reception of the
        // test packet to be detected.
        static SLEEP_MILLIS: u64 = 500;
        static SLEEP_ITERS: u32 = 6;

        let mut found_test_packet = false;

        for _ in 0..SLEEP_ITERS {
            thread::sleep(Duration::from_millis(SLEEP_MILLIS));
            if let Ok(true) = channel_rx.try_recv() {
                found_test_packet = true;
                break;
            }
        }

        assert!(found_test_packet);
    }
}
