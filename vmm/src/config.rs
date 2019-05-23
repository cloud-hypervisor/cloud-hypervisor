// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use linux_loader::cmdline::Cmdline;
use net_util::MacAddr;
use std::convert::From;
use std::net::AddrParseError;
use std::net::Ipv4Addr;
use std::path::Path;
use std::result;
use vm_memory::GuestAddress;

pub const DEFAULT_VCPUS: &str = "1";
pub const DEFAULT_MEMORY: &str = "512";
pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";
const CMDLINE_OFFSET: GuestAddress = GuestAddress(0x20000);

/// Errors associated with VM configuration parameters.
#[derive(Debug)]
pub enum Error<'a> {
    /// Failed parsing cpus parameters.
    ParseCpusParams(std::num::ParseIntError),
    /// Failed parsing memory parameters.
    ParseMemoryParams(std::num::ParseIntError),
    /// Failed parsing kernel parameters.
    ParseKernelParams,
    /// Failed parsing kernel command line parameters.
    ParseCmdlineParams,
    /// Failed parsing disks parameters.
    ParseDisksParams,
    /// Failed parsing random number generator parameters.
    ParseRngParams,
    /// Failed parsing network ip parameter.
    ParseNetIpParam(AddrParseError),
    /// Failed parsing network mask parameter.
    ParseNetMaskParam(AddrParseError),
    /// Failed parsing network mac parameter.
    ParseNetMacParam(&'a str),
}
pub type Result<'a, T> = result::Result<T, Error<'a>>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub kernel: &'a str,
    pub cmdline: Option<&'a str>,
    pub disks: Vec<&'a str>,
    pub rng: &'a str,
    pub net: Option<&'a str>,
}

pub struct CpusConfig(pub u8);

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self> {
        Ok(CpusConfig(
            cpus.parse::<u8>().map_err(Error::ParseCpusParams)?,
        ))
    }
}

impl From<&CpusConfig> for u8 {
    fn from(val: &CpusConfig) -> Self {
        val.0
    }
}

pub struct MemoryConfig(pub u64);

impl MemoryConfig {
    pub fn parse(memory: &str) -> Result<Self> {
        Ok(MemoryConfig(
            memory.parse::<u64>().map_err(Error::ParseMemoryParams)?,
        ))
    }
}

impl From<&MemoryConfig> for u64 {
    fn from(val: &MemoryConfig) -> Self {
        val.0
    }
}

pub struct KernelConfig<'a> {
    pub path: &'a Path,
}

impl<'a> KernelConfig<'a> {
    pub fn parse(kernel: &'a str) -> Result<Self> {
        Ok(KernelConfig {
            path: Path::new(kernel),
        })
    }
}

pub struct CmdlineConfig {
    pub args: Cmdline,
    pub offset: GuestAddress,
}

impl CmdlineConfig {
    pub fn parse(cmdline: Option<&str>) -> Result<Self> {
        let cmdline_str = cmdline
            .map(std::string::ToString::to_string)
            .unwrap_or_else(String::new);
        let mut args = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        args.insert_str(cmdline_str).unwrap();

        Ok(CmdlineConfig {
            args,
            offset: CMDLINE_OFFSET,
        })
    }
}

#[derive(Debug)]
pub struct DiskConfig<'a> {
    pub path: &'a Path,
}

impl<'a> DiskConfig<'a> {
    pub fn parse(disk: &'a str) -> Result<Self> {
        Ok(DiskConfig {
            path: Path::new(disk),
        })
    }
}

pub struct RngConfig<'a> {
    pub src: &'a Path,
}

impl<'a> RngConfig<'a> {
    pub fn parse(rng: &'a str) -> Result<Self> {
        Ok(RngConfig {
            src: Path::new(rng),
        })
    }
}

pub struct NetConfig<'a> {
    pub tap: Option<&'a str>,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub mac: MacAddr,
}

impl<'a> NetConfig<'a> {
    pub fn parse(net: Option<&'a str>) -> Result<Option<Self>> {
        if net.is_none() {
            return Ok(None);
        }

        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = net.unwrap().split(',').collect();

        let mut tap_str: &str = "";
        let mut ip_str: &str = "";
        let mut mask_str: &str = "";
        let mut mac_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("tap=") {
                tap_str = &param[4..];
            } else if param.starts_with("ip=") {
                ip_str = &param[3..];
            } else if param.starts_with("mask=") {
                mask_str = &param[5..];
            } else if param.starts_with("mac=") {
                mac_str = &param[4..];
            }
        }

        let mut tap: Option<&str> = None;
        let mut ip: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 1);
        let mut mask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);;
        let mut mac: MacAddr = MacAddr::local_random();

        if !tap_str.is_empty() {
            tap = Some(tap_str);
        }
        if !ip_str.is_empty() {
            ip = ip_str.parse().map_err(Error::ParseNetIpParam)?;
        }
        if !mask_str.is_empty() {
            mask = mask_str.parse().map_err(Error::ParseNetMaskParam)?;
        }
        if !mac_str.is_empty() {
            mac = MacAddr::parse_str(mac_str).map_err(Error::ParseNetMacParam)?;
        }

        Ok(Some(NetConfig { tap, ip, mask, mac }))
    }
}

pub struct VmConfig<'a> {
    pub cpus: CpusConfig,
    pub memory: MemoryConfig,
    pub kernel: KernelConfig<'a>,
    pub cmdline: CmdlineConfig,
    pub disks: Vec<DiskConfig<'a>>,
    pub rng: RngConfig<'a>,
    pub net: Option<NetConfig<'a>>,
}

impl<'a> VmConfig<'a> {
    pub fn parse(vm_params: VmParams<'a>) -> Result<Self> {
        let mut disks: Vec<DiskConfig> = Vec::new();
        for disk in vm_params.disks.iter() {
            disks.push(DiskConfig::parse(disk)?);
        }

        Ok(VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory)?,
            kernel: KernelConfig::parse(vm_params.kernel)?,
            cmdline: CmdlineConfig::parse(vm_params.cmdline)?,
            disks,
            rng: RngConfig::parse(vm_params.rng)?,
            net: NetConfig::parse(vm_params.net)?,
        })
    }
}
