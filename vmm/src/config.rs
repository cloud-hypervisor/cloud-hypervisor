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
pub const DEFAULT_MEMORY: &str = "size=512";
pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";
const CMDLINE_OFFSET: GuestAddress = GuestAddress(0x20000);

/// Errors associated with VM configuration parameters.
#[derive(Debug)]
pub enum Error<'a> {
    /// Failed parsing cpus parameters.
    ParseCpusParams(std::num::ParseIntError),
    /// Failed parsing memory size parameter.
    ParseMemorySizeParam(std::num::ParseIntError),
    /// Failed parsing memory file parameter.
    ParseMemoryFileParam,
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
    /// Failed parsing fs tag parameter.
    ParseFsTagParam,
    /// Failed parsing fs socket path parameter.
    ParseFsSockParam,
    /// Failed parsing fs number of queues parameter.
    ParseFsNumQueuesParam(std::num::ParseIntError),
    /// Failed parsing fs queue size parameter.
    ParseFsQueueSizeParam(std::num::ParseIntError),
    /// Failed parsing persitent memory file parameter.
    ParsePmemFileParam,
    /// Failed parsing persitent memory size parameter.
    ParsePmemSizeParam(std::num::ParseIntError),
}
pub type Result<'a, T> = result::Result<T, Error<'a>>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub kernel: &'a str,
    pub cmdline: Option<&'a str>,
    pub disks: Vec<&'a str>,
    pub net: Option<&'a str>,
    pub rng: &'a str,
    pub fs: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
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

pub struct MemoryConfig<'a> {
    pub size: u64,
    pub file: Option<&'a Path>,
}

impl<'a> MemoryConfig<'a> {
    pub fn parse(memory: &'a str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = memory.split(',').collect();

        let mut size_str: &str = "";
        let mut file_str: &str = "";
        let mut backed = false;

        for param in params_list.iter() {
            if param.starts_with("size=") {
                size_str = &param[5..];
            } else if param.starts_with("file=") {
                backed = true;
                file_str = &param[5..];
            }
        }

        let file = if backed {
            if file_str.is_empty() {
                return Err(Error::ParseMemoryFileParam);
            }

            Some(Path::new(file_str))
        } else {
            None
        };

        Ok(MemoryConfig {
            size: size_str
                .parse::<u64>()
                .map_err(Error::ParseMemorySizeParam)?,
            file,
        })
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

#[derive(Debug)]
pub struct FsConfig<'a> {
    pub tag: &'a str,
    pub sock: &'a Path,
    pub num_queues: usize,
    pub queue_size: u16,
}

impl<'a> FsConfig<'a> {
    pub fn parse(fs: &'a str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = fs.split(',').collect();

        let mut tag: &str = "";
        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("tag=") {
                tag = &param[4..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            }
        }

        let mut num_queues: usize = 1;
        let mut queue_size: u16 = 1024;

        if tag.is_empty() {
            return Err(Error::ParseFsTagParam);
        }
        if sock.is_empty() {
            return Err(Error::ParseFsSockParam);
        }
        if !num_queues_str.is_empty() {
            num_queues = num_queues_str
                .parse()
                .map_err(Error::ParseFsNumQueuesParam)?;
        }
        if !queue_size_str.is_empty() {
            queue_size = queue_size_str
                .parse()
                .map_err(Error::ParseFsQueueSizeParam)?;
        }

        Ok(FsConfig {
            tag,
            sock: Path::new(sock),
            num_queues,
            queue_size,
        })
    }
}

pub struct PmemConfig<'a> {
    pub file: &'a Path,
    pub size: u64,
}

impl<'a> PmemConfig<'a> {
    pub fn parse(pmem: &'a str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = pmem.split(',').collect();

        let mut file_str: &str = "";
        let mut size_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("file=") {
                file_str = &param[5..];
            } else if param.starts_with("size=") {
                size_str = &param[5..];
            }
        }

        if file_str.is_empty() {
            return Err(Error::ParsePmemFileParam);
        }

        Ok(PmemConfig {
            file: Path::new(file_str),
            size: size_str.parse::<u64>().map_err(Error::ParsePmemSizeParam)?,
        })
    }
}

pub struct VmConfig<'a> {
    pub cpus: CpusConfig,
    pub memory: MemoryConfig<'a>,
    pub kernel: KernelConfig<'a>,
    pub cmdline: CmdlineConfig,
    pub disks: Vec<DiskConfig<'a>>,
    pub net: Option<NetConfig<'a>>,
    pub rng: RngConfig<'a>,
    pub fs: Option<Vec<FsConfig<'a>>>,
    pub pmem: Option<Vec<PmemConfig<'a>>>,
}

impl<'a> VmConfig<'a> {
    pub fn parse(vm_params: VmParams<'a>) -> Result<Self> {
        let mut disks: Vec<DiskConfig> = Vec::new();
        for disk in vm_params.disks.iter() {
            disks.push(DiskConfig::parse(disk)?);
        }

        let mut fs: Option<Vec<FsConfig>> = None;
        if let Some(fs_list) = &vm_params.fs {
            let mut fs_config_list = Vec::new();
            for item in fs_list.iter() {
                fs_config_list.push(FsConfig::parse(item)?);
            }
            fs = Some(fs_config_list);
        }

        let mut pmem: Option<Vec<PmemConfig>> = None;
        if let Some(pmem_list) = &vm_params.pmem {
            let mut pmem_config_list = Vec::new();
            for item in pmem_list.iter() {
                pmem_config_list.push(PmemConfig::parse(item)?);
            }
            pmem = Some(pmem_config_list);
        }

        Ok(VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory)?,
            kernel: KernelConfig::parse(vm_params.kernel)?,
            cmdline: CmdlineConfig::parse(vm_params.cmdline)?,
            disks,
            net: NetConfig::parse(vm_params.net)?,
            rng: RngConfig::parse(vm_params.rng)?,
            fs,
            pmem,
        })
    }
}
