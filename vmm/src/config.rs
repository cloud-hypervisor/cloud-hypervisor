// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vm_virtio;

use linux_loader::cmdline::Cmdline;
use net_util::MacAddr;
use std::convert::From;
use std::net::AddrParseError;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::result;
use vm_virtio::vhost_user::VhostUserConfig;

pub const DEFAULT_VCPUS: &str = "1";
pub const DEFAULT_MEMORY: &str = "size=512M";
pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";

/// Errors associated with VM configuration parameters.
#[derive(Debug)]
pub enum Error<'a> {
    /// Failed parsing cpus parameters.
    ParseCpusParams(std::num::ParseIntError),
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
    /// Failed parsing fs dax parameter.
    ParseFsDax,
    /// Cannot have dax=off along with cache_size parameter.
    InvalidCacheSizeWithDaxOff,
    /// Failed parsing persitent memory file parameter.
    ParsePmemFileParam,
    /// Failed parsing size parameter.
    ParseSizeParam(std::num::ParseIntError),
    /// Failed parsing console parameter.
    ParseConsoleParam,
    /// Both console and serial are tty.
    ParseTTYParam,
    /// Failed parsing vhost-user-net mac parameter.
    ParseVuNetMacParam(&'a str),
    /// Failed parsing vhost-user sock parameter.
    ParseVuSockParam,
    /// Failed parsing vhost-user queue number parameter.
    ParseVuNumQueuesParam(std::num::ParseIntError),
    /// Failed parsing vhost-user queue size parameter.
    ParseVuQueueSizeParam(std::num::ParseIntError),
    /// Failed parsing vhost-user-net server parameter.
    ParseVuNetServerParam(std::num::ParseIntError),
    /// Failed parsing vhost-user-blk wce parameter.
    ParseVuBlkWceParam(std::str::ParseBoolError),
    /// Failed parsing vsock context ID parameter.
    ParseVsockCidParam(std::num::ParseIntError),
    /// Failed parsing vsock socket path parameter.
    ParseVsockSockParam,
}
pub type Result<'a, T> = result::Result<T, Error<'a>>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub kernel: &'a str,
    pub cmdline: Option<&'a str>,
    pub disks: Option<Vec<&'a str>>,
    pub net: Option<Vec<&'a str>>,
    pub rng: &'a str,
    pub fs: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
    pub serial: &'a str,
    pub console: &'a str,
    pub devices: Option<Vec<&'a str>>,
    pub vhost_user_net: Option<Vec<&'a str>>,
    pub vhost_user_blk: Option<Vec<&'a str>>,
    pub vsock: Option<Vec<&'a str>>,
}

fn parse_size(size: &str) -> Result<u64> {
    let s = size.trim();

    let shift = if s.ends_with('K') {
        10
    } else if s.ends_with('M') {
        20
    } else if s.ends_with('G') {
        30
    } else {
        0
    };

    let s = s.trim_end_matches(|c| c == 'K' || c == 'M' || c == 'G');
    let res = s.parse::<u64>().map_err(Error::ParseSizeParam)?;
    Ok(res << shift)
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct MemoryConfig {
    pub size: u64,
    pub file: Option<PathBuf>,
}

impl MemoryConfig {
    pub fn parse(memory: &str) -> Result<Self> {
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

            Some(PathBuf::from(file_str))
        } else {
            None
        };

        Ok(MemoryConfig {
            size: parse_size(size_str)?,
            file,
        })
    }
}

#[derive(Clone, Debug)]
pub struct KernelConfig {
    pub path: PathBuf,
}

impl KernelConfig {
    pub fn parse(kernel: &str) -> Result<Self> {
        Ok(KernelConfig {
            path: PathBuf::from(kernel),
        })
    }
}

#[derive(Clone)]
pub struct CmdlineConfig {
    pub args: Cmdline,
}

impl CmdlineConfig {
    pub fn parse(cmdline: Option<&str>) -> Result<Self> {
        let cmdline_str = cmdline
            .map(std::string::ToString::to_string)
            .unwrap_or_else(String::new);
        let mut args = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        args.insert_str(cmdline_str).unwrap();

        Ok(CmdlineConfig { args })
    }
}

#[derive(Clone, Debug)]
pub struct DiskConfig {
    pub path: PathBuf,
}

impl DiskConfig {
    pub fn parse(disk: &str) -> Result<Self> {
        Ok(DiskConfig {
            path: PathBuf::from(disk),
        })
    }
}

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub tap: Option<String>,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub mac: MacAddr,
}

impl NetConfig {
    pub fn parse(net: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = net.split(',').collect();

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

        let mut tap: Option<String> = None;
        let mut ip: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 1);
        let mut mask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);;
        let mut mac: MacAddr = MacAddr::local_random();

        if !tap_str.is_empty() {
            tap = Some(tap_str.to_string());
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

        Ok(NetConfig { tap, ip, mask, mac })
    }
}

#[derive(Clone, Debug)]
pub struct RngConfig {
    pub src: PathBuf,
}

impl RngConfig {
    pub fn parse(rng: &str) -> Result<Self> {
        Ok(RngConfig {
            src: PathBuf::from(rng),
        })
    }
}

#[derive(Clone, Debug)]
pub struct FsConfig {
    pub tag: String,
    pub sock: PathBuf,
    pub num_queues: usize,
    pub queue_size: u16,
    pub cache_size: Option<u64>,
}

impl FsConfig {
    pub fn parse(fs: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = fs.split(',').collect();

        let mut tag: &str = "";
        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";
        let mut dax_str: &str = "";
        let mut cache_size_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("tag=") {
                tag = &param[4..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            } else if param.starts_with("dax=") {
                dax_str = &param[4..];
            } else if param.starts_with("cache_size=") {
                cache_size_str = &param[11..];
            }
        }

        let mut num_queues: usize = 1;
        let mut queue_size: u16 = 1024;
        let mut dax: bool = true;
        // Default cache size set to 8Gib.
        let mut cache_size: Option<u64> = Some(0x0002_0000_0000);

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
        if !dax_str.is_empty() {
            match dax_str {
                "on" => dax = true,
                "off" => dax = false,
                _ => return Err(Error::ParseFsDax),
            }
        }

        // Take appropriate decision about cache_size based on DAX being
        // enabled or disabled.
        if !dax {
            if !cache_size_str.is_empty() {
                return Err(Error::InvalidCacheSizeWithDaxOff);
            }
            cache_size = None;
        } else if !cache_size_str.is_empty() {
            cache_size = Some(parse_size(cache_size_str)?);
        }

        Ok(FsConfig {
            tag: tag.to_string(),
            sock: PathBuf::from(sock),
            num_queues,
            queue_size,
            cache_size,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PmemConfig {
    pub file: PathBuf,
    pub size: u64,
}

impl PmemConfig {
    pub fn parse(pmem: &str) -> Result<Self> {
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
            file: PathBuf::from(file_str),
            size: parse_size(size_str)?,
        })
    }
}

#[derive(Clone, PartialEq)]
pub enum ConsoleOutputMode {
    Off,
    Tty,
    File,
    Null,
}

impl ConsoleOutputMode {
    pub fn input_enabled(&self) -> bool {
        match self {
            ConsoleOutputMode::Tty => true,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct ConsoleConfig {
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
}

impl ConsoleConfig {
    pub fn parse(param: &str) -> Result<Self> {
        if param == "off" {
            Ok(Self {
                mode: ConsoleOutputMode::Off,
                file: None,
            })
        } else if param == "tty" {
            Ok(Self {
                mode: ConsoleOutputMode::Tty,
                file: None,
            })
        } else if param.starts_with("file=") {
            Ok(Self {
                mode: ConsoleOutputMode::File,
                file: Some(PathBuf::from(&param[5..])),
            })
        } else if param.starts_with("null") {
            Ok(Self {
                mode: ConsoleOutputMode::Null,
                file: None,
            })
        } else {
            Err(Error::ParseConsoleParam)
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub path: PathBuf,
}

impl DeviceConfig {
    pub fn parse(device: &str) -> Result<Self> {
        Ok(DeviceConfig {
            path: PathBuf::from(device),
        })
    }
}

#[derive(Clone, Debug)]
pub struct VhostUserNetConfig {
    pub mac: MacAddr,
    pub vu_cfg: VhostUserConfig,
}

impl VhostUserNetConfig {
    pub fn parse(vhost_user_net: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = vhost_user_net.split(',').collect();

        let mut mac_str: &str = "";
        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("mac=") {
                mac_str = &param[4..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            }
        }

        let mut mac: MacAddr = MacAddr::local_random();
        let mut num_queues: usize = 2;
        let mut queue_size: u16 = 256;

        if !mac_str.is_empty() {
            mac = MacAddr::parse_str(mac_str).map_err(Error::ParseVuNetMacParam)?;
        }
        if sock.is_empty() {
            return Err(Error::ParseVuSockParam);
        }
        if !num_queues_str.is_empty() {
            num_queues = num_queues_str
                .parse()
                .map_err(Error::ParseVuNumQueuesParam)?;
        }
        if !queue_size_str.is_empty() {
            queue_size = queue_size_str
                .parse()
                .map_err(Error::ParseVuQueueSizeParam)?;
        }

        let vu_cfg = VhostUserConfig {
            sock: sock.to_string(),
            num_queues,
            queue_size,
        };

        Ok(VhostUserNetConfig { mac, vu_cfg })
    }
}

#[derive(Clone, Debug)]
pub struct VsockConfig {
    pub cid: u64,
    pub sock: PathBuf,
}

impl VsockConfig {
    pub fn parse(vsock: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = vsock.split(',').collect();

        let mut cid_str: &str = "";
        let mut sock_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("cid=") {
                cid_str = &param[4..];
            } else if param.starts_with("sock=") {
                sock_str = &param[5..];
            }
        }

        if sock_str.is_empty() {
            return Err(Error::ParseVsockSockParam);
        }

        Ok(VsockConfig {
            cid: cid_str.parse::<u64>().map_err(Error::ParseVsockCidParam)?,
            sock: PathBuf::from(sock_str),
        })
    }
}

#[derive(Clone, Debug)]
pub struct VhostUserBlkConfig {
    pub wce: bool,
    pub vu_cfg: VhostUserConfig,
}

impl VhostUserBlkConfig {
    pub fn parse(vhost_user_blk: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = vhost_user_blk.split(',').collect();

        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";
        let mut wce_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            } else if param.starts_with("wce=") {
                wce_str = &param[4..];
            }
        }

        let mut num_queues: usize = 1;
        let mut queue_size: u16 = 128;
        let mut wce: bool = true;

        if !num_queues_str.is_empty() {
            num_queues = num_queues_str
                .parse()
                .map_err(Error::ParseVuNumQueuesParam)?;
        }
        if !queue_size_str.is_empty() {
            queue_size = queue_size_str
                .parse()
                .map_err(Error::ParseVuQueueSizeParam)?;
        }
        if !wce_str.is_empty() {
            wce = wce_str.parse().map_err(Error::ParseVuBlkWceParam)?;
        }

        let vu_cfg = VhostUserConfig {
            sock: sock.to_string(),
            num_queues,
            queue_size,
        };

        Ok(VhostUserBlkConfig { wce, vu_cfg })
    }
}

#[derive(Clone)]
pub struct VmConfig {
    pub cpus: CpusConfig,
    pub memory: MemoryConfig,
    pub kernel: KernelConfig,
    pub cmdline: CmdlineConfig,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    pub rng: RngConfig,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    pub serial: ConsoleConfig,
    pub console: ConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub vhost_user_net: Option<Vec<VhostUserNetConfig>>,
    pub vhost_user_blk: Option<Vec<VhostUserBlkConfig>>,
    pub vsock: Option<Vec<VsockConfig>>,
}

impl VmConfig {
    pub fn parse(vm_params: VmParams) -> Result<Self> {
        let mut disks: Option<Vec<DiskConfig>> = None;
        if let Some(disk_list) = &vm_params.disks {
            let mut disk_config_list = Vec::new();
            for item in disk_list.iter() {
                disk_config_list.push(DiskConfig::parse(item)?);
            }
            disks = Some(disk_config_list);
        }

        let mut net: Option<Vec<NetConfig>> = None;
        if let Some(net_list) = &vm_params.net {
            let mut net_config_list = Vec::new();
            for item in net_list.iter() {
                net_config_list.push(NetConfig::parse(item)?);
            }
            net = Some(net_config_list);
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

        let console = ConsoleConfig::parse(vm_params.console)?;
        let serial = ConsoleConfig::parse(vm_params.serial)?;
        if console.mode == ConsoleOutputMode::Tty && serial.mode == ConsoleOutputMode::Tty {
            return Err(Error::ParseTTYParam);
        }

        let mut devices: Option<Vec<DeviceConfig>> = None;
        if let Some(device_list) = &vm_params.devices {
            let mut device_config_list = Vec::new();
            for item in device_list.iter() {
                device_config_list.push(DeviceConfig::parse(item)?);
            }
            devices = Some(device_config_list);
        }

        let mut vhost_user_net: Option<Vec<VhostUserNetConfig>> = None;
        if let Some(vhost_user_net_list) = &vm_params.vhost_user_net {
            let mut vhost_user_net_config_list = Vec::new();
            for item in vhost_user_net_list.iter() {
                vhost_user_net_config_list.push(VhostUserNetConfig::parse(item)?);
            }
            vhost_user_net = Some(vhost_user_net_config_list);
        }

        let mut vsock: Option<Vec<VsockConfig>> = None;
        if let Some(vsock_list) = &vm_params.vsock {
            let mut vsock_config_list = Vec::new();
            for item in vsock_list.iter() {
                vsock_config_list.push(VsockConfig::parse(item)?);
            }
            vsock = Some(vsock_config_list);
        }

        let mut vhost_user_blk: Option<Vec<VhostUserBlkConfig>> = None;
        if let Some(vhost_user_blk_list) = &vm_params.vhost_user_blk {
            let mut vhost_user_blk_config_list = Vec::new();
            for item in vhost_user_blk_list.iter() {
                vhost_user_blk_config_list.push(VhostUserBlkConfig::parse(item)?);
            }
            vhost_user_blk = Some(vhost_user_blk_config_list);
        }

        Ok(VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory)?,
            kernel: KernelConfig::parse(vm_params.kernel)?,
            cmdline: CmdlineConfig::parse(vm_params.cmdline)?,
            disks,
            net,
            rng: RngConfig::parse(vm_params.rng)?,
            fs,
            pmem,
            serial,
            console,
            devices,
            vhost_user_net,
            vhost_user_blk,
            vsock,
        })
    }
}
