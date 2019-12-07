// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vm_virtio;

use net_util::MacAddr;
use std::convert::From;
use std::net::AddrParseError;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::result;

pub const DEFAULT_VCPUS: u8 = 1;
pub const DEFAULT_MEMORY_MB: u64 = 512;
pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";

/// Errors associated with VM configuration parameters.
#[derive(Debug)]
pub enum Error<'a> {
    /// Failed parsing cpus parameters.
    ParseCpusParams(std::num::ParseIntError),
    /// Unexpected vCPU parameter
    ParseCpusUnknownParam,
    /// Max is less than boot
    ParseCpusMaxLowerThanBoot,
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
    /// Missing kernel configuration
    ValidateMissingKernelConfig,
    /// Failed parsing generic on|off parameter.
    ParseOnOff,
}
pub type Result<'a, T> = result::Result<T, Error<'a>>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub kernel: Option<&'a str>,
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

fn parse_on_off(param: &str) -> Result<bool> {
    if !param.is_empty() {
        let res = match param {
            "on" => true,
            "off" => false,
            _ => return Err(Error::ParseOnOff),
        };

        Ok(res)
    } else {
        Ok(false)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CpusConfig {
    pub boot_vcpus: u8,
    pub max_vcpus: u8,
}

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self> {
        if let Ok(legacy_vcpu_count) = cpus.parse::<u8>() {
            error!("Using deprecated vCPU syntax. Use --cpus boot=<boot_vcpus>[,max=<max_vcpus]");
            Ok(CpusConfig {
                boot_vcpus: legacy_vcpu_count,
                max_vcpus: legacy_vcpu_count,
            })
        } else {
            // Split the parameters based on the comma delimiter
            let params_list: Vec<&str> = cpus.split(',').collect();

            let mut boot_str: &str = "";
            let mut max_str: &str = "";

            for param in params_list.iter() {
                if param.starts_with("boot=") {
                    boot_str = &param["boot=".len()..];
                } else if param.starts_with("max=") {
                    max_str = &param["max=".len()..];
                } else {
                    return Err(Error::ParseCpusUnknownParam);
                }
            }

            let boot_vcpus: u8 = boot_str.parse().map_err(Error::ParseCpusParams)?;
            let max_vcpus = if max_str != "" {
                max_str.parse().map_err(Error::ParseCpusParams)?
            } else {
                boot_vcpus
            };

            if max_vcpus < boot_vcpus {
                return Err(Error::ParseCpusMaxLowerThanBoot);
            }

            Ok(CpusConfig {
                boot_vcpus,
                max_vcpus,
            })
        }
    }
}

impl Default for CpusConfig {
    fn default() -> Self {
        CpusConfig {
            boot_vcpus: DEFAULT_VCPUS,
            max_vcpus: DEFAULT_VCPUS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MemoryConfig {
    pub size: u64,
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub mergeable: bool,
}

impl MemoryConfig {
    pub fn parse(memory: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = memory.split(',').collect();

        let mut size_str: &str = "";
        let mut file_str: &str = "";
        let mut mergeable_str: &str = "";
        let mut backed = false;

        for param in params_list.iter() {
            if param.starts_with("size=") {
                size_str = &param[5..];
            } else if param.starts_with("file=") {
                backed = true;
                file_str = &param[5..];
            } else if param.starts_with("mergeable=") {
                mergeable_str = &param[10..];
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
            mergeable: parse_on_off(mergeable_str)?,
        })
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            size: DEFAULT_MEMORY_MB << 20,
            file: None,
            mergeable: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KernelConfig {
    pub path: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CmdlineConfig {
    pub args: String,
}

impl CmdlineConfig {
    pub fn parse(cmdline: Option<&str>) -> Result<Self> {
        let args = cmdline
            .map(std::string::ToString::to_string)
            .unwrap_or_else(String::new);

        Ok(CmdlineConfig { args })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiskConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub iommu: bool,
}

impl DiskConfig {
    pub fn parse(disk: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = disk.split(',').collect();

        let mut path_str: &str = "";
        let mut iommu_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("path=") {
                path_str = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            }
        }

        Ok(DiskConfig {
            path: PathBuf::from(path_str),
            iommu: parse_on_off(iommu_str)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetConfig {
    pub tap: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub mac: MacAddr,
    #[serde(default)]
    pub iommu: bool,
}

impl NetConfig {
    pub fn parse(net: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = net.split(',').collect();

        let mut tap_str: &str = "";
        let mut ip_str: &str = "";
        let mut mask_str: &str = "";
        let mut mac_str: &str = "";
        let mut iommu_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("tap=") {
                tap_str = &param[4..];
            } else if param.starts_with("ip=") {
                ip_str = &param[3..];
            } else if param.starts_with("mask=") {
                mask_str = &param[5..];
            } else if param.starts_with("mac=") {
                mac_str = &param[4..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            }
        }

        let mut ip: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 1);
        let mut mask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let mut mac: MacAddr = MacAddr::local_random();
        let iommu = parse_on_off(iommu_str)?;

        if !ip_str.is_empty() {
            ip = ip_str.parse().map_err(Error::ParseNetIpParam)?;
        }
        if !mask_str.is_empty() {
            mask = mask_str.parse().map_err(Error::ParseNetMaskParam)?;
        }
        if !mac_str.is_empty() {
            mac = MacAddr::parse_str(mac_str).map_err(Error::ParseNetMacParam)?;
        }

        Ok(NetConfig {
            tap: tap_str.to_string(),
            ip,
            mask,
            mac,
            iommu,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RngConfig {
    pub src: PathBuf,
    #[serde(default)]
    pub iommu: bool,
}

impl RngConfig {
    pub fn parse(rng: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = rng.split(',').collect();

        let mut src_str: &str = "";
        let mut iommu_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("src=") {
                src_str = &param[4..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            }
        }

        Ok(RngConfig {
            src: PathBuf::from(src_str),
            iommu: parse_on_off(iommu_str)?,
        })
    }
}

impl Default for RngConfig {
    fn default() -> Self {
        RngConfig {
            src: PathBuf::from(DEFAULT_RNG_SOURCE),
            iommu: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FsConfig {
    pub tag: String,
    pub sock: PathBuf,
    pub num_queues: usize,
    pub queue_size: u16,
    pub dax: bool,
    pub cache_size: u64,
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
        let mut cache_size: u64 = 0x0002_0000_0000;

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
            cache_size = 0;
        } else if !cache_size_str.is_empty() {
            cache_size = parse_size(cache_size_str)?;
        }

        Ok(FsConfig {
            tag: tag.to_string(),
            sock: PathBuf::from(sock),
            num_queues,
            queue_size,
            dax,
            cache_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PmemConfig {
    pub file: PathBuf,
    pub size: u64,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub mergeable: bool,
}

impl PmemConfig {
    pub fn parse(pmem: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = pmem.split(',').collect();

        let mut file_str: &str = "";
        let mut size_str: &str = "";
        let mut iommu_str: &str = "";
        let mut mergeable_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("file=") {
                file_str = &param[5..];
            } else if param.starts_with("size=") {
                size_str = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            } else if param.starts_with("mergeable=") {
                mergeable_str = &param[10..];
            }
        }

        if file_str.is_empty() {
            return Err(Error::ParsePmemFileParam);
        }

        Ok(PmemConfig {
            file: PathBuf::from(file_str),
            size: parse_size(size_str)?,
            iommu: parse_on_off(iommu_str)?,
            mergeable: parse_on_off(mergeable_str)?,
        })
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Clone, Deserialize, Serialize)]
pub struct ConsoleConfig {
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    #[serde(default)]
    pub iommu: bool,
}

impl ConsoleConfig {
    pub fn parse(console: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = console.split(',').collect();

        let mut valid = false;
        let mut file: Option<PathBuf> = None;
        let mut mode: ConsoleOutputMode = ConsoleOutputMode::Off;
        let mut iommu_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            } else {
                if *param == "off" {
                    mode = ConsoleOutputMode::Off;
                    file = None;
                } else if *param == "tty" {
                    mode = ConsoleOutputMode::Tty;
                    file = None;
                } else if param.starts_with("file=") {
                    mode = ConsoleOutputMode::File;
                    file = Some(PathBuf::from(&param[5..]));
                } else if param.starts_with("null") {
                    mode = ConsoleOutputMode::Null;
                    file = None;
                } else {
                    return Err(Error::ParseConsoleParam);
                }
                valid = true;
            }
        }

        if !valid {
            return Err(Error::ParseConsoleParam);
        }

        Ok(Self {
            mode,
            file,
            iommu: parse_on_off(iommu_str)?,
        })
    }

    pub fn default_serial() -> Self {
        ConsoleConfig {
            file: None,
            mode: ConsoleOutputMode::Null,
            iommu: false,
        }
    }

    pub fn default_console() -> Self {
        ConsoleConfig {
            file: None,
            mode: ConsoleOutputMode::Tty,
            iommu: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub iommu: bool,
}

impl DeviceConfig {
    pub fn parse(device: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = device.split(',').collect();

        let mut path_str: &str = "";
        let mut iommu_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("path=") {
                path_str = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            }
        }

        Ok(DeviceConfig {
            path: PathBuf::from(path_str),
            iommu: parse_on_off(iommu_str)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VuConfig {
    pub sock: String,
    pub num_queues: usize,
    pub queue_size: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VhostUserNetConfig {
    pub mac: MacAddr,
    pub vu_cfg: VuConfig,
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

        let vu_cfg = VuConfig {
            sock: sock.to_string(),
            num_queues,
            queue_size,
        };

        Ok(VhostUserNetConfig { mac, vu_cfg })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VsockConfig {
    pub cid: u64,
    pub sock: PathBuf,
    #[serde(default)]
    pub iommu: bool,
}

impl VsockConfig {
    pub fn parse(vsock: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = vsock.split(',').collect();

        let mut cid_str: &str = "";
        let mut sock_str: &str = "";
        let mut iommu_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("cid=") {
                cid_str = &param[4..];
            } else if param.starts_with("sock=") {
                sock_str = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            }
        }

        if sock_str.is_empty() {
            return Err(Error::ParseVsockSockParam);
        }

        Ok(VsockConfig {
            cid: cid_str.parse::<u64>().map_err(Error::ParseVsockCidParam)?,
            sock: PathBuf::from(sock_str),
            iommu: parse_on_off(iommu_str)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VhostUserBlkConfig {
    pub wce: bool,
    pub vu_cfg: VuConfig,
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

        let vu_cfg = VuConfig {
            sock: sock.to_string(),
            num_queues,
            queue_size,
        };

        Ok(VhostUserBlkConfig { wce, vu_cfg })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VmConfig {
    #[serde(default)]
    pub cpus: CpusConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    pub kernel: Option<KernelConfig>,
    pub cmdline: CmdlineConfig,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    #[serde(default)]
    pub rng: RngConfig,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default = "ConsoleConfig::default_serial")]
    pub serial: ConsoleConfig,
    #[serde(default = "ConsoleConfig::default_console")]
    pub console: ConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub vhost_user_net: Option<Vec<VhostUserNetConfig>>,
    pub vhost_user_blk: Option<Vec<VhostUserBlkConfig>>,
    pub vsock: Option<Vec<VsockConfig>>,
    #[serde(default)]
    pub iommu: bool,
}

impl VmConfig {
    pub fn valid(&self) -> bool {
        self.kernel.is_some()
    }

    pub fn parse(vm_params: VmParams) -> Result<Self> {
        let mut iommu = false;

        let mut disks: Option<Vec<DiskConfig>> = None;
        if let Some(disk_list) = &vm_params.disks {
            let mut disk_config_list = Vec::new();
            for item in disk_list.iter() {
                let disk_config = DiskConfig::parse(item)?;
                if disk_config.iommu {
                    iommu = true;
                }
                disk_config_list.push(disk_config);
            }
            disks = Some(disk_config_list);
        }

        let mut net: Option<Vec<NetConfig>> = None;
        if let Some(net_list) = &vm_params.net {
            let mut net_config_list = Vec::new();
            for item in net_list.iter() {
                let net_config = NetConfig::parse(item)?;
                if net_config.iommu {
                    iommu = true;
                }
                net_config_list.push(net_config);
            }
            net = Some(net_config_list);
        }

        let rng = RngConfig::parse(vm_params.rng)?;
        if rng.iommu {
            iommu = true;
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
                let pmem_config = PmemConfig::parse(item)?;
                if pmem_config.iommu {
                    iommu = true;
                }
                pmem_config_list.push(pmem_config);
            }
            pmem = Some(pmem_config_list);
        }

        let console = ConsoleConfig::parse(vm_params.console)?;
        if console.iommu {
            iommu = true;
        }
        let serial = ConsoleConfig::parse(vm_params.serial)?;
        if console.mode == ConsoleOutputMode::Tty && serial.mode == ConsoleOutputMode::Tty {
            return Err(Error::ParseTTYParam);
        }

        let mut devices: Option<Vec<DeviceConfig>> = None;
        if let Some(device_list) = &vm_params.devices {
            let mut device_config_list = Vec::new();
            for item in device_list.iter() {
                let device_config = DeviceConfig::parse(item)?;
                if device_config.iommu {
                    iommu = true;
                }
                device_config_list.push(device_config);
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
                let vsock_config = VsockConfig::parse(item)?;
                if vsock_config.iommu {
                    iommu = true;
                }
                vsock_config_list.push(vsock_config);
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

        let mut kernel: Option<KernelConfig> = None;
        if let Some(k) = vm_params.kernel {
            kernel = Some(KernelConfig {
                path: PathBuf::from(k),
            });
        }

        Ok(VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory)?,
            kernel,
            cmdline: CmdlineConfig::parse(vm_params.cmdline)?,
            disks,
            net,
            rng,
            fs,
            pmem,
            serial,
            console,
            devices,
            vhost_user_net,
            vhost_user_blk,
            vsock,
            iommu,
        })
    }
}
