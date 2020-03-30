// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vm_virtio;

use clap::ArgMatches;
use net_util::MacAddr;
use std::collections::HashMap;
use std::convert::From;
use std::io;
use std::net::AddrParseError;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;

pub const DEFAULT_VCPUS: u8 = 1;
pub const DEFAULT_MEMORY_MB: u64 = 512;
pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";
pub const DEFAULT_NUM_QUEUES_VUNET: usize = 2;
pub const DEFAULT_QUEUE_SIZE_VUNET: u16 = 256;
pub const DEFAULT_NUM_QUEUES_VUBLK: usize = 1;
pub const DEFAULT_QUEUE_SIZE_VUBLK: u16 = 128;

/// Errors associated with VM configuration parameters.
#[derive(Debug)]
pub enum Error {
    /// Max is less than boot
    ParseCpusMaxLowerThanBoot,
    /// Failed parsing memory hotplug_method parameter.
    ParseMemoryHotplugMethodParam(ParseHotplugMethodError),
    /// Failed parsing memory file parameter.
    ParseMemoryFileParam,
    /// Failed parsing kernel parameters.
    ParseKernelParams,
    /// Failed parsing kernel command line parameters.
    ParseCmdlineParams,
    /// Failed parsing disks parameters.
    ParseDisksParams,
    /// Failed parsing disk queue number parameter.
    ParseDiskNumQueuesParam(std::num::ParseIntError),
    /// Failed parsing disk poll_queue parameter.
    ParseDiskPollQueueParam(std::str::ParseBoolError),
    /// Failed parsing disk queue size parameter.
    ParseDiskQueueSizeParam(std::num::ParseIntError),
    /// Failed to parse vhost parameters
    ParseDiskVhostParam(std::str::ParseBoolError),
    /// Failed parsing disk wce parameter.
    ParseDiskWceParam(std::str::ParseBoolError),
    /// Both socket and path specified
    ParseDiskSocketAndPath,
    /// Failed parsing random number generator parameters.
    ParseRngParams,
    /// Failed parsing network ip parameter.
    ParseNetIpParam(AddrParseError),
    /// Failed parsing network mask parameter.
    ParseNetMaskParam(AddrParseError),
    /// Failed parsing network mac parameter.
    ParseNetMacParam(io::Error),
    /// Failed parsing network queue number parameter.
    ParseNetNumQueuesParam(std::num::ParseIntError),
    /// Failed parsing network queue size parameter.
    ParseNetQueueSizeParam(std::num::ParseIntError),
    /// Failed to parse vhost parameters
    ParseNetVhostParam(std::str::ParseBoolError),
    /// Need a vhost socket
    ParseNetVhostSocketRequired,
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
    ParseVuNetMacParam(io::Error),
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
    /// Error parsing CPU options
    ParseCpus(OptionParserError),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Default)]
pub struct OptionParser {
    options: HashMap<String, OptionParserValue>,
}

struct OptionParserValue {
    value: Option<String>,
}

#[derive(Debug)]
pub enum OptionParserError {
    UnknownOption(String),
    InvalidSyntax(String),
    Conversion(String, String),
}

type OptionParserResult<T> = std::result::Result<T, OptionParserError>;

impl OptionParser {
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
        }
    }

    pub fn parse(&mut self, input: &str) -> OptionParserResult<()> {
        if input.trim().is_empty() {
            return Ok(());
        }

        let options_list: Vec<&str> = input.trim().split(',').collect();

        for option in options_list.iter() {
            let parts: Vec<&str> = option.split('=').collect();

            if parts.len() != 2 {
                return Err(OptionParserError::InvalidSyntax((*option).to_owned()));
            }

            match self.options.get_mut(parts[0]) {
                None => return Err(OptionParserError::UnknownOption(parts[0].to_owned())),
                Some(value) => {
                    value.value = Some(parts[1].trim().to_owned());
                }
            }
        }

        Ok(())
    }

    pub fn add(&mut self, option: &str) -> &mut Self {
        self.options
            .insert(option.to_owned(), OptionParserValue { value: None });

        self
    }

    pub fn get(&self, option: &str) -> Option<String> {
        self.options.get(option).and_then(|v| v.value.clone())
    }

    pub fn is_set(&self, option: &str) -> bool {
        self.options
            .get(option)
            .and_then(|v| v.value.as_ref())
            .is_some()
    }

    pub fn convert<T: FromStr>(&self, option: &str) -> OptionParserResult<Option<T>> {
        match self.options.get(option).and_then(|v| v.value.as_ref()) {
            None => Ok(None),
            Some(v) => Ok(Some(v.parse().map_err(|_| {
                OptionParserError::Conversion(option.to_owned(), v.to_owned())
            })?)),
        }
    }
}

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub kernel: Option<&'a str>,
    pub initramfs: Option<&'a str>,
    pub cmdline: Option<&'a str>,
    pub disks: Option<Vec<&'a str>>,
    pub net: Option<Vec<&'a str>>,
    pub rng: &'a str,
    pub fs: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
    pub serial: &'a str,
    pub console: &'a str,
    pub devices: Option<Vec<&'a str>>,
    pub vsock: Option<Vec<&'a str>>,
}

impl<'a> VmParams<'a> {
    pub fn from_arg_matches(args: &'a ArgMatches) -> Self {
        // These .unwrap()s cannot fail as there is a default value defined
        let cpus = args.value_of("cpus").unwrap();
        let memory = args.value_of("memory").unwrap();
        let rng = args.value_of("rng").unwrap();
        let serial = args.value_of("serial").unwrap();

        let kernel = args.value_of("kernel");
        let initramfs = args.value_of("initramfs");
        let cmdline = args.value_of("cmdline");

        let disks: Option<Vec<&str>> = args.values_of("disk").map(|x| x.collect());
        let net: Option<Vec<&str>> = args.values_of("net").map(|x| x.collect());
        let console = args.value_of("console").unwrap();
        let fs: Option<Vec<&str>> = args.values_of("fs").map(|x| x.collect());
        let pmem: Option<Vec<&str>> = args.values_of("pmem").map(|x| x.collect());
        let devices: Option<Vec<&str>> = args.values_of("device").map(|x| x.collect());
        let vsock: Option<Vec<&str>> = args.values_of("vsock").map(|x| x.collect());

        VmParams {
            cpus,
            memory,
            kernel,
            initramfs,
            cmdline,
            disks,
            net,
            rng,
            fs,
            pmem,
            serial,
            console,
            devices,
            vsock,
        }
    }
}

struct Toggle(bool);

enum ToggleParseError {
    InvalidValue(String),
}

impl FromStr for Toggle {
    type Err = ToggleParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Toggle(parse_on_off(s).map_err(|_| {
            ToggleParseError::InvalidValue(s.to_owned())
        })?))
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum HotplugMethod {
    Acpi,
    VirtioMem,
}

impl Default for HotplugMethod {
    fn default() -> Self {
        HotplugMethod::Acpi
    }
}

#[derive(Debug)]
pub enum ParseHotplugMethodError {
    InvalidValue(String),
}

impl FromStr for HotplugMethod {
    type Err = ParseHotplugMethodError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "acpi" => Ok(HotplugMethod::Acpi),
            "virtio-mem" => Ok(HotplugMethod::VirtioMem),
            _ => Err(ParseHotplugMethodError::InvalidValue(s.to_owned())),
        }
    }
}

struct ByteSized(u64);

enum ByteSizedParseError {
    InvalidValue(String),
}

impl FromStr for ByteSized {
    type Err = ByteSizedParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(ByteSized(parse_size(s).map_err(|_| {
            ByteSizedParseError::InvalidValue(s.to_owned())
        })?))
    }
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CpusConfig {
    pub boot_vcpus: u8,
    pub max_vcpus: u8,
}

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("boot").add("max");
        parser.parse(cpus).map_err(Error::ParseCpus)?;

        let boot_vcpus: u8 = parser
            .convert("boot")
            .map_err(Error::ParseCpus)?
            .unwrap_or(DEFAULT_VCPUS);
        let max_vcpus: u8 = parser
            .convert("max")
            .map_err(Error::ParseCpus)?
            .unwrap_or(boot_vcpus);

        if max_vcpus < boot_vcpus {
            return Err(Error::ParseCpusMaxLowerThanBoot);
        }

        Ok(CpusConfig {
            boot_vcpus,
            max_vcpus,
        })
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct MemoryConfig {
    pub size: u64,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub hotplug_method: HotplugMethod,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
}

impl MemoryConfig {
    pub fn parse(memory: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = memory.split(',').collect();

        let mut size_str: &str = "512M";
        let mut file_str: &str = "";
        let mut mergeable_str: &str = "";
        let mut backed = false;
        let mut hotplug_method_str: &str = "acpi";
        let mut hotplug_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("size=") {
                size_str = &param[5..];
            } else if param.starts_with("file=") {
                backed = true;
                file_str = &param[5..];
            } else if param.starts_with("mergeable=") {
                mergeable_str = &param[10..];
            } else if param.starts_with("hotplug_method=") {
                hotplug_method_str = &param[15..];
            } else if param.starts_with("hotplug_size=") {
                hotplug_str = &param[13..]
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

        let hotplug_method = hotplug_method_str[..]
            .parse()
            .map_err(Error::ParseMemoryHotplugMethodParam)?;

        Ok(MemoryConfig {
            size: parse_size(size_str)?,
            file,
            mergeable: parse_on_off(mergeable_str)?,
            hotplug_method,
            hotplug_size: if hotplug_str == "" {
                None
            } else {
                Some(parse_size(hotplug_str)?)
            },
        })
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            size: DEFAULT_MEMORY_MB << 20,
            file: None,
            mergeable: false,
            hotplug_method: HotplugMethod::Acpi,
            hotplug_size: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct KernelConfig {
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct InitramfsConfig {
    pub path: PathBuf,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DiskConfig {
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_diskconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_diskconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default = "default_diskconfig_wce")]
    pub wce: bool,
    #[serde(default = "default_diskconfig_poll_queue")]
    pub poll_queue: bool,
}

fn default_diskconfig_num_queues() -> usize {
    DEFAULT_NUM_QUEUES_VUBLK
}

fn default_diskconfig_queue_size() -> u16 {
    DEFAULT_QUEUE_SIZE_VUBLK
}

fn default_diskconfig_wce() -> bool {
    true
}

fn default_diskconfig_poll_queue() -> bool {
    true
}

impl DiskConfig {
    pub const SYNTAX: &'static str = "Disk parameters \
         \"path=<disk_image_path>,readonly=on|off,iommu=on|off,num_queues=<number_of_queues>,\
         queue_size=<size_of_each_queue>,vhost_user=<vhost_user_enable>,\
         socket=<vhost_user_socket_path>,wce=<true|false, default true>\"";

    pub fn parse(disk: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = disk.split(',').collect();

        let mut path_str: &str = "";
        let mut readonly_str: &str = "";
        let mut direct_str: &str = "";
        let mut iommu_str: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";
        let mut vhost_socket_str: &str = "";
        let mut vhost_user_str: &str = "";
        let mut wce_str: &str = "";
        let mut poll_queue_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("path=") {
                path_str = &param[5..];
            } else if param.starts_with("readonly=") {
                readonly_str = &param[9..];
            } else if param.starts_with("direct=") {
                direct_str = &param[7..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            } else if param.starts_with("vhost_user=") {
                vhost_user_str = &param[11..];
            } else if param.starts_with("socket=") {
                vhost_socket_str = &param[7..];
            } else if param.starts_with("wce=") {
                wce_str = &param[4..];
            } else if param.starts_with("poll_queue=") {
                poll_queue_str = &param[11..];
            }
        }

        let mut num_queues: usize = default_diskconfig_num_queues();
        let mut queue_size: u16 = default_diskconfig_queue_size();
        let mut vhost_user = false;
        let mut vhost_socket = None;
        let mut wce: bool = default_diskconfig_wce();
        let mut poll_queue: bool = default_diskconfig_poll_queue();
        let mut path = None;

        if !num_queues_str.is_empty() {
            num_queues = num_queues_str
                .parse()
                .map_err(Error::ParseDiskNumQueuesParam)?;
        }
        if !queue_size_str.is_empty() {
            queue_size = queue_size_str
                .parse()
                .map_err(Error::ParseDiskQueueSizeParam)?;
        }
        if !vhost_user_str.is_empty() {
            vhost_user = vhost_user_str.parse().map_err(Error::ParseDiskVhostParam)?;
        }
        if !vhost_socket_str.is_empty() {
            vhost_socket = Some(vhost_socket_str.to_owned());
        }
        if !wce_str.is_empty() {
            if !vhost_user {
                warn!("wce parameter currently only has effect when used vhost_user=true");
            }
            wce = wce_str.parse().map_err(Error::ParseDiskWceParam)?;
        }
        if !poll_queue_str.is_empty() {
            if !vhost_user {
                warn!("poll_queue parameter currently only has effect when used vhost_user=true");
            }
            poll_queue = poll_queue_str
                .parse()
                .map_err(Error::ParseDiskPollQueueParam)?;
        }
        if !path_str.is_empty() {
            path = Some(PathBuf::from(path_str))
        }

        if vhost_socket.as_ref().and(path.as_ref()).is_some() {
            return Err(Error::ParseDiskSocketAndPath);
        }

        Ok(DiskConfig {
            path,
            readonly: parse_on_off(readonly_str)?,
            direct: parse_on_off(direct_str)?,
            iommu: parse_on_off(iommu_str)?,
            num_queues,
            queue_size,
            vhost_socket,
            vhost_user,
            wce,
            poll_queue,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct NetConfig {
    #[serde(default = "default_netconfig_tap")]
    pub tap: Option<String>,
    #[serde(default = "default_netconfig_ip")]
    pub ip: Ipv4Addr,
    #[serde(default = "default_netconfig_mask")]
    pub mask: Ipv4Addr,
    #[serde(default = "default_netconfig_mac")]
    pub mac: MacAddr,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_netconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_netconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
}

fn default_netconfig_tap() -> Option<String> {
    None
}

fn default_netconfig_ip() -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 249, 1)
}

fn default_netconfig_mask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}

fn default_netconfig_mac() -> MacAddr {
    MacAddr::local_random()
}

fn default_netconfig_num_queues() -> usize {
    DEFAULT_NUM_QUEUES_VUNET
}

fn default_netconfig_queue_size() -> u16 {
    DEFAULT_QUEUE_SIZE_VUNET
}

impl NetConfig {
    pub const SYNTAX: &'static str = "Network parameters \
    \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,iommu=on|off,\
    num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\
    vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>\"";

    pub fn parse(net: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = net.split(',').collect();

        let mut tap_str: &str = "";
        let mut ip_str: &str = "";
        let mut mask_str: &str = "";
        let mut mac_str: &str = "";
        let mut iommu_str: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";
        let mut vhost_socket_str: &str = "";
        let mut vhost_user_str: &str = "";

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
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            } else if param.starts_with("vhost_user=") {
                vhost_user_str = &param[11..];
            } else if param.starts_with("socket=") {
                vhost_socket_str = &param[7..];
            }
        }

        let mut tap: Option<String> = default_netconfig_tap();
        let mut ip: Ipv4Addr = default_netconfig_ip();
        let mut mask: Ipv4Addr = default_netconfig_mask();
        let mut mac: MacAddr = default_netconfig_mac();
        let iommu = parse_on_off(iommu_str)?;
        let mut num_queues: usize = default_netconfig_num_queues();
        let mut queue_size: u16 = default_netconfig_queue_size();
        let mut vhost_user = false;
        let mut vhost_socket = None;

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
        if !num_queues_str.is_empty() {
            num_queues = num_queues_str
                .parse()
                .map_err(Error::ParseNetNumQueuesParam)?;
        }
        if !queue_size_str.is_empty() {
            queue_size = queue_size_str
                .parse()
                .map_err(Error::ParseNetQueueSizeParam)?;
        }
        if !vhost_user_str.is_empty() {
            vhost_user = vhost_user_str.parse().map_err(Error::ParseNetVhostParam)?;
        }
        if !vhost_socket_str.is_empty() {
            vhost_socket = Some(vhost_socket_str.to_owned());
        }

        Ok(NetConfig {
            tap,
            ip,
            mask,
            mac,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct FsConfig {
    pub tag: String,
    pub sock: PathBuf,
    #[serde(default = "default_fsconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_fsconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default = "default_fsconfig_dax")]
    pub dax: bool,
    #[serde(default = "default_fsconfig_cache_size")]
    pub cache_size: u64,
}

fn default_fsconfig_num_queues() -> usize {
    1
}

fn default_fsconfig_queue_size() -> u16 {
    1024
}

fn default_fsconfig_dax() -> bool {
    true
}

fn default_fsconfig_cache_size() -> u64 {
    0x0002_0000_0000
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

        let mut num_queues: usize = default_fsconfig_num_queues();
        let mut queue_size: u16 = default_fsconfig_queue_size();
        let mut dax: bool = default_fsconfig_dax();
        // Default cache size set to 8Gib.
        let mut cache_size: u64 = default_fsconfig_cache_size();

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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct PmemConfig {
    pub file: PathBuf,
    pub size: u64,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub discard_writes: bool,
}

impl PmemConfig {
    pub const SYNTAX: &'static str = "Persistent memory parameters \
    \"file=<backing_file_path>,size=<persistent_memory_size>,iommu=on|off,\
    mergeable=on|off,discard_writes=on|off,\"";
    pub fn parse(pmem: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = pmem.split(',').collect();

        let mut file_str: &str = "";
        let mut size_str: &str = "";
        let mut iommu_str: &str = "";
        let mut mergeable_str: &str = "";
        let mut discard_writes_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("file=") {
                file_str = &param[5..];
            } else if param.starts_with("size=") {
                size_str = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            } else if param.starts_with("mergeable=") {
                mergeable_str = &param[10..];
            } else if param.starts_with("discard_writes=") {
                discard_writes_str = &param[15..];
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
            discard_writes: parse_on_off(discard_writes_str)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ConsoleConfig {
    #[serde(default = "default_consoleconfig_file")]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    #[serde(default)]
    pub iommu: bool,
}

fn default_consoleconfig_file() -> Option<PathBuf> {
    None
}

impl ConsoleConfig {
    pub fn parse(console: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = console.split(',').collect();

        let mut valid = false;
        let mut file: Option<PathBuf> = default_consoleconfig_file();
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DeviceConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
}

impl DeviceConfig {
    pub const SYNTAX: &'static str =
        "Direct device assignment parameters \"path=<device_path>,iommu=on|off,id=<device_id>\"";
    pub fn parse(device: &str) -> Result<Self> {
        // Split the parameters based on the comma delimiter
        let params_list: Vec<&str> = device.split(',').collect();

        let mut path_str: &str = "";
        let mut iommu_str: &str = "";
        let mut id_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("path=") {
                path_str = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu_str = &param[6..];
            } else if param.starts_with("id=") {
                id_str = &param[3..];
            }
        }

        let id = if !id_str.is_empty() {
            Some(String::from(id_str))
        } else {
            None
        };

        Ok(DeviceConfig {
            path: PathBuf::from(path_str),
            iommu: parse_on_off(iommu_str)?,
            id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct VmConfig {
    #[serde(default)]
    pub cpus: CpusConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    pub kernel: Option<KernelConfig>,
    pub initramfs: Option<InitramfsConfig>,
    #[serde(default)]
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

        let mut kernel: Option<KernelConfig> = None;
        if let Some(k) = vm_params.kernel {
            kernel = Some(KernelConfig {
                path: PathBuf::from(k),
            });
        }

        let mut initramfs: Option<InitramfsConfig> = None;
        if let Some(k) = vm_params.initramfs {
            initramfs = Some(InitramfsConfig {
                path: PathBuf::from(k),
            });
        }

        Ok(VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory)?,
            kernel,
            initramfs,
            cmdline: CmdlineConfig::parse(vm_params.cmdline)?,
            disks,
            net,
            rng,
            fs,
            pmem,
            serial,
            console,
            devices,
            vsock,
            iommu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_parser() -> std::result::Result<(), OptionParserError> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size");

        assert!(parser
            .parse("size=128M,file=/dev/shm,hanging_param")
            .is_err());
        assert!(parser
            .parse("size=128M,file=/dev/shm,too_many_equals=foo=bar")
            .is_err());
        assert!(parser.parse("size=128M,file=/dev/shm").is_ok());

        assert_eq!(parser.get("size"), Some("128M".to_owned()));
        assert_eq!(parser.get("file"), Some("/dev/shm".to_owned()));
        assert!(!parser.is_set("mergeable"));
        assert!(parser.is_set("size"));
        Ok(())
    }

    #[test]
    fn test_cpu_parsing() -> Result<()> {
        assert_eq!(CpusConfig::parse("")?, CpusConfig::default());

        assert_eq!(
            CpusConfig::parse("boot=1")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=1,max=2")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 2,
            }
        );
        assert!(CpusConfig::parse("boot=2,max=1").is_err());
        Ok(())
    }

    #[test]
    fn test_mem_parsing() -> Result<()> {
        assert_eq!(MemoryConfig::parse("")?, MemoryConfig::default());
        // Default string
        assert_eq!(MemoryConfig::parse("size=512M")?, MemoryConfig::default());
        assert_eq!(
            MemoryConfig::parse("size=512M,file=/some/file")?,
            MemoryConfig {
                size: 512 << 20,
                file: Some(PathBuf::from("/some/file")),
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("size=512M,mergeable=on")?,
            MemoryConfig {
                size: 512 << 20,
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("mergeable=on")?,
            MemoryConfig {
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("size=1G,mergeable=off")?,
            MemoryConfig {
                size: 1 << 30,
                mergeable: false,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi")?,
            MemoryConfig {
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi,hotplug_size=512M")?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=virtio-mem,hotplug_size=512M")?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                hotplug_method: HotplugMethod::VirtioMem,
                ..Default::default()
            }
        );
        Ok(())
    }
}
