// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vm_virtio;

use clap::ArgMatches;
use net_util::MacAddr;
use std::collections::HashMap;
use std::convert::From;
use std::fmt;
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
    /// Both socket and path specified
    ParseDiskSocketAndPath,
    /// Filesystem tag is missing
    ParseFsTagMissing,
    /// Filesystem socket is missing
    ParseFsSockMissing,
    /// Cannot have dax=off along with cache_size parameter.
    InvalidCacheSizeWithDaxOff,
    /// Missing persistant memory file parameter.
    ParsePmemFileMissing,
    /// Missing persistant memory size parameter.
    ParsePmemSizeMissing,
    /// Both console and serial are tty.
    ParseTTYParam,
    /// Missing vsock socket path parameter.
    ParseVsockSockMissing,
    /// Missing vsock cid parameter.
    ParseVsockCidMissing,
    /// Error parsing CPU options
    ParseCpus(OptionParserError),
    /// Error parsing memory options
    ParseMemory(OptionParserError),
    /// Error parsing disk options
    ParseDisk(OptionParserError),
    /// Error parsing network options
    ParseNetwork(OptionParserError),
    /// Error parsing RNG options
    ParseRNG(OptionParserError),
    /// Error parsing filesystem parameters
    ParseFileSystem(OptionParserError),
    /// Error parsing persistent memorry parameters
    ParsePersistentMemory(OptionParserError),
    /// Failed parsing console
    ParseConsole(OptionParserError),
    /// Missing file value for console
    ParseConsoleFileMissing,
    /// No mode given for console
    ParseConsoleInvalidModeGiven,
    /// Failed parsing device parameters
    ParseDevice(OptionParserError),
    /// Missing path from device,
    ParseDevicePathMissing,
    /// Failed to parse vsock parameters
    ParseVsock(OptionParserError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            ParseConsole(o) => write!(f, "Error parsing --console: {}", o),
            ParseConsoleFileMissing => {
                write!(f, "Error parsing --console: path missing when using file")
            }
            ParseConsoleInvalidModeGiven => {
                write!(f, "Error parsing --console: invalid console mode given")
            }
            ParseCpus(o) => write!(f, "Error parsing --cpus: {}", o),
            ParseCpusMaxLowerThanBoot => {
                write!(f, "Error parsing --cpus: max CPUs greater than boot CPUs")
            }
            ParseDevice(o) => write!(f, "Error parsing --device: {}", o),
            ParseDevicePathMissing => write!(f, "Error parsing --device: path missing"),
            ParseDiskSocketAndPath => write!(
                f,
                "Error parsing --disk: vhost socket and disk path both provided"
            ),
            ParseFileSystem(o) => write!(f, "Error parsing --fs: {}", o),
            ParseFsSockMissing => write!(f, "Error parsing --fs: sock missing"),
            ParseFsTagMissing => write!(f, "Error parsing --fs: tag missing"),
            InvalidCacheSizeWithDaxOff => {
                write!(f, "Error parsing --fs: cache_size used with dax=on")
            }
            ParsePersistentMemory(o) => write!(f, "Error parsing --pmem: {}", o),
            ParsePmemFileMissing => write!(f, "Error parsing --pmem: file missing"),
            ParsePmemSizeMissing => write!(f, "Error parsing --pmem: size missing"),
            ParseTTYParam => write!(
                f,
                "Console mode tty specified for both --serial and --console"
            ),
            ParseVsock(o) => write!(f, "Error parsing --vsock: {}", o),
            ParseVsockCidMissing => write!(f, "Error parsing --vsock: cid missing"),
            ParseVsockSockMissing => write!(f, "Error parsing --vsock: sock missing"),
            ParseMemory(o) => write!(f, "Error parsing --memory: {}", o),
            ParseNetwork(o) => write!(f, "Error parsing --net: {}", o),
            ParseDisk(o) => write!(f, "Error parsing --disk: {}", o),
            ParseRNG(o) => write!(f, "Error parsing --rng: {}", o),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Default)]
pub struct OptionParser {
    options: HashMap<String, OptionParserValue>,
}

struct OptionParserValue {
    value: Option<String>,
    requires_value: bool,
}

#[derive(Debug)]
pub enum OptionParserError {
    UnknownOption(String),
    InvalidSyntax(String),
    Conversion(String, String),
}

impl fmt::Display for OptionParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OptionParserError::UnknownOption(s) => write!(f, "unknown option: {}", s),
            OptionParserError::InvalidSyntax(s) => write!(f, "invalid syntax:{}", s),
            OptionParserError::Conversion(field, value) => {
                write!(f, "unable to parse {} for {}", value, field)
            }
        }
    }
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

            match self.options.get_mut(parts[0]) {
                None => return Err(OptionParserError::UnknownOption(parts[0].to_owned())),
                Some(value) => {
                    if value.requires_value {
                        if parts.len() != 2 {
                            return Err(OptionParserError::InvalidSyntax((*option).to_owned()));
                        }
                        value.value = Some(parts[1].trim().to_owned());
                    } else {
                        value.value = Some(String::new());
                    }
                }
            }
        }

        Ok(())
    }

    pub fn add(&mut self, option: &str) -> &mut Self {
        self.options.insert(
            option.to_owned(),
            OptionParserValue {
                value: None,
                requires_value: true,
            },
        );

        self
    }

    pub fn add_valueless(&mut self, option: &str) -> &mut Self {
        self.options.insert(
            option.to_owned(),
            OptionParserValue {
                value: None,
                requires_value: false,
            },
        );

        self
    }

    pub fn get(&self, option: &str) -> Option<String> {
        self.options
            .get(option)
            .and_then(|v| v.value.clone())
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
    }

    pub fn is_set(&self, option: &str) -> bool {
        self.options
            .get(option)
            .and_then(|v| v.value.as_ref())
            .is_some()
    }

    pub fn convert<T: FromStr>(&self, option: &str) -> OptionParserResult<Option<T>> {
        match self.get(option) {
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
        match s.to_lowercase().as_str() {
            "" => Ok(Toggle(false)),
            "on" => Ok(Toggle(true)),
            "off" => Ok(Toggle(false)),
            "true" => Ok(Toggle(true)),
            "false" => Ok(Toggle(false)),
            _ => Err(ToggleParseError::InvalidValue(s.to_owned())),
        }
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
        Ok(ByteSized({
            let s = s.trim();
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
            s.parse::<u64>()
                .map_err(|_| ByteSizedParseError::InvalidValue(s.to_owned()))?
                << shift
        }))
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
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size");
        parser.parse(memory).map_err(Error::ParseMemory)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseMemory)?
            .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
            .0;
        let file = parser.get("file").map(PathBuf::from);
        let mergeable = parser
            .convert::<Toggle>("mergeable")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let hotplug_method = parser
            .convert("hotplug_method")
            .map_err(Error::ParseMemory)?
            .unwrap_or_default();
        let hotplug_size = parser
            .convert::<ByteSized>("hotplug_size")
            .map_err(Error::ParseMemory)?
            .map(|v| v.0);

        Ok(MemoryConfig {
            size,
            file,
            mergeable,
            hotplug_method,
            hotplug_size,
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

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            path: None,
            readonly: false,
            direct: false,
            iommu: false,
            num_queues: default_diskconfig_num_queues(),
            queue_size: default_diskconfig_queue_size(),
            vhost_user: false,
            vhost_socket: None,
            wce: default_diskconfig_wce(),
            poll_queue: default_diskconfig_poll_queue(),
        }
    }
}

impl DiskConfig {
    pub const SYNTAX: &'static str = "Disk parameters \
         \"path=<disk_image_path>,readonly=on|off,iommu=on|off,num_queues=<number_of_queues>,\
         queue_size=<size_of_each_queue>,vhost_user=<vhost_user_enable>,\
         socket=<vhost_user_socket_path>,wce=<true|false, default true>\"";

    pub fn parse(disk: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("readonly")
            .add("direct")
            .add("iommu")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket")
            .add("wce")
            .add("poll_queue");
        parser.parse(disk).map_err(Error::ParseDisk)?;

        let path = parser.get("path").map(PathBuf::from);
        let readonly = parser
            .convert::<Toggle>("readonly")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let direct = parser
            .convert::<Toggle>("direct")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(default_diskconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(default_diskconfig_num_queues);
        let vhost_user = parser
            .convert("vhost_user")
            .map_err(Error::ParseDisk)?
            .unwrap_or(false);
        let vhost_socket = parser.get("socket");
        let wce = parser
            .convert("wce")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(default_diskconfig_wce);
        let poll_queue = parser
            .convert("poll_queue")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(default_diskconfig_poll_queue);

        if parser.is_set("wce") && !vhost_user {
            warn!("wce parameter currently only has effect when used vhost_user=true");
        }

        if parser.is_set("poll_queue") && !vhost_user {
            warn!("poll_queue parameter currently only has effect when used vhost_user=true");
        }

        if vhost_socket.as_ref().and(path.as_ref()).is_some() {
            return Err(Error::ParseDiskSocketAndPath);
        }

        Ok(DiskConfig {
            path,
            readonly,
            direct,
            iommu,
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

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            tap: default_netconfig_tap(),
            ip: default_netconfig_ip(),
            mask: default_netconfig_mask(),
            mac: default_netconfig_mac(),
            iommu: false,
            num_queues: default_netconfig_num_queues(),
            queue_size: default_netconfig_queue_size(),
            vhost_user: false,
            vhost_socket: None,
        }
    }
}

impl NetConfig {
    pub const SYNTAX: &'static str = "Network parameters \
    \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,iommu=on|off,\
    num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\
    vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>\"";

    pub fn parse(net: &str) -> Result<Self> {
        let mut parser = OptionParser::new();

        parser
            .add("tap")
            .add("ip")
            .add("mask")
            .add("mac")
            .add("iommu")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket");
        parser.parse(net).map_err(Error::ParseNetwork)?;

        let tap = parser.get("tap");
        let ip = parser
            .convert("ip")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_ip);
        let mask = parser
            .convert("mask")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_mask);
        let mac = parser
            .convert("mac")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_mac);
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(false))
            .0;
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_num_queues);
        let vhost_user = parser
            .convert("vhost_user")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(false);
        let vhost_socket = parser.get("socket");

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
        let mut parser = OptionParser::new();
        parser.add("src").add("iommu");
        parser.parse(rng).map_err(Error::ParseRNG)?;

        let src = PathBuf::from(
            parser
                .get("src")
                .unwrap_or_else(|| DEFAULT_RNG_SOURCE.to_owned()),
        );
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseRNG)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(RngConfig { src, iommu })
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

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            tag: "".to_owned(),
            sock: PathBuf::new(),
            num_queues: default_fsconfig_num_queues(),
            queue_size: default_fsconfig_queue_size(),
            dax: default_fsconfig_dax(),
            cache_size: default_fsconfig_cache_size(),
        }
    }
}

impl FsConfig {
    pub fn parse(fs: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("tag")
            .add("dax")
            .add("cache_size")
            .add("queue_size")
            .add("num_queues")
            .add("sock");
        parser.parse(fs).map_err(Error::ParseFileSystem)?;

        let tag = parser.get("tag").ok_or(Error::ParseFsTagMissing)?;
        let sock = PathBuf::from(parser.get("sock").ok_or(Error::ParseFsSockMissing)?);

        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_num_queues);

        let dax = parser
            .convert::<Toggle>("dax")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(|| Toggle(default_fsconfig_dax()))
            .0;

        if parser.is_set("cache_size") && !dax {
            return Err(Error::InvalidCacheSizeWithDaxOff);
        }

        let cache_size = parser
            .convert::<ByteSized>("cache_size")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(|| ByteSized(default_fsconfig_cache_size()))
            .0;

        Ok(FsConfig {
            tag,
            sock,
            num_queues,
            queue_size,
            dax,
            cache_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
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
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("iommu")
            .add("discard_writes");
        parser.parse(pmem).map_err(Error::ParsePersistentMemory)?;

        let file = PathBuf::from(parser.get("file").ok_or(Error::ParsePmemFileMissing)?);
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseMemory)?
            .ok_or(Error::ParsePmemSizeMissing)?
            .0;
        let mergeable = parser
            .convert::<Toggle>("mergeable")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let discard_writes = parser
            .convert::<Toggle>("discard_writes")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(PmemConfig {
            file,
            size,
            iommu,
            mergeable,
            discard_writes,
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
        let mut parser = OptionParser::new();
        parser
            .add_valueless("off")
            .add_valueless("tty")
            .add_valueless("null")
            .add("file")
            .add("iommu");
        parser.parse(console).map_err(Error::ParseConsole)?;

        let mut file: Option<PathBuf> = default_consoleconfig_file();
        let mut mode: ConsoleOutputMode = ConsoleOutputMode::Off;

        if parser.is_set("off") {
        } else if parser.is_set("tty") {
            mode = ConsoleOutputMode::Tty
        } else if parser.is_set("null") {
            mode = ConsoleOutputMode::Null
        } else if parser.is_set("file") {
            mode = ConsoleOutputMode::File;
            file = Some(PathBuf::from(
                parser.get("file").ok_or(Error::ParseConsoleFileMissing)?,
            ));
        } else {
            return Err(Error::ParseConsoleInvalidModeGiven);
        }
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseConsole)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(Self { mode, file, iommu })
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
        let mut parser = OptionParser::new();
        parser.add("path").add("id").add("iommu");
        parser.parse(device).map_err(Error::ParseDevice)?;

        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(Error::ParseDevicePathMissing)?;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseDevice)?
            .unwrap_or(Toggle(false))
            .0;
        let id = parser.get("id");
        Ok(DeviceConfig { path, iommu, id })
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
        let mut parser = OptionParser::new();
        parser.add("sock").add("cid").add("iommu");
        parser.parse(vsock).map_err(Error::ParseVsock)?;

        let sock = parser
            .get("sock")
            .map(PathBuf::from)
            .ok_or(Error::ParseVsockSockMissing)?;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseVsock)?
            .unwrap_or(Toggle(false))
            .0;
        let cid = parser
            .convert("cid")
            .map_err(Error::ParseVsock)?
            .ok_or(Error::ParseVsockCidMissing)?;

        Ok(VsockConfig { cid, sock, iommu })
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

    #[test]
    fn test_disk_parsing() -> Result<()> {
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,vhost_user=true")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                vhost_user: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                queue_size: 256,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256,num_queues=4")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                queue_size: 256,
                num_queues: 4,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,direct=on")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                direct: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,wce=true")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                wce: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,wce=false")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                wce: false,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,poll_queue=false")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                poll_queue: false,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,poll_queue=true")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                poll_queue: true,
                ..Default::default()
            }
        );
        assert!(DiskConfig::parse("path=/path/to_file,socket=/path/to_socket").is_err());

        Ok(())
    }

    #[test]
    fn test_net_parsing() -> Result<()> {
        // mac address is random
        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,tap=tap0,ip=192.168.100.1,mask=255.255.255.128"
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                tap: Some("tap0".to_owned()),
                ip: "192.168.100.1".parse().unwrap(),
                mask: "255.255.255.128".parse().unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,vhost_user=true,socket=/tmp/socket")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                vhost_user: true,
                vhost_socket: Some("/tmp/socket".to_owned()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,num_queues=4,queue_size=1024,iommu=on")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                num_queues: 4,
                queue_size: 1024,
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_rng() -> Result<()> {
        assert_eq!(RngConfig::parse("")?, RngConfig::default());
        assert_eq!(
            RngConfig::parse("src=/dev/random")?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                ..Default::default()
            }
        );
        assert_eq!(
            RngConfig::parse("src=/dev/random,iommu=on")?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                iommu: true,
            }
        );
        assert_eq!(
            RngConfig::parse("iommu=on")?,
            RngConfig {
                iommu: true,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_fs() -> Result<()> {
        // "tag" and "socket" must be supplied
        assert!(FsConfig::parse("").is_err());
        assert!(FsConfig::parse("tag=mytag").is_err());
        assert!(FsConfig::parse("sock=/tmp/sock").is_err());
        assert_eq!(
            FsConfig::parse("tag=mytag,sock=/tmp/sock")?,
            FsConfig {
                sock: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,sock=/tmp/sock")?,
            FsConfig {
                sock: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,sock=/tmp/sock,num_queues=4,queue_size=1024")?,
            FsConfig {
                sock: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                num_queues: 4,
                queue_size: 1024,
                ..Default::default()
            }
        );
        // DAX on -> default cache size
        assert_eq!(
            FsConfig::parse("tag=mytag,sock=/tmp/sock,dax=on")?,
            FsConfig {
                sock: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                dax: true,
                cache_size: default_fsconfig_cache_size(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,sock=/tmp/sock,dax=on,cache_size=4G")?,
            FsConfig {
                sock: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                dax: true,
                cache_size: 4 << 30,
                ..Default::default()
            }
        );
        // Cache size without DAX is an error
        assert!(FsConfig::parse("tag=mytag,sock=/tmp/sock,dax=off,cache_size=4G").is_err());
        Ok(())
    }

    #[test]
    fn test_pmem_parsing() -> Result<()> {
        // Must always give a file and size
        assert!(PmemConfig::parse("").is_err());
        assert!(PmemConfig::parse("file=/tmp/pmem").is_err());
        assert!(PmemConfig::parse("size=128M").is_err());
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: 128 << 20,
                ..Default::default()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,iommu=on,mergeable=on,discard_writes=on")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: 128 << 20,
                mergeable: true,
                discard_writes: true,
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_console_parsing() -> Result<()> {
        assert!(ConsoleConfig::parse("").is_err());
        assert!(ConsoleConfig::parse("badmode").is_err());
        assert_eq!(
            ConsoleConfig::parse("off")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Off,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("tty")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("null")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: false,
                file: Some(PathBuf::from("/tmp/console"))
            }
        );
        assert_eq!(
            ConsoleConfig::parse("null,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: true,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: true,
                file: Some(PathBuf::from("/tmp/console"))
            }
        );
        Ok(())
    }

    #[test]
    fn test_device_parsing() -> Result<()> {
        // Device must have a path provided
        assert!(DeviceConfig::parse("").is_err());
        assert_eq!(
            DeviceConfig::parse("path=/path/to/device")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: false
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: true
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on,id=mydevice0")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: Some("mydevice0".to_owned()),
                iommu: true
            }
        );

        Ok(())
    }

    #[test]
    fn test_vsock_parsing() -> Result<()> {
        // sock and cid is required
        assert!(VsockConfig::parse("").is_err());
        assert_eq!(
            VsockConfig::parse("sock=/tmp/sock,cid=1")?,
            VsockConfig {
                cid: 1,
                sock: PathBuf::from("/tmp/sock"),
                iommu: false
            }
        );
        assert_eq!(
            VsockConfig::parse("sock=/tmp/sock,cid=1,iommu=on")?,
            VsockConfig {
                cid: 1,
                sock: PathBuf::from("/tmp/sock"),
                iommu: true
            }
        );
        Ok(())
    }
}
