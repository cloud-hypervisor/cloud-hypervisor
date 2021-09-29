// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::ArgMatches;
use net_util::MacAddr;
use option_parser::{
    ByteSized, IntegerList, OptionParser, OptionParserError, StringList, Toggle, TupleTwoIntegers,
};
use std::collections::HashMap;
use std::convert::From;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;

use virtio_devices::{RateLimiterConfig, TokenBucketConfig};

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
    /// Filesystem tag is missing
    ParseFsTagMissing,
    /// Filesystem socket is missing
    ParseFsSockMissing,
    /// Cannot have dax=off along with cache_size parameter.
    InvalidCacheSizeWithDaxOff,
    /// Missing persistent memory file parameter.
    ParsePmemFileMissing,
    /// Missing vsock socket path parameter.
    ParseVsockSockMissing,
    /// Missing vsock cid parameter.
    ParseVsockCidMissing,
    /// Missing restore source_url parameter.
    ParseRestoreSourceUrlMissing,
    /// Error parsing CPU options
    ParseCpus(OptionParserError),
    /// Error parsing memory options
    ParseMemory(OptionParserError),
    /// Error parsing memory zone options
    ParseMemoryZone(OptionParserError),
    /// Missing 'id' from memory zone
    ParseMemoryZoneIdMissing,
    /// Error parsing disk options
    ParseDisk(OptionParserError),
    /// Error parsing network options
    ParseNetwork(OptionParserError),
    /// Error parsing RNG options
    ParseRng(OptionParserError),
    /// Error parsing balloon options
    ParseBalloon(OptionParserError),
    /// Error parsing filesystem parameters
    ParseFileSystem(OptionParserError),
    /// Error parsing persistent memory parameters
    ParsePersistentMemory(OptionParserError),
    /// Failed parsing console
    ParseConsole(OptionParserError),
    /// No mode given for console
    ParseConsoleInvalidModeGiven,
    /// Failed parsing device parameters
    ParseDevice(OptionParserError),
    /// Missing path from device,
    ParseDevicePathMissing,
    /// Failed to parse vsock parameters
    ParseVsock(OptionParserError),
    /// Failed to parse restore parameters
    ParseRestore(OptionParserError),
    /// Failed to parse SGX EPC parameters
    #[cfg(target_arch = "x86_64")]
    ParseSgxEpc(OptionParserError),
    /// Missing 'id' from SGX EPC section
    #[cfg(target_arch = "x86_64")]
    ParseSgxEpcIdMissing,
    /// Failed to parse NUMA parameters
    ParseNuma(OptionParserError),
    /// Failed to validate configuration
    Validation(ValidationError),
    #[cfg(feature = "tdx")]
    /// Failed to parse TDX config
    ParseTdx(OptionParserError),
    #[cfg(feature = "tdx")]
    // No TDX firmware
    FirmwarePathMissing,
    /// Failed to parse userspace device
    ParseUserDevice(OptionParserError),
    /// Missing socket for userspace device
    ParseUserDeviceSocketMissing,
}

#[derive(Debug)]
pub enum ValidationError {
    /// Both console and serial are tty.
    DoubleTtyMode,
    /// No kernel specified
    KernelMissing,
    /// Missing file value for console
    ConsoleFileMissing,
    /// Max is less than boot
    CpusMaxLowerThanBoot,
    /// Both socket and path specified
    DiskSocketAndPath,
    /// Using vhost user requires shared memory
    VhostUserRequiresSharedMemory,
    /// No socket provided for vhost_use
    VhostUserMissingSocket,
    /// Trying to use IOMMU without PCI
    IommuUnsupported,
    /// Trying to use VFIO without PCI
    VfioUnsupported,
    /// CPU topology count doesn't match max
    CpuTopologyCount,
    /// One part of the CPU topology was zero
    CpuTopologyZeroPart,
    /// Virtio needs a min of 2 queues
    VnetQueueLowerThan2,
    /// The input queue number for virtio_net must match the number of input fds
    VnetQueueFdMismatch,
    /// Using reserved fd
    VnetReservedFd,
    /// Hugepages not turned on
    HugePageSizeWithoutHugePages,
    /// Huge page size is not power of 2
    InvalidHugePageSize(u64),
    /// CPU Hotplug not permitted with TDX
    #[cfg(feature = "tdx")]
    TdxNoCpuHotplug,
    /// Specifying kernel not permitted with TDX
    #[cfg(feature = "tdx")]
    TdxKernelSpecified,
    /// Insuffient vCPUs for queues
    TooManyQueues,
    /// Need shared memory for vfio-user
    UserDevicesRequireSharedMemory,
    /// Memory zone is reused across NUMA nodes
    MemoryZoneReused(String, u32, u32),
}

type ValidationResult<T> = std::result::Result<T, ValidationError>;

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ValidationError::*;
        match self {
            DoubleTtyMode => write!(f, "Console mode tty specified for both serial and console"),
            KernelMissing => write!(f, "No kernel specified"),
            ConsoleFileMissing => write!(f, "Path missing when using file console mode"),
            CpusMaxLowerThanBoot => write!(f, "Max CPUs greater than boot CPUs"),
            DiskSocketAndPath => write!(f, "Disk path and vhost socket both provided"),
            VhostUserRequiresSharedMemory => {
                write!(f, "Using vhost-user requires using shared memory")
            }
            VhostUserMissingSocket => write!(f, "No socket provided when using vhost-user"),
            IommuUnsupported => write!(f, "Using an IOMMU without PCI support is unsupported"),
            VfioUnsupported => write!(f, "Using VFIO without PCI support is unsupported"),
            CpuTopologyZeroPart => write!(f, "No part of the CPU topology can be zero"),
            CpuTopologyCount => write!(
                f,
                "Product of CPU topology parts does not match maximum vCPUs"
            ),
            VnetQueueLowerThan2 => write!(f, "Number of queues to virtio_net less than 2"),
            VnetQueueFdMismatch => write!(
                f,
                "Number of queues to virtio_net does not match the number of input FDs"
            ),
            VnetReservedFd => write!(f, "Reserved fd number (<= 2)"),
            HugePageSizeWithoutHugePages => {
                write!(f, "Huge page size specified but huge pages not enabled")
            }
            InvalidHugePageSize(s) => {
                write!(f, "Huge page size is not power of 2: {}", s)
            }
            #[cfg(feature = "tdx")]
            TdxNoCpuHotplug => {
                write!(f, "CPU hotplug not possible with TDX")
            }
            #[cfg(feature = "tdx")]
            TdxKernelSpecified => {
                write!(f, "Direct kernel boot not possible with TDX")
            }
            TooManyQueues => {
                write!(f, "Number of vCPUs is insufficient for number of queues")
            }
            UserDevicesRequireSharedMemory => {
                write!(f, "Using user devices requires using shared memory")
            }
            MemoryZoneReused(s, u1, u2) => {
                write!(
                    f,
                    "Memory zone: {} belongs to multiple NUMA nodes {} and {}",
                    s, u1, u2
                )
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            ParseConsole(o) => write!(f, "Error parsing --console: {}", o),
            ParseConsoleInvalidModeGiven => {
                write!(f, "Error parsing --console: invalid console mode given")
            }
            ParseCpus(o) => write!(f, "Error parsing --cpus: {}", o),

            ParseDevice(o) => write!(f, "Error parsing --device: {}", o),
            ParseDevicePathMissing => write!(f, "Error parsing --device: path missing"),
            ParseFileSystem(o) => write!(f, "Error parsing --fs: {}", o),
            ParseFsSockMissing => write!(f, "Error parsing --fs: socket missing"),
            ParseFsTagMissing => write!(f, "Error parsing --fs: tag missing"),
            InvalidCacheSizeWithDaxOff => {
                write!(f, "Error parsing --fs: cache_size used with dax=on")
            }
            ParsePersistentMemory(o) => write!(f, "Error parsing --pmem: {}", o),
            ParsePmemFileMissing => write!(f, "Error parsing --pmem: file missing"),
            ParseVsock(o) => write!(f, "Error parsing --vsock: {}", o),
            ParseVsockCidMissing => write!(f, "Error parsing --vsock: cid missing"),
            ParseVsockSockMissing => write!(f, "Error parsing --vsock: socket missing"),
            ParseMemory(o) => write!(f, "Error parsing --memory: {}", o),
            ParseMemoryZone(o) => write!(f, "Error parsing --memory-zone: {}", o),
            ParseMemoryZoneIdMissing => write!(f, "Error parsing --memory-zone: id missing"),
            ParseNetwork(o) => write!(f, "Error parsing --net: {}", o),
            ParseDisk(o) => write!(f, "Error parsing --disk: {}", o),
            ParseRng(o) => write!(f, "Error parsing --rng: {}", o),
            ParseBalloon(o) => write!(f, "Error parsing --balloon: {}", o),
            ParseRestore(o) => write!(f, "Error parsing --restore: {}", o),
            #[cfg(target_arch = "x86_64")]
            ParseSgxEpc(o) => write!(f, "Error parsing --sgx-epc: {}", o),
            #[cfg(target_arch = "x86_64")]
            ParseSgxEpcIdMissing => write!(f, "Error parsing --sgx-epc: id missing"),
            ParseNuma(o) => write!(f, "Error parsing --numa: {}", o),
            ParseRestoreSourceUrlMissing => {
                write!(f, "Error parsing --restore: source_url missing")
            }
            ParseUserDeviceSocketMissing => {
                write!(f, "Error parsing --user-device: socket missing")
            }
            ParseUserDevice(o) => write!(f, "Error parsing --user-device: {}", o),
            Validation(v) => write!(f, "Error validating configuration: {}", v),
            #[cfg(feature = "tdx")]
            ParseTdx(o) => write!(f, "Error parsing --tdx: {}", o),
            #[cfg(feature = "tdx")]
            FirmwarePathMissing => write!(f, "TDX firmware missing"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub memory_zones: Option<Vec<&'a str>>,
    pub kernel: Option<&'a str>,
    pub initramfs: Option<&'a str>,
    pub cmdline: Option<&'a str>,
    pub disks: Option<Vec<&'a str>>,
    pub net: Option<Vec<&'a str>>,
    pub rng: &'a str,
    pub balloon: Option<&'a str>,
    pub fs: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
    pub serial: &'a str,
    pub console: &'a str,
    pub devices: Option<Vec<&'a str>>,
    pub user_devices: Option<Vec<&'a str>>,
    pub vsock: Option<&'a str>,
    #[cfg(target_arch = "x86_64")]
    pub sgx_epc: Option<Vec<&'a str>>,
    pub numa: Option<Vec<&'a str>>,
    pub watchdog: bool,
    #[cfg(feature = "tdx")]
    pub tdx: Option<&'a str>,
}

impl<'a> VmParams<'a> {
    pub fn from_arg_matches(args: &'a ArgMatches) -> Self {
        // These .unwrap()s cannot fail as there is a default value defined
        let cpus = args.value_of("cpus").unwrap();
        let memory = args.value_of("memory").unwrap();
        let memory_zones: Option<Vec<&str>> = args.values_of("memory-zone").map(|x| x.collect());
        let rng = args.value_of("rng").unwrap();
        let serial = args.value_of("serial").unwrap();

        let kernel = args.value_of("kernel");
        let initramfs = args.value_of("initramfs");
        let cmdline = args.value_of("cmdline");

        let disks: Option<Vec<&str>> = args.values_of("disk").map(|x| x.collect());
        let net: Option<Vec<&str>> = args.values_of("net").map(|x| x.collect());
        let console = args.value_of("console").unwrap();
        let balloon = args.value_of("balloon");
        let fs: Option<Vec<&str>> = args.values_of("fs").map(|x| x.collect());
        let pmem: Option<Vec<&str>> = args.values_of("pmem").map(|x| x.collect());
        let devices: Option<Vec<&str>> = args.values_of("device").map(|x| x.collect());
        let user_devices: Option<Vec<&str>> = args.values_of("user-device").map(|x| x.collect());
        let vsock: Option<&str> = args.value_of("vsock");
        #[cfg(target_arch = "x86_64")]
        let sgx_epc: Option<Vec<&str>> = args.values_of("sgx-epc").map(|x| x.collect());
        let numa: Option<Vec<&str>> = args.values_of("numa").map(|x| x.collect());
        let watchdog = args.is_present("watchdog");
        #[cfg(feature = "tdx")]
        let tdx = args.value_of("tdx");
        VmParams {
            cpus,
            memory,
            memory_zones,
            kernel,
            initramfs,
            cmdline,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            devices,
            user_devices,
            vsock,
            #[cfg(target_arch = "x86_64")]
            sgx_epc,
            numa,
            watchdog,
            #[cfg(feature = "tdx")]
            tdx,
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

pub enum CpuTopologyParseError {
    InvalidValue(String),
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CpuTopology {
    pub threads_per_core: u8,
    pub cores_per_die: u8,
    pub dies_per_package: u8,
    pub packages: u8,
}

impl FromStr for CpuTopology {
    type Err = CpuTopologyParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 4 {
            return Err(Self::Err::InvalidValue(s.to_owned()));
        }

        let t = CpuTopology {
            threads_per_core: parts[0]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            cores_per_die: parts[1]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            dies_per_package: parts[2]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            packages: parts[3]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
        };

        Ok(t)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CpusConfig {
    pub boot_vcpus: u8,
    pub max_vcpus: u8,
    #[serde(default)]
    pub topology: Option<CpuTopology>,
    #[serde(default)]
    pub kvm_hyperv: bool,
    #[serde(default)]
    pub max_phys_bits: Option<u8>,
}

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("boot")
            .add("max")
            .add("topology")
            .add("kvm_hyperv")
            .add("max_phys_bits");
        parser.parse(cpus).map_err(Error::ParseCpus)?;

        let boot_vcpus: u8 = parser
            .convert("boot")
            .map_err(Error::ParseCpus)?
            .unwrap_or(DEFAULT_VCPUS);
        let max_vcpus: u8 = parser
            .convert("max")
            .map_err(Error::ParseCpus)?
            .unwrap_or(boot_vcpus);
        let topology = parser.convert("topology").map_err(Error::ParseCpus)?;
        let kvm_hyperv = parser
            .convert::<Toggle>("kvm_hyperv")
            .map_err(Error::ParseCpus)?
            .unwrap_or(Toggle(false))
            .0;
        let max_phys_bits = parser
            .convert::<u8>("max_phys_bits")
            .map_err(Error::ParseCpus)?;

        Ok(CpusConfig {
            boot_vcpus,
            max_vcpus,
            topology,
            kvm_hyperv,
            max_phys_bits,
        })
    }
}

impl Default for CpusConfig {
    fn default() -> Self {
        CpusConfig {
            boot_vcpus: DEFAULT_VCPUS,
            max_vcpus: DEFAULT_VCPUS,
            topology: None,
            kvm_hyperv: false,
            max_phys_bits: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct MemoryZoneConfig {
    pub id: String,
    pub size: u64,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub host_numa_node: Option<u32>,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct MemoryConfig {
    pub size: u64,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub hotplug_method: HotplugMethod,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub zones: Option<Vec<MemoryZoneConfig>>,
}

impl MemoryConfig {
    pub fn parse(memory: &str, memory_zones: Option<Vec<&str>>) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size")
            .add("hotplugged_size")
            .add("shared")
            .add("hugepages")
            .add("hugepage_size")
            .add("prefault");
        parser.parse(memory).map_err(Error::ParseMemory)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseMemory)?
            .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
            .0;
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
        let hotplugged_size = parser
            .convert::<ByteSized>("hotplugged_size")
            .map_err(Error::ParseMemory)?
            .map(|v| v.0);
        let shared = parser
            .convert::<Toggle>("shared")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let hugepages = parser
            .convert::<Toggle>("hugepages")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let hugepage_size = parser
            .convert::<ByteSized>("hugepage_size")
            .map_err(Error::ParseMemory)?
            .map(|v| v.0);
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;

        let zones: Option<Vec<MemoryZoneConfig>> = if let Some(memory_zones) = &memory_zones {
            let mut zones = Vec::new();
            for memory_zone in memory_zones.iter() {
                let mut parser = OptionParser::new();
                parser
                    .add("id")
                    .add("size")
                    .add("file")
                    .add("shared")
                    .add("hugepages")
                    .add("hugepage_size")
                    .add("host_numa_node")
                    .add("hotplug_size")
                    .add("hotplugged_size")
                    .add("prefault");
                parser.parse(memory_zone).map_err(Error::ParseMemoryZone)?;

                let id = parser.get("id").ok_or(Error::ParseMemoryZoneIdMissing)?;
                let size = parser
                    .convert::<ByteSized>("size")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
                    .0;
                let file = parser.get("file").map(PathBuf::from);
                let shared = parser
                    .convert::<Toggle>("shared")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let hugepages = parser
                    .convert::<Toggle>("hugepages")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let hugepage_size = parser
                    .convert::<ByteSized>("hugepage_size")
                    .map_err(Error::ParseMemoryZone)?
                    .map(|v| v.0);

                let host_numa_node = parser
                    .convert::<u32>("host_numa_node")
                    .map_err(Error::ParseMemoryZone)?;
                let hotplug_size = parser
                    .convert::<ByteSized>("hotplug_size")
                    .map_err(Error::ParseMemoryZone)?
                    .map(|v| v.0);
                let hotplugged_size = parser
                    .convert::<ByteSized>("hotplugged_size")
                    .map_err(Error::ParseMemoryZone)?
                    .map(|v| v.0);
                let prefault = parser
                    .convert::<Toggle>("prefault")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(Toggle(false))
                    .0;

                zones.push(MemoryZoneConfig {
                    id,
                    size,
                    file,
                    shared,
                    hugepages,
                    hugepage_size,
                    host_numa_node,
                    hotplug_size,
                    hotplugged_size,
                    prefault,
                });
            }
            Some(zones)
        } else {
            None
        };

        Ok(MemoryConfig {
            size,
            mergeable,
            hotplug_method,
            hotplug_size,
            hotplugged_size,
            shared,
            hugepages,
            hugepage_size,
            prefault,
            zones,
        })
    }

    pub fn total_size(&self) -> u64 {
        let mut size = self.size;
        if let Some(hotplugged_size) = self.hotplugged_size {
            size += hotplugged_size;
        }

        if let Some(zones) = &self.zones {
            for zone in zones.iter() {
                size += zone.size;
                if let Some(hotplugged_size) = zone.hotplugged_size {
                    size += hotplugged_size;
                }
            }
        }

        size
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            size: DEFAULT_MEMORY_MB << 20,
            mergeable: false,
            hotplug_method: HotplugMethod::Acpi,
            hotplug_size: None,
            hotplugged_size: None,
            shared: false,
            hugepages: false,
            hugepage_size: None,
            prefault: false,
            zones: None,
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
    #[serde(default = "default_diskconfig_poll_queue")]
    pub poll_queue: bool,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default)]
    pub id: Option<String>,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_io_uring: bool,
}

fn default_diskconfig_num_queues() -> usize {
    DEFAULT_NUM_QUEUES_VUBLK
}

fn default_diskconfig_queue_size() -> u16 {
    DEFAULT_QUEUE_SIZE_VUBLK
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
            poll_queue: default_diskconfig_poll_queue(),
            id: None,
            disable_io_uring: false,
            rate_limiter_config: None,
        }
    }
}

impl DiskConfig {
    pub const SYNTAX: &'static str = "Disk parameters \
         \"path=<disk_image_path>,readonly=on|off,direct=on|off,iommu=on|off,\
         num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\
         vhost_user=on|off,socket=<vhost_user_socket_path>,poll_queue=on|off,\
         bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
         ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,\
         id=<device_id>\"";

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
            .add("poll_queue")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("id")
            .add("_disable_io_uring");
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
            .convert::<Toggle>("vhost_user")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let vhost_socket = parser.get("socket");
        let poll_queue = parser
            .convert::<Toggle>("poll_queue")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(|| Toggle(default_diskconfig_poll_queue()))
            .0;
        let id = parser.get("id");
        let disable_io_uring = parser
            .convert::<Toggle>("_disable_io_uring")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let bw_size = parser
            .convert("bw_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(Error::ParseDisk)?
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

        if parser.is_set("poll_queue") && !vhost_user {
            warn!("poll_queue parameter currently only has effect when used vhost_user=true");
        }

        Ok(DiskConfig {
            path,
            readonly,
            direct,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            poll_queue,
            rate_limiter_config,
            id,
            disable_io_uring,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum VhostMode {
    Client,
    Server,
}

impl Default for VhostMode {
    fn default() -> Self {
        VhostMode::Client
    }
}

#[derive(Debug)]
pub enum ParseVhostModeError {
    InvalidValue(String),
}

impl FromStr for VhostMode {
    type Err = ParseVhostModeError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "client" => Ok(VhostMode::Client),
            "server" => Ok(VhostMode::Server),
            _ => Err(ParseVhostModeError::InvalidValue(s.to_owned())),
        }
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
    pub host_mac: Option<MacAddr>,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_netconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_netconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub vhost_mode: VhostMode,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub fds: Option<Vec<i32>>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
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
            host_mac: None,
            iommu: false,
            num_queues: default_netconfig_num_queues(),
            queue_size: default_netconfig_queue_size(),
            vhost_user: false,
            vhost_socket: None,
            vhost_mode: VhostMode::Client,
            id: None,
            fds: None,
            rate_limiter_config: None,
        }
    }
}

impl NetConfig {
    pub const SYNTAX: &'static str = "Network parameters \
    \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,fd=<fd1:fd2...>,iommu=on|off,\
    num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,id=<device_id>,\
    vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>,vhost_mode=client|server,\
    bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
    ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>\"";

    pub fn parse(net: &str) -> Result<Self> {
        let mut parser = OptionParser::new();

        parser
            .add("tap")
            .add("ip")
            .add("mask")
            .add("mac")
            .add("host_mac")
            .add("iommu")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket")
            .add("vhost_mode")
            .add("id")
            .add("fd")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time");
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
        let host_mac = parser.convert("host_mac").map_err(Error::ParseNetwork)?;
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
            .convert::<Toggle>("vhost_user")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(false))
            .0;
        let vhost_socket = parser.get("socket");
        let vhost_mode = parser
            .convert("vhost_mode")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let id = parser.get("id");
        let fds = parser
            .convert::<IntegerList>("fd")
            .map_err(Error::ParseNetwork)?
            .map(|v| v.0.iter().map(|e| *e as i32).collect());

        let bw_size = parser
            .convert("bw_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(Error::ParseDisk)?
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

        let config = NetConfig {
            tap,
            ip,
            mask,
            mac,
            host_mac,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            vhost_mode,
            id,
            fds,
            rate_limiter_config,
        };
        Ok(config)
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues < 2 {
            return Err(ValidationError::VnetQueueLowerThan2);
        }

        if self.fds.is_some() && self.fds.as_ref().unwrap().len() * 2 != self.num_queues {
            return Err(ValidationError::VnetQueueFdMismatch);
        }

        if let Some(fds) = self.fds.as_ref() {
            for fd in fds {
                if *fd <= 2 {
                    return Err(ValidationError::VnetReservedFd);
                }
            }
        }

        if (self.num_queues / 2) > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        Ok(())
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
        parser.parse(rng).map_err(Error::ParseRng)?;

        let src = PathBuf::from(
            parser
                .get("src")
                .unwrap_or_else(|| DEFAULT_RNG_SOURCE.to_owned()),
        );
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseRng)?
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
pub struct BalloonConfig {
    pub size: u64,
    /// Option to deflate the balloon in case the guest is out of memory.
    #[serde(default)]
    pub deflate_on_oom: bool,
}

impl BalloonConfig {
    pub const SYNTAX: &'static str =
        "Balloon parameters \"size=<balloon_size>,deflate_on_oom=on|off\"";

    pub fn parse(balloon: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("size");
        parser.add("deflate_on_oom");
        parser.parse(balloon).map_err(Error::ParseBalloon)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseBalloon)?
            .map(|v| v.0)
            .unwrap_or(0);

        let deflate_on_oom = parser
            .convert::<Toggle>("deflate_on_oom")
            .map_err(Error::ParseBalloon)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(BalloonConfig {
            size,
            deflate_on_oom,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct FsConfig {
    pub tag: String,
    pub socket: PathBuf,
    #[serde(default = "default_fsconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_fsconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default = "default_fsconfig_dax")]
    pub dax: bool,
    #[serde(default = "default_fsconfig_cache_size")]
    pub cache_size: u64,
    #[serde(default)]
    pub id: Option<String>,
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
            socket: PathBuf::new(),
            num_queues: default_fsconfig_num_queues(),
            queue_size: default_fsconfig_queue_size(),
            dax: default_fsconfig_dax(),
            cache_size: default_fsconfig_cache_size(),
            id: None,
        }
    }
}

impl FsConfig {
    pub const SYNTAX: &'static str = "virtio-fs parameters \
    \"tag=<tag_name>,socket=<socket_path>,num_queues=<number_of_queues>,\
    queue_size=<size_of_each_queue>,dax=on|off,cache_size=<DAX cache size: \
    default 8Gib>,id=<device_id>\"";

    pub fn parse(fs: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("tag")
            .add("dax")
            .add("cache_size")
            .add("queue_size")
            .add("num_queues")
            .add("socket")
            .add("id");
        parser.parse(fs).map_err(Error::ParseFileSystem)?;

        let tag = parser.get("tag").ok_or(Error::ParseFsTagMissing)?;
        let socket = PathBuf::from(parser.get("socket").ok_or(Error::ParseFsSockMissing)?);

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

        let id = parser.get("id");

        Ok(FsConfig {
            tag,
            socket,
            num_queues,
            queue_size,
            dax,
            cache_size,
            id,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct PmemConfig {
    pub file: PathBuf,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub discard_writes: bool,
    #[serde(default)]
    pub id: Option<String>,
}

impl PmemConfig {
    pub const SYNTAX: &'static str = "Persistent memory parameters \
    \"file=<backing_file_path>,size=<persistent_memory_size>,iommu=on|off,\
    mergeable=on|off,discard_writes=on|off,id=<device_id>\"";
    pub fn parse(pmem: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("iommu")
            .add("discard_writes")
            .add("id");
        parser.parse(pmem).map_err(Error::ParsePersistentMemory)?;

        let file = PathBuf::from(parser.get("file").ok_or(Error::ParsePmemFileMissing)?);
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParsePersistentMemory)?
            .map(|v| v.0);
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
        let id = parser.get("id");

        Ok(PmemConfig {
            file,
            size,
            iommu,
            mergeable,
            discard_writes,
            id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ConsoleOutputMode {
    Off,
    Pty,
    Tty,
    File,
    Null,
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
            .add_valueless("pty")
            .add_valueless("tty")
            .add_valueless("null")
            .add("file")
            .add("iommu");
        parser.parse(console).map_err(Error::ParseConsole)?;

        let mut file: Option<PathBuf> = default_consoleconfig_file();
        let mut mode: ConsoleOutputMode = ConsoleOutputMode::Off;

        if parser.is_set("off") {
        } else if parser.is_set("pty") {
            mode = ConsoleOutputMode::Pty
        } else if parser.is_set("tty") {
            mode = ConsoleOutputMode::Tty
        } else if parser.is_set("null") {
            mode = ConsoleOutputMode::Null
        } else if parser.is_set("file") {
            mode = ConsoleOutputMode::File;
            file =
                Some(PathBuf::from(parser.get("file").ok_or(
                    Error::Validation(ValidationError::ConsoleFileMissing),
                )?));
        } else {
            return Err(Error::ParseConsoleInvalidModeGiven);
        }
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseConsole)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(Self { file, mode, iommu })
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct UserDeviceConfig {
    pub socket: PathBuf,
    #[serde(default)]
    pub id: Option<String>,
}

impl UserDeviceConfig {
    pub const SYNTAX: &'static str = "Userspace device socket=<socket_path>,id=<device_id>\"";
    pub fn parse(user_device: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("socket").add("id");
        parser.parse(user_device).map_err(Error::ParseUserDevice)?;

        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(Error::ParseUserDeviceSocketMissing)?;

        let id = parser.get("id");

        Ok(UserDeviceConfig { socket, id })
    }
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct VsockConfig {
    pub cid: u64,
    pub socket: PathBuf,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
}

impl VsockConfig {
    pub const SYNTAX: &'static str = "Virtio VSOCK parameters \
        \"cid=<context_id>,socket=<socket_path>,iommu=on|off,id=<device_id>\"";
    pub fn parse(vsock: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("socket").add("cid").add("iommu").add("id");
        parser.parse(vsock).map_err(Error::ParseVsock)?;

        let socket = parser
            .get("socket")
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
        let id = parser.get("id");

        Ok(VsockConfig {
            cid,
            socket,
            iommu,
            id,
        })
    }
}

#[cfg(feature = "tdx")]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct TdxConfig {
    pub firmware: PathBuf,
}

#[cfg(feature = "tdx")]
impl TdxConfig {
    pub fn parse(tdx: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("firmware");
        parser.parse(tdx).map_err(Error::ParseTdx)?;
        let firmware = parser
            .get("firmware")
            .map(PathBuf::from)
            .ok_or(Error::FirmwarePathMissing)?;
        Ok(TdxConfig { firmware })
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct SgxEpcConfig {
    pub id: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub prefault: bool,
}

#[cfg(target_arch = "x86_64")]
impl SgxEpcConfig {
    pub const SYNTAX: &'static str = "SGX EPC parameters \
        \"id=<epc_section_identifier>,size=<epc_section_size>,prefault=on|off\"";
    pub fn parse(sgx_epc: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("id").add("size").add("prefault");
        parser.parse(sgx_epc).map_err(Error::ParseSgxEpc)?;

        let id = parser.get("id").ok_or(Error::ParseSgxEpcIdMissing)?;
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseSgxEpc)?
            .unwrap_or(ByteSized(0))
            .0;
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(Error::ParseSgxEpc)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(SgxEpcConfig { id, size, prefault })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct NumaDistance {
    #[serde(default)]
    pub destination: u32,
    #[serde(default)]
    pub distance: u8,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct NumaConfig {
    #[serde(default)]
    pub guest_numa_id: u32,
    #[serde(default)]
    pub cpus: Option<Vec<u8>>,
    #[serde(default)]
    pub distances: Option<Vec<NumaDistance>>,
    #[serde(default)]
    pub memory_zones: Option<Vec<String>>,
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub sgx_epc_sections: Option<Vec<String>>,
}

impl NumaConfig {
    pub const SYNTAX: &'static str = "Settings related to a given NUMA node \
        \"guest_numa_id=<node_id>,cpus=<cpus_id>,distances=<list_of_distances_to_destination_nodes>,\
        memory_zones=<list_of_memory_zones>,sgx_epc_sections=<list_of_sgx_epc_sections>\"";
    pub fn parse(numa: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("guest_numa_id")
            .add("cpus")
            .add("distances")
            .add("memory_zones")
            .add("sgx_epc_sections");
        parser.parse(numa).map_err(Error::ParseNuma)?;

        let guest_numa_id = parser
            .convert::<u32>("guest_numa_id")
            .map_err(Error::ParseNuma)?
            .unwrap_or(0);
        let cpus = parser
            .convert::<IntegerList>("cpus")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0.iter().map(|e| *e as u8).collect());
        let distances = parser
            .convert::<TupleTwoIntegers>("distances")
            .map_err(Error::ParseNuma)?
            .map(|v| {
                v.0.iter()
                    .map(|(e1, e2)| NumaDistance {
                        destination: *e1 as u32,
                        distance: *e2 as u8,
                    })
                    .collect()
            });
        let memory_zones = parser
            .convert::<StringList>("memory_zones")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0);
        #[cfg(target_arch = "x86_64")]
        let sgx_epc_sections = parser
            .convert::<StringList>("sgx_epc_sections")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0);

        Ok(NumaConfig {
            guest_numa_id,
            cpus,
            distances,
            memory_zones,
            #[cfg(target_arch = "x86_64")]
            sgx_epc_sections,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Default)]
pub struct RestoreConfig {
    pub source_url: PathBuf,
    #[serde(default)]
    pub prefault: bool,
}

impl RestoreConfig {
    pub const SYNTAX: &'static str = "Restore from a VM snapshot. \
        \nRestore parameters \"source_url=<source_url>,prefault=on|off\" \
        \n`source_url` should be a valid URL (e.g file:///foo/bar or tcp://192.168.1.10/foo) \
        \n`prefault` brings memory pages in when enabled (disabled by default)";
    pub fn parse(restore: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("source_url").add("prefault");
        parser.parse(restore).map_err(Error::ParseRestore)?;

        let source_url = parser
            .get("source_url")
            .map(PathBuf::from)
            .ok_or(Error::ParseRestoreSourceUrlMissing)?;
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(Error::ParseRestore)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(RestoreConfig {
            source_url,
            prefault,
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
    #[serde(default)]
    pub initramfs: Option<InitramfsConfig>,
    #[serde(default)]
    pub cmdline: CmdlineConfig,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    #[serde(default)]
    pub rng: RngConfig,
    pub balloon: Option<BalloonConfig>,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default = "ConsoleConfig::default_serial")]
    pub serial: ConsoleConfig,
    #[serde(default = "ConsoleConfig::default_console")]
    pub console: ConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub user_devices: Option<Vec<UserDeviceConfig>>,
    pub vsock: Option<VsockConfig>,
    #[serde(default)]
    pub iommu: bool,
    #[cfg(target_arch = "x86_64")]
    pub sgx_epc: Option<Vec<SgxEpcConfig>>,
    pub numa: Option<Vec<NumaConfig>>,
    #[serde(default)]
    pub watchdog: bool,
    #[cfg(feature = "tdx")]
    pub tdx: Option<TdxConfig>,
}

impl VmConfig {
    pub fn validate(&self) -> ValidationResult<()> {
        #[cfg(not(feature = "tdx"))]
        self.kernel.as_ref().ok_or(ValidationError::KernelMissing)?;

        #[cfg(feature = "tdx")]
        {
            let tdx_enabled = self.tdx.is_some();
            if !tdx_enabled && self.kernel.is_none() {
                return Err(ValidationError::KernelMissing);
            }
            if tdx_enabled && (self.cpus.max_vcpus != self.cpus.boot_vcpus) {
                return Err(ValidationError::TdxNoCpuHotplug);
            }
            if tdx_enabled && self.kernel.is_some() {
                return Err(ValidationError::TdxKernelSpecified);
            }
        }

        if self.console.mode == ConsoleOutputMode::Tty && self.serial.mode == ConsoleOutputMode::Tty
        {
            return Err(ValidationError::DoubleTtyMode);
        }

        if self.console.mode == ConsoleOutputMode::File && self.console.file.is_none() {
            return Err(ValidationError::ConsoleFileMissing);
        }

        if self.serial.mode == ConsoleOutputMode::File && self.serial.file.is_none() {
            return Err(ValidationError::ConsoleFileMissing);
        }

        if self.cpus.max_vcpus < self.cpus.boot_vcpus {
            return Err(ValidationError::CpusMaxLowerThanBoot);
        }

        if let Some(disks) = &self.disks {
            for disk in disks {
                if disk.vhost_socket.as_ref().and(disk.path.as_ref()).is_some() {
                    return Err(ValidationError::DiskSocketAndPath);
                }
                if disk.vhost_user && !self.memory.shared {
                    return Err(ValidationError::VhostUserRequiresSharedMemory);
                }
                if disk.vhost_user && disk.vhost_socket.is_none() {
                    return Err(ValidationError::VhostUserMissingSocket);
                }
                disk.validate(self)?;
            }
        }

        if let Some(nets) = &self.net {
            for net in nets {
                if net.vhost_user && !self.memory.shared {
                    return Err(ValidationError::VhostUserRequiresSharedMemory);
                }
                net.validate(self)?;
            }
        }

        if let Some(fses) = &self.fs {
            if !fses.is_empty() && !self.memory.shared {
                return Err(ValidationError::VhostUserRequiresSharedMemory);
            }
            for fs in fses {
                fs.validate(self)?;
            }
        }

        if let Some(t) = &self.cpus.topology {
            if t.threads_per_core == 0
                || t.cores_per_die == 0
                || t.dies_per_package == 0
                || t.packages == 0
            {
                return Err(ValidationError::CpuTopologyZeroPart);
            }

            let total = t.threads_per_core * t.cores_per_die * t.dies_per_package * t.packages;
            if total != self.cpus.max_vcpus {
                return Err(ValidationError::CpuTopologyCount);
            }
        }

        if let Some(hugepage_size) = &self.memory.hugepage_size {
            if !self.memory.hugepages {
                return Err(ValidationError::HugePageSizeWithoutHugePages);
            }
            if !hugepage_size.is_power_of_two() {
                return Err(ValidationError::InvalidHugePageSize(*hugepage_size));
            }
        }

        if let Some(user_devices) = &self.user_devices {
            if !user_devices.is_empty() && !self.memory.shared {
                return Err(ValidationError::UserDevicesRequireSharedMemory);
            }
        }

        if let Some(numa) = &self.numa {
            let mut used_numa_node_memory_zones = HashMap::new();
            for numa_node in numa.iter() {
                for memory_zone in numa_node.memory_zones.clone().unwrap().iter() {
                    if !used_numa_node_memory_zones.contains_key(memory_zone) {
                        used_numa_node_memory_zones
                            .insert(memory_zone.to_string(), numa_node.guest_numa_id);
                    } else {
                        return Err(ValidationError::MemoryZoneReused(
                            memory_zone.to_string(),
                            *used_numa_node_memory_zones
                                .get(&memory_zone.to_string())
                                .unwrap(),
                            numa_node.guest_numa_id,
                        ));
                    }
                }
            }
        }

        Ok(())
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

        let mut balloon: Option<BalloonConfig> = None;
        if let Some(balloon_params) = &vm_params.balloon {
            balloon = Some(BalloonConfig::parse(balloon_params)?);
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

        let mut user_devices: Option<Vec<UserDeviceConfig>> = None;
        if let Some(user_device_list) = &vm_params.user_devices {
            let mut user_device_config_list = Vec::new();
            for item in user_device_list.iter() {
                let user_device_config = UserDeviceConfig::parse(item)?;
                user_device_config_list.push(user_device_config);
            }
            user_devices = Some(user_device_config_list);
        }

        let mut vsock: Option<VsockConfig> = None;
        if let Some(vs) = &vm_params.vsock {
            let vsock_config = VsockConfig::parse(vs)?;
            if vsock_config.iommu {
                iommu = true;
            }
            vsock = Some(vsock_config);
        }

        #[cfg(target_arch = "x86_64")]
        let mut sgx_epc: Option<Vec<SgxEpcConfig>> = None;
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(sgx_epc_list) = &vm_params.sgx_epc {
                let mut sgx_epc_config_list = Vec::new();
                for item in sgx_epc_list.iter() {
                    let sgx_epc_config = SgxEpcConfig::parse(item)?;
                    sgx_epc_config_list.push(sgx_epc_config);
                }
                sgx_epc = Some(sgx_epc_config_list);
            }
        }

        let mut numa: Option<Vec<NumaConfig>> = None;
        if let Some(numa_list) = &vm_params.numa {
            let mut numa_config_list = Vec::new();
            for item in numa_list.iter() {
                let numa_config = NumaConfig::parse(item)?;
                numa_config_list.push(numa_config);
            }
            numa = Some(numa_config_list);
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

        #[cfg(feature = "tdx")]
        let tdx = vm_params.tdx.map(TdxConfig::parse).transpose()?;

        let config = VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory, vm_params.memory_zones)?,
            kernel,
            initramfs,
            cmdline: CmdlineConfig::parse(vm_params.cmdline)?,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            devices,
            user_devices,
            vsock,
            iommu,
            #[cfg(target_arch = "x86_64")]
            sgx_epc,
            numa,
            watchdog: vm_params.watchdog,
            #[cfg(feature = "tdx")]
            tdx,
        };
        config.validate().map_err(Error::Validation)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_parser() {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size");

        assert!(parser.parse("size=128M,hanging_param").is_err());
        assert!(parser.parse("size=128M,too_many_equals=foo=bar").is_err());
        assert!(parser.parse("size=128M,file=/dev/shm").is_err());
        assert!(parser.parse("size=128M").is_ok());

        assert_eq!(parser.get("size"), Some("128M".to_owned()));
        assert!(!parser.is_set("mergeable"));
        assert!(parser.is_set("size"));
    }

    #[test]
    fn test_cpu_parsing() -> Result<()> {
        assert_eq!(CpusConfig::parse("")?, CpusConfig::default());

        assert_eq!(
            CpusConfig::parse("boot=1")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=1,max=2")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 2,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=8,topology=2:2:1:2")?,
            CpusConfig {
                boot_vcpus: 8,
                max_vcpus: 8,
                topology: Some(CpuTopology {
                    threads_per_core: 2,
                    cores_per_die: 2,
                    dies_per_package: 1,
                    packages: 2
                }),
                ..Default::default()
            }
        );

        assert!(CpusConfig::parse("boot=8,topology=2:2:1").is_err());
        assert!(CpusConfig::parse("boot=8,topology=2:2:1:x").is_err());
        assert_eq!(
            CpusConfig::parse("boot=1,kvm_hyperv=on")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                kvm_hyperv: true,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_mem_parsing() -> Result<()> {
        assert_eq!(MemoryConfig::parse("", None)?, MemoryConfig::default());
        // Default string
        assert_eq!(
            MemoryConfig::parse("size=512M", None)?,
            MemoryConfig::default()
        );
        assert_eq!(
            MemoryConfig::parse("size=512M,mergeable=on", None)?,
            MemoryConfig {
                size: 512 << 20,
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("mergeable=on", None)?,
            MemoryConfig {
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("size=1G,mergeable=off", None)?,
            MemoryConfig {
                size: 1 << 30,
                mergeable: false,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi", None)?,
            MemoryConfig {
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi,hotplug_size=512M", None)?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=virtio-mem,hotplug_size=512M", None)?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                hotplug_method: HotplugMethod::VirtioMem,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hugepages=on,size=1G,hugepage_size=2M", None)?,
            MemoryConfig {
                hugepage_size: Some(2 << 20),
                size: 1 << 30,
                hugepages: true,
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
            DiskConfig::parse("path=/path/to_file,id=mydisk0")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                id: Some("mydisk0".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("vhost_user=true,socket=/tmp/sock")?,
            DiskConfig {
                vhost_socket: Some(String::from("/tmp/sock")),
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
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
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

        Ok(())
    }

    #[test]
    fn test_net_parsing() -> Result<()> {
        // mac address is random
        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,id=mynet0")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                id: Some("mynet0".to_owned()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,tap=tap0,ip=192.168.100.1,mask=255.255.255.128"
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                tap: Some("tap0".to_owned()),
                ip: "192.168.100.1".parse().unwrap(),
                mask: "255.255.255.128".parse().unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,vhost_user=true,socket=/tmp/sock"
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                vhost_user: true,
                vhost_socket: Some("/tmp/sock".to_owned()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,num_queues=4,queue_size=1024,iommu=on")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                num_queues: 4,
                queue_size: 1024,
                iommu: true,
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,fd=3:7,num_queues=4")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                fds: Some(vec![3, 7]),
                num_queues: 4,
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
        assert!(FsConfig::parse("socket=/tmp/sock").is_err());
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock,num_queues=4,queue_size=1024")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                num_queues: 4,
                queue_size: 1024,
                ..Default::default()
            }
        );
        // DAX on -> default cache size
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock,dax=on")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                dax: true,
                cache_size: default_fsconfig_cache_size(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock,dax=on,cache_size=4G")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                dax: true,
                cache_size: 4 << 30,
                ..Default::default()
            }
        );
        // Cache size without DAX is an error
        assert!(FsConfig::parse("tag=mytag,socket=/tmp/sock,dax=off,cache_size=4G").is_err());
        Ok(())
    }

    #[test]
    fn test_pmem_parsing() -> Result<()> {
        // Must always give a file and size
        assert!(PmemConfig::parse("").is_err());
        assert!(PmemConfig::parse("size=128M").is_err());
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,id=mypmem0")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                id: Some("mypmem0".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,iommu=on,mergeable=on,discard_writes=on")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
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
            ConsoleConfig::parse("pty")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Pty,
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
        // socket and cid is required
        assert!(VsockConfig::parse("").is_err());
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=1")?,
            VsockConfig {
                cid: 1,
                socket: PathBuf::from("/tmp/sock"),
                iommu: false,
                id: None,
            }
        );
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=1,iommu=on")?,
            VsockConfig {
                cid: 1,
                socket: PathBuf::from("/tmp/sock"),
                iommu: true,
                id: None,
            }
        );
        Ok(())
    }

    #[test]
    fn test_config_validation() {
        let valid_config = VmConfig {
            cpus: CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                ..Default::default()
            },
            memory: MemoryConfig {
                size: 536_870_912,
                mergeable: false,
                hotplug_method: HotplugMethod::Acpi,
                hotplug_size: None,
                hotplugged_size: None,
                shared: false,
                hugepages: false,
                hugepage_size: None,
                prefault: false,
                zones: None,
            },
            kernel: Some(KernelConfig {
                path: PathBuf::from("/path/to/kernel"),
            }),
            initramfs: None,
            cmdline: CmdlineConfig {
                args: String::from(""),
            },
            disks: None,
            net: None,
            rng: RngConfig {
                src: PathBuf::from("/dev/urandom"),
                iommu: false,
            },
            balloon: None,
            fs: None,
            pmem: None,
            serial: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Null,
                iommu: false,
            },
            console: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
            },
            devices: None,
            user_devices: None,
            vsock: None,
            iommu: false,
            #[cfg(target_arch = "x86_64")]
            sgx_epc: None,
            numa: None,
            watchdog: false,
            #[cfg(feature = "tdx")]
            tdx: None,
        };

        assert!(valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::Tty;
        invalid_config.console.mode = ConsoleOutputMode::Tty;
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.kernel = None;
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::File;
        invalid_config.serial.file = None;
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.cpus.max_vcpus = 16;
        invalid_config.cpus.boot_vcpus = 32;
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.cpus.max_vcpus = 16;
        invalid_config.cpus.boot_vcpus = 16;
        invalid_config.cpus.topology = Some(CpuTopology {
            threads_per_core: 2,
            cores_per_die: 8,
            dies_per_package: 1,
            packages: 2,
        });
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_socket: Some("/path/to/sock".to_owned()),
            path: Some(PathBuf::from("/path/to/image")),
            ..Default::default()
        }]);
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            ..Default::default()
        }]);
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        assert!(invalid_config.validate().is_err());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        still_valid_config.memory.shared = true;
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            ..Default::default()
        }]);
        assert!(invalid_config.validate().is_err());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        still_valid_config.memory.shared = true;
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            fds: Some(vec![0]),
            ..Default::default()
        }]);
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config.clone();
        invalid_config.fs = Some(vec![FsConfig {
            ..Default::default()
        }]);
        assert!(invalid_config.validate().is_err());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.shared = true;
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.hugepages = true;
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.hugepages = true;
        still_valid_config.memory.hugepage_size = Some(2 << 20);
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.hugepages = false;
        invalid_config.memory.hugepage_size = Some(2 << 20);
        assert!(invalid_config.validate().is_err());

        let mut invalid_config = valid_config;
        invalid_config.memory.hugepages = true;
        invalid_config.memory.hugepage_size = Some(3 << 20);
        assert!(invalid_config.validate().is_err());
    }
}
