// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub use crate::vm_config::*;
use option_parser::{
    ByteSized, IntegerList, OptionParser, OptionParserError, StringList, Toggle, Tuple,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::convert::From;
use std::fmt;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;
use thiserror::Error;
use virtio_devices::{RateLimiterConfig, TokenBucketConfig};

const MAX_NUM_PCI_SEGMENTS: u16 = 16;

/// Errors associated with VM configuration parameters.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem tag is missing
    ParseFsTagMissing,
    /// Filesystem socket is missing
    ParseFsSockMissing,
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
    /// Invalid CPU features
    InvalidCpuFeatures(String),
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
    /// Failed parsing vsock parameters
    ParseVsock(OptionParserError),
    /// Failed parsing restore parameters
    ParseRestore(OptionParserError),
    /// Failed parsing SGX EPC parameters
    #[cfg(target_arch = "x86_64")]
    ParseSgxEpc(OptionParserError),
    /// Missing 'id' from SGX EPC section
    #[cfg(target_arch = "x86_64")]
    ParseSgxEpcIdMissing,
    /// Failed parsing NUMA parameters
    ParseNuma(OptionParserError),
    /// Failed validating configuration
    Validation(ValidationError),
    #[cfg(feature = "tdx")]
    /// Failed parsing TDX config
    ParseTdx(OptionParserError),
    #[cfg(feature = "tdx")]
    /// No TDX firmware
    FirmwarePathMissing,
    /// Failed parsing userspace device
    ParseUserDevice(OptionParserError),
    /// Missing socket for userspace device
    ParseUserDeviceSocketMissing,
    /// Failed parsing platform parameters
    ParsePlatform(OptionParserError),
    /// Failed parsing vDPA device
    ParseVdpa(OptionParserError),
    /// Missing path for vDPA device
    ParseVdpaPathMissing,
    /// Failed parsing TPM device
    ParseTpm(OptionParserError),
    /// Missing path for TPM device
    ParseTpmPathMissing,
}

#[derive(Debug, PartialEq, Eq, Error)]
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
    #[cfg(target_arch = "aarch64")]
    /// Dies per package must be 1
    CpuTopologyDiesPerPackage,
    /// Virtio needs a min of 2 queues
    VnetQueueLowerThan2,
    /// The input queue number for virtio_net must match the number of input fds
    VnetQueueFdMismatch,
    /// Using reserved fd
    VnetReservedFd,
    /// Hardware checksum offload is disabled.
    NoHardwareChecksumOffload,
    /// Hugepages not turned on
    HugePageSizeWithoutHugePages,
    /// Huge page size is not power of 2
    InvalidHugePageSize(u64),
    /// CPU Hotplug is not permitted with TDX
    #[cfg(feature = "tdx")]
    TdxNoCpuHotplug,
    /// Missing firmware for TDX
    #[cfg(feature = "tdx")]
    TdxFirmwareMissing,
    /// Insuffient vCPUs for queues
    TooManyQueues,
    /// Need shared memory for vfio-user
    UserDevicesRequireSharedMemory,
    /// Memory zone is reused across NUMA nodes
    MemoryZoneReused(String, u32, u32),
    /// Invalid number of PCI segments
    InvalidNumPciSegments(u16),
    /// Invalid PCI segment id
    InvalidPciSegment(u16),
    /// Balloon too big
    BalloonLargerThanRam(u64, u64),
    /// On a IOMMU segment but not behind IOMMU
    OnIommuSegment(u16),
    // On a IOMMU segment but IOMMU not suported
    IommuNotSupportedOnSegment(u16),
    // Identifier is not unique
    IdentifierNotUnique(String),
    /// Invalid identifier
    InvalidIdentifier(String),
    /// Placing the device behind a virtual IOMMU is not supported
    IommuNotSupported,
    /// Duplicated device path (device added twice)
    DuplicateDevicePath(String),
    /// Provided MTU is lower than what the VIRTIO specification expects
    InvalidMtu(u16),
}

type ValidationResult<T> = std::result::Result<T, ValidationError>;

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ValidationError::*;
        match self {
            DoubleTtyMode => write!(f, "Console mode tty specified for both serial and console"),
            KernelMissing => write!(f, "No kernel specified"),
            ConsoleFileMissing => write!(f, "Path missing when using file console mode"),
            CpusMaxLowerThanBoot => write!(f, "Max CPUs lower than boot CPUs"),
            DiskSocketAndPath => write!(f, "Disk path and vhost socket both provided"),
            VhostUserRequiresSharedMemory => {
                write!(
                    f,
                    "Using vhost-user requires using shared memory or huge pages"
                )
            }
            VhostUserMissingSocket => write!(f, "No socket provided when using vhost-user"),
            IommuUnsupported => write!(f, "Using an IOMMU without PCI support is unsupported"),
            VfioUnsupported => write!(f, "Using VFIO without PCI support is unsupported"),
            CpuTopologyZeroPart => write!(f, "No part of the CPU topology can be zero"),
            CpuTopologyCount => write!(
                f,
                "Product of CPU topology parts does not match maximum vCPUs"
            ),
            #[cfg(target_arch = "aarch64")]
            CpuTopologyDiesPerPackage => write!(f, "Dies per package must be 1"),
            VnetQueueLowerThan2 => write!(f, "Number of queues to virtio_net less than 2"),
            VnetQueueFdMismatch => write!(
                f,
                "Number of queues to virtio_net does not match the number of input FDs"
            ),
            VnetReservedFd => write!(f, "Reserved fd number (<= 2)"),
            NoHardwareChecksumOffload => write!(
                f,
                "\"offload_tso\" and \"offload_ufo\" depend on \"offload_tso\""
            ),
            HugePageSizeWithoutHugePages => {
                write!(f, "Huge page size specified but huge pages not enabled")
            }
            InvalidHugePageSize(s) => {
                write!(f, "Huge page size is not power of 2: {s}")
            }
            #[cfg(feature = "tdx")]
            TdxNoCpuHotplug => {
                write!(f, "CPU hotplug is not permitted with TDX")
            }
            #[cfg(feature = "tdx")]
            TdxFirmwareMissing => {
                write!(f, "No TDX firmware specified")
            }
            TooManyQueues => {
                write!(f, "Number of vCPUs is insufficient for number of queues")
            }
            UserDevicesRequireSharedMemory => {
                write!(
                    f,
                    "Using user devices requires using shared memory or huge pages"
                )
            }
            MemoryZoneReused(s, u1, u2) => {
                write!(
                    f,
                    "Memory zone: {s} belongs to multiple NUMA nodes {u1} and {u2}"
                )
            }
            InvalidNumPciSegments(n) => {
                write!(
                    f,
                    "Number of PCI segments ({n}) not in range of 1 to {MAX_NUM_PCI_SEGMENTS}"
                )
            }
            InvalidPciSegment(pci_segment) => {
                write!(f, "Invalid PCI segment id: {pci_segment}")
            }
            BalloonLargerThanRam(balloon_size, ram_size) => {
                write!(
                    f,
                    "Ballon size ({balloon_size}) greater than RAM ({ram_size})"
                )
            }
            OnIommuSegment(pci_segment) => {
                write!(
                    f,
                    "Device is on an IOMMU PCI segment ({pci_segment}) but not placed behind IOMMU"
                )
            }
            IommuNotSupportedOnSegment(pci_segment) => {
                write!(
                    f,
                    "Device is on an IOMMU PCI segment ({pci_segment}) but does not support being placed behind IOMMU"
                )
            }
            IdentifierNotUnique(s) => {
                write!(f, "Identifier {s} is not unique")
            }
            InvalidIdentifier(s) => {
                write!(f, "Identifier {s} is invalid")
            }
            IommuNotSupported => {
                write!(f, "Device does not support being placed behind IOMMU")
            }
            DuplicateDevicePath(p) => write!(f, "Duplicated device path: {p}"),
            &InvalidMtu(mtu) => {
                write!(
                    f,
                    "Provided MTU {mtu} is lower than 1280 (expected by VIRTIO specification)"
                )
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            ParseConsole(o) => write!(f, "Error parsing --console: {o}"),
            ParseConsoleInvalidModeGiven => {
                write!(f, "Error parsing --console: invalid console mode given")
            }
            ParseCpus(o) => write!(f, "Error parsing --cpus: {o}"),
            InvalidCpuFeatures(o) => write!(f, "Invalid feature in --cpus features list: {o}"),
            ParseDevice(o) => write!(f, "Error parsing --device: {o}"),
            ParseDevicePathMissing => write!(f, "Error parsing --device: path missing"),
            ParseFileSystem(o) => write!(f, "Error parsing --fs: {o}"),
            ParseFsSockMissing => write!(f, "Error parsing --fs: socket missing"),
            ParseFsTagMissing => write!(f, "Error parsing --fs: tag missing"),
            ParsePersistentMemory(o) => write!(f, "Error parsing --pmem: {o}"),
            ParsePmemFileMissing => write!(f, "Error parsing --pmem: file missing"),
            ParseVsock(o) => write!(f, "Error parsing --vsock: {o}"),
            ParseVsockCidMissing => write!(f, "Error parsing --vsock: cid missing"),
            ParseVsockSockMissing => write!(f, "Error parsing --vsock: socket missing"),
            ParseMemory(o) => write!(f, "Error parsing --memory: {o}"),
            ParseMemoryZone(o) => write!(f, "Error parsing --memory-zone: {o}"),
            ParseMemoryZoneIdMissing => write!(f, "Error parsing --memory-zone: id missing"),
            ParseNetwork(o) => write!(f, "Error parsing --net: {o}"),
            ParseDisk(o) => write!(f, "Error parsing --disk: {o}"),
            ParseRng(o) => write!(f, "Error parsing --rng: {o}"),
            ParseBalloon(o) => write!(f, "Error parsing --balloon: {o}"),
            ParseRestore(o) => write!(f, "Error parsing --restore: {o}"),
            #[cfg(target_arch = "x86_64")]
            ParseSgxEpc(o) => write!(f, "Error parsing --sgx-epc: {o}"),
            #[cfg(target_arch = "x86_64")]
            ParseSgxEpcIdMissing => write!(f, "Error parsing --sgx-epc: id missing"),
            ParseNuma(o) => write!(f, "Error parsing --numa: {o}"),
            ParseRestoreSourceUrlMissing => {
                write!(f, "Error parsing --restore: source_url missing")
            }
            ParseUserDeviceSocketMissing => {
                write!(f, "Error parsing --user-device: socket missing")
            }
            ParseUserDevice(o) => write!(f, "Error parsing --user-device: {o}"),
            Validation(v) => write!(f, "Error validating configuration: {v}"),
            #[cfg(feature = "tdx")]
            ParseTdx(o) => write!(f, "Error parsing --tdx: {o}"),
            #[cfg(feature = "tdx")]
            FirmwarePathMissing => write!(f, "TDX firmware missing"),
            ParsePlatform(o) => write!(f, "Error parsing --platform: {o}"),
            ParseVdpa(o) => write!(f, "Error parsing --vdpa: {o}"),
            ParseVdpaPathMissing => write!(f, "Error parsing --vdpa: path missing"),
            ParseTpm(o) => write!(f, "Error parsing --tpm: {o}"),
            ParseTpmPathMissing => write!(f, "Error parsing --tpm: path missing"),
        }
    }
}

pub fn add_to_config<T>(items: &mut Option<Vec<T>>, item: T) {
    if let Some(items) = items {
        items.push(item);
    } else {
        *items = Some(vec![item]);
    }
}

pub type Result<T> = result::Result<T, Error>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub memory_zones: Option<Vec<&'a str>>,
    pub firmware: Option<&'a str>,
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
    pub vdpa: Option<Vec<&'a str>>,
    pub vsock: Option<&'a str>,
    #[cfg(target_arch = "x86_64")]
    pub sgx_epc: Option<Vec<&'a str>>,
    pub numa: Option<Vec<&'a str>>,
    pub watchdog: bool,
    #[cfg(feature = "guest_debug")]
    pub gdb: bool,
    pub platform: Option<&'a str>,
    pub tpm: Option<&'a str>,
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

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("boot")
            .add("max")
            .add("topology")
            .add("kvm_hyperv")
            .add("max_phys_bits")
            .add("affinity")
            .add("features");
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
            .map_err(Error::ParseCpus)?
            .unwrap_or(DEFAULT_MAX_PHYS_BITS);
        let affinity = parser
            .convert::<Tuple<u8, Vec<u8>>>("affinity")
            .map_err(Error::ParseCpus)?
            .map(|v| {
                v.0.iter()
                    .map(|(e1, e2)| CpuAffinity {
                        vcpu: *e1,
                        host_cpus: e2.clone(),
                    })
                    .collect()
            });
        let features_list = parser
            .convert::<StringList>("features")
            .map_err(Error::ParseCpus)?
            .unwrap_or_default();
        // Some ugliness here as the features being checked might be disabled
        // at compile time causing the below allow and the need to specify the
        // ref type in the match.
        // The issue will go away once kvm_hyperv is moved under the features
        // list as it will always be checked for.
        #[allow(unused_mut)]
        let mut features = CpuFeatures::default();
        for s in features_list.0 {
            match <std::string::String as AsRef<str>>::as_ref(&s) {
                #[cfg(target_arch = "x86_64")]
                "amx" => {
                    features.amx = true;
                    Ok(())
                }
                _ => Err(Error::InvalidCpuFeatures(s)),
            }?;
        }

        Ok(CpusConfig {
            boot_vcpus,
            max_vcpus,
            topology,
            kvm_hyperv,
            max_phys_bits,
            affinity,
            features,
        })
    }
}

impl PlatformConfig {
    pub fn parse(platform: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("num_pci_segments")
            .add("iommu_segments")
            .add("serial_number")
            .add("uuid")
            .add("oem_strings");
        #[cfg(feature = "tdx")]
        parser.add("tdx");
        parser.parse(platform).map_err(Error::ParsePlatform)?;

        let num_pci_segments: u16 = parser
            .convert("num_pci_segments")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(DEFAULT_NUM_PCI_SEGMENTS);
        let iommu_segments = parser
            .convert::<IntegerList>("iommu_segments")
            .map_err(Error::ParsePlatform)?
            .map(|v| v.0.iter().map(|e| *e as u16).collect());
        let serial_number = parser
            .convert("serial_number")
            .map_err(Error::ParsePlatform)?;
        let uuid = parser.convert("uuid").map_err(Error::ParsePlatform)?;
        let oem_strings = parser
            .convert::<StringList>("oem_strings")
            .map_err(Error::ParsePlatform)?
            .map(|v| v.0);
        #[cfg(feature = "tdx")]
        let tdx = parser
            .convert::<Toggle>("tdx")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(Toggle(false))
            .0;
        Ok(PlatformConfig {
            num_pci_segments,
            iommu_segments,
            serial_number,
            uuid,
            oem_strings,
            #[cfg(feature = "tdx")]
            tdx,
        })
    }

    pub fn validate(&self) -> ValidationResult<()> {
        if self.num_pci_segments == 0 || self.num_pci_segments > MAX_NUM_PCI_SEGMENTS {
            return Err(ValidationError::InvalidNumPciSegments(
                self.num_pci_segments,
            ));
        }

        if let Some(iommu_segments) = &self.iommu_segments {
            for segment in iommu_segments {
                if *segment >= self.num_pci_segments {
                    return Err(ValidationError::InvalidPciSegment(*segment));
                }
            }
        }

        Ok(())
    }
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
            .add("prefault")
            .add("thp");
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
        let thp = parser
            .convert::<Toggle>("thp")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(true))
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
            thp,
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

impl DiskConfig {
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
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("id")
            .add("_disable_io_uring")
            .add("pci_segment");
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
        let id = parser.get("id");
        let disable_io_uring = parser
            .convert::<Toggle>("_disable_io_uring")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
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

        Ok(DiskConfig {
            path,
            readonly,
            direct,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            rate_limiter_config,
            id,
            disable_io_uring,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        if self.vhost_user && self.iommu {
            return Err(ValidationError::IommuNotSupported);
        }

        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
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

impl NetConfig {
    pub fn parse(net: &str) -> Result<Self> {
        let mut parser = OptionParser::new();

        parser
            .add("tap")
            .add("ip")
            .add("mask")
            .add("mac")
            .add("host_mac")
            .add("offload_tso")
            .add("offload_ufo")
            .add("offload_csum")
            .add("mtu")
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
            .add("ops_refill_time")
            .add("pci_segment");
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
        let offload_tso = parser
            .convert::<Toggle>("offload_tso")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(true))
            .0;
        let offload_ufo = parser
            .convert::<Toggle>("offload_ufo")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(true))
            .0;
        let offload_csum = parser
            .convert::<Toggle>("offload_csum")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(true))
            .0;
        let mtu = parser.convert("mtu").map_err(Error::ParseNetwork)?;
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
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let bw_size = parser
            .convert("bw_size")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(Error::ParseNetwork)?
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
            mtu,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            vhost_mode,
            id,
            fds,
            fds_validated: false,
            rate_limiter_config,
            pci_segment,
            offload_tso,
            offload_ufo,
            offload_csum,
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

        if self.vhost_user && self.iommu {
            return Err(ValidationError::IommuNotSupported);
        }

        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        if let Some(mtu) = self.mtu {
            if mtu < virtio_devices::net::MIN_MTU {
                return Err(ValidationError::InvalidMtu(mtu));
            }
        }

        if !self.offload_csum && (self.offload_tso || self.offload_ufo) {
            return Err(ValidationError::NoHardwareChecksumOffload);
        }

        Ok(())
    }
}

impl Drop for NetConfig {
    fn drop(&mut self) {
        if self.fds_validated {
            if let Some(mut fds) = self.fds.take() {
                for fd in fds.drain(..) {
                    // SAFETY: Safe as the fds were validated by creating TAP devices successfully
                    unsafe { libc::close(fd) };
                }
            }
        }
    }
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

impl BalloonConfig {
    pub fn parse(balloon: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("size");
        parser.add("deflate_on_oom");
        parser.add("free_page_reporting");
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

        let free_page_reporting = parser
            .convert::<Toggle>("free_page_reporting")
            .map_err(Error::ParseBalloon)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(BalloonConfig {
            size,
            deflate_on_oom,
            free_page_reporting,
        })
    }
}

impl FsConfig {
    pub fn parse(fs: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("tag")
            .add("queue_size")
            .add("num_queues")
            .add("socket")
            .add("id")
            .add("pci_segment");
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

        let id = parser.get("id");

        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_default();

        Ok(FsConfig {
            tag,
            socket,
            num_queues,
            queue_size,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) {
                    return Err(ValidationError::IommuNotSupportedOnSegment(
                        self.pci_segment,
                    ));
                }
            }
        }

        Ok(())
    }
}

impl PmemConfig {
    pub fn parse(pmem: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("iommu")
            .add("discard_writes")
            .add("id")
            .add("pci_segment");
        parser.parse(pmem).map_err(Error::ParsePersistentMemory)?;

        let file = PathBuf::from(parser.get("file").ok_or(Error::ParsePmemFileMissing)?);
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParsePersistentMemory)?
            .map(|v| v.0);
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
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or_default();

        Ok(PmemConfig {
            file,
            size,
            iommu,
            discard_writes,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
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
}

impl DeviceConfig {
    pub fn parse(device: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("path").add("id").add("iommu").add("pci_segment");
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
        let pci_segment = parser
            .convert::<u16>("pci_segment")
            .map_err(Error::ParseDevice)?
            .unwrap_or_default();

        Ok(DeviceConfig {
            path,
            iommu,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

impl UserDeviceConfig {
    pub fn parse(user_device: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("socket").add("id").add("pci_segment");
        parser.parse(user_device).map_err(Error::ParseUserDevice)?;

        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(Error::ParseUserDeviceSocketMissing)?;
        let id = parser.get("id");
        let pci_segment = parser
            .convert::<u16>("pci_segment")
            .map_err(Error::ParseUserDevice)?
            .unwrap_or_default();

        Ok(UserDeviceConfig {
            socket,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) {
                    return Err(ValidationError::IommuNotSupportedOnSegment(
                        self.pci_segment,
                    ));
                }
            }
        }

        Ok(())
    }
}

impl VdpaConfig {
    pub fn parse(vdpa: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("num_queues")
            .add("iommu")
            .add("id")
            .add("pci_segment");
        parser.parse(vdpa).map_err(Error::ParseVdpa)?;

        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(Error::ParseVdpaPathMissing)?;
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseVdpa)?
            .unwrap_or_else(default_vdpaconfig_num_queues);
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseVdpa)?
            .unwrap_or(Toggle(false))
            .0;
        let id = parser.get("id");
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseVdpa)?
            .unwrap_or_default();

        Ok(VdpaConfig {
            path,
            num_queues,
            iommu,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

impl VsockConfig {
    pub fn parse(vsock: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("socket")
            .add("cid")
            .add("iommu")
            .add("id")
            .add("pci_segment");
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
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseVsock)?
            .unwrap_or_default();

        Ok(VsockConfig {
            cid,
            socket,
            iommu,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if self.pci_segment >= platform_config.num_pci_segments {
                return Err(ValidationError::InvalidPciSegment(self.pci_segment));
            }

            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl SgxEpcConfig {
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

impl NumaConfig {
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
            .convert::<Tuple<u64, u64>>("distances")
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoreConfig {
    pub source_url: PathBuf,
    #[serde(default)]
    pub prefault: bool,
}

impl RestoreConfig {
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

impl TpmConfig {
    pub fn parse(tpm: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("socket");
        parser.parse(tpm).map_err(Error::ParseTpm)?;
        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(Error::ParseTpmPathMissing)?;
        Ok(TpmConfig { socket })
    }
}

impl VmConfig {
    fn validate_identifier(
        id_list: &mut BTreeSet<String>,
        id: &Option<String>,
    ) -> ValidationResult<()> {
        if let Some(id) = id.as_ref() {
            if id.starts_with("__") {
                return Err(ValidationError::InvalidIdentifier(id.clone()));
            }

            if !id_list.insert(id.clone()) {
                return Err(ValidationError::IdentifierNotUnique(id.clone()));
            }
        }

        Ok(())
    }

    pub fn backed_by_shared_memory(&self) -> bool {
        if self.memory.shared || self.memory.hugepages {
            return true;
        }

        if self.memory.size == 0 {
            for zone in self.memory.zones.as_ref().unwrap() {
                if !zone.shared && !zone.hugepages {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    // Also enables virtio-iommu if the config needs it
    // Returns the list of unique identifiers provided through the
    // configuration.
    pub fn validate(&mut self) -> ValidationResult<BTreeSet<String>> {
        let mut id_list = BTreeSet::new();

        self.payload
            .as_ref()
            .ok_or(ValidationError::KernelMissing)?;

        #[cfg(feature = "tdx")]
        {
            let tdx_enabled = self.platform.as_ref().map(|p| p.tdx).unwrap_or(false);
            // At this point we know payload isn't None.
            if tdx_enabled && self.payload.as_ref().unwrap().firmware.is_none() {
                return Err(ValidationError::TdxFirmwareMissing);
            }
            if tdx_enabled && (self.cpus.max_vcpus != self.cpus.boot_vcpus) {
                return Err(ValidationError::TdxNoCpuHotplug);
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
                if disk.vhost_user && !self.backed_by_shared_memory() {
                    return Err(ValidationError::VhostUserRequiresSharedMemory);
                }
                if disk.vhost_user && disk.vhost_socket.is_none() {
                    return Err(ValidationError::VhostUserMissingSocket);
                }
                disk.validate(self)?;
                self.iommu |= disk.iommu;

                Self::validate_identifier(&mut id_list, &disk.id)?;
            }
        }

        if let Some(nets) = &self.net {
            for net in nets {
                if net.vhost_user && !self.backed_by_shared_memory() {
                    return Err(ValidationError::VhostUserRequiresSharedMemory);
                }
                net.validate(self)?;
                self.iommu |= net.iommu;

                Self::validate_identifier(&mut id_list, &net.id)?;
            }
        }

        if let Some(fses) = &self.fs {
            if !fses.is_empty() && !self.backed_by_shared_memory() {
                return Err(ValidationError::VhostUserRequiresSharedMemory);
            }
            for fs in fses {
                fs.validate(self)?;

                Self::validate_identifier(&mut id_list, &fs.id)?;
            }
        }

        if let Some(pmems) = &self.pmem {
            for pmem in pmems {
                pmem.validate(self)?;
                self.iommu |= pmem.iommu;

                Self::validate_identifier(&mut id_list, &pmem.id)?;
            }
        }

        self.iommu |= self.rng.iommu;
        self.iommu |= self.console.iommu;

        if let Some(t) = &self.cpus.topology {
            if t.threads_per_core == 0
                || t.cores_per_die == 0
                || t.dies_per_package == 0
                || t.packages == 0
            {
                return Err(ValidationError::CpuTopologyZeroPart);
            }

            // The setting of dies doesen't apply on AArch64.
            // Only '1' value is accepted, so its impact on the vcpu topology
            // setting can be ignored.
            #[cfg(target_arch = "aarch64")]
            if t.dies_per_package != 1 {
                return Err(ValidationError::CpuTopologyDiesPerPackage);
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
            if !user_devices.is_empty() && !self.backed_by_shared_memory() {
                return Err(ValidationError::UserDevicesRequireSharedMemory);
            }

            for user_device in user_devices {
                user_device.validate(self)?;

                Self::validate_identifier(&mut id_list, &user_device.id)?;
            }
        }

        if let Some(vdpa_devices) = &self.vdpa {
            for vdpa_device in vdpa_devices {
                vdpa_device.validate(self)?;
                self.iommu |= vdpa_device.iommu;

                Self::validate_identifier(&mut id_list, &vdpa_device.id)?;
            }
        }

        if let Some(balloon) = &self.balloon {
            let mut ram_size = self.memory.size;

            if let Some(zones) = &self.memory.zones {
                for zone in zones {
                    ram_size += zone.size;
                }
            }

            if balloon.size >= ram_size {
                return Err(ValidationError::BalloonLargerThanRam(
                    balloon.size,
                    ram_size,
                ));
            }
        }

        if let Some(devices) = &self.devices {
            let mut device_paths = BTreeSet::new();
            for device in devices {
                if !device_paths.insert(device.path.to_string_lossy()) {
                    return Err(ValidationError::DuplicateDevicePath(
                        device.path.to_string_lossy().to_string(),
                    ));
                }

                device.validate(self)?;
                self.iommu |= device.iommu;

                Self::validate_identifier(&mut id_list, &device.id)?;
            }
        }

        if let Some(vsock) = &self.vsock {
            vsock.validate(self)?;
            self.iommu |= vsock.iommu;

            Self::validate_identifier(&mut id_list, &vsock.id)?;
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
                            *used_numa_node_memory_zones.get(memory_zone).unwrap(),
                            numa_node.guest_numa_id,
                        ));
                    }
                }
            }
        }

        if let Some(zones) = &self.memory.zones {
            for zone in zones.iter() {
                let id = zone.id.clone();
                Self::validate_identifier(&mut id_list, &Some(id))?;
            }
        }

        #[cfg(target_arch = "x86_64")]
        if let Some(sgx_epcs) = &self.sgx_epc {
            for sgx_epc in sgx_epcs.iter() {
                let id = sgx_epc.id.clone();
                Self::validate_identifier(&mut id_list, &Some(id))?;
            }
        }

        self.platform.as_ref().map(|p| p.validate()).transpose()?;
        self.iommu |= self
            .platform
            .as_ref()
            .map(|p| p.iommu_segments.is_some())
            .unwrap_or_default();

        Ok(id_list)
    }

    pub fn parse(vm_params: VmParams) -> Result<Self> {
        let mut disks: Option<Vec<DiskConfig>> = None;
        if let Some(disk_list) = &vm_params.disks {
            let mut disk_config_list = Vec::new();
            for item in disk_list.iter() {
                let disk_config = DiskConfig::parse(item)?;
                disk_config_list.push(disk_config);
            }
            disks = Some(disk_config_list);
        }

        let mut net: Option<Vec<NetConfig>> = None;
        if let Some(net_list) = &vm_params.net {
            let mut net_config_list = Vec::new();
            for item in net_list.iter() {
                let net_config = NetConfig::parse(item)?;
                net_config_list.push(net_config);
            }
            net = Some(net_config_list);
        }

        let rng = RngConfig::parse(vm_params.rng)?;

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
                pmem_config_list.push(pmem_config);
            }
            pmem = Some(pmem_config_list);
        }

        let console = ConsoleConfig::parse(vm_params.console)?;
        let serial = ConsoleConfig::parse(vm_params.serial)?;

        let mut devices: Option<Vec<DeviceConfig>> = None;
        if let Some(device_list) = &vm_params.devices {
            let mut device_config_list = Vec::new();
            for item in device_list.iter() {
                let device_config = DeviceConfig::parse(item)?;
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

        let mut vdpa: Option<Vec<VdpaConfig>> = None;
        if let Some(vdpa_list) = &vm_params.vdpa {
            let mut vdpa_config_list = Vec::new();
            for item in vdpa_list.iter() {
                let vdpa_config = VdpaConfig::parse(item)?;
                vdpa_config_list.push(vdpa_config);
            }
            vdpa = Some(vdpa_config_list);
        }

        let mut vsock: Option<VsockConfig> = None;
        if let Some(vs) = &vm_params.vsock {
            let vsock_config = VsockConfig::parse(vs)?;
            vsock = Some(vsock_config);
        }

        let platform = vm_params.platform.map(PlatformConfig::parse).transpose()?;

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

        let payload = if vm_params.kernel.is_some() || vm_params.firmware.is_some() {
            Some(PayloadConfig {
                kernel: vm_params.kernel.map(PathBuf::from),
                initramfs: vm_params.initramfs.map(PathBuf::from),
                cmdline: vm_params.cmdline.map(|s| s.to_string()),
                firmware: vm_params.firmware.map(PathBuf::from),
            })
        } else {
            None
        };

        let mut tpm: Option<TpmConfig> = None;
        if let Some(tc) = vm_params.tpm {
            let tpm_conf = TpmConfig::parse(tc)?;
            tpm = Some(TpmConfig {
                socket: tpm_conf.socket,
            });
        }

        #[cfg(feature = "guest_debug")]
        let gdb = vm_params.gdb;

        let mut config = VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory, vm_params.memory_zones)?,
            payload,
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
            vdpa,
            vsock,
            iommu: false, // updated in VmConfig::validate()
            #[cfg(target_arch = "x86_64")]
            sgx_epc,
            numa,
            watchdog: vm_params.watchdog,
            #[cfg(feature = "guest_debug")]
            gdb,
            platform,
            tpm,
        };
        config.validate().map_err(Error::Validation)?;
        Ok(config)
    }

    #[cfg(feature = "tdx")]
    pub fn is_tdx_enabled(&self) -> bool {
        self.platform.as_ref().map(|p| p.tdx).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, os::fd::AsRawFd};

    use super::*;
    use net_util::MacAddr;

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
        assert_eq!(
            CpusConfig::parse("boot=2,affinity=[0@[0,2],1@[1,3]]")?,
            CpusConfig {
                boot_vcpus: 2,
                max_vcpus: 2,
                affinity: Some(vec![
                    CpuAffinity {
                        vcpu: 0,
                        host_cpus: vec![0, 2],
                    },
                    CpuAffinity {
                        vcpu: 1,
                        host_cpus: vec![1, 3],
                    }
                ]),
                ..Default::default()
            },
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
                fds: None,
                id: None,
                tap: None,
                vhost_socket: None,
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,id=mynet0")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                id: Some("mynet0".to_owned()),
                fds: None,
                tap: None,
                vhost_socket: None,
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
                fds: None,
                id: None,
                vhost_socket: None,
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
                fds: None,
                id: None,
                tap: None,
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
                fds: None,
                id: None,
                tap: None,
                vhost_socket: None,
                ..Default::default()
            }
        );

        // SAFETY: Safe as the file was just opened
        let fd1 = unsafe { libc::dup(File::open("/dev/null").unwrap().as_raw_fd()) };
        // SAFETY: Safe as the file was just opened
        let fd2 = unsafe { libc::dup(File::open("/dev/null").unwrap().as_raw_fd()) };

        assert_eq!(
            &format!(
                "{:?}",
                NetConfig::parse(&format!(
                    "mac=de:ad:be:ef:12:34,fd=[{fd1},{fd2}],num_queues=4"
                ))?
            ),
            &format!("NetConfig {{ tap: None, ip: 192.168.249.1, mask: 255.255.255.0, \
                mac: MacAddr {{ bytes: [222, 173, 190, 239, 18, 52] }}, host_mac: None, mtu: None, \
                iommu: false, num_queues: 4, queue_size: 256, vhost_user: false, vhost_socket: None, \
                vhost_mode: Client, id: None, fds: Some([{fd1}, {fd2}]), \
                rate_limiter_config: None, pci_segment: 0, offload_tso: true, offload_ufo: true, offload_csum: true }}")
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
            PmemConfig::parse("file=/tmp/pmem,size=128M,iommu=on,discard_writes=on")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
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
                iommu: false,
                ..Default::default()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: true,
                ..Default::default()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on,id=mydevice0")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: Some("mydevice0".to_owned()),
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_vdpa_parsing() -> Result<()> {
        // path is required
        assert!(VdpaConfig::parse("").is_err());
        assert_eq!(
            VdpaConfig::parse("path=/dev/vhost-vdpa")?,
            VdpaConfig {
                path: PathBuf::from("/dev/vhost-vdpa"),
                num_queues: 1,
                id: None,
                ..Default::default()
            }
        );
        assert_eq!(
            VdpaConfig::parse("path=/dev/vhost-vdpa,num_queues=2,id=my_vdpa")?,
            VdpaConfig {
                path: PathBuf::from("/dev/vhost-vdpa"),
                num_queues: 2,
                id: Some("my_vdpa".to_owned()),
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_tpm_parsing() -> Result<()> {
        // path is required
        assert!(TpmConfig::parse("").is_err());
        assert_eq!(
            TpmConfig::parse("socket=/var/run/tpm.sock")?,
            TpmConfig {
                socket: PathBuf::from("/var/run/tpm.sock"),
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
                ..Default::default()
            }
        );
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=1,iommu=on")?,
            VsockConfig {
                cid: 1,
                socket: PathBuf::from("/tmp/sock"),
                iommu: true,
                id: None,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_config_validation() {
        let mut valid_config = VmConfig {
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
                thp: true,
            },
            payload: Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                ..Default::default()
            }),
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
            vdpa: None,
            vsock: None,
            iommu: false,
            #[cfg(target_arch = "x86_64")]
            sgx_epc: None,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            platform: None,
            tpm: None,
        };

        assert!(valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::Tty;
        invalid_config.console.mode = ConsoleOutputMode::Tty;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::DoubleTtyMode)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.payload = None;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::KernelMissing)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::File;
        invalid_config.serial.file = None;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::ConsoleFileMissing)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.cpus.max_vcpus = 16;
        invalid_config.cpus.boot_vcpus = 32;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::CpusMaxLowerThanBoot)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.cpus.max_vcpus = 16;
        invalid_config.cpus.boot_vcpus = 16;
        invalid_config.cpus.topology = Some(CpuTopology {
            threads_per_core: 2,
            cores_per_die: 8,
            dies_per_package: 1,
            packages: 2,
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::CpuTopologyCount)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_socket: Some("/path/to/sock".to_owned()),
            path: Some(PathBuf::from("/path/to/image")),
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::DiskSocketAndPath)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserMissingSocket)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

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
            fds: None,
            id: None,
            tap: None,
            vhost_socket: None,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            fds: None,
            id: None,
            tap: None,
            ..Default::default()
        }]);
        still_valid_config.memory.shared = true;
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            fds: Some(vec![0]),
            id: None,
            tap: None,
            vhost_socket: None,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VnetReservedFd)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            offload_csum: false,
            fds: None,
            id: None,
            tap: None,
            vhost_socket: None,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::NoHardwareChecksumOffload)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.fs = Some(vec![FsConfig {
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

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
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::HugePageSizeWithoutHugePages)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.hugepages = true;
        invalid_config.memory.hugepage_size = Some(3 << 20);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidHugePageSize(3 << 20))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            ..Default::default()
        });
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 17,
            ..Default::default()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidNumPciSegments(17))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![17, 18]),
            ..Default::default()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidPciSegment(17))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.disks = Some(vec![DiskConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.net = Some(vec![NetConfig {
            iommu: true,
            pci_segment: 1,
            fds: None,
            id: None,
            tap: None,
            vhost_socket: None,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.pmem = Some(vec![PmemConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.devices = Some(vec![DeviceConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.vsock = Some(VsockConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        });
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.disks = Some(vec![DiskConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.net = Some(vec![NetConfig {
            iommu: false,
            pci_segment: 1,
            fds: None,
            id: None,
            tap: None,
            vhost_socket: None,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.pmem = Some(vec![PmemConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.devices = Some(vec![DeviceConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.vsock = Some(VsockConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.user_devices = Some(vec![UserDeviceConfig {
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::IommuNotSupportedOnSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.vdpa = Some(vec![VdpaConfig {
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.fs = Some(vec![FsConfig {
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::IommuNotSupportedOnSegment(1))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.devices = Some(vec![
            DeviceConfig {
                path: "/device1".into(),
                ..Default::default()
            },
            DeviceConfig {
                path: "/device2".into(),
                ..Default::default()
            },
        ]);
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config;
        invalid_config.devices = Some(vec![
            DeviceConfig {
                path: "/device1".into(),
                ..Default::default()
            },
            DeviceConfig {
                path: "/device1".into(),
                ..Default::default()
            },
        ]);
        assert!(invalid_config.validate().is_err());
    }
}
