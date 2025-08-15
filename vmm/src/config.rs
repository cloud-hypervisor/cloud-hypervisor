// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::{BTreeSet, HashMap};
#[cfg(feature = "ivshmem")]
use std::fs;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;

use clap::ArgMatches;
use option_parser::{
    ByteSized, IntegerList, OptionParser, OptionParserError, StringList, Toggle, Tuple,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_blk::VIRTIO_BLK_ID_BYTES;
use virtio_devices::block::MINIMUM_BLOCK_QUEUE_SIZE;
use virtio_devices::vhost_user::VIRTIO_FS_TAG_LEN;
use virtio_devices::{RateLimiterConfig, TokenBucketConfig};

use crate::landlock::LandlockAccess;
use crate::vm_config::*;

const MAX_NUM_PCI_SEGMENTS: u16 = 96;
const MAX_IOMMU_ADDRESS_WIDTH_BITS: u8 = 64;

/// Errors associated with VM configuration parameters.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem tag is missing
    #[error("Error parsing --fs: tag missing")]
    ParseFsTagMissing,
    /// Filesystem tag is too long
    #[error("Error parsing --fs: max tag length is {VIRTIO_FS_TAG_LEN}")]
    ParseFsTagTooLong,
    /// Filesystem socket is missing
    #[error("Error parsing --fs: socket missing")]
    ParseFsSockMissing,
    /// Missing persistent memory file parameter.
    #[error("Error parsing --pmem: file missing")]
    ParsePmemFileMissing,
    /// Missing vsock socket path parameter.
    #[error("Error parsing --vsock: socket missing")]
    ParseVsockSockMissing,
    /// Missing vsock cid parameter.
    #[error("Error parsing --vsock: cid missing")]
    ParseVsockCidMissing,
    /// Missing restore source_url parameter.
    #[error("Error parsing --restore: source_url missing")]
    ParseRestoreSourceUrlMissing,
    /// Error parsing CPU options
    #[error("Error parsing --cpus")]
    ParseCpus(#[source] OptionParserError),
    /// Invalid CPU features
    #[error("Invalid feature in --cpus features list: {0}")]
    InvalidCpuFeatures(String),
    /// Error parsing memory options
    #[error("Error parsing --memory")]
    ParseMemory(#[source] OptionParserError),
    /// Error parsing memory zone options
    #[error("Error parsing --memory-zone")]
    ParseMemoryZone(#[source] OptionParserError),
    /// Missing 'id' from memory zone
    #[error("Error parsing --memory-zone: id missing")]
    ParseMemoryZoneIdMissing,
    /// Error parsing rate-limiter group options
    #[error("Error parsing --rate-limit-group")]
    ParseRateLimiterGroup(#[source] OptionParserError),
    /// Error parsing disk options
    #[error("Error parsing --disk")]
    ParseDisk(#[source] OptionParserError),
    /// Error parsing network options
    #[error("Error parsing --net")]
    ParseNetwork(#[source] OptionParserError),
    /// Error parsing RNG options
    #[error("Error parsing --rng")]
    ParseRng(#[source] OptionParserError),
    /// Error parsing balloon options
    #[error("Error parsing --balloon")]
    ParseBalloon(#[source] OptionParserError),
    /// Error parsing filesystem parameters
    #[error("Error parsing --fs")]
    ParseFileSystem(#[source] OptionParserError),
    /// Error parsing persistent memory parameters
    #[error("Error parsing --pmem")]
    ParsePersistentMemory(#[source] OptionParserError),
    /// Failed parsing console
    #[error("Error parsing --console")]
    ParseConsole(#[source] OptionParserError),
    #[cfg(target_arch = "x86_64")]
    /// Failed parsing debug-console
    #[error("Error parsing --debug-console")]
    ParseDebugConsole(#[source] OptionParserError),
    /// No mode given for console
    #[error("Error parsing --console: invalid console mode given")]
    ParseConsoleInvalidModeGiven,
    /// Failed parsing device parameters
    #[error("Error parsing --device")]
    ParseDevice(#[source] OptionParserError),
    /// Missing path from device,
    #[error("Error parsing --device: path missing")]
    ParseDevicePathMissing,
    /// Failed parsing vsock parameters
    #[error("Error parsing --vsock")]
    ParseVsock(#[source] OptionParserError),
    /// Failed parsing restore parameters
    #[error("Error parsing --restore")]
    ParseRestore(#[source] OptionParserError),
    /// Failed parsing NUMA parameters
    #[error("Error parsing --numa")]
    ParseNuma(#[source] OptionParserError),
    /// Failed validating configuration
    #[error("Error validating configuration")]
    Validation(#[source] ValidationError),
    #[cfg(feature = "sev_snp")]
    #[error("Error parsing --sev_snp")]
    /// Failed parsing SEV-SNP config
    ParseSevSnp(#[source] OptionParserError),
    #[cfg(feature = "tdx")]
    #[error("Error parsing --tdx")]
    /// Failed parsing TDX config
    ParseTdx(#[source] OptionParserError),
    #[cfg(feature = "tdx")]
    #[error("TDX firmware missing")]
    /// No TDX firmware
    FirmwarePathMissing,
    /// Failed parsing userspace device
    #[error("Error parsing --user-device")]
    ParseUserDevice(#[source] OptionParserError),
    /// Missing socket for userspace device
    #[error("Error parsing --user-device: socket missing")]
    ParseUserDeviceSocketMissing,
    /// Error parsing pci segment options
    #[error("Error parsing --pci-segment")]
    ParsePciSegment(#[source] OptionParserError),
    /// Failed parsing platform parameters
    #[error("Error parsing --platform")]
    ParsePlatform(#[source] OptionParserError),
    /// Failed parsing vDPA device
    #[error("Error parsing --vdpa")]
    ParseVdpa(#[source] OptionParserError),
    /// Missing path for vDPA device
    #[error("Error parsing --vdpa: path missing")]
    ParseVdpaPathMissing,
    /// Failed parsing TPM device
    #[error("Error parsing --tpm")]
    ParseTpm(#[source] OptionParserError),
    #[cfg(feature = "ivshmem")]
    /// Failed parsing ivsmem device
    #[error("Error parsing --ivshmem")]
    ParseIvshmem(#[source] OptionParserError),
    /// Missing path for TPM device
    #[error("Error parsing --tpm: path missing")]
    ParseTpmPathMissing,
    #[cfg(feature = "ivshmem")]
    /// Missing path for ivsmem device
    #[error("Error parsing --ivshmem: path missing")]
    ParseIvshmemPathMissing,
    /// Error parsing Landlock rules
    #[error("Error parsing --landlock-rules")]
    ParseLandlockRules(#[source] OptionParserError),
    /// Missing fields in Landlock rules
    #[error("Error parsing --landlock-rules: path/access field missing")]
    ParseLandlockMissingFields,
    #[cfg(feature = "fw_cfg")]
    /// Failed Parsing FwCfgItem config
    #[error("Error parsing --fw-cfg-config items")]
    ParseFwCfgItem(#[source] OptionParserError),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// Missing file value for console
    #[error("Path missing when using file console mode")]
    ConsoleFileMissing,
    /// Missing socket path for console
    #[error("Path missing when using socket console mode")]
    ConsoleSocketPathMissing,
    /// Max is less than boot
    #[error("Max CPUs lower than boot CPUs")]
    CpusMaxLowerThanBoot,
    /// Missing file value for debug-console
    #[cfg(target_arch = "x86_64")]
    #[error("Path missing when using file mode for debug console")]
    DebugconFileMissing,
    /// Both socket and path specified
    #[error("Disk path and vhost socket both provided")]
    DiskSocketAndPath,
    /// Using vhost user requires shared memory
    #[error("Using vhost-user requires using shared memory or huge pages")]
    VhostUserRequiresSharedMemory,
    /// No socket provided for vhost_use
    #[error("No socket provided when using vhost-user")]
    VhostUserMissingSocket,
    /// Trying to use IOMMU without PCI
    #[error("Using an IOMMU without PCI support is unsupported")]
    IommuUnsupported,
    /// Trying to use VFIO without PCI
    #[error("Using VFIO without PCI support is unsupported")]
    VfioUnsupported,
    /// CPU topology count doesn't match max
    #[error("Product of CPU topology parts does not match maximum vCPU")]
    CpuTopologyCount,
    /// One part of the CPU topology was zero
    #[error("No part of the CPU topology can be zero")]
    CpuTopologyZeroPart,
    #[cfg(target_arch = "aarch64")]
    /// Dies per package must be 1
    #[error("Dies per package must be 1")]
    CpuTopologyDiesPerPackage,
    /// Virtio needs a min of 2 queues
    #[error("Number of queues to virtio_net less than 2")]
    VnetQueueLowerThan2,
    /// The input queue number for virtio_net must match the number of input fds
    #[error("Number of queues to virtio_net does not match the number of input FDs")]
    VnetQueueFdMismatch,
    /// Using reserved fd
    #[error("Reserved fd number (<= 2)")]
    VnetReservedFd,
    /// Hardware checksum offload is disabled.
    #[error("\"offload_tso\" and \"offload_ufo\" depend on \"offload_csum\"")]
    NoHardwareChecksumOffload,
    /// Hugepages not turned on
    #[error("Huge page size specified but huge pages not enabled")]
    HugePageSizeWithoutHugePages,
    /// Huge page size is not power of 2
    #[error("Huge page size is not power of 2: {0}")]
    InvalidHugePageSize(u64),
    /// CPU Hotplug is not permitted with TDX
    #[cfg(feature = "tdx")]
    #[error("CPU hotplug is not permitted with TDX")]
    TdxNoCpuHotplug,
    /// Missing firmware for TDX
    #[cfg(feature = "tdx")]
    #[error("No TDX firmware specified")]
    TdxFirmwareMissing,
    /// Insufficient vCPUs for queues
    #[error("Number of vCPUs is insufficient for number of queues")]
    TooManyQueues,
    /// Invalid queue size
    #[error("Queue size is smaller than {MINIMUM_BLOCK_QUEUE_SIZE}: {0}")]
    InvalidQueueSize(u16),
    /// Need shared memory for vfio-user
    #[error("Using user devices requires using shared memory or huge pages")]
    UserDevicesRequireSharedMemory,
    /// VSOCK Context Identifier has a special meaning, unsuitable for a VM.
    #[error("{0} is a special VSOCK CID")]
    VsockSpecialCid(u32),
    /// Memory zone is reused across NUMA nodes
    #[error("Memory zone: {0} belongs to multiple NUMA nodes: {1} and {2}")]
    MemoryZoneReused(String, u32, u32),
    /// Invalid number of PCI segments
    #[error("Number of PCI segments ({0}) not in range of 1 to {MAX_NUM_PCI_SEGMENTS}")]
    InvalidNumPciSegments(u16),
    /// Invalid PCI segment id
    #[error("Invalid PCI segment id: {0}")]
    InvalidPciSegment(u16),
    /// Invalid PCI segment aperture weight
    #[error("Invalid PCI segment aperture weight: {0}")]
    InvalidPciSegmentApertureWeight(u32),
    /// Invalid IOMMU address width in bits
    #[error("IOMMU address width in bits ({0}) should be less than or equal to {MAX_IOMMU_ADDRESS_WIDTH_BITS}")]
    InvalidIommuAddressWidthBits(u8),
    /// Balloon too big
    #[error("Ballon size ({0}) greater than RAM ({1})")]
    BalloonLargerThanRam(u64, u64),
    /// On a IOMMU segment but not behind IOMMU
    #[error("Device is on an IOMMU PCI segment ({0}) but not placed behind IOMMU")]
    OnIommuSegment(u16),
    // On a IOMMU segment but IOMMU not supported
    #[error(
        "Device is on an IOMMU PCI segment ({0}) but does not support being placed behind IOMMU"
    )]
    IommuNotSupportedOnSegment(u16),
    // Identifier is not unique
    #[error("Identifier {0} is not unique")]
    IdentifierNotUnique(String),
    /// Invalid identifier
    #[error("Identifier {0} is not invalid")]
    InvalidIdentifier(String),
    /// Placing the device behind a virtual IOMMU is not supported
    #[error("Device does not support being placed behind IOMMU")]
    IommuNotSupported,
    /// Duplicated device path (device added twice)
    #[error("Duplicated device path: {0}")]
    DuplicateDevicePath(String),
    /// Provided MTU is lower than what the VIRTIO specification expects
    #[error("Provided MTU {0} is lower than 1280 (expected by VIRTIO specification)")]
    InvalidMtu(u16),
    /// PCI segment is reused across NUMA nodes
    #[error("PCI segment: {0} belongs to multiple NUMA nodes {1} and {2}")]
    PciSegmentReused(u16, u32, u32),
    /// Default PCI segment is assigned to NUMA node other than 0.
    #[error("Default PCI segment assigned to non-zero NUMA node {0}")]
    DefaultPciSegmentInvalidNode(u32),
    /// Invalid rate-limiter group
    #[error("Invalid rate-limiter group")]
    InvalidRateLimiterGroup,
    /// The specified I/O port was invalid. It should be provided in hex, such as `0xe9`.
    #[cfg(target_arch = "x86_64")]
    #[error("The IO port was not properly provided in hex or a `0x` prefix is missing: {0}")]
    InvalidIoPortHex(String),
    #[cfg(feature = "sev_snp")]
    #[error("Invalid host data format")]
    InvalidHostData,
    /// Restore expects all net ids that have fds
    #[error("Net id {0} is associated with FDs and is required")]
    RestoreMissingRequiredNetId(String),
    /// Number of FDs passed during Restore are incorrect to the NetConfig
    #[error("Number of Net FDs passed for '{0}' during Restore: {1}. Expected: {2}")]
    RestoreNetFdCountMismatch(String, usize, usize),
    /// Path provided in landlock-rules doesn't exist
    #[error("Path {0:?} provided in landlock-rules does not exist")]
    LandlockPathDoesNotExist(PathBuf),
    /// Access provided in landlock-rules in invalid
    #[error("access provided in landlock-rules in invalid")]
    InvalidLandlockAccess(String),
    /// Invalid block device serial length
    #[error("Block device serial length ({0}) exceeds maximum allowed length ({1})")]
    InvalidSerialLength(usize, usize),
    #[cfg(feature = "fw_cfg")]
    /// FwCfg missing kernel
    #[error("Error --fw-cfg-config: missing --kernel")]
    FwCfgMissingKernel,
    #[cfg(feature = "fw_cfg")]
    /// FwCfg missing cmdline
    #[error("Error --fw-cfg-config: missing --cmdline")]
    FwCfgMissingCmdline,
    #[cfg(feature = "fw_cfg")]
    /// FwCfg missing initramfs
    #[error("Error --fw-cfg-config: missing --initramfs")]
    FwCfgMissingInitramfs,
    #[cfg(feature = "ivshmem")]
    /// Invalid Ivshmem input size
    #[error("Invalid ivshmem input size")]
    InvalidIvshmemInputSize(u64),
    #[cfg(feature = "ivshmem")]
    /// Invalid Ivshmem backend file size
    #[error("Invalid ivshmem backend file size")]
    InvalidIvshmemSize(u64),
    #[cfg(feature = "ivshmem")]
    /// Invalid Ivshmem backend file path
    #[error("Invalid ivshmem backend file path")]
    InvalidIvshmemPath,
    #[error("Payload configuration is not bootable")]
    PayloadError(#[from] PayloadConfigError),
}

type ValidationResult<T> = std::result::Result<T, ValidationError>;

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
    pub rate_limit_groups: Option<Vec<&'a str>>,
    pub disks: Option<Vec<&'a str>>,
    pub net: Option<Vec<&'a str>>,
    pub rng: &'a str,
    pub balloon: Option<&'a str>,
    pub fs: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
    pub serial: &'a str,
    pub console: &'a str,
    #[cfg(target_arch = "x86_64")]
    pub debug_console: &'a str,
    pub devices: Option<Vec<&'a str>>,
    pub user_devices: Option<Vec<&'a str>>,
    pub vdpa: Option<Vec<&'a str>>,
    pub vsock: Option<&'a str>,
    #[cfg(feature = "pvmemcontrol")]
    pub pvmemcontrol: bool,
    pub pvpanic: bool,
    pub numa: Option<Vec<&'a str>>,
    pub watchdog: bool,
    #[cfg(feature = "guest_debug")]
    pub gdb: bool,
    pub pci_segments: Option<Vec<&'a str>>,
    pub platform: Option<&'a str>,
    pub tpm: Option<&'a str>,
    #[cfg(feature = "igvm")]
    pub igvm: Option<&'a str>,
    #[cfg(feature = "sev_snp")]
    pub host_data: Option<&'a str>,
    pub landlock_enable: bool,
    pub landlock_rules: Option<Vec<&'a str>>,
    #[cfg(feature = "fw_cfg")]
    pub fw_cfg_config: Option<&'a str>,
    #[cfg(feature = "ivshmem")]
    pub ivshmem: Option<&'a str>,
}

impl<'a> VmParams<'a> {
    pub fn from_arg_matches(args: &'a ArgMatches) -> Self {
        // These .unwrap()s cannot fail as there is a default value defined
        let cpus = args.get_one::<String>("cpus").unwrap();
        let memory = args.get_one::<String>("memory").unwrap();
        let memory_zones: Option<Vec<&str>> = args
            .get_many::<String>("memory-zone")
            .map(|x| x.map(|y| y as &str).collect());
        let rng = args.get_one::<String>("rng").unwrap();
        let serial = args.get_one::<String>("serial").unwrap();
        let firmware = args.get_one::<String>("firmware").map(|x| x as &str);
        let kernel = args.get_one::<String>("kernel").map(|x| x as &str);
        let initramfs = args.get_one::<String>("initramfs").map(|x| x as &str);
        let cmdline = args.get_one::<String>("cmdline").map(|x| x as &str);
        let rate_limit_groups: Option<Vec<&str>> = args
            .get_many::<String>("rate-limit-group")
            .map(|x| x.map(|y| y as &str).collect());
        let disks: Option<Vec<&str>> = args
            .get_many::<String>("disk")
            .map(|x| x.map(|y| y as &str).collect());
        let net: Option<Vec<&str>> = args
            .get_many::<String>("net")
            .map(|x| x.map(|y| y as &str).collect());
        let console = args.get_one::<String>("console").unwrap();
        #[cfg(target_arch = "x86_64")]
        let debug_console = args.get_one::<String>("debug-console").unwrap().as_str();
        let balloon = args.get_one::<String>("balloon").map(|x| x as &str);
        let fs: Option<Vec<&str>> = args
            .get_many::<String>("fs")
            .map(|x| x.map(|y| y as &str).collect());
        let pmem: Option<Vec<&str>> = args
            .get_many::<String>("pmem")
            .map(|x| x.map(|y| y as &str).collect());
        let devices: Option<Vec<&str>> = args
            .get_many::<String>("device")
            .map(|x| x.map(|y| y as &str).collect());
        let user_devices: Option<Vec<&str>> = args
            .get_many::<String>("user-device")
            .map(|x| x.map(|y| y as &str).collect());
        let vdpa: Option<Vec<&str>> = args
            .get_many::<String>("vdpa")
            .map(|x| x.map(|y| y as &str).collect());
        let vsock: Option<&str> = args.get_one::<String>("vsock").map(|x| x as &str);
        #[cfg(feature = "pvmemcontrol")]
        let pvmemcontrol = args.get_flag("pvmemcontrol");
        let pvpanic = args.get_flag("pvpanic");
        let numa: Option<Vec<&str>> = args
            .get_many::<String>("numa")
            .map(|x| x.map(|y| y as &str).collect());
        let watchdog = args.get_flag("watchdog");
        let pci_segments: Option<Vec<&str>> = args
            .get_many::<String>("pci-segment")
            .map(|x| x.map(|y| y as &str).collect());
        let platform = args.get_one::<String>("platform").map(|x| x as &str);
        #[cfg(feature = "guest_debug")]
        let gdb = args.contains_id("gdb");
        let tpm: Option<&str> = args.get_one::<String>("tpm").map(|x| x as &str);
        #[cfg(feature = "igvm")]
        let igvm = args.get_one::<String>("igvm").map(|x| x as &str);
        #[cfg(feature = "sev_snp")]
        let host_data = args.get_one::<String>("host-data").map(|x| x as &str);
        let landlock_enable = args.get_flag("landlock");
        let landlock_rules: Option<Vec<&str>> = args
            .get_many::<String>("landlock-rules")
            .map(|x| x.map(|y| y as &str).collect());
        #[cfg(feature = "fw_cfg")]
        let fw_cfg_config: Option<&str> =
            args.get_one::<String>("fw-cfg-config").map(|x| x as &str);
        #[cfg(feature = "ivshmem")]
        let ivshmem: Option<&str> = args.get_one::<String>("ivshmem").map(|x| x as &str);
        VmParams {
            cpus,
            memory,
            memory_zones,
            firmware,
            kernel,
            initramfs,
            cmdline,
            rate_limit_groups,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            #[cfg(target_arch = "x86_64")]
            debug_console,
            devices,
            user_devices,
            vdpa,
            vsock,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol,
            pvpanic,
            numa,
            watchdog,
            #[cfg(feature = "guest_debug")]
            gdb,
            pci_segments,
            platform,
            tpm,
            #[cfg(feature = "igvm")]
            igvm,
            #[cfg(feature = "sev_snp")]
            host_data,
            landlock_enable,
            landlock_rules,
            #[cfg(feature = "fw_cfg")]
            fw_cfg_config,
            #[cfg(feature = "ivshmem")]
            ivshmem,
        }
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
            .convert::<Tuple<u8, Vec<usize>>>("affinity")
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

impl PciSegmentConfig {
    pub const SYNTAX: &'static str = "PCI Segment parameters \
         \"pci_segment=<segment_id>,mmio32_aperture_weight=<scale>,mmio64_aperture_weight=<scale>\"";

    pub fn parse(disk: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("mmio32_aperture_weight")
            .add("mmio64_aperture_weight")
            .add("pci_segment");
        parser.parse(disk).map_err(Error::ParsePciSegment)?;

        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParsePciSegment)?
            .unwrap_or_default();
        let mmio32_aperture_weight = parser
            .convert("mmio32_aperture_weight")
            .map_err(Error::ParsePciSegment)?
            .unwrap_or(DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT);
        let mmio64_aperture_weight = parser
            .convert("mmio64_aperture_weight")
            .map_err(Error::ParsePciSegment)?
            .unwrap_or(DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT);

        Ok(PciSegmentConfig {
            pci_segment,
            mmio32_aperture_weight,
            mmio64_aperture_weight,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        let num_pci_segments = match &vm_config.platform {
            Some(platform_config) => platform_config.num_pci_segments,
            None => 1,
        };

        if self.pci_segment >= num_pci_segments {
            return Err(ValidationError::InvalidPciSegment(self.pci_segment));
        }

        if self.mmio32_aperture_weight == 0 {
            return Err(ValidationError::InvalidPciSegmentApertureWeight(
                self.mmio32_aperture_weight,
            ));
        }

        if self.mmio64_aperture_weight == 0 {
            return Err(ValidationError::InvalidPciSegmentApertureWeight(
                self.mmio64_aperture_weight,
            ));
        }

        Ok(())
    }
}

impl PlatformConfig {
    pub fn parse(platform: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("num_pci_segments")
            .add("iommu_segments")
            .add("iommu_address_width")
            .add("serial_number")
            .add("uuid")
            .add("oem_strings");
        #[cfg(feature = "tdx")]
        parser.add("tdx");
        #[cfg(feature = "sev_snp")]
        parser.add("sev_snp");
        parser.parse(platform).map_err(Error::ParsePlatform)?;

        let num_pci_segments: u16 = parser
            .convert("num_pci_segments")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(DEFAULT_NUM_PCI_SEGMENTS);
        let iommu_segments = parser
            .convert::<IntegerList>("iommu_segments")
            .map_err(Error::ParsePlatform)?
            .map(|v| v.0.iter().map(|e| *e as u16).collect());
        let iommu_address_width_bits: u8 = parser
            .convert("iommu_address_width")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(MAX_IOMMU_ADDRESS_WIDTH_BITS);
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
        #[cfg(feature = "sev_snp")]
        let sev_snp = parser
            .convert::<Toggle>("sev_snp")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(Toggle(false))
            .0;
        Ok(PlatformConfig {
            num_pci_segments,
            iommu_segments,
            iommu_address_width_bits,
            serial_number,
            uuid,
            oem_strings,
            #[cfg(feature = "tdx")]
            tdx,
            #[cfg(feature = "sev_snp")]
            sev_snp,
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

        if self.iommu_address_width_bits > MAX_IOMMU_ADDRESS_WIDTH_BITS {
            return Err(ValidationError::InvalidIommuAddressWidthBits(
                self.iommu_address_width_bits,
            ));
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

impl RateLimiterGroupConfig {
    pub const SYNTAX: &'static str = "Rate Limit Group parameters \
        \"bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
        ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,\
        id=<device_id>\"";

    pub fn parse(rate_limit_group: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("id");
        parser
            .parse(rate_limit_group)
            .map_err(Error::ParseRateLimiterGroup)?;

        let id = parser.get("id").unwrap_or_default();
        let bw_size = parser
            .convert("bw_size")
            .map_err(Error::ParseRateLimiterGroup)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(Error::ParseRateLimiterGroup)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(Error::ParseRateLimiterGroup)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(Error::ParseRateLimiterGroup)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(Error::ParseRateLimiterGroup)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(Error::ParseRateLimiterGroup)?
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

        Ok(RateLimiterGroupConfig {
            id,
            rate_limiter_config: RateLimiterConfig {
                bandwidth: bw_tb_config,
                ops: ops_tb_config,
            },
        })
    }

    pub fn validate(&self, _vm_config: &VmConfig) -> ValidationResult<()> {
        if self.rate_limiter_config.bandwidth.is_none() && self.rate_limiter_config.ops.is_none() {
            return Err(ValidationError::InvalidRateLimiterGroup);
        }

        if self.id.is_empty() {
            return Err(ValidationError::InvalidRateLimiterGroup);
        }

        Ok(())
    }
}

impl DiskConfig {
    pub const SYNTAX: &'static str = "Disk parameters \
         \"path=<disk_image_path>,readonly=on|off,direct=on|off,iommu=on|off,\
         num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\
         vhost_user=on|off,socket=<vhost_user_socket_path>,\
         bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
         ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,\
         id=<device_id>,pci_segment=<segment_id>,rate_limit_group=<group_id>,\
         queue_affinity=<list_of_queue_indices_with_their_associated_cpuset>,\
         serial=<serial_number>";

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
            .add("_disable_aio")
            .add("pci_segment")
            .add("serial")
            .add("rate_limit_group")
            .add("queue_affinity");
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
        let disable_aio = parser
            .convert::<Toggle>("_disable_aio")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let rate_limit_group = parser.get("rate_limit_group");
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
        let serial = parser.get("serial");
        let queue_affinity = parser
            .convert::<Tuple<u16, Vec<usize>>>("queue_affinity")
            .map_err(Error::ParseDisk)?
            .map(|v| {
                v.0.iter()
                    .map(|(e1, e2)| VirtQueueAffinity {
                        queue_index: *e1,
                        host_cpus: e2.clone(),
                    })
                    .collect()
            });
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
            rate_limit_group,
            rate_limiter_config,
            id,
            disable_io_uring,
            disable_aio,
            pci_segment,
            serial,
            queue_affinity,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        if self.queue_size <= MINIMUM_BLOCK_QUEUE_SIZE {
            return Err(ValidationError::InvalidQueueSize(self.queue_size));
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

        if self.rate_limiter_config.is_some() && self.rate_limit_group.is_some() {
            return Err(ValidationError::InvalidRateLimiterGroup);
        }

        // Check Block device serial length
        if let Some(ref serial) = self.serial {
            if serial.len() > VIRTIO_BLK_ID_BYTES as usize {
                return Err(ValidationError::InvalidSerialLength(
                    serial.len(),
                    VIRTIO_BLK_ID_BYTES as usize,
                ));
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
    pub const SYNTAX: &'static str = "Network parameters \
    \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,fd=<fd1,fd2...>,iommu=on|off,\
    num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,id=<device_id>,\
    vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>,vhost_mode=client|server,\
    bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
    ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,pci_segment=<segment_id>\
    offload_tso=on|off,offload_ufo=on|off,offload_csum=on|off\"";

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
    pub const SYNTAX: &'static str =
        "Balloon parameters \"size=<balloon_size>,deflate_on_oom=on|off,\
        free_page_reporting=on|off\"";

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
    pub const SYNTAX: &'static str = "virtio-fs parameters \
    \"tag=<tag_name>,socket=<socket_path>,num_queues=<number_of_queues>,\
    queue_size=<size_of_each_queue>,id=<device_id>,pci_segment=<segment_id>\"";

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
        if tag.len() > virtio_devices::vhost_user::VIRTIO_FS_TAG_LEN {
            return Err(Error::ParseFsTagTooLong);
        }
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

#[cfg(feature = "fw_cfg")]
impl FwCfgConfig {
    pub const SYNTAX: &'static str = "Boot params to pass to FW CFG device \
    \"e820=on|off,kernel=on|off,cmdline=on|off,initramfs=on|off,acpi_table=on|off, \
    items=[name0=<backing_file_path>,file0=<file_path>:name1=<backing_file_path>,file1=<file_path>]\"";
    pub fn parse(fw_cfg_config: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("e820")
            .add("kernel")
            .add("cmdline")
            .add("initramfs")
            .add("acpi_table")
            .add("items");
        parser.parse(fw_cfg_config).map_err(Error::ParseFwCfgItem)?;
        let e820 = parser
            .convert::<Toggle>("e820")
            .map_err(Error::ParseFwCfgItem)?
            .unwrap_or(Toggle(true))
            .0;
        let kernel = parser
            .convert::<Toggle>("kernel")
            .map_err(Error::ParseFwCfgItem)?
            .unwrap_or(Toggle(true))
            .0;
        let cmdline = parser
            .convert::<Toggle>("cmdline")
            .map_err(Error::ParseFwCfgItem)?
            .unwrap_or(Toggle(true))
            .0;
        let initramfs = parser
            .convert::<Toggle>("initramfs")
            .map_err(Error::ParseFwCfgItem)?
            .unwrap_or(Toggle(true))
            .0;
        let acpi_tables = parser
            .convert::<Toggle>("acpi_table")
            .map_err(Error::ParseFwCfgItem)?
            .unwrap_or(Toggle(true))
            .0;
        let items = if parser.is_set("items") {
            Some(
                parser
                    .convert::<FwCfgItemList>("items")
                    .map_err(Error::ParseFwCfgItem)?
                    .unwrap(),
            )
        } else {
            None
        };

        Ok(FwCfgConfig {
            e820,
            kernel,
            cmdline,
            initramfs,
            acpi_tables,
            items,
        })
    }
    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        let payload = vm_config.payload.as_ref().unwrap();
        if self.kernel && payload.kernel.is_none() {
            return Err(ValidationError::FwCfgMissingKernel);
        } else if self.cmdline && payload.cmdline.is_none() {
            return Err(ValidationError::FwCfgMissingCmdline);
        } else if self.initramfs && payload.initramfs.is_none() {
            return Err(ValidationError::FwCfgMissingInitramfs);
        }
        Ok(())
    }
}

#[cfg(feature = "fw_cfg")]
impl FwCfgItem {
    pub fn parse(fw_cfg: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("name").add("file");
        parser.parse(fw_cfg).map_err(Error::ParseFwCfgItem)?;

        let name =
            parser
                .get("name")
                .ok_or(Error::ParseFwCfgItem(OptionParserError::InvalidValue(
                    "missing FwCfgItem name".to_string(),
                )))?;
        let file = parser
            .get("file")
            .map(PathBuf::from)
            .ok_or(Error::ParseFwCfgItem(OptionParserError::InvalidValue(
                "missing FwCfgItem file path".to_string(),
            )))?;
        Ok(FwCfgItem { name, file })
    }
}

impl PmemConfig {
    pub const SYNTAX: &'static str = "Persistent memory parameters \
    \"file=<backing_file_path>,size=<persistent_memory_size>,iommu=on|off,\
    discard_writes=on|off,id=<device_id>,pci_segment=<segment_id>\"";

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
            .add("iommu")
            .add("socket");
        parser.parse(console).map_err(Error::ParseConsole)?;

        let mut file: Option<PathBuf> = default_consoleconfig_file();
        let mut socket: Option<PathBuf> = None;
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
        } else if parser.is_set("socket") {
            mode = ConsoleOutputMode::Socket;
            socket = Some(PathBuf::from(parser.get("socket").ok_or(
                Error::Validation(ValidationError::ConsoleSocketPathMissing),
            )?));
        } else {
            return Err(Error::ParseConsoleInvalidModeGiven);
        }
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseConsole)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(Self {
            file,
            mode,
            iommu,
            socket,
        })
    }
}

#[cfg(target_arch = "x86_64")]
impl DebugConsoleConfig {
    pub fn parse(debug_console_ops: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add_valueless("off")
            .add_valueless("pty")
            .add_valueless("tty")
            .add_valueless("null")
            .add("file")
            .add("iobase");
        parser
            .parse(debug_console_ops)
            .map_err(Error::ParseConsole)?;

        let mut file: Option<PathBuf> = default_consoleconfig_file();
        let mut iobase: Option<u16> = None;
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

        if parser.is_set("iobase") {
            if let Some(iobase_opt) = parser.get("iobase") {
                if !iobase_opt.starts_with("0x") {
                    return Err(Error::Validation(ValidationError::InvalidIoPortHex(
                        iobase_opt,
                    )));
                }
                iobase = Some(u16::from_str_radix(&iobase_opt[2..], 16).map_err(|_| {
                    Error::Validation(ValidationError::InvalidIoPortHex(iobase_opt))
                })?);
            }
        }

        Ok(Self { file, mode, iobase })
    }
}

impl DeviceConfig {
    pub const SYNTAX: &'static str =
        "Direct device assignment parameters \"path=<device_path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>\"";

    pub fn parse(device: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("id")
            .add("iommu")
            .add("pci_segment")
            .add("x_nv_gpudirect_clique");
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
        let x_nv_gpudirect_clique = parser
            .convert::<u8>("x_nv_gpudirect_clique")
            .map_err(Error::ParseDevice)?;
        Ok(DeviceConfig {
            path,
            iommu,
            id,
            pci_segment,
            x_nv_gpudirect_clique,
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
    pub const SYNTAX: &'static str =
        "Userspace device socket=<socket_path>,id=<device_id>,pci_segment=<segment_id>\"";

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
    pub const SYNTAX: &'static str = "vDPA device \
        \"path=<device_path>,num_queues=<number_of_queues>,iommu=on|off,\
        id=<device_id>,pci_segment=<segment_id>\"";

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
    pub const SYNTAX: &'static str = "Virtio VSOCK parameters \
        \"cid=<context_id>,socket=<socket_path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>\"";

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

impl NumaConfig {
    pub const SYNTAX: &'static str = "Settings related to a given NUMA node \
        \"guest_numa_id=<node_id>,cpus=<cpus_id>,distances=<list_of_distances_to_destination_nodes>,\
        memory_zones=<list_of_memory_zones>,\
        pci_segments=<list_of_pci_segments>\"";

    pub fn parse(numa: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("guest_numa_id")
            .add("cpus")
            .add("distances")
            .add("memory_zones")
            .add("pci_segments");

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
        let pci_segments = parser
            .convert::<IntegerList>("pci_segments")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0.iter().map(|e| *e as u16).collect());
        Ok(NumaConfig {
            guest_numa_id,
            cpus,
            distances,
            memory_zones,
            pci_segments,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoredNetConfig {
    pub id: String,
    #[serde(default)]
    pub num_fds: usize,
    #[serde(
        default,
        serialize_with = "serialize_restorednetconfig_fds",
        deserialize_with = "deserialize_restorednetconfig_fds"
    )]
    pub fds: Option<Vec<i32>>,
}

fn serialize_restorednetconfig_fds<S>(
    x: &Option<Vec<i32>>,
    s: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(x) = x {
        warn!("'RestoredNetConfig' contains FDs that can't be serialized correctly. Serializing them as invalid FDs.");
        let invalid_fds = vec![-1; x.len()];
        s.serialize_some(&invalid_fds)
    } else {
        s.serialize_none()
    }
}

fn deserialize_restorednetconfig_fds<'de, D>(
    d: D,
) -> std::result::Result<Option<Vec<i32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fds: Option<Vec<i32>> = Option::deserialize(d)?;
    if let Some(invalid_fds) = invalid_fds {
        warn!("'RestoredNetConfig' contains FDs that can't be deserialized correctly. Deserializing them as invalid FDs.");
        Ok(Some(vec![-1; invalid_fds.len()]))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoreConfig {
    pub source_url: PathBuf,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub net_fds: Option<Vec<RestoredNetConfig>>,
}

impl RestoreConfig {
    pub const SYNTAX: &'static str = "Restore from a VM snapshot. \
        \nRestore parameters \"source_url=<source_url>,prefault=on|off,\
        net_fds=<list_of_net_ids_with_their_associated_fds>\" \
        \n`source_url` should be a valid URL (e.g file:///foo/bar or tcp://192.168.1.10/foo) \
        \n`prefault` brings memory pages in when enabled (disabled by default) \
        \n`net_fds` is a list of net ids with new file descriptors. \
        Only net devices backed by FDs directly are needed as input.";

    pub fn parse(restore: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("source_url").add("prefault").add("net_fds");
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
        let net_fds = parser
            .convert::<Tuple<String, Vec<u64>>>("net_fds")
            .map_err(Error::ParseRestore)?
            .map(|v| {
                v.0.iter()
                    .map(|(id, fds)| RestoredNetConfig {
                        id: id.clone(),
                        num_fds: fds.len(),
                        fds: Some(fds.iter().map(|e| *e as i32).collect()),
                    })
                    .collect()
            });

        Ok(RestoreConfig {
            source_url,
            prefault,
            net_fds,
        })
    }

    // Ensure all net devices from 'VmConfig' backed by FDs have a
    // corresponding 'RestoreNetConfig' with a matched 'id' and expected
    // number of FDs.
    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        let mut restored_net_with_fds = HashMap::new();
        for n in self.net_fds.iter().flatten() {
            assert_eq!(
                n.num_fds,
                n.fds.as_ref().map_or(0, |f| f.len()),
                "Invalid 'RestoredNetConfig' with conflicted fields."
            );
            if restored_net_with_fds.insert(n.id.clone(), n).is_some() {
                return Err(ValidationError::IdentifierNotUnique(n.id.clone()));
            }
        }

        for net_fds in vm_config.net.iter().flatten() {
            if let Some(expected_fds) = &net_fds.fds {
                let expected_id = net_fds
                    .id
                    .as_ref()
                    .expect("Invalid 'NetConfig' with empty 'id' for VM restore.");
                if let Some(r) = restored_net_with_fds.remove(expected_id) {
                    if r.num_fds != expected_fds.len() {
                        return Err(ValidationError::RestoreNetFdCountMismatch(
                            expected_id.clone(),
                            r.num_fds,
                            expected_fds.len(),
                        ));
                    }
                } else {
                    return Err(ValidationError::RestoreMissingRequiredNetId(
                        expected_id.clone(),
                    ));
                }
            }
        }

        if !restored_net_with_fds.is_empty() {
            warn!("Ignoring unused 'net_fds' for VM restore.")
        }

        Ok(())
    }
}

impl TpmConfig {
    pub const SYNTAX: &'static str = "TPM device \
        \"(UNIX Domain Socket from swtpm) socket=</path/to/a/socket>\"";

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

impl LandlockConfig {
    pub const SYNTAX: &'static str = "Landlock parameters \
        \"path=<path/to/{file/dir}>,access=[rw]\"";

    pub fn parse(landlock_rule: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("path").add("access");
        parser
            .parse(landlock_rule)
            .map_err(Error::ParseLandlockRules)?;

        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(Error::ParseLandlockMissingFields)?;

        let access = parser
            .get("access")
            .ok_or(Error::ParseLandlockMissingFields)?;

        if access.chars().count() > 2 {
            return Err(Error::ParseLandlockRules(OptionParserError::InvalidValue(
                access.to_string(),
            )));
        }

        Ok(LandlockConfig { path, access })
    }

    pub fn validate(&self) -> ValidationResult<()> {
        if !self.path.exists() {
            return Err(ValidationError::LandlockPathDoesNotExist(self.path.clone()));
        }
        LandlockAccess::try_from(self.access.as_str())
            .map_err(|e| ValidationError::InvalidLandlockAccess(e.to_string()))?;
        Ok(())
    }
}

#[cfg(feature = "ivshmem")]
impl IvshmemConfig {
    pub const SYNTAX: &'static str = "Ivshmem device. Specify the backend file path and size \
    for the shared memory: \"path=</path/to/a/file>, size=<file_size>\" \
    \nThe <file_size> must be a power of 2 (e.g., 2M, 4M, etc.), as it represents the size \
    of the memory region mapped to the guest. Default size is 128M.";
    pub fn parse(ivshmem: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("path").add("size");
        parser.parse(ivshmem).map_err(Error::ParseIvshmem)?;
        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(Error::ParseIvshmemPathMissing)?;
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseIvshmem)?
            .unwrap_or(ByteSized((DEFAULT_IVSHMEM_SIZE << 20) as u64))
            .0;
        Ok(IvshmemConfig {
            path,
            size: size as usize,
        })
    }

    pub fn validate(&self) -> ValidationResult<()> {
        let size = self.size as u64;
        let path = &self.path;
        // size must = 2^n
        if !size.is_power_of_two() {
            return Err(ValidationError::InvalidIvshmemInputSize(size));
        }
        let metadata = fs::metadata(path.to_str().unwrap())
            .map_err(|_| ValidationError::InvalidIvshmemPath)?;
        if metadata.len() < size {
            return Err(ValidationError::InvalidIvshmemSize(metadata.len()));
        }
        Ok(())
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

        // Is the payload configuration bootable?
        self.payload
            .as_mut()
            .ok_or(ValidationError::PayloadError(
                PayloadConfigError::MissingBootitem,
            ))?
            .validate()?;

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

        #[cfg(feature = "sev_snp")]
        {
            let host_data_opt = &self.payload.as_ref().unwrap().host_data;

            if let Some(host_data) = host_data_opt {
                if host_data.len() != 64 {
                    return Err(ValidationError::InvalidHostData);
                }
            }
        }
        // The 'conflict' check is introduced in commit 24438e0390d3
        // (vm-virtio: Enable the vmm support for virtio-console).
        //
        // Allow simultaneously set serial and console as TTY mode, for
        // someone want to use virtio console for better performance, and
        // want to keep legacy serial to catch boot stage logs for debug.
        // Using such double tty mode, you need to configure the kernel
        // properly, such as:
        // "console=hvc0 earlyprintk=ttyS0"

        let mut tty_consoles = Vec::new();
        if self.console.mode == ConsoleOutputMode::Tty {
            tty_consoles.push("virtio-console");
        };
        if self.serial.mode == ConsoleOutputMode::Tty {
            tty_consoles.push("serial-console");
        };
        #[cfg(target_arch = "x86_64")]
        if self.debug_console.mode == ConsoleOutputMode::Tty {
            tty_consoles.push("debug-console");
        };
        if tty_consoles.len() > 1 {
            warn!("Using TTY output for multiple consoles: {:?}", tty_consoles);
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

        if let Some(rate_limit_groups) = &self.rate_limit_groups {
            for rate_limit_group in rate_limit_groups {
                rate_limit_group.validate(self)?;

                Self::validate_identifier(&mut id_list, &Some(rate_limit_group.id.clone()))?;
            }
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
                if let Some(rate_limit_group) = &disk.rate_limit_group {
                    if let Some(rate_limit_groups) = &self.rate_limit_groups {
                        if !rate_limit_groups
                            .iter()
                            .any(|cfg| &cfg.id == rate_limit_group)
                        {
                            return Err(ValidationError::InvalidRateLimiterGroup);
                        }
                    } else {
                        return Err(ValidationError::InvalidRateLimiterGroup);
                    }
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

            // The setting of dies doesn't apply on AArch64.
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

        if let Some(vsock) = &self.vsock {
            if [!0, 0, 1, 2].contains(&vsock.cid) {
                return Err(ValidationError::VsockSpecialCid(vsock.cid));
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

        let num_pci_segments = match &self.platform {
            Some(platform_config) => platform_config.num_pci_segments,
            None => 1,
        };
        if let Some(numa) = &self.numa {
            let mut used_numa_node_memory_zones = HashMap::new();
            let mut used_pci_segments = HashMap::new();
            for numa_node in numa.iter() {
                if let Some(memory_zones) = numa_node.memory_zones.clone() {
                    for memory_zone in memory_zones.iter() {
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

                if let Some(pci_segments) = numa_node.pci_segments.clone() {
                    for pci_segment in pci_segments.iter() {
                        if *pci_segment >= num_pci_segments {
                            return Err(ValidationError::InvalidPciSegment(*pci_segment));
                        }
                        if *pci_segment == 0 && numa_node.guest_numa_id != 0 {
                            return Err(ValidationError::DefaultPciSegmentInvalidNode(
                                numa_node.guest_numa_id,
                            ));
                        }
                        if !used_pci_segments.contains_key(pci_segment) {
                            used_pci_segments.insert(*pci_segment, numa_node.guest_numa_id);
                        } else {
                            return Err(ValidationError::PciSegmentReused(
                                *pci_segment,
                                *used_pci_segments.get(pci_segment).unwrap(),
                                numa_node.guest_numa_id,
                            ));
                        }
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

        if let Some(pci_segments) = &self.pci_segments {
            for pci_segment in pci_segments {
                pci_segment.validate(self)?;
            }
        }

        self.platform.as_ref().map(|p| p.validate()).transpose()?;
        self.iommu |= self
            .platform
            .as_ref()
            .map(|p| p.iommu_segments.is_some())
            .unwrap_or_default();

        if let Some(landlock_rules) = &self.landlock_rules {
            for landlock_rule in landlock_rules {
                landlock_rule.validate()?;
            }
        }
        #[cfg(feature = "ivshmem")]
        if let Some(ivshmem_config) = &self.ivshmem {
            ivshmem_config.validate()?;
        }

        Ok(id_list)
    }

    pub fn parse(vm_params: VmParams) -> Result<Self> {
        let mut rate_limit_groups: Option<Vec<RateLimiterGroupConfig>> = None;
        if let Some(rate_limit_group_list) = &vm_params.rate_limit_groups {
            let mut rate_limit_group_config_list = Vec::new();
            for item in rate_limit_group_list.iter() {
                let rate_limit_group_config = RateLimiterGroupConfig::parse(item)?;
                rate_limit_group_config_list.push(rate_limit_group_config);
            }
            rate_limit_groups = Some(rate_limit_group_config_list);
        }

        let mut disks: Option<Vec<DiskConfig>> = None;
        if let Some(disk_list) = &vm_params.disks {
            let mut disk_config_list = Vec::new();
            for item in disk_list.iter() {
                let disk_config = DiskConfig::parse(item)?;
                disk_config_list.push(disk_config);
            }
            disks = Some(disk_config_list);
        }

        #[cfg(feature = "fw_cfg")]
        let fw_cfg_config = if let Some(fw_cfg_config_str) = vm_params.fw_cfg_config {
            let fw_cfg_config = FwCfgConfig::parse(fw_cfg_config_str)?;
            Some(fw_cfg_config)
        } else {
            None
        };

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

        #[cfg(feature = "pvmemcontrol")]
        let pvmemcontrol: Option<PvmemcontrolConfig> = vm_params
            .pvmemcontrol
            .then_some(PvmemcontrolConfig::default());

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
        #[cfg(target_arch = "x86_64")]
        let debug_console = DebugConsoleConfig::parse(vm_params.debug_console)?;

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

        let mut pci_segments: Option<Vec<PciSegmentConfig>> = None;
        if let Some(pci_segment_list) = &vm_params.pci_segments {
            let mut pci_segment_config_list = Vec::new();
            for item in pci_segment_list.iter() {
                let pci_segment_config = PciSegmentConfig::parse(item)?;
                pci_segment_config_list.push(pci_segment_config);
            }
            pci_segments = Some(pci_segment_config_list);
        }

        let platform = vm_params.platform.map(PlatformConfig::parse).transpose()?;

        let mut numa: Option<Vec<NumaConfig>> = None;
        if let Some(numa_list) = &vm_params.numa {
            let mut numa_config_list = Vec::new();
            for item in numa_list.iter() {
                let numa_config = NumaConfig::parse(item)?;
                numa_config_list.push(numa_config);
            }
            numa = Some(numa_config_list);
        }

        #[cfg(not(feature = "igvm"))]
        let payload_present = vm_params.kernel.is_some() || vm_params.firmware.is_some();

        #[cfg(feature = "igvm")]
        let payload_present =
            vm_params.kernel.is_some() || vm_params.firmware.is_some() || vm_params.igvm.is_some();

        let payload = if payload_present {
            Some(PayloadConfig {
                kernel: vm_params.kernel.map(PathBuf::from),
                initramfs: vm_params.initramfs.map(PathBuf::from),
                cmdline: vm_params.cmdline.map(|s| s.to_string()),
                firmware: vm_params.firmware.map(PathBuf::from),
                #[cfg(feature = "igvm")]
                igvm: vm_params.igvm.map(PathBuf::from),
                #[cfg(feature = "sev_snp")]
                host_data: vm_params.host_data.map(|s| s.to_string()),
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config,
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

        let mut landlock_rules: Option<Vec<LandlockConfig>> = None;
        if let Some(ll_rules) = vm_params.landlock_rules {
            landlock_rules = Some(
                ll_rules
                    .iter()
                    .map(|rule| LandlockConfig::parse(rule))
                    .collect::<Result<Vec<LandlockConfig>>>()?,
            );
        }

        #[cfg(feature = "ivshmem")]
        let mut ivshmem: Option<IvshmemConfig> = None;
        #[cfg(feature = "ivshmem")]
        if let Some(iv) = vm_params.ivshmem {
            let ivshmem_conf = IvshmemConfig::parse(iv)?;
            ivshmem = Some(ivshmem_conf);
        }

        let mut config = VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory, vm_params.memory_zones)?,
            payload,
            rate_limit_groups,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            #[cfg(target_arch = "x86_64")]
            debug_console,
            devices,
            user_devices,
            vdpa,
            vsock,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol,
            pvpanic: vm_params.pvpanic,
            iommu: false, // updated in VmConfig::validate()
            numa,
            watchdog: vm_params.watchdog,
            #[cfg(feature = "guest_debug")]
            gdb,
            pci_segments,
            platform,
            tpm,
            preserved_fds: None,
            landlock_enable: vm_params.landlock_enable,
            landlock_rules,
            #[cfg(feature = "ivshmem")]
            ivshmem,
        };
        config.validate().map_err(Error::Validation)?;
        Ok(config)
    }

    pub fn remove_device(&mut self, id: &str) -> bool {
        let mut removed = false;

        // Remove if VFIO device
        if let Some(devices) = self.devices.as_mut() {
            let len = devices.len();
            devices.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= devices.len() != len;
        }

        // Remove if VFIO user device
        if let Some(user_devices) = self.user_devices.as_mut() {
            let len = user_devices.len();
            user_devices.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= user_devices.len() != len;
        }

        // Remove if disk device
        if let Some(disks) = self.disks.as_mut() {
            let len = disks.len();
            disks.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= disks.len() != len;
        }

        // Remove if fs device
        if let Some(fs) = self.fs.as_mut() {
            let len = fs.len();
            fs.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= fs.len() != len;
        }

        // Remove if net device
        if let Some(net) = self.net.as_mut() {
            let len = net.len();
            net.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= net.len() != len;
        }

        // Remove if pmem device
        if let Some(pmem) = self.pmem.as_mut() {
            let len = pmem.len();
            pmem.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= pmem.len() != len;
        }

        // Remove if vDPA device
        if let Some(vdpa) = self.vdpa.as_mut() {
            let len = vdpa.len();
            vdpa.retain(|dev| dev.id.as_ref().map(|id| id.as_ref()) != Some(id));
            removed |= vdpa.len() != len;
        }

        // Remove if vsock device
        if let Some(vsock) = self.vsock.as_ref() {
            if vsock.id.as_ref().map(|id| id.as_ref()) == Some(id) {
                self.vsock = None;
                removed = true;
            }
        }

        removed
    }

    /// # Safety
    /// To use this safely, the caller must guarantee that the input
    /// fds are all valid.
    pub unsafe fn add_preserved_fds(&mut self, mut fds: Vec<i32>) {
        if fds.is_empty() {
            return;
        }

        if let Some(preserved_fds) = &self.preserved_fds {
            fds.append(&mut preserved_fds.clone());
        }

        self.preserved_fds = Some(fds);
    }

    #[cfg(feature = "tdx")]
    pub fn is_tdx_enabled(&self) -> bool {
        self.platform.as_ref().map(|p| p.tdx).unwrap_or(false)
    }

    #[cfg(feature = "sev_snp")]
    pub fn is_sev_snp_enabled(&self) -> bool {
        self.platform.as_ref().map(|p| p.sev_snp).unwrap_or(false)
    }
}

impl Clone for VmConfig {
    fn clone(&self) -> Self {
        VmConfig {
            cpus: self.cpus.clone(),
            memory: self.memory.clone(),
            payload: self.payload.clone(),
            rate_limit_groups: self.rate_limit_groups.clone(),
            disks: self.disks.clone(),
            net: self.net.clone(),
            rng: self.rng.clone(),
            balloon: self.balloon.clone(),
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: self.pvmemcontrol.clone(),
            fs: self.fs.clone(),
            pmem: self.pmem.clone(),
            serial: self.serial.clone(),
            console: self.console.clone(),
            #[cfg(target_arch = "x86_64")]
            debug_console: self.debug_console.clone(),
            devices: self.devices.clone(),
            user_devices: self.user_devices.clone(),
            vdpa: self.vdpa.clone(),
            vsock: self.vsock.clone(),
            numa: self.numa.clone(),
            pci_segments: self.pci_segments.clone(),
            platform: self.platform.clone(),
            tpm: self.tpm.clone(),
            preserved_fds: self
                .preserved_fds
                .as_ref()
                // SAFETY: FFI call with valid FDs
                .map(|fds| fds.iter().map(|fd| unsafe { libc::dup(*fd) }).collect()),
            landlock_rules: self.landlock_rules.clone(),
            #[cfg(feature = "ivshmem")]
            ivshmem: self.ivshmem.clone(),
            ..*self
        }
    }
}

impl Drop for VmConfig {
    fn drop(&mut self) {
        if let Some(mut fds) = self.preserved_fds.take() {
            for fd in fds.drain(..) {
                // SAFETY: FFI call with valid FDs
                unsafe { libc::close(fd) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::io::AsRawFd;

    use net_util::MacAddr;

    use super::*;

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

        CpusConfig::parse("boot=8,topology=2:2:1").unwrap_err();
        CpusConfig::parse("boot=8,topology=2:2:1:x").unwrap_err();
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
    fn test_rate_limit_group_parsing() -> Result<()> {
        assert_eq!(
            RateLimiterGroupConfig::parse("id=group0,bw_size=1000,bw_refill_time=100")?,
            RateLimiterGroupConfig {
                id: "group0".to_string(),
                rate_limiter_config: RateLimiterConfig {
                    bandwidth: Some(TokenBucketConfig {
                        size: 1000,
                        one_time_burst: Some(0),
                        refill_time: 100,
                    }),
                    ops: None,
                }
            }
        );
        assert_eq!(
            RateLimiterGroupConfig::parse("id=group0,ops_size=1000,ops_refill_time=100")?,
            RateLimiterGroupConfig {
                id: "group0".to_string(),
                rate_limiter_config: RateLimiterConfig {
                    bandwidth: None,
                    ops: Some(TokenBucketConfig {
                        size: 1000,
                        one_time_burst: Some(0),
                        refill_time: 100,
                    }),
                }
            }
        );
        Ok(())
    }

    #[test]
    fn test_pci_segment_parsing() -> Result<()> {
        assert_eq!(
            PciSegmentConfig::parse("pci_segment=0")?,
            PciSegmentConfig {
                pci_segment: 0,
                mmio32_aperture_weight: 1,
                mmio64_aperture_weight: 1,
            }
        );
        assert_eq!(
            PciSegmentConfig::parse(
                "pci_segment=0,mmio32_aperture_weight=1,mmio64_aperture_weight=1"
            )?,
            PciSegmentConfig {
                pci_segment: 0,
                mmio32_aperture_weight: 1,
                mmio64_aperture_weight: 1,
            }
        );
        assert_eq!(
            PciSegmentConfig::parse("pci_segment=0,mmio32_aperture_weight=2")?,
            PciSegmentConfig {
                pci_segment: 0,
                mmio32_aperture_weight: 2,
                mmio64_aperture_weight: 1,
            }
        );
        assert_eq!(
            PciSegmentConfig::parse("pci_segment=0,mmio64_aperture_weight=2")?,
            PciSegmentConfig {
                pci_segment: 0,
                mmio32_aperture_weight: 1,
                mmio64_aperture_weight: 2,
            }
        );

        Ok(())
    }

    fn disk_fixture() -> DiskConfig {
        DiskConfig {
            path: Some(PathBuf::from("/path/to_file")),
            readonly: false,
            direct: false,
            iommu: false,
            num_queues: 1,
            queue_size: 128,
            vhost_user: false,
            vhost_socket: None,
            id: None,
            disable_io_uring: false,
            disable_aio: false,
            rate_limit_group: None,
            rate_limiter_config: None,
            pci_segment: 0,
            serial: None,
            queue_affinity: None,
        }
    }

    #[test]
    fn test_disk_parsing() -> Result<()> {
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig { ..disk_fixture() }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,id=mydisk0")?,
            DiskConfig {
                id: Some("mydisk0".to_owned()),
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("vhost_user=true,socket=/tmp/sock")?,
            DiskConfig {
                path: None,
                vhost_socket: Some(String::from("/tmp/sock")),
                vhost_user: true,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on")?,
            DiskConfig {
                iommu: true,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256")?,
            DiskConfig {
                iommu: true,
                queue_size: 256,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256,num_queues=4")?,
            DiskConfig {
                iommu: true,
                queue_size: 256,
                num_queues: 4,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,direct=on")?,
            DiskConfig {
                direct: true,
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,serial=test")?,
            DiskConfig {
                serial: Some(String::from("test")),
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,rate_limit_group=group0")?,
            DiskConfig {
                rate_limit_group: Some("group0".to_string()),
                ..disk_fixture()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,queue_affinity=[0@[1],1@[2],2@[3,4],3@[5-8]]")?,
            DiskConfig {
                queue_affinity: Some(vec![
                    VirtQueueAffinity {
                        queue_index: 0,
                        host_cpus: vec![1],
                    },
                    VirtQueueAffinity {
                        queue_index: 1,
                        host_cpus: vec![2],
                    },
                    VirtQueueAffinity {
                        queue_index: 2,
                        host_cpus: vec![3, 4],
                    },
                    VirtQueueAffinity {
                        queue_index: 3,
                        host_cpus: vec![5, 6, 7, 8],
                    }
                ]),
                ..disk_fixture()
            }
        );
        Ok(())
    }

    fn net_fixture() -> NetConfig {
        NetConfig {
            tap: None,
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 249, 1)),
            mask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
            host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
            mtu: None,
            iommu: false,
            num_queues: 2,
            queue_size: 256,
            vhost_user: false,
            vhost_socket: None,
            vhost_mode: VhostMode::Client,
            id: None,
            fds: None,
            rate_limiter_config: None,
            pci_segment: 0,
            offload_tso: true,
            offload_ufo: true,
            offload_csum: true,
        }
    }

    #[test]
    fn test_net_parsing() -> Result<()> {
        // mac address is random
        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef")?,
            net_fixture(),
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,id=mynet0")?,
            NetConfig {
                id: Some("mynet0".to_owned()),
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,tap=tap0,ip=192.168.100.1,mask=255.255.255.128"
            )?,
            NetConfig {
                tap: Some("tap0".to_owned()),
                ip: "192.168.100.1".parse().unwrap(),
                mask: "255.255.255.128".parse().unwrap(),
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,vhost_user=true,socket=/tmp/sock"
            )?,
            NetConfig {
                vhost_user: true,
                vhost_socket: Some("/tmp/sock".to_owned()),
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,num_queues=4,queue_size=1024,iommu=on")?,
            NetConfig {
                num_queues: 4,
                queue_size: 1024,
                iommu: true,
                ..net_fixture()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,fd=[3,7],num_queues=4")?,
            NetConfig {
                host_mac: None,
                fds: Some(vec![3, 7]),
                num_queues: 4,
                ..net_fixture()
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

    fn fs_fixture() -> FsConfig {
        FsConfig {
            socket: PathBuf::from("/tmp/sock"),
            tag: "mytag".to_owned(),
            num_queues: 1,
            queue_size: 1024,
            id: None,
            pci_segment: 0,
        }
    }

    #[test]
    fn test_parse_fs() -> Result<()> {
        // "tag" and "socket" must be supplied
        FsConfig::parse("").unwrap_err();
        FsConfig::parse("tag=mytag").unwrap_err();
        FsConfig::parse("socket=/tmp/sock").unwrap_err();
        assert_eq!(FsConfig::parse("tag=mytag,socket=/tmp/sock")?, fs_fixture());
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock,num_queues=4,queue_size=1024")?,
            FsConfig {
                num_queues: 4,
                queue_size: 1024,
                ..fs_fixture()
            }
        );

        Ok(())
    }

    fn pmem_fixture() -> PmemConfig {
        PmemConfig {
            file: PathBuf::from("/tmp/pmem"),
            size: Some(128 << 20),
            iommu: false,
            discard_writes: false,
            id: None,
            pci_segment: 0,
        }
    }

    #[test]
    fn test_pmem_parsing() -> Result<()> {
        // Must always give a file and size
        PmemConfig::parse("").unwrap_err();
        PmemConfig::parse("size=128M").unwrap_err();
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M")?,
            pmem_fixture()
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,id=mypmem0")?,
            PmemConfig {
                id: Some("mypmem0".to_owned()),
                ..pmem_fixture()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,iommu=on,discard_writes=on")?,
            PmemConfig {
                discard_writes: true,
                iommu: true,
                ..pmem_fixture()
            }
        );

        Ok(())
    }

    #[test]
    fn test_console_parsing() -> Result<()> {
        ConsoleConfig::parse("").unwrap_err();
        ConsoleConfig::parse("badmode").unwrap_err();
        assert_eq!(
            ConsoleConfig::parse("off")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Off,
                iommu: false,
                file: None,
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("pty")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Pty,
                iommu: false,
                file: None,
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("tty")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                file: None,
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("null")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: false,
                file: None,
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: false,
                file: Some(PathBuf::from("/tmp/console")),
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("null,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: true,
                file: None,
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: true,
                file: Some(PathBuf::from("/tmp/console")),
                socket: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("socket=/tmp/serial.sock,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Socket,
                iommu: true,
                file: None,
                socket: Some(PathBuf::from("/tmp/serial.sock")),
            }
        );
        Ok(())
    }

    fn device_fixture() -> DeviceConfig {
        DeviceConfig {
            path: PathBuf::from("/path/to/device"),
            id: None,
            iommu: false,
            pci_segment: 0,
            x_nv_gpudirect_clique: None,
        }
    }

    #[test]
    fn test_device_parsing() -> Result<()> {
        // Device must have a path provided
        DeviceConfig::parse("").unwrap_err();
        assert_eq!(
            DeviceConfig::parse("path=/path/to/device")?,
            device_fixture()
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on")?,
            DeviceConfig {
                iommu: true,
                ..device_fixture()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on,id=mydevice0")?,
            DeviceConfig {
                id: Some("mydevice0".to_owned()),
                iommu: true,
                ..device_fixture()
            }
        );

        Ok(())
    }

    fn vdpa_fixture() -> VdpaConfig {
        VdpaConfig {
            path: PathBuf::from("/dev/vhost-vdpa"),
            num_queues: 1,
            iommu: false,
            id: None,
            pci_segment: 0,
        }
    }

    #[test]
    fn test_vdpa_parsing() -> Result<()> {
        // path is required
        VdpaConfig::parse("").unwrap_err();
        assert_eq!(VdpaConfig::parse("path=/dev/vhost-vdpa")?, vdpa_fixture());
        assert_eq!(
            VdpaConfig::parse("path=/dev/vhost-vdpa,num_queues=2,id=my_vdpa")?,
            VdpaConfig {
                num_queues: 2,
                id: Some("my_vdpa".to_owned()),
                ..vdpa_fixture()
            }
        );
        Ok(())
    }

    #[test]
    fn test_tpm_parsing() -> Result<()> {
        // path is required
        TpmConfig::parse("").unwrap_err();
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
        VsockConfig::parse("").unwrap_err();
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=3")?,
            VsockConfig {
                cid: 3,
                socket: PathBuf::from("/tmp/sock"),
                iommu: false,
                id: None,
                pci_segment: 0,
            }
        );
        assert_eq!(
            VsockConfig::parse("socket=/tmp/sock,cid=3,iommu=on")?,
            VsockConfig {
                cid: 3,
                socket: PathBuf::from("/tmp/sock"),
                iommu: true,
                id: None,
                pci_segment: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn test_restore_parsing() -> Result<()> {
        assert_eq!(
            RestoreConfig::parse("source_url=/path/to/snapshot")?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                net_fds: None,
            }
        );
        assert_eq!(
            RestoreConfig::parse(
                "source_url=/path/to/snapshot,prefault=off,net_fds=[net0@[3,4],net1@[5,6,7,8]]"
            )?,
            RestoreConfig {
                source_url: PathBuf::from("/path/to/snapshot"),
                prefault: false,
                net_fds: Some(vec![
                    RestoredNetConfig {
                        id: "net0".to_string(),
                        num_fds: 2,
                        fds: Some(vec![3, 4]),
                    },
                    RestoredNetConfig {
                        id: "net1".to_string(),
                        num_fds: 4,
                        fds: Some(vec![5, 6, 7, 8]),
                    }
                ]),
            }
        );
        // Parsing should fail as source_url is a required field
        RestoreConfig::parse("prefault=off").unwrap_err();
        Ok(())
    }

    #[test]
    fn test_restore_config_validation() {
        // interested in only VmConfig.net, so set rest to default values
        let mut snapshot_vm_config = VmConfig {
            cpus: CpusConfig::default(),
            memory: MemoryConfig::default(),
            payload: None,
            rate_limit_groups: None,
            disks: None,
            rng: RngConfig::default(),
            balloon: None,
            fs: None,
            pmem: None,
            serial: default_serial(),
            console: default_console(),
            #[cfg(target_arch = "x86_64")]
            debug_console: DebugConsoleConfig::default(),
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: None,
            pvpanic: false,
            iommu: false,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            pci_segments: None,
            platform: None,
            tpm: None,
            preserved_fds: None,
            net: Some(vec![
                NetConfig {
                    id: Some("net0".to_owned()),
                    num_queues: 2,
                    fds: Some(vec![-1, -1, -1, -1]),
                    ..net_fixture()
                },
                NetConfig {
                    id: Some("net1".to_owned()),
                    num_queues: 1,
                    fds: Some(vec![-1, -1]),
                    ..net_fixture()
                },
                NetConfig {
                    id: Some("net2".to_owned()),
                    fds: None,
                    ..net_fixture()
                },
            ]),
            landlock_enable: false,
            landlock_rules: None,
            #[cfg(feature = "ivshmem")]
            ivshmem: None,
        };

        let valid_config = RestoreConfig {
            source_url: PathBuf::from("/path/to/snapshot"),
            prefault: false,
            net_fds: Some(vec![
                RestoredNetConfig {
                    id: "net0".to_string(),
                    num_fds: 4,
                    fds: Some(vec![3, 4, 5, 6]),
                },
                RestoredNetConfig {
                    id: "net1".to_string(),
                    num_fds: 2,
                    fds: Some(vec![7, 8]),
                },
            ]),
        };
        valid_config.validate(&snapshot_vm_config).unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.net_fds = Some(vec![RestoredNetConfig {
            id: "netx".to_string(),
            num_fds: 4,
            fds: Some(vec![3, 4, 5, 6]),
        }]);
        assert_eq!(
            invalid_config.validate(&snapshot_vm_config),
            Err(ValidationError::RestoreMissingRequiredNetId(
                "net0".to_string()
            ))
        );

        invalid_config.net_fds = Some(vec![
            RestoredNetConfig {
                id: "net0".to_string(),
                num_fds: 4,
                fds: Some(vec![3, 4, 5, 6]),
            },
            RestoredNetConfig {
                id: "net0".to_string(),
                num_fds: 4,
                fds: Some(vec![3, 4, 5, 6]),
            },
        ]);
        assert_eq!(
            invalid_config.validate(&snapshot_vm_config),
            Err(ValidationError::IdentifierNotUnique("net0".to_string()))
        );

        invalid_config.net_fds = Some(vec![RestoredNetConfig {
            id: "net0".to_string(),
            num_fds: 4,
            fds: Some(vec![3, 4, 5, 6]),
        }]);
        assert_eq!(
            invalid_config.validate(&snapshot_vm_config),
            Err(ValidationError::RestoreMissingRequiredNetId(
                "net1".to_string()
            ))
        );

        invalid_config.net_fds = Some(vec![RestoredNetConfig {
            id: "net0".to_string(),
            num_fds: 2,
            fds: Some(vec![3, 4]),
        }]);
        assert_eq!(
            invalid_config.validate(&snapshot_vm_config),
            Err(ValidationError::RestoreNetFdCountMismatch(
                "net0".to_string(),
                2,
                4
            ))
        );

        let another_valid_config = RestoreConfig {
            source_url: PathBuf::from("/path/to/snapshot"),
            prefault: false,
            net_fds: None,
        };
        snapshot_vm_config.net = Some(vec![NetConfig {
            id: Some("net2".to_owned()),
            fds: None,
            ..net_fixture()
        }]);
        another_valid_config.validate(&snapshot_vm_config).unwrap();
    }

    fn platform_fixture() -> PlatformConfig {
        PlatformConfig {
            num_pci_segments: MAX_NUM_PCI_SEGMENTS,
            iommu_segments: None,
            iommu_address_width_bits: MAX_IOMMU_ADDRESS_WIDTH_BITS,
            serial_number: None,
            uuid: None,
            oem_strings: None,
            #[cfg(feature = "tdx")]
            tdx: false,
            #[cfg(feature = "sev_snp")]
            sev_snp: false,
        }
    }

    fn numa_fixture() -> NumaConfig {
        NumaConfig {
            guest_numa_id: 0,
            cpus: None,
            distances: None,
            memory_zones: None,
            pci_segments: None,
        }
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
                firmware: None,
                cmdline: None,
                initramfs: None,
                #[cfg(feature = "igvm")]
                igvm: None,
                #[cfg(feature = "sev_snp")]
                host_data: Some(
                    "243eb7dc1a21129caa91dcbb794922b933baecb5823a377eb431188673288c07".to_string(),
                ),
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config: None,
            }),
            rate_limit_groups: None,
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
                socket: None,
            },
            console: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                socket: None,
            },
            #[cfg(target_arch = "x86_64")]
            debug_console: DebugConsoleConfig::default(),
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: None,
            pvpanic: false,
            iommu: false,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            pci_segments: None,
            platform: None,
            tpm: None,
            preserved_fds: None,
            landlock_enable: false,
            landlock_rules: None,
            #[cfg(feature = "ivshmem")]
            ivshmem: None,
        };

        valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::Tty;
        invalid_config.console.mode = ConsoleOutputMode::Tty;
        valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.payload = None;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::PayloadError(
                PayloadConfigError::MissingBootitem
            ))
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
            ..disk_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::DiskSocketAndPath)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.disks = Some(vec![DiskConfig {
            path: None,
            vhost_user: true,
            ..disk_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserMissingSocket)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            path: None,
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..disk_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.disks = Some(vec![DiskConfig {
            path: None,
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..disk_fixture()
        }]);
        still_valid_config.memory.shared = true;
        still_valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            ..net_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..net_fixture()
        }]);
        still_valid_config.memory.shared = true;
        still_valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            fds: Some(vec![0]),
            ..net_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VnetReservedFd)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            offload_csum: false,
            ..net_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::NoHardwareChecksumOffload)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.fs = Some(vec![fs_fixture()]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.shared = true;
        still_valid_config.validate().unwrap();

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.hugepages = true;
        still_valid_config.validate().unwrap();

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.hugepages = true;
        still_valid_config.memory.hugepage_size = Some(2 << 20);
        still_valid_config.validate().unwrap();

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
        still_valid_config.platform = Some(platform_fixture());
        still_valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: MAX_NUM_PCI_SEGMENTS + 1,
            ..platform_fixture()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidNumPciSegments(
                MAX_NUM_PCI_SEGMENTS + 1
            ))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        still_valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![MAX_NUM_PCI_SEGMENTS + 1, MAX_NUM_PCI_SEGMENTS + 2]),
            ..platform_fixture()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidPciSegment(MAX_NUM_PCI_SEGMENTS + 1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            iommu_address_width_bits: MAX_IOMMU_ADDRESS_WIDTH_BITS + 1,
            ..platform_fixture()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidIommuAddressWidthBits(
                MAX_IOMMU_ADDRESS_WIDTH_BITS + 1
            ))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        still_valid_config.disks = Some(vec![DiskConfig {
            iommu: true,
            pci_segment: 1,
            ..disk_fixture()
        }]);
        still_valid_config.validate().unwrap();

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        still_valid_config.net = Some(vec![NetConfig {
            iommu: true,
            pci_segment: 1,
            ..net_fixture()
        }]);
        still_valid_config.validate().unwrap();

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        still_valid_config.pmem = Some(vec![PmemConfig {
            iommu: true,
            pci_segment: 1,
            ..pmem_fixture()
        }]);
        still_valid_config.validate().unwrap();

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        still_valid_config.devices = Some(vec![DeviceConfig {
            iommu: true,
            pci_segment: 1,
            ..device_fixture()
        }]);
        still_valid_config.validate().unwrap();

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        still_valid_config.vsock = Some(VsockConfig {
            cid: 3,
            socket: PathBuf::new(),
            id: None,
            iommu: true,
            pci_segment: 1,
        });
        still_valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.disks = Some(vec![DiskConfig {
            iommu: false,
            pci_segment: 1,
            ..disk_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.net = Some(vec![NetConfig {
            iommu: false,
            pci_segment: 1,
            ..net_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: MAX_NUM_PCI_SEGMENTS,
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.pmem = Some(vec![PmemConfig {
            iommu: false,
            pci_segment: 1,
            ..pmem_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: MAX_NUM_PCI_SEGMENTS,
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.devices = Some(vec![DeviceConfig {
            iommu: false,
            pci_segment: 1,
            ..device_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.vsock = Some(VsockConfig {
            cid: 3,
            socket: PathBuf::new(),
            id: None,
            iommu: false,
            pci_segment: 1,
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.user_devices = Some(vec![UserDeviceConfig {
            pci_segment: 1,
            socket: PathBuf::new(),
            id: None,
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::IommuNotSupportedOnSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.vdpa = Some(vec![VdpaConfig {
            pci_segment: 1,
            ..vdpa_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.platform = Some(PlatformConfig {
            iommu_segments: Some(vec![1, 2, 3]),
            ..platform_fixture()
        });
        invalid_config.fs = Some(vec![FsConfig {
            pci_segment: 1,
            ..fs_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::IommuNotSupportedOnSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 2,
            ..platform_fixture()
        });
        invalid_config.numa = Some(vec![
            NumaConfig {
                guest_numa_id: 0,
                pci_segments: Some(vec![1]),
                ..numa_fixture()
            },
            NumaConfig {
                guest_numa_id: 1,
                pci_segments: Some(vec![1]),
                ..numa_fixture()
            },
        ]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::PciSegmentReused(1, 0, 1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.pci_segments = Some(vec![PciSegmentConfig {
            pci_segment: 0,
            mmio32_aperture_weight: 1,
            mmio64_aperture_weight: 0,
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidPciSegmentApertureWeight(0))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.pci_segments = Some(vec![PciSegmentConfig {
            pci_segment: 0,
            mmio32_aperture_weight: 0,
            mmio64_aperture_weight: 1,
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidPciSegmentApertureWeight(0))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.numa = Some(vec![
            NumaConfig {
                guest_numa_id: 0,
                ..numa_fixture()
            },
            NumaConfig {
                guest_numa_id: 1,
                pci_segments: Some(vec![0]),
                ..numa_fixture()
            },
        ]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::DefaultPciSegmentInvalidNode(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.numa = Some(vec![
            NumaConfig {
                guest_numa_id: 0,
                pci_segments: Some(vec![0]),
                ..numa_fixture()
            },
            NumaConfig {
                guest_numa_id: 1,
                pci_segments: Some(vec![1]),
                ..numa_fixture()
            },
        ]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidPciSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            rate_limit_group: Some("foo".into()),
            ..disk_fixture()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidRateLimiterGroup)
        );

        // Test serial length validation
        let mut valid_serial_config = valid_config.clone();
        valid_serial_config.disks = Some(vec![DiskConfig {
            serial: Some("valid_serial".to_string()),
            ..disk_fixture()
        }]);
        valid_serial_config.validate().unwrap();

        // Test empty string serial (should be valid)
        let mut empty_serial_config = valid_config.clone();
        empty_serial_config.disks = Some(vec![DiskConfig {
            serial: Some("".to_string()),
            ..disk_fixture()
        }]);
        empty_serial_config.validate().unwrap();

        // Test None serial (should be valid)
        let mut none_serial_config = valid_config.clone();
        none_serial_config.disks = Some(vec![DiskConfig {
            serial: None,
            ..disk_fixture()
        }]);
        none_serial_config.validate().unwrap();

        // Test maximum length serial (exactly VIRTIO_BLK_ID_BYTES)
        let max_serial = "a".repeat(VIRTIO_BLK_ID_BYTES as usize);
        let mut max_serial_config = valid_config.clone();
        max_serial_config.disks = Some(vec![DiskConfig {
            serial: Some(max_serial),
            ..disk_fixture()
        }]);
        max_serial_config.validate().unwrap();

        // Test serial length exceeding VIRTIO_BLK_ID_BYTES
        let long_serial = "a".repeat(VIRTIO_BLK_ID_BYTES as usize + 1);
        let mut invalid_serial_config = valid_config.clone();
        invalid_serial_config.disks = Some(vec![DiskConfig {
            serial: Some(long_serial.clone()),
            ..disk_fixture()
        }]);
        assert_eq!(
            invalid_serial_config.validate(),
            Err(ValidationError::InvalidSerialLength(
                long_serial.len(),
                VIRTIO_BLK_ID_BYTES as usize
            ))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.devices = Some(vec![
            DeviceConfig {
                path: "/device1".into(),
                ..device_fixture()
            },
            DeviceConfig {
                path: "/device2".into(),
                ..device_fixture()
            },
        ]);
        still_valid_config.validate().unwrap();

        let mut invalid_config = valid_config.clone();
        invalid_config.devices = Some(vec![
            DeviceConfig {
                path: "/device1".into(),
                ..device_fixture()
            },
            DeviceConfig {
                path: "/device1".into(),
                ..device_fixture()
            },
        ]);
        invalid_config.validate().unwrap_err();
        #[cfg(feature = "sev_snp")]
        {
            // Payload with empty host data
            let mut config_with_no_host_data = valid_config.clone();
            config_with_no_host_data.payload = Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                firmware: None,
                cmdline: None,
                initramfs: None,
                #[cfg(feature = "igvm")]
                igvm: None,
                #[cfg(feature = "sev_snp")]
                host_data: Some("".to_string()),
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config: None,
            });
            config_with_no_host_data.validate().unwrap_err();

            // Payload with no host data provided
            let mut valid_config_with_no_host_data = valid_config.clone();
            valid_config_with_no_host_data.payload = Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                firmware: None,
                cmdline: None,
                initramfs: None,
                #[cfg(feature = "igvm")]
                igvm: None,
                #[cfg(feature = "sev_snp")]
                host_data: None,
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config: None,
            });
            valid_config_with_no_host_data.validate().unwrap();

            // Payload with invalid host data length i.e less than 64
            let mut config_with_invalid_host_data = valid_config.clone();
            config_with_invalid_host_data.payload = Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                firmware: None,
                cmdline: None,
                initramfs: None,
                #[cfg(feature = "igvm")]
                igvm: None,
                #[cfg(feature = "sev_snp")]
                host_data: Some(
                    "243eb7dc1a21129caa91dcbb794922b933baecb5823a377eb43118867328".to_string(),
                ),
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config: None,
            });
            config_with_invalid_host_data.validate().unwrap_err();
        }

        let mut still_valid_config = valid_config;
        // SAFETY: Safe as the file was just opened
        let fd1 = unsafe { libc::dup(File::open("/dev/null").unwrap().as_raw_fd()) };
        // SAFETY: Safe as the file was just opened
        let fd2 = unsafe { libc::dup(File::open("/dev/null").unwrap().as_raw_fd()) };
        // SAFETY: safe as both FDs are valid
        unsafe {
            still_valid_config.add_preserved_fds(vec![fd1, fd2]);
        }
        let _still_valid_config = still_valid_config.clone();
    }
    #[test]
    fn test_landlock_parsing() -> Result<()> {
        // should not be empty
        LandlockConfig::parse("").unwrap_err();
        // access should not be empty
        LandlockConfig::parse("path=/dir/path1").unwrap_err();
        LandlockConfig::parse("path=/dir/path1,access=rwr").unwrap_err();
        assert_eq!(
            LandlockConfig::parse("path=/dir/path1,access=rw")?,
            LandlockConfig {
                path: PathBuf::from("/dir/path1"),
                access: "rw".to_string(),
            }
        );
        Ok(())
    }
    #[test]
    #[cfg(feature = "fw_cfg")]
    fn test_fw_cfg_config_item_list_parsing() -> Result<()> {
        // Empty list
        FwCfgConfig::parse("items=[]").unwrap_err();
        // Missing closing bracket
        FwCfgConfig::parse("items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item")
            .unwrap_err();
        // Single Item
        assert_eq!(
            FwCfgConfig::parse(
                "items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item]"
            )?,
            FwCfgConfig {
                items: Some(FwCfgItemList {
                    item_list: vec![FwCfgItem {
                        name: "opt/org.test/fw_cfg_test_item".to_string(),
                        file: PathBuf::from("/tmp/fw_cfg_test_item"),
                    }]
                }),
                ..Default::default()
            },
        );
        // Multiple Items
        assert_eq!(
            FwCfgConfig::parse(
                "items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item:name=opt/org.test/fw_cfg_test_item2,file=/tmp/fw_cfg_test_item2]"
            )?,
            FwCfgConfig {
                items: Some(FwCfgItemList {
                    item_list: vec![FwCfgItem {
                        name: "opt/org.test/fw_cfg_test_item".to_string(),
                        file: PathBuf::from("/tmp/fw_cfg_test_item"),
                    },
                    FwCfgItem {
                        name: "opt/org.test/fw_cfg_test_item2".to_string(),
                        file: PathBuf::from("/tmp/fw_cfg_test_item2"),
                    }]
                }),
                ..Default::default()
        },

        );
        Ok(())
    }
}
