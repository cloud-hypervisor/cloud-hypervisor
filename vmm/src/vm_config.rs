// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::{fs, result};

#[cfg(feature = "fw_cfg")]
use api_types::FwCfgItemList;
#[cfg(feature = "pvmemcontrol")]
use api_types::PvmemcontrolConfig;
use api_types::{
    ConsoleOutputMode, CpusConfig, HotplugMethod, MemoryZoneConfig, NumaDistance, VhostMode,
    VirtQueueAffinity,
};
use block::ImageType;
pub use block::fcntl::LockGranularityChoice;
#[cfg(target_arch = "x86_64")]
use devices::debug_console;
use log::{debug, warn};
use net_util::MacAddr;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_devices::RateLimiterConfig;

use crate::Landlock;
use crate::landlock::LandlockError;

pub type LandlockResult<T> = result::Result<T, LandlockError>;

/// Trait to apply Landlock on VmConfig elements
pub(crate) trait ApplyLandlock {
    /// Apply Landlock rules to file paths
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()>;
}

// When booting with PVH boot the maximum physical addressable size
// is a 46 bit address space even when the host supports with 5-level
// paging.
pub const DEFAULT_MAX_PHYS_BITS: u8 = 46;

pub const DEFAULT_VCPUS: u32 = 1;

pub const DEFAULT_NUM_PCI_SEGMENTS: u16 = 1;
pub fn default_platformconfig_num_pci_segments() -> u16 {
    DEFAULT_NUM_PCI_SEGMENTS
}

pub const DEFAULT_IOMMU_ADDRESS_WIDTH_BITS: u8 = 64;
pub fn default_platformconfig_iommu_address_width_bits() -> u8 {
    DEFAULT_IOMMU_ADDRESS_WIDTH_BITS
}

pub fn default_platformconfig_vfio_p2p_dma() -> bool {
    true
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PlatformConfig {
    #[serde(default = "default_platformconfig_num_pci_segments")]
    pub num_pci_segments: u16,
    #[serde(default)]
    pub iommu_segments: Option<Box<[u16]>>,
    #[serde(default = "default_platformconfig_iommu_address_width_bits")]
    pub iommu_address_width_bits: u8,
    #[serde(default, alias = "serial_number")]
    pub system_serial_number: Option<String>,
    #[serde(default, alias = "uuid")]
    pub system_uuid: Option<String>,
    #[serde(default)]
    pub oem_strings: Option<Box<[String]>>,
    #[serde(default)]
    pub system_manufacturer: Option<String>,
    #[serde(default)]
    pub system_product_name: Option<String>,
    #[serde(default)]
    pub system_version: Option<String>,
    #[serde(default)]
    pub system_family: Option<String>,
    #[serde(default)]
    pub system_sku_number: Option<String>,
    #[serde(default)]
    pub chassis_asset_tag: Option<String>,
    #[cfg(feature = "tdx")]
    #[serde(default)]
    pub tdx: bool,
    #[cfg(feature = "sev_snp")]
    #[serde(default)]
    pub sev_snp: bool,
    #[serde(default)]
    pub iommufd: bool,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "deserialize_platformconfig_iommufd_fd")]
    pub iommufd_fd: Option<i32>,
    #[serde(default = "default_platformconfig_vfio_p2p_dma")]
    pub vfio_p2p_dma: bool,
}

#[cfg(target_arch = "x86_64")]
impl PlatformConfig {
    /// Returns `None` if no SMBIOS-relevant platform fields are set, otherwise
    /// `Some` with a [`SmbiosConfig`] built from the populated fields.
    pub fn smbios_config(&self) -> Option<arch::x86_64::SmbiosConfig> {
        let has_system = [
            &self.system_serial_number,
            &self.system_uuid,
            &self.system_manufacturer,
            &self.system_product_name,
            &self.system_version,
            &self.system_family,
            &self.system_sku_number,
        ]
        .iter()
        .any(|v| v.is_some());

        let system = has_system.then_some(arch::x86_64::SmbiosSystem {
            manufacturer: self.system_manufacturer.clone(),
            product_name: self.system_product_name.clone(),
            version: self.system_version.clone(),
            serial_number: self.system_serial_number.clone(),
            uuid: self.system_uuid.clone(),
            sku_number: self.system_sku_number.clone(),
            family: self.system_family.clone(),
        });

        let chassis =
            self.chassis_asset_tag
                .clone()
                .map(|asset_tag| arch::x86_64::SmbiosChassisConfig {
                    asset_tag: Some(asset_tag),
                });

        let smbios = arch::x86_64::SmbiosConfig {
            system,
            chassis,
            oem_strings: self.oem_strings.clone().unwrap_or_default(),
        };

        (!smbios.is_empty()).then_some(smbios)
    }
}

fn deserialize_platformconfig_iommufd_fd<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fd: Option<i32> = Option::deserialize(d)?;
    if invalid_fd.is_some() {
        debug!(
            "FD in 'PlatformConfig::iommufd_fd' won't be deserialized as it is most likely invalid now. Deserializing it as -1."
        );
        Ok(Some(-1))
    } else {
        Ok(None)
    }
}

pub const DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT: u32 = 1;

fn default_pci_segment_aperture_weight() -> u32 {
    DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PciSegmentConfig {
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default = "default_pci_segment_aperture_weight")]
    pub mmio32_aperture_weight: u32,
    #[serde(default = "default_pci_segment_aperture_weight")]
    pub mmio64_aperture_weight: u32,
}

impl ApplyLandlock for MemoryZoneConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        if let Some(file) = &self.file {
            landlock.add_rule_with_access(file, "rw")?;
        }
        Ok(())
    }
}

fn default_memoryconfig_thp() -> bool {
    true
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
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
    pub reserve: bool,
    #[serde(default)]
    pub zones: Option<Vec<MemoryZoneConfig>>,
    #[serde(default = "default_memoryconfig_thp")]
    pub thp: bool,
}

pub const DEFAULT_MEMORY_MB: u64 = 512;

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
            reserve: false,
            zones: None,
            thp: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RateLimiterGroupConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub rate_limiter_config: RateLimiterConfig,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct PciDeviceCommonConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "<&bool as std::ops::Not>::not")]
    pub iommu: bool,
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default)]
    pub pci_device_id: Option<u8>,
}

impl From<api_types::PciDeviceCommonConfig> for PciDeviceCommonConfig {
    fn from(value: api_types::PciDeviceCommonConfig) -> Self {
        Self {
            id: value.id,
            iommu: value.iommu,
            pci_segment: value.pci_segment,
            pci_device_id: value.pci_device_id,
        }
    }
}

impl From<&PciDeviceCommonConfig> for api_types::PciDeviceCommonConfig {
    fn from(value: &PciDeviceCommonConfig) -> Self {
        Self {
            id: value.id.clone(),
            iommu: value.iommu,
            pci_segment: value.pci_segment,
            pci_device_id: value.pci_device_id,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DiskConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub direct: bool,
    #[serde(default = "default_diskconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_diskconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub rate_limit_group: Option<String>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_io_uring: bool,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_aio: bool,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub queue_affinity: Option<Box<[VirtQueueAffinity]>>,
    #[serde(default)]
    pub backing_files: bool,
    #[serde(default = "default_diskconfig_sparse")]
    pub sparse: bool,
    #[serde(default)]
    pub image_type: ImageType,
    #[serde(default)]
    pub lock_granularity: LockGranularityChoice,
}

impl ApplyLandlock for DiskConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        if let Some(path) = &self.path {
            landlock.add_rule_with_access(path, "rw")?;
        }
        Ok(())
    }
}

pub const DEFAULT_DISK_NUM_QUEUES: usize = 1;

pub fn default_diskconfig_num_queues() -> usize {
    DEFAULT_DISK_NUM_QUEUES
}

pub const DEFAULT_DISK_QUEUE_SIZE: u16 = 128;

pub fn default_diskconfig_queue_size() -> u16 {
    DEFAULT_DISK_QUEUE_SIZE
}

pub fn default_diskconfig_sparse() -> bool {
    true
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NetConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    #[serde(default = "default_netconfig_tap")]
    pub tap: Option<String>,
    pub ip: Option<IpAddr>,
    pub mask: Option<IpAddr>,
    #[serde(default = "default_netconfig_mac")]
    pub mac: MacAddr,
    #[serde(default)]
    pub host_mac: Option<MacAddr>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default = "default_netconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_netconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub vhost_mode: VhostMode,
    // Special deserialize handling:
    // Therefore, we don't serialize FDs, and whatever value is here after
    // deserialization is invalid.
    //
    // Valid FDs are transmitted via a different channel (SCM_RIGHTS message)
    // and will be populated into this struct on the destination VMM eventually.
    #[serde(default, deserialize_with = "deserialize_netconfig_fds")]
    pub fds: Option<Vec<i32>>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default = "default_netconfig_true")]
    pub offload_tso: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_ufo: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_csum: bool,
}

impl From<api_types::NetConfig> for NetConfig {
    fn from(value: api_types::NetConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            tap: value.tap,
            ip: value.ip,
            mask: value.mask,
            mac: value.mac,
            host_mac: value.host_mac,
            mtu: value.mtu,
            num_queues: value.num_queues,
            queue_size: value.queue_size,
            vhost_user: value.vhost_user,
            vhost_socket: value.vhost_socket,
            vhost_mode: value.vhost_mode,
            fds: value.fds,
            rate_limiter_config: value.rate_limiter_config,
            offload_tso: value.offload_tso,
            offload_ufo: value.offload_ufo,
            offload_csum: value.offload_csum,
        }
    }
}

impl From<&NetConfig> for api_types::NetConfig {
    fn from(value: &NetConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            tap: value.tap.clone(),
            ip: value.ip,
            mask: value.mask,
            mac: value.mac,
            host_mac: value.host_mac,
            mtu: value.mtu,
            num_queues: value.num_queues,
            queue_size: value.queue_size,
            vhost_user: value.vhost_user,
            vhost_socket: value.vhost_socket.clone(),
            vhost_mode: value.vhost_mode.clone(),
            fds: value.fds.clone(),
            rate_limiter_config: value.rate_limiter_config,
            offload_tso: value.offload_tso,
            offload_ufo: value.offload_ufo,
            offload_csum: value.offload_csum,
        }
    }
}

pub fn default_netconfig_true() -> bool {
    true
}

pub fn default_netconfig_tap() -> Option<String> {
    None
}

pub fn default_netconfig_mac() -> MacAddr {
    MacAddr::local_random()
}

pub const DEFAULT_NET_NUM_QUEUES: usize = 2;

pub fn default_netconfig_num_queues() -> usize {
    DEFAULT_NET_NUM_QUEUES
}

pub const DEFAULT_NET_QUEUE_SIZE: u16 = 256;

pub fn default_netconfig_queue_size() -> u16 {
    DEFAULT_NET_QUEUE_SIZE
}

fn deserialize_netconfig_fds<'de, D>(d: D) -> Result<Option<Vec<i32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fds: Option<Vec<i32>> = Option::deserialize(d)?;
    if let Some(invalid_fds) = invalid_fds {
        debug!(
            "FDs in 'NetConfig' won't be deserialized as they are most likely invalid now. Deserializing them as -1."
        );
        Ok(Some(vec![-1; invalid_fds.len()]))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RngConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub src: PathBuf,
}

impl RngConfig {
    pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";
}

impl Default for RngConfig {
    fn default() -> Self {
        RngConfig {
            src: PathBuf::from(Self::DEFAULT_RNG_SOURCE),
            pci_common: PciDeviceCommonConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RtcConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
}

impl From<api_types::RtcConfig> for RtcConfig {
    fn from(value: api_types::RtcConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
        }
    }
}

impl From<&RtcConfig> for api_types::RtcConfig {
    fn from(value: &RtcConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
        }
    }
}

impl ApplyLandlock for RngConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        // Rng Path only need read access
        landlock.add_rule_with_access(&self.src, "r")?;
        Ok(())
    }
}

impl From<api_types::RngConfig> for RngConfig {
    fn from(value: api_types::RngConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            src: value.src,
        }
    }
}

impl From<&RngConfig> for api_types::RngConfig {
    fn from(value: &RngConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            src: value.src.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BalloonConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub size: u64,
    /// Option to deflate the balloon in case the guest is out of memory.
    #[serde(default)]
    pub deflate_on_oom: bool,
    /// Option to enable free page reporting from the guest.
    #[serde(default)]
    pub free_page_reporting: bool,
}

impl From<api_types::BalloonConfig> for BalloonConfig {
    fn from(value: api_types::BalloonConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            size: value.size,
            deflate_on_oom: value.deflate_on_oom,
            free_page_reporting: value.free_page_reporting,
        }
    }
}

impl From<&BalloonConfig> for api_types::BalloonConfig {
    fn from(value: &BalloonConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            size: value.size,
            deflate_on_oom: value.deflate_on_oom,
            free_page_reporting: value.free_page_reporting,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FsConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub tag: String,
    pub socket: PathBuf,
    #[serde(default = "default_fsconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_fsconfig_queue_size")]
    pub queue_size: u16,
}

pub fn default_fsconfig_num_queues() -> usize {
    1
}

pub fn default_fsconfig_queue_size() -> u16 {
    1024
}

impl ApplyLandlock for FsConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GenericVhostUserConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub socket: PathBuf,
    pub queue_sizes: Vec<u16>,
    pub device_type: u32,
}

impl ApplyLandlock for GenericVhostUserConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PmemConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub file: PathBuf,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub discard_writes: bool,
}

impl ApplyLandlock for PmemConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let access = if self.discard_writes { "r" } else { "rw" };
        landlock.add_rule_with_access(&self.file, access)?;
        Ok(())
    }
}

/// Common configuration for plain console configs.
///
/// Independent of PCI or legacy devices.
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CommonConsoleConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    #[serde(default)]
    pub socket: Option<PathBuf>,
}

impl ApplyLandlock for CommonConsoleConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        if self.mode == ConsoleOutputMode::Pty {
            landlock.add_rule_with_access(Path::new("/dev/pts"), "rw")?;
            landlock.add_rule_with_access(Path::new("/dev/ptmx"), "rw")?;
        }
        if let Some(file) = &self.file {
            landlock.add_rule_with_access(file, "rw")?;
        }
        if let Some(socket) = &self.socket {
            landlock.add_rule_with_access(socket, "rw")?;
        }
        Ok(())
    }
}

/// Configuration for a legacy serial console device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SerialConfig {
    #[serde(flatten)]
    pub common: CommonConsoleConfig,
}

impl SerialConfig {
    pub const SYNTAX: &str = "Control serial port: \"off|null|pty|tty|file=<path>|socket=<path>\"";
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            common: CommonConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Null,
                socket: None,
            },
        }
    }
}

impl ApplyLandlock for SerialConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        self.common.apply_landlock(landlock)
    }
}

/// Configuration for a virtio-console device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConsoleConfig {
    #[serde(flatten)]
    pub common: CommonConsoleConfig,
    #[serde(default, flatten)]
    pub pci_common: PciDeviceCommonConfig,
}

impl ConsoleConfig {
    pub const SYNTAX: &str = "Control (virtio) console: \"off|null|pty|tty|file=<path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            common: CommonConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                socket: None,
            },
            pci_common: PciDeviceCommonConfig::default(),
        }
    }
}

impl ApplyLandlock for ConsoleConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        self.common.apply_landlock(landlock)
    }
}

#[cfg(target_arch = "x86_64")]
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DebugConsoleConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    /// Optionally dedicated I/O-port, if the default port should not be used.
    pub iobase: Option<u16>,
}

#[cfg(target_arch = "x86_64")]
impl Default for DebugConsoleConfig {
    fn default() -> Self {
        Self {
            file: None,
            mode: ConsoleOutputMode::Off,
            iobase: Some(debug_console::DEFAULT_PORT as u16),
        }
    }
}
#[cfg(target_arch = "x86_64")]
impl ApplyLandlock for DebugConsoleConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        if self.mode == ConsoleOutputMode::Pty {
            landlock.add_rule_with_access(Path::new("/dev/pts"), "rw")?;
            landlock.add_rule_with_access(Path::new("/dev/ptmx"), "rw")?;
        }
        if let Some(file) = &self.file {
            landlock.add_rule_with_access(file, "rw")?;
        }
        Ok(())
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    #[serde(default)]
    pub path: Option<PathBuf>,
    // FDs are not serialized and any deserialized value is invalid; see NetConfig::fds.
    #[serde(default, deserialize_with = "deserialize_deviceconfig_fd")]
    pub fd: Option<i32>,
    #[serde(default)]
    pub x_nv_gpudirect_clique: Option<u8>,
    #[serde(default)]
    pub x_exclude_mmap_bars: Vec<u64>,
}

fn deserialize_deviceconfig_fd<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fd: Option<i32> = Option::deserialize(d)?;
    if invalid_fd.is_some() {
        debug!(
            "FD in 'DeviceConfig' won't be deserialized as it is most likely invalid now. Deserializing it as -1."
        );
        Ok(Some(-1))
    } else {
        Ok(None)
    }
}

impl ApplyLandlock for DeviceConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        // When the device is supplied via an externally-opened FD, there is no
        // path to grant access to: the file is already open. Skip the rule.
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let device_path = fs::read_link(path).map_err(LandlockError::OpenPath)?;
        let iommu_group = device_path.file_name();
        let iommu_group_str = iommu_group
            .ok_or(LandlockError::InvalidPath)?
            .to_str()
            .ok_or(LandlockError::InvalidPath)?;

        let mut vfio_group_path = PathBuf::from("/dev/vfio");
        vfio_group_path.push(iommu_group_str);
        landlock.add_rule_with_access(&vfio_group_path, "rw")?;

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct UserDeviceConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub socket: PathBuf,
}

impl ApplyLandlock for UserDeviceConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VdpaConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub path: PathBuf,
    #[serde(default = "default_vdpaconfig_num_queues")]
    pub num_queues: usize,
}

pub fn default_vdpaconfig_num_queues() -> usize {
    1
}

impl ApplyLandlock for VdpaConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.path, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VsockConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub cid: u32,
    pub socket: PathBuf,
}

impl ApplyLandlock for VsockConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        if let Some(parent) = self.socket.parent() {
            landlock.add_rule_with_access(parent, "w")?;
        }

        landlock.add_rule_with_access(&self.socket, "rw")?;

        Ok(())
    }
}

#[cfg(feature = "ivshmem")]
pub const DEFAULT_IVSHMEM_SIZE: usize = 128;

#[cfg(feature = "ivshmem")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IvshmemConfig {
    #[serde(flatten)]
    pub pci_common: PciDeviceCommonConfig,
    pub path: PathBuf,
    pub size: usize,
}

#[cfg(feature = "ivshmem")]
impl Default for IvshmemConfig {
    fn default() -> Self {
        Self {
            pci_common: PciDeviceCommonConfig::default(),
            path: PathBuf::new(),
            size: DEFAULT_IVSHMEM_SIZE << 20,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NumaConfig {
    pub guest_numa_id: u32,
    #[serde(default)]
    pub cpus: Option<Box<[u32]>>,
    #[serde(default)]
    pub distances: Option<Box<[NumaDistance]>>,
    #[serde(default)]
    pub memory_zones: Option<Box<[String]>>,
    #[serde(default)]
    pub pci_segments: Option<Box<[u16]>>,
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Errors describing a misconfigured payload, i.e., a configuration that
/// can't be booted by Cloud Hypervisor.
///
/// This typically is the case for invalid combinations of cmdline, kernel,
/// firmware, and initrd.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadConfigError {
    /// Specifying a kernel is not supported when a firmware is provided.
    #[error("Specifying a kernel is not supported when a firmware is provided")]
    FirmwarePlusOtherPayloads,
    /// No bootitem provided: neither firmware nor kernel.
    #[error("No bootitem provided: neither firmware nor kernel")]
    MissingBootitem,
    #[cfg(feature = "igvm")]
    /// Specifying a kernel or firmware is not supported when an igvm is provided.
    #[error("Specifying a kernel or firmware is not supported when an igvm is provided")]
    IgvmPlusOtherPayloads,
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
    #[cfg(feature = "fw_cfg")]
    /// Invalid fw_cfg item content
    #[error(
        "Error --fw-cfg-config: invalid item '{0}' (exactly one of 'file' or 'string' is required)"
    )]
    FwCfgInvalidItem(String),
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayloadConfig {
    #[serde(default)]
    pub firmware: Option<PathBuf>,
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    #[serde(default)]
    pub cmdline: Option<String>,
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
    #[cfg(feature = "igvm")]
    #[serde(default)]
    pub igvm: Option<PathBuf>,
    #[cfg(feature = "sev_snp")]
    #[serde(default)]
    pub host_data: Option<String>,
    #[cfg(feature = "fw_cfg")]
    pub fw_cfg_config: Option<FwCfgConfig>,
}

#[cfg(feature = "fw_cfg")]
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct FwCfgConfig {
    pub e820: bool,
    pub kernel: bool,
    pub cmdline: bool,
    pub initramfs: bool,
    pub acpi_tables: bool,
    pub items: Option<FwCfgItemList>,
}

#[cfg(feature = "fw_cfg")]
impl Default for FwCfgConfig {
    fn default() -> Self {
        FwCfgConfig {
            e820: true,
            kernel: true,
            cmdline: true,
            initramfs: true,
            acpi_tables: true,
            items: None,
        }
    }
}

impl PayloadConfig {
    /// Validates the payload config.
    ///
    /// Succeeds if Cloud Hypervisor will be able to boot the configuration.
    /// Further, warns for some odd configurations.
    pub fn validate(&mut self) -> Result<(), PayloadConfigError> {
        #[cfg(feature = "igvm")]
        {
            if self.igvm.is_some() {
                if self.firmware.is_some() {
                    return Err(PayloadConfigError::IgvmPlusOtherPayloads);
                }
                return Ok(());
            }
        }
        match (&self.firmware, &self.kernel) {
            (Some(_firmware), Some(_kernel)) => Err(PayloadConfigError::FirmwarePlusOtherPayloads),
            (Some(_firmware), None) => {
                if self.cmdline.is_some() {
                    warn!("Ignoring cmdline parameter as firmware is provided as the payload");
                    self.cmdline = None;
                }
                if self.initramfs.is_some() {
                    warn!("Ignoring initramfs parameter as firmware is provided as the payload");
                    self.initramfs = None;
                }
                Ok(())
            }
            (None, Some(_kernel)) => Ok(()),
            (None, None) => Err(PayloadConfigError::MissingBootitem),
        }?;

        #[cfg(feature = "fw_cfg")]
        if let Some(fw_cfg_config) = &self.fw_cfg_config {
            fw_cfg_config.validate(self)?;
        }

        Ok(())
    }
}

impl ApplyLandlock for PayloadConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        // Payload only needs read access
        if let Some(firmware) = &self.firmware {
            landlock.add_rule_with_access(firmware, "r")?;
        }

        if let Some(kernel) = &self.kernel {
            landlock.add_rule_with_access(kernel, "r")?;
        }

        if let Some(initramfs) = &self.initramfs {
            landlock.add_rule_with_access(initramfs, "r")?;
        }

        #[cfg(feature = "igvm")]
        if let Some(igvm) = &self.igvm {
            landlock.add_rule_with_access(igvm, "r")?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct TpmConfig {
    pub socket: PathBuf,
}

impl ApplyLandlock for TpmConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LandlockConfig {
    pub path: PathBuf,
    pub access: String,
}

impl ApplyLandlock for LandlockConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.path, self.access.clone().as_str())?;
        Ok(())
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VmConfig {
    #[serde(default)]
    pub cpus: CpusConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    pub payload: Option<PayloadConfig>,
    pub rate_limit_groups: Option<Box<[RateLimiterGroupConfig]>>,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    #[serde(default)]
    pub rng: RngConfig,
    pub balloon: Option<BalloonConfig>,
    pub generic_vhost_user: Option<Vec<GenericVhostUserConfig>>,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default)]
    pub serial: SerialConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub debug_console: DebugConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub user_devices: Option<Vec<UserDeviceConfig>>,
    pub vdpa: Option<Vec<VdpaConfig>>,
    pub vsock: Option<VsockConfig>,
    #[cfg(feature = "pvmemcontrol")]
    #[serde(default)]
    pub pvmemcontrol: Option<PvmemcontrolConfig>,
    #[serde(default)]
    pub pvpanic: bool,
    #[serde(default)]
    pub iommu: bool,
    pub numa: Option<Box<[NumaConfig]>>,
    #[serde(default)]
    pub watchdog: bool,
    #[serde(default)]
    pub rtc: Option<RtcConfig>,
    #[cfg(feature = "guest_debug")]
    #[serde(default)]
    pub gdb: bool,
    pub pci_segments: Option<Box<[PciSegmentConfig]>>,
    pub platform: Option<PlatformConfig>,
    pub tpm: Option<TpmConfig>,
    // Preserved FDs are the ones that share the same life-time as its holding
    // VmConfig instance, such as FDs for creating TAP devices.
    // Preserved FDs will stay open as long as the holding VmConfig instance is
    // valid, and will be closed when the holding VmConfig instance is destroyed.
    //
    // This is populated as devices are added at runtime. Removing them again
    // causes the FDs to be closed early. This allows management software to
    // gracefully clean up resources (e.g., libvirt closes tap devices).
    #[serde(skip)]
    pub preserved_fds: Option<HashSet<i32>>,
    #[serde(default)]
    pub landlock_enable: bool,
    pub landlock_rules: Option<Box<[LandlockConfig]>>,
    #[cfg(feature = "ivshmem")]
    pub ivshmem: Option<IvshmemConfig>,
}

impl VmConfig {
    pub(crate) fn apply_landlock(&self) -> LandlockResult<()> {
        let mut landlock = Landlock::new()?;

        #[cfg(target_arch = "aarch64")]
        {
            landlock.add_rule_with_access(Path::new("/sys/devices/system/cpu/cpu0/cache"), "r")?;
        }

        if let Some(mem_zones) = &self.memory.zones {
            for zone in mem_zones.iter() {
                zone.apply_landlock(&mut landlock)?;
            }
        }

        let disks = &self.disks;
        if let Some(disks) = disks {
            for disk in disks.iter() {
                disk.apply_landlock(&mut landlock)?;
            }
        }

        self.rng.apply_landlock(&mut landlock)?;

        if let Some(fs_configs) = &self.fs {
            for fs_config in fs_configs.iter() {
                fs_config.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(generic_vhost_user_configs) = &self.generic_vhost_user {
            for generic_vhost_user_config in generic_vhost_user_configs.iter() {
                generic_vhost_user_config.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(pmem_configs) = &self.pmem {
            for pmem_config in pmem_configs.iter() {
                pmem_config.apply_landlock(&mut landlock)?;
            }
        }

        self.console.apply_landlock(&mut landlock)?;
        self.serial.apply_landlock(&mut landlock)?;

        #[cfg(target_arch = "x86_64")]
        {
            self.debug_console.apply_landlock(&mut landlock)?;
        }

        if let Some(devices) = &self.devices {
            landlock.add_rule_with_access(Path::new("/dev/vfio/vfio"), "rw")?;

            for device in devices.iter() {
                device.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(user_devices) = &self.user_devices {
            for user_devices in user_devices.iter() {
                user_devices.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(vdpa_configs) = &self.vdpa {
            for vdpa_config in vdpa_configs.iter() {
                vdpa_config.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(vsock_config) = &self.vsock {
            vsock_config.apply_landlock(&mut landlock)?;
        }

        if let Some(payload) = &self.payload {
            payload.apply_landlock(&mut landlock)?;
        }

        #[cfg(feature = "sev_snp")]
        if self.platform.as_ref().is_some_and(|p| p.sev_snp) {
            landlock.add_rule_with_access(Path::new("/dev/sev"), "rw")?;
        }

        if let Some(tpm_config) = &self.tpm {
            tpm_config.apply_landlock(&mut landlock)?;
        }

        if self.net.is_some() {
            landlock.add_rule_with_access(Path::new("/dev/net/tun"), "rw")?;
        }

        if let Some(landlock_rules) = &self.landlock_rules {
            for landlock_rule in landlock_rules.iter() {
                landlock_rule.apply_landlock(&mut landlock)?;
            }
        }

        landlock.restrict_self()?;

        Ok(())
    }

    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    pub(crate) fn max_apic_id(&self) -> u32 {
        if let Some(topology) = &self.cpus.topology {
            arch::x86_64::get_max_x2apic_id((
                topology.threads_per_core,
                topology.cores_per_die,
                topology.dies_per_package,
                topology.packages,
            ))
        } else {
            self.cpus.max_vcpus
        }
    }
}
