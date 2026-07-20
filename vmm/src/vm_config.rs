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
    ConsoleOutputMode, CpusConfig, HotplugMethod, ImageType, LockGranularityChoice,
    MemoryZoneConfig, NumaDistance, VhostMode, VirtQueueAffinity,
};
#[cfg(target_arch = "x86_64")]
use devices::debug_console;
use log::warn;
use net_util::MacAddr;
use thiserror::Error;
use virtio_devices::RateLimiterConfig;

use crate::Landlock;
use crate::config::ValidationError;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformConfig {
    pub num_pci_segments: u16,
    pub iommu_segments: Option<Box<[u16]>>,
    pub iommu_address_width_bits: u8,
    pub system_serial_number: Option<String>,
    pub system_uuid: Option<String>,
    pub oem_strings: Option<Box<[String]>>,
    pub system_manufacturer: Option<String>,
    pub system_product_name: Option<String>,
    pub system_version: Option<String>,
    pub system_family: Option<String>,
    pub system_sku_number: Option<String>,
    pub chassis_asset_tag: Option<String>,
    #[cfg(feature = "tdx")]
    pub tdx: bool,
    #[cfg(feature = "sev_snp")]
    pub sev_snp: bool,
    pub iommufd: bool,
    pub iommufd_fd: Option<i32>,
    pub vfio_p2p_dma: bool,
}

impl From<api_types::PlatformConfig> for PlatformConfig {
    fn from(value: api_types::PlatformConfig) -> Self {
        Self {
            num_pci_segments: value.num_pci_segments,
            iommu_segments: value.iommu_segments,
            iommu_address_width_bits: value.iommu_address_width_bits,
            system_serial_number: value.system_serial_number,
            system_uuid: value.system_uuid,
            oem_strings: value.oem_strings,
            system_manufacturer: value.system_manufacturer,
            system_product_name: value.system_product_name,
            system_version: value.system_version,
            system_family: value.system_family,
            system_sku_number: value.system_sku_number,
            chassis_asset_tag: value.chassis_asset_tag,
            #[cfg(feature = "tdx")]
            tdx: value.tdx,
            #[cfg(feature = "sev_snp")]
            sev_snp: value.sev_snp,
            iommufd: value.iommufd,
            iommufd_fd: value.iommufd_fd,
            vfio_p2p_dma: value.vfio_p2p_dma,
        }
    }
}

impl From<&PlatformConfig> for api_types::PlatformConfig {
    fn from(value: &PlatformConfig) -> Self {
        Self {
            num_pci_segments: value.num_pci_segments,
            iommu_segments: value.iommu_segments.clone(),
            iommu_address_width_bits: value.iommu_address_width_bits,
            system_serial_number: value.system_serial_number.clone(),
            system_uuid: value.system_uuid.clone(),
            oem_strings: value.oem_strings.clone(),
            system_manufacturer: value.system_manufacturer.clone(),
            system_product_name: value.system_product_name.clone(),
            system_version: value.system_version.clone(),
            system_family: value.system_family.clone(),
            system_sku_number: value.system_sku_number.clone(),
            chassis_asset_tag: value.chassis_asset_tag.clone(),
            #[cfg(feature = "tdx")]
            tdx: value.tdx,
            #[cfg(feature = "sev_snp")]
            sev_snp: value.sev_snp,
            iommufd: value.iommufd,
            iommufd_fd: value.iommufd_fd,
            vfio_p2p_dma: value.vfio_p2p_dma,
        }
    }
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

pub const DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciSegmentConfig {
    pub pci_segment: u16,
    pub mmio32_aperture_weight: u32,
    pub mmio64_aperture_weight: u32,
}

impl From<api_types::PciSegmentConfig> for PciSegmentConfig {
    fn from(value: api_types::PciSegmentConfig) -> Self {
        Self {
            pci_segment: value.pci_segment,
            mmio32_aperture_weight: value.mmio32_aperture_weight,
            mmio64_aperture_weight: value.mmio64_aperture_weight,
        }
    }
}

impl From<&PciSegmentConfig> for api_types::PciSegmentConfig {
    fn from(value: &PciSegmentConfig) -> Self {
        Self {
            pci_segment: value.pci_segment,
            mmio32_aperture_weight: value.mmio32_aperture_weight,
            mmio64_aperture_weight: value.mmio64_aperture_weight,
        }
    }
}

impl ApplyLandlock for MemoryZoneConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        if let Some(file) = &self.file {
            landlock.add_rule_with_access(file, "rw")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryConfig {
    pub size: u64,
    pub mergeable: bool,
    pub hotplug_method: HotplugMethod,
    pub hotplug_size: Option<u64>,
    pub hotplugged_size: Option<u64>,
    pub shared: bool,
    pub hugepages: bool,
    pub hugepage_size: Option<u64>,
    pub prefault: bool,
    pub reserve: bool,
    pub zones: Option<Vec<MemoryZoneConfig>>,
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

impl From<api_types::MemoryConfig> for MemoryConfig {
    fn from(value: api_types::MemoryConfig) -> Self {
        Self {
            size: value.size,
            mergeable: value.mergeable,
            hotplug_method: value.hotplug_method,
            hotplug_size: value.hotplug_size,
            hotplugged_size: value.hotplugged_size,
            shared: value.shared,
            hugepages: value.hugepages,
            hugepage_size: value.hugepage_size,
            prefault: value.prefault,
            reserve: value.reserve,
            zones: value.zones,
            thp: value.thp,
        }
    }
}

impl From<&MemoryConfig> for api_types::MemoryConfig {
    fn from(value: &MemoryConfig) -> Self {
        Self {
            size: value.size,
            mergeable: value.mergeable,
            hotplug_method: value.hotplug_method,
            hotplug_size: value.hotplug_size,
            hotplugged_size: value.hotplugged_size,
            shared: value.shared,
            hugepages: value.hugepages,
            hugepage_size: value.hugepage_size,
            prefault: value.prefault,
            reserve: value.reserve,
            zones: value.zones.clone(),
            thp: value.thp,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimiterGroupConfig {
    pub id: String,
    pub rate_limiter_config: RateLimiterConfig,
}

impl From<api_types::RateLimiterGroupConfig> for RateLimiterGroupConfig {
    fn from(value: api_types::RateLimiterGroupConfig) -> Self {
        Self {
            id: value.id,
            rate_limiter_config: value.rate_limiter_config,
        }
    }
}

impl From<&RateLimiterGroupConfig> for api_types::RateLimiterGroupConfig {
    fn from(value: &RateLimiterGroupConfig) -> Self {
        Self {
            id: value.id.clone(),
            rate_limiter_config: value.rate_limiter_config,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PciDeviceCommonConfig {
    pub id: Option<String>,
    pub iommu: bool,
    pub pci_segment: u16,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub path: Option<PathBuf>,
    pub readonly: bool,
    pub direct: bool,
    pub num_queues: usize,
    pub queue_size: u16,
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    pub rate_limit_group: Option<String>,
    pub rate_limiter_config: Option<RateLimiterConfig>,
    // For testing use only. Not exposed in API.
    pub disable_io_uring: bool,
    // For testing use only. Not exposed in API.
    pub disable_aio: bool,
    pub serial: Option<String>,
    pub queue_affinity: Option<Box<[VirtQueueAffinity]>>,
    pub backing_files: bool,
    pub sparse: bool,
    pub image_type: ImageType,
    pub lock_granularity: LockGranularityChoice,
}

impl From<api_types::DiskConfig> for DiskConfig {
    fn from(value: api_types::DiskConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            path: value.path,
            readonly: value.readonly,
            direct: value.direct,
            num_queues: value.num_queues,
            queue_size: value.queue_size,
            vhost_user: value.vhost_user,
            vhost_socket: value.vhost_socket,
            rate_limit_group: value.rate_limit_group,
            rate_limiter_config: value.rate_limiter_config,
            disable_io_uring: value.disable_io_uring,
            disable_aio: value.disable_aio,
            serial: value.serial,
            queue_affinity: value.queue_affinity,
            backing_files: value.backing_files,
            sparse: value.sparse,
            image_type: value.image_type,
            lock_granularity: value.lock_granularity,
        }
    }
}

impl From<&DiskConfig> for api_types::DiskConfig {
    fn from(value: &DiskConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            path: value.path.clone(),
            readonly: value.readonly,
            direct: value.direct,
            num_queues: value.num_queues,
            queue_size: value.queue_size,
            vhost_user: value.vhost_user,
            vhost_socket: value.vhost_socket.clone(),
            rate_limit_group: value.rate_limit_group.clone(),
            rate_limiter_config: value.rate_limiter_config,
            disable_io_uring: value.disable_io_uring,
            disable_aio: value.disable_aio,
            serial: value.serial.clone(),
            queue_affinity: value.queue_affinity.clone(),
            backing_files: value.backing_files,
            sparse: value.sparse,
            image_type: value.image_type,
            lock_granularity: value.lock_granularity,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub tap: Option<String>,
    pub ip: Option<IpAddr>,
    pub mask: Option<IpAddr>,
    pub mac: MacAddr,
    pub host_mac: Option<MacAddr>,
    pub mtu: Option<u16>,
    pub num_queues: usize,
    pub queue_size: u16,
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    pub vhost_mode: VhostMode,
    pub fds: Option<Vec<i32>>,
    pub rate_limiter_config: Option<RateLimiterConfig>,
    pub offload_tso: bool,
    pub offload_ufo: bool,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RngConfig {
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RtcConfig {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalloonConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub size: u64,
    /// Option to deflate the balloon in case the guest is out of memory.
    pub deflate_on_oom: bool,
    /// Option to enable free page reporting from the guest.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub tag: String,
    pub socket: PathBuf,
    pub num_queues: usize,
    pub queue_size: u16,
}

impl From<api_types::FsConfig> for FsConfig {
    fn from(value: api_types::FsConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            tag: value.tag,
            socket: value.socket,
            num_queues: value.num_queues,
            queue_size: value.queue_size,
        }
    }
}

impl From<&FsConfig> for api_types::FsConfig {
    fn from(value: &FsConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            tag: value.tag.clone(),
            socket: value.socket.clone(),
            num_queues: value.num_queues,
            queue_size: value.queue_size,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericVhostUserConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub socket: PathBuf,
    pub queue_sizes: Vec<u16>,
    pub device_type: u32,
}

impl From<api_types::GenericVhostUserConfig> for GenericVhostUserConfig {
    fn from(value: api_types::GenericVhostUserConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            socket: value.socket,
            queue_sizes: value.queue_sizes,
            device_type: value.device_type,
        }
    }
}

impl From<&GenericVhostUserConfig> for api_types::GenericVhostUserConfig {
    fn from(value: &GenericVhostUserConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            socket: value.socket.clone(),
            queue_sizes: value.queue_sizes.clone(),
            device_type: value.device_type,
        }
    }
}

impl ApplyLandlock for GenericVhostUserConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PmemConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub file: PathBuf,
    pub size: Option<u64>,
    pub discard_writes: bool,
}

impl From<api_types::PmemConfig> for PmemConfig {
    fn from(value: api_types::PmemConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            file: value.file,
            size: value.size,
            discard_writes: value.discard_writes,
        }
    }
}

impl From<&PmemConfig> for api_types::PmemConfig {
    fn from(value: &PmemConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            file: value.file.clone(),
            size: value.size,
            discard_writes: value.discard_writes,
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonConsoleConfig {
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    pub socket: Option<PathBuf>,
}

impl From<api_types::CommonConsoleConfig> for CommonConsoleConfig {
    fn from(value: api_types::CommonConsoleConfig) -> Self {
        Self {
            file: value.file,
            mode: value.mode,
            socket: value.socket,
        }
    }
}

impl From<&CommonConsoleConfig> for api_types::CommonConsoleConfig {
    fn from(value: &CommonConsoleConfig) -> Self {
        Self {
            file: value.file.clone(),
            mode: value.mode.clone(),
            socket: value.socket.clone(),
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerialConfig {
    pub common: CommonConsoleConfig,
}

impl From<api_types::SerialConfig> for SerialConfig {
    fn from(value: api_types::SerialConfig) -> Self {
        Self {
            common: value.common.into(),
        }
    }
}

impl From<&SerialConfig> for api_types::SerialConfig {
    fn from(value: &SerialConfig) -> Self {
        Self {
            common: (&value.common).into(),
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleConfig {
    pub common: CommonConsoleConfig,
    pub pci_common: PciDeviceCommonConfig,
}

impl From<api_types::ConsoleConfig> for ConsoleConfig {
    fn from(value: api_types::ConsoleConfig) -> Self {
        Self {
            common: value.common.into(),
            pci_common: value.pci_common.into(),
        }
    }
}

impl From<&ConsoleConfig> for api_types::ConsoleConfig {
    fn from(value: &ConsoleConfig) -> Self {
        Self {
            common: (&value.common).into(),
            pci_common: (&value.pci_common).into(),
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugConsoleConfig {
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    /// Optionally dedicated I/O-port, if the default port should not be used.
    pub iobase: Option<u16>,
}

#[cfg(target_arch = "x86_64")]
impl From<api_types::DebugConsoleConfig> for DebugConsoleConfig {
    fn from(value: api_types::DebugConsoleConfig) -> Self {
        Self {
            file: value.file,
            mode: value.mode,
            iobase: value.iobase,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl From<&DebugConsoleConfig> for api_types::DebugConsoleConfig {
    fn from(value: &DebugConsoleConfig) -> Self {
        Self {
            file: value.file.clone(),
            mode: value.mode.clone(),
            iobase: value.iobase,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub path: Option<PathBuf>,
    pub fd: Option<i32>,
    pub x_nv_gpudirect_clique: Option<u8>,
    pub x_exclude_mmap_bars: Vec<u64>,
}

impl From<api_types::DeviceConfig> for DeviceConfig {
    fn from(value: api_types::DeviceConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            path: value.path,
            fd: value.fd,
            x_nv_gpudirect_clique: value.x_nv_gpudirect_clique,
            x_exclude_mmap_bars: value.x_exclude_mmap_bars,
        }
    }
}

impl From<&DeviceConfig> for api_types::DeviceConfig {
    fn from(value: &DeviceConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            path: value.path.clone(),
            fd: value.fd,
            x_nv_gpudirect_clique: value.x_nv_gpudirect_clique,
            x_exclude_mmap_bars: value.x_exclude_mmap_bars.clone(),
        }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDeviceConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub socket: PathBuf,
}

impl From<api_types::UserDeviceConfig> for UserDeviceConfig {
    fn from(value: api_types::UserDeviceConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            socket: value.socket,
        }
    }
}

impl From<&UserDeviceConfig> for api_types::UserDeviceConfig {
    fn from(value: &UserDeviceConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            socket: value.socket.clone(),
        }
    }
}

impl ApplyLandlock for UserDeviceConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdpaConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub path: PathBuf,
    pub num_queues: usize,
}

impl From<api_types::VdpaConfig> for VdpaConfig {
    fn from(value: api_types::VdpaConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            path: value.path,
            num_queues: value.num_queues,
        }
    }
}

impl From<&VdpaConfig> for api_types::VdpaConfig {
    fn from(value: &VdpaConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            path: value.path.clone(),
            num_queues: value.num_queues,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VsockConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub cid: u32,
    pub socket: PathBuf,
}

impl From<api_types::VsockConfig> for VsockConfig {
    fn from(value: api_types::VsockConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            cid: value.cid,
            socket: value.socket,
        }
    }
}

impl From<&VsockConfig> for api_types::VsockConfig {
    fn from(value: &VsockConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            cid: value.cid,
            socket: value.socket.clone(),
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvshmemConfig {
    pub pci_common: PciDeviceCommonConfig,
    pub path: PathBuf,
    pub size: usize,
}

#[cfg(feature = "ivshmem")]
impl From<api_types::IvshmemConfig> for IvshmemConfig {
    fn from(value: api_types::IvshmemConfig) -> Self {
        Self {
            pci_common: value.pci_common.into(),
            path: value.path,
            size: value.size,
        }
    }
}

#[cfg(feature = "ivshmem")]
impl From<&IvshmemConfig> for api_types::IvshmemConfig {
    fn from(value: &IvshmemConfig) -> Self {
        Self {
            pci_common: (&value.pci_common).into(),
            path: value.path.clone(),
            size: value.size,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumaConfig {
    pub guest_numa_id: u32,
    pub cpus: Option<Box<[u32]>>,
    pub distances: Option<Box<[NumaDistance]>>,
    pub memory_zones: Option<Box<[String]>>,
    pub pci_segments: Option<Box<[u16]>>,
    pub device_id: Option<String>,
}

impl From<api_types::NumaConfig> for NumaConfig {
    fn from(value: api_types::NumaConfig) -> Self {
        Self {
            guest_numa_id: value.guest_numa_id,
            cpus: value.cpus,
            distances: value.distances,
            memory_zones: value.memory_zones,
            pci_segments: value.pci_segments,
            device_id: value.device_id,
        }
    }
}

impl From<&NumaConfig> for api_types::NumaConfig {
    fn from(value: &NumaConfig) -> Self {
        Self {
            guest_numa_id: value.guest_numa_id,
            cpus: value.cpus.clone(),
            distances: value.distances.clone(),
            memory_zones: value.memory_zones.clone(),
            pci_segments: value.pci_segments.clone(),
            device_id: value.device_id.clone(),
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadConfig {
    pub firmware: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub initramfs: Option<PathBuf>,
    #[cfg(feature = "igvm")]
    pub igvm: Option<PathBuf>,
    #[cfg(feature = "sev_snp")]
    pub host_data: Option<String>,
    #[cfg(feature = "fw_cfg")]
    pub fw_cfg_config: Option<FwCfgConfig>,
}

impl From<api_types::PayloadConfig> for PayloadConfig {
    fn from(value: api_types::PayloadConfig) -> Self {
        Self {
            firmware: value.firmware,
            kernel: value.kernel,
            cmdline: value.cmdline,
            initramfs: value.initramfs,
            #[cfg(feature = "igvm")]
            igvm: value.igvm,
            #[cfg(feature = "sev_snp")]
            host_data: value.host_data,
            #[cfg(feature = "fw_cfg")]
            fw_cfg_config: value.fw_cfg_config.map(Into::into),
        }
    }
}

impl From<&PayloadConfig> for api_types::PayloadConfig {
    fn from(value: &PayloadConfig) -> Self {
        Self {
            firmware: value.firmware.clone(),
            kernel: value.kernel.clone(),
            cmdline: value.cmdline.clone(),
            initramfs: value.initramfs.clone(),
            #[cfg(feature = "igvm")]
            igvm: value.igvm.clone(),
            #[cfg(feature = "sev_snp")]
            host_data: value.host_data.clone(),
            #[cfg(feature = "fw_cfg")]
            fw_cfg_config: value.fw_cfg_config.as_ref().map(Into::into),
        }
    }
}

#[cfg(feature = "fw_cfg")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FwCfgConfig {
    pub e820: bool,
    pub kernel: bool,
    pub cmdline: bool,
    pub initramfs: bool,
    pub acpi_tables: bool,
    pub items: Option<FwCfgItemList>,
}

#[cfg(feature = "fw_cfg")]
impl From<api_types::FwCfgConfig> for FwCfgConfig {
    fn from(value: api_types::FwCfgConfig) -> Self {
        Self {
            e820: value.e820,
            kernel: value.kernel,
            cmdline: value.cmdline,
            initramfs: value.initramfs,
            acpi_tables: value.acpi_tables,
            items: value.items,
        }
    }
}

#[cfg(feature = "fw_cfg")]
impl From<&FwCfgConfig> for api_types::FwCfgConfig {
    fn from(value: &FwCfgConfig) -> Self {
        Self {
            e820: value.e820,
            kernel: value.kernel,
            cmdline: value.cmdline,
            initramfs: value.initramfs,
            acpi_tables: value.acpi_tables,
            items: value.items.clone(),
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmConfig {
    pub socket: PathBuf,
}

impl From<api_types::TpmConfig> for TpmConfig {
    fn from(value: api_types::TpmConfig) -> Self {
        Self {
            socket: value.socket,
        }
    }
}

impl From<&TpmConfig> for api_types::TpmConfig {
    fn from(value: &TpmConfig) -> Self {
        Self {
            socket: value.socket.clone(),
        }
    }
}

impl ApplyLandlock for TpmConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.socket, "rw")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LandlockConfig {
    pub path: PathBuf,
    pub access: String,
}

impl From<api_types::LandlockConfig> for LandlockConfig {
    fn from(value: api_types::LandlockConfig) -> Self {
        Self {
            path: value.path,
            access: value.access,
        }
    }
}

impl From<&LandlockConfig> for api_types::LandlockConfig {
    fn from(value: &LandlockConfig) -> Self {
        Self {
            path: value.path.clone(),
            access: value.access.clone(),
        }
    }
}

impl ApplyLandlock for LandlockConfig {
    fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_access(&self.path, self.access.clone().as_str())?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VmConfig {
    pub cpus: CpusConfig,
    pub memory: MemoryConfig,
    pub payload: Option<PayloadConfig>,
    pub rate_limit_groups: Option<Box<[RateLimiterGroupConfig]>>,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    pub rng: RngConfig,
    pub balloon: Option<BalloonConfig>,
    pub generic_vhost_user: Option<Vec<GenericVhostUserConfig>>,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    pub serial: SerialConfig,
    pub console: ConsoleConfig,
    #[cfg(target_arch = "x86_64")]
    pub debug_console: DebugConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub user_devices: Option<Vec<UserDeviceConfig>>,
    pub vdpa: Option<Vec<VdpaConfig>>,
    pub vsock: Option<VsockConfig>,
    #[cfg(feature = "pvmemcontrol")]
    pub pvmemcontrol: Option<PvmemcontrolConfig>,
    pub pvpanic: bool,
    pub iommu: bool,
    pub numa: Option<Box<[NumaConfig]>>,
    pub watchdog: bool,
    pub rtc: Option<RtcConfig>,
    #[cfg(feature = "guest_debug")]
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
    pub preserved_fds: Option<HashSet<i32>>,
    pub landlock_enable: bool,
    pub landlock_rules: Option<Box<[LandlockConfig]>>,
    #[cfg(feature = "ivshmem")]
    pub ivshmem: Option<IvshmemConfig>,
}

impl TryFrom<api_types::VmConfig> for VmConfig {
    type Error = ValidationError;

    fn try_from(value: api_types::VmConfig) -> Result<Self, Self::Error> {
        let mut vm_config = Self {
            cpus: value.cpus,
            memory: value.memory.into(),
            payload: value.payload.map(Into::into),
            rate_limit_groups: value.rate_limit_groups.map(|configs| {
                configs
                    .into_vec()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            disks: value
                .disks
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            net: value
                .net
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            rng: value.rng.into(),
            balloon: value.balloon.map(Into::into),
            generic_vhost_user: value
                .generic_vhost_user
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            fs: value
                .fs
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            pmem: value
                .pmem
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            serial: value.serial.into(),
            console: value.console.into(),
            #[cfg(target_arch = "x86_64")]
            debug_console: value.debug_console.into(),
            devices: value
                .devices
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            user_devices: value
                .user_devices
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            vdpa: value
                .vdpa
                .map(|configs| configs.into_iter().map(Into::into).collect()),
            vsock: value.vsock.map(Into::into),
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: value.pvmemcontrol,
            pvpanic: value.pvpanic,
            iommu: value.iommu,
            numa: value.numa.map(|configs| {
                configs
                    .into_vec()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            watchdog: value.watchdog,
            rtc: value.rtc.map(Into::into),
            #[cfg(feature = "guest_debug")]
            gdb: value.gdb,
            pci_segments: value.pci_segments.map(|configs| {
                configs
                    .into_vec()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            platform: value.platform.map(Into::into),
            tpm: value.tpm.map(Into::into),
            preserved_fds: None,
            landlock_enable: value.landlock_enable,
            landlock_rules: value.landlock_rules.map(|configs| {
                configs
                    .into_vec()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            #[cfg(feature = "ivshmem")]
            ivshmem: value.ivshmem.map(Into::into),
        };
        vm_config.validate()?;
        Ok(vm_config)
    }
}

impl From<&VmConfig> for api_types::VmConfig {
    fn from(value: &VmConfig) -> Self {
        Self {
            cpus: value.cpus.clone(),
            memory: (&value.memory).into(),
            payload: value.payload.as_ref().map(Into::into),
            rate_limit_groups: value.rate_limit_groups.as_ref().map(|configs| {
                configs
                    .iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            disks: value
                .disks
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            net: value
                .net
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            rng: (&value.rng).into(),
            balloon: value.balloon.as_ref().map(Into::into),
            generic_vhost_user: value
                .generic_vhost_user
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            fs: value
                .fs
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            pmem: value
                .pmem
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            serial: (&value.serial).into(),
            console: (&value.console).into(),
            #[cfg(target_arch = "x86_64")]
            debug_console: (&value.debug_console).into(),
            devices: value
                .devices
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            user_devices: value
                .user_devices
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            vdpa: value
                .vdpa
                .as_ref()
                .map(|configs| configs.iter().map(Into::into).collect()),
            vsock: value.vsock.as_ref().map(Into::into),
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: value.pvmemcontrol.clone(),
            pvpanic: value.pvpanic,
            iommu: value.iommu,
            numa: value.numa.as_ref().map(|configs| {
                configs
                    .iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            watchdog: value.watchdog,
            rtc: value.rtc.as_ref().map(Into::into),
            #[cfg(feature = "guest_debug")]
            gdb: value.gdb,
            pci_segments: value.pci_segments.as_ref().map(|configs| {
                configs
                    .iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            platform: value.platform.as_ref().map(Into::into),
            tpm: value.tpm.as_ref().map(Into::into),
            landlock_enable: value.landlock_enable,
            landlock_rules: value.landlock_rules.as_ref().map(|configs| {
                configs
                    .iter()
                    .map(Into::into)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }),
            #[cfg(feature = "ivshmem")]
            ivshmem: value.ivshmem.as_ref().map(Into::into),
        }
    }
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
