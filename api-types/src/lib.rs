// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

mod migration;
mod restore;
mod vm_config;
mod vm_coredump;
mod vm_info;
mod vm_remove_device;
mod vm_resize;
mod vm_resize_disk;
mod vm_resize_zone;
mod vm_snapshot;
mod vm_state;
mod vmm_ping_response;

pub use block::ImageType;
pub use block::fcntl::{LockGranularityChoice, LockGranularityParseError};
pub use migration::{
    MigrationMode, TimeoutStrategy, VmReceiveMigrationData, VmReceiveMigrationDataParseError,
    VmSendMigrationData, VmSendMigrationDataParseError,
};
pub use restore::{
    MemoryRestoreMode, MemoryRestoreModeParseError, RestoreConfig, RestoreConfigParseError,
    RestoredNetConfig, RestoredVfioConfig, VmMemoryZoneUpdateData,
};
use serde::Deserialize;
#[cfg(feature = "pvmemcontrol")]
pub use vm_config::PvmemcontrolConfig;
pub use vm_config::balloon_config::{BalloonConfig, BalloonConfigParseError};
pub use vm_config::console_config::{
    CommonConsoleConfig, CommonConsoleConfigParseError, ConsoleConfig, ConsoleConfigParseError,
    ConsoleOutputMode, SerialConfig, SerialConfigParseError,
};
#[cfg(target_arch = "x86_64")]
pub use vm_config::console_config::{DebugConsoleConfig, DebugConsoleConfigParseError};
pub use vm_config::cpus_config::{
    CoreScheduling, CpuAffinity, CpuFeatures, CpuTopology, CpuTopologyParseError, CpusConfig,
    CpusConfigParseError, ParseCoreSchedulingError,
};
pub use vm_config::device_config::{DeviceConfig, DeviceConfigParseError};
pub use vm_config::disk_config::{DiskConfig, DiskConfigParseError, VirtQueueAffinity};
pub use vm_config::fs_config::{FsConfig, FsConfigParseError};
#[cfg(feature = "fw_cfg")]
pub use vm_config::fw_cfg_config::{
    FwCfgConfig, FwCfgConfigParseError, FwCfgItem, FwCfgItemError, FwCfgItemList,
};
pub use vm_config::generic_vhost_user_config::{
    GenericVhostUserConfig, GenericVhostUserConfigParseError,
};
#[cfg(feature = "ivshmem")]
pub use vm_config::ivshmem_config::{IvshmemConfig, IvshmemConfigParseError};
pub use vm_config::landlock_config::{LandlockConfig, LandlockConfigParseError};
pub use vm_config::memory_config::{
    HotplugMethod, MemoryConfig, MemoryConfigParseError, MemoryZoneConfig,
};
pub use vm_config::net_config::{NetConfig, NetConfigParseError, ParseVhostModeError, VhostMode};
pub use vm_config::numa_config::{NumaConfig, NumaDistance};
pub use vm_config::payload_config::PayloadConfig;
pub use vm_config::pci_device_common_config::{
    PciDeviceCommonConfig, PciDeviceCommonConfigParseError,
};
pub use vm_config::pci_segment_config::{PciSegmentConfig, PciSegmentConfigParseError};
pub use vm_config::platform_config::{PlatformConfig, PlatformConfigParseError};
pub use vm_config::pmem_config::{PmemConfig, PmemConfigParseError};
pub use vm_config::rate_limiter_group_config::{
    RateLimiterGroupConfig, RateLimiterGroupConfigParseError,
};
pub use vm_config::rng_config::{RngConfig, RngConfigParseError};
pub use vm_config::rtc_config::{RtcConfig, RtcConfigParseError};
pub use vm_config::tpm_config::{TpmConfig, TpmConfigParseError};
pub use vm_config::user_device_config::{UserDeviceConfig, UserDeviceConfigParseError};
pub use vm_config::vdpa_config::{VdpaConfig, VdpaConfigParseError};
pub use vm_config::vsock_config::{VsockConfig, VsockConfigParseError};
pub use vm_config::{VmConfig, VmConfigParseError, VmParams};
pub use vm_coredump::VmCoredumpData;
pub use vm_info::{DeviceNode, DeviceTree, VmInfoResponse};
pub use vm_remove_device::VmRemoveDeviceData;
pub use vm_resize::VmResizeData;
pub use vm_resize_disk::VmResizeDiskData;
pub use vm_resize_zone::VmResizeZoneData;
pub use vm_snapshot::VmSnapshotConfig;
pub use vm_state::VmState;
pub use vmm_ping_response::VmmPingResponse;

pub(crate) fn deserialize_restored_fd<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fd: Option<i32> = Option::deserialize(d)?;
    if invalid_fd.is_some() {
        Ok(Some(-1))
    } else {
        Ok(None)
    }
}
