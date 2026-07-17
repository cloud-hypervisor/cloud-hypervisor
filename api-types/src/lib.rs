// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

mod migration;
mod restore;
mod vm_config;
mod vm_coredump;
mod vm_remove_device;
mod vm_resize;
mod vm_resize_disk;
mod vm_resize_zone;
mod vm_snapshot;
mod vmm_ping_response;

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
pub use vm_config::console_config::ConsoleOutputMode;
pub use vm_config::cpus_config::{
    CoreScheduling, CpuAffinity, CpuFeatures, CpuTopology, CpuTopologyParseError, CpusConfig,
    CpusConfigParseError, ParseCoreSchedulingError,
};
pub use vm_config::disk_config::VirtQueueAffinity;
pub use vm_config::memory_config::{HotplugMethod, MemoryZoneConfig};
pub use vm_config::net_config::{ParseVhostModeError, VhostMode};
pub use vm_config::numa_config::NumaDistance;
pub use vm_coredump::VmCoredumpData;
pub use vm_remove_device::VmRemoveDeviceData;
pub use vm_resize::VmResizeData;
pub use vm_resize_disk::VmResizeDiskData;
pub use vm_resize_zone::VmResizeZoneData;
pub use vm_snapshot::VmSnapshotConfig;
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
