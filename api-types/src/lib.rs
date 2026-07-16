// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

mod vm_coredump;
mod vm_remove_device;
mod vm_resize;
mod vm_resize_disk;
mod vm_resize_zone;
mod vm_snapshot;

pub use vm_coredump::VmCoredumpData;
pub use vm_remove_device::VmRemoveDeviceData;
pub use vm_resize::VmResizeData;
pub use vm_resize_disk::VmResizeDiskData;
pub use vm_resize_zone::VmResizeZoneData;
pub use vm_snapshot::VmSnapshotConfig;
