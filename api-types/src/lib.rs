// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

mod vm_resize;
mod vm_resize_disk;
mod vm_resize_zone;

pub use vm_resize::VmResizeData;
pub use vm_resize_disk::VmResizeDiskData;
pub use vm_resize_zone::VmResizeZoneData;
