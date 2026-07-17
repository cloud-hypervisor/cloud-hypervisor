// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "pvmemcontrol")]
use serde::{Deserialize, Serialize};

pub(crate) mod balloon_config;
pub(crate) mod console_config;
pub(crate) mod cpus_config;
pub(crate) mod device_config;
pub(crate) mod disk_config;
pub(crate) mod fs_config;
#[cfg(feature = "fw_cfg")]
pub(crate) mod fw_cfg_config;
pub(crate) mod memory_config;
pub(crate) mod net_config;
pub(crate) mod numa_config;
pub(crate) mod pci_device_common_config;
pub(crate) mod pci_segment_config;
pub(crate) mod pmem_config;
pub(crate) mod rng_config;
pub(crate) mod rtc_config;
pub(crate) mod user_device_config;
pub(crate) mod vdpa_config;
pub(crate) mod vsock_config;

#[cfg(feature = "pvmemcontrol")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct PvmemcontrolConfig {}
