// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "pvmemcontrol")]
use serde::{Deserialize, Serialize};

pub(crate) mod console_config;
pub(crate) mod cpus_config;
pub(crate) mod disk_config;
#[cfg(feature = "fw_cfg")]
pub(crate) mod fw_cfg_config;
pub(crate) mod memory_config;
pub(crate) mod net_config;
pub(crate) mod numa_config;
pub(crate) mod pci_device_common_config;
pub(crate) mod rtc_config;

#[cfg(feature = "pvmemcontrol")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct PvmemcontrolConfig {}
