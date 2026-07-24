// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[cfg(feature = "fw_cfg")]
use super::fw_cfg_config::FwCfgConfig;

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
