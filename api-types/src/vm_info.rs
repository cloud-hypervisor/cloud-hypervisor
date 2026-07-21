// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use pci::PciBdf;
use serde::{Deserialize, Serialize};
use vm_device::Resource;

use crate::{VmConfig, VmState};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DeviceTree(pub HashMap<String, DeviceNode>);

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceNode {
    pub id: String,
    pub resources: Vec<Resource>,
    pub parent: Option<String>,
    pub children: Vec<String>,
    pub pci_bdf: Option<PciBdf>,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Deserialize, Serialize)]
pub struct VmInfoResponse {
    pub config: Box<VmConfig>,
    pub state: VmState,
    pub memory_actual_size: u64,
    pub device_tree: Option<DeviceTree>,
}
