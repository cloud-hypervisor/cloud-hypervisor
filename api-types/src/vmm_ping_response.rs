// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub struct VmmPingResponse {
    pub build_version: String,
    pub version: String,
    pub pid: i64,
    pub features: Vec<String>,
}
