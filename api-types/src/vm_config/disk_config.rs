// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VirtQueueAffinity {
    pub queue_index: u16,
    pub host_cpus: Box<[usize]>,
}
