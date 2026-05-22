// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod gic;
pub mod regs;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ExtendedReg {
    pub id: u64,
    pub data: Vec<u8>,
}
