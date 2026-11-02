// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Format adapters.

pub mod qcow2;
pub mod qcow2_chain;
#[cfg(test)]
#[path = "../../../../cloud-hypervisor/tests/common/mod.rs"]
pub mod test_utils;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;
