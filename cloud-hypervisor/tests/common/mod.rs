// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod live_migration;
pub(crate) mod tests_wrappers;
pub(crate) mod utils;

#[cfg(not(feature = "mshv"))]
pub(crate) mod snapshot_restore_common;
