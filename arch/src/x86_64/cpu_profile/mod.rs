// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod cpuid_adjustments;

// TODO: Auto generate the CpuProfile enum with a build script once we introduce user facing CPU profiles.

/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between hosts with potentially different CPU models.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CpuProfile {
    #[default]
    Host,
}
