// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod cpuid_adjustments;

/*
NOTE: This CpuProfile enum is a temporary stub that will be replaced in a follow up PR.
*/

/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between host's with potentially different CPU models.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CpuProfile {
    #[default]
    Host,
}
