// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use hypervisor::arch::x86::CpuIdEntry;
use hypervisor::{CpuVendor, HypervisorType};
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::x86_64::CpuidReg;
use crate::x86_64::cpuid_definitions::{Parameters, deserialize_from_hex, serialize_as_hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between host's with potentially different CPU models.
pub enum CpuProfile {
    #[default]
    Host,
    Skylake,
    SapphireRapids,
}

impl CpuProfile {
    /// Loads pre-generated data associated with a CPU profile.
    ///
    /// If the `amx` flag is false then the AMX tile state components will be
    /// zeroed out from the associated profile data. This is necessary because
    /// they will then not be present in the vector of [`CpuidEntry`] values
    /// obtained from the hypervisor.
    //
    // We can only generate CPU profiles for the KVM hypervisor for the time being.
    #[cfg(feature = "kvm")]
    pub(in crate::x86_64) fn data(&self, amx: bool) -> Option<CpuProfileData> {
        let mut data: CpuProfileData = match self {
            Self::Host => None,
            Self::Skylake => todo!(),
            Self::SapphireRapids => todo!(),
        }?;

        if !amx {
            // In this case we will need to wipe out the AMX tile state components (if they are included in the profile)
            for adj in data.adjustments.iter_mut() {
                if adj.0.sub_leaf.start() != adj.0.sub_leaf.end() {
                    // The generated profiles produce as many sub-leaf entries as possible, and only use ranges for
                    // values not found.
                    continue;
                }
                let sub_leaf = *adj.0.sub_leaf.start();
                let leaf = adj.0.leaf;
                if (leaf == 0xd) && (sub_leaf == 0) && (adj.0.register == CpuidReg::EAX) {
                    adj.1.replacements &= !((1 << 17) | (1 << 18));
                }

                if (leaf == 0xd) && (sub_leaf == 1) && (adj.0.register == CpuidReg::ECX) {
                    adj.1.replacements &= !((1 << 17) | (1 << 18));
                }

                if (leaf == 0xd) && ((sub_leaf == 17) | (sub_leaf == 18)) {
                    adj.1.replacements = 0;
                }
            }
        }

        Some(data)
    }

    #[cfg(not(feature = "kvm"))]
    pub(in crate::x86_64) fn data(&self, _amx: bool) -> Option<CpuProfileData> {
        if matches!(*self, Self::Host) {
            return None;
        }
        // This will need to be addressed before upstreaming.
        // We will probably need one profile per hypervisor.
        unimplemented!()
    }
}

/// Every [`CpuProfile`] different from `Host` has associated [`CpuProfileData`].
///
/// New constructors of this struct may only be generated through the CHV CLI (when built from source with
/// the `cpu-profile-generation` feature) which other hosts may then attempt to load in order to
/// increase the likelihood of successful live migrations among all hosts that opted in to the given
/// CPU profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CpuProfileData {
    /// The hypervisor used when generating this CPU profile.
    pub(in crate::x86_64) hypervisor: HypervisorType,
    /// The vendor of the CPU belonging to the host that generated this CPU profile.
    pub(in crate::x86_64) cpu_vendor: CpuVendor,
    /// Adjustments necessary to become compatible with the desired target.
    pub(in crate::x86_64) adjustments: Vec<(Parameters, CpuidOutputRegisterAdjustments)>,
}

/* TODO: The [`CpuProfile`] struct will likely need a few more iterations. The following
section should explain why:

# MSR restrictions

CPU profiles also need to restrict which MSRs may be manipulated by the guest as various physical CPUs
can have differing supported MSRs.

The CPU profile will thus necessarily need to contain some data related to MSR restrictions. That will
be taken care of in a follow up MR.

*/

/// Used for adjusting an entire cpuid output register (EAX, EBX, ECX or EDX)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CpuidOutputRegisterAdjustments {
    #[serde(serialize_with = "serialize_as_hex")]
    #[serde(deserialize_with = "deserialize_from_hex")]
    pub(in crate::x86_64) replacements: u32,
    /// Used to zero out the area `replacements` occupy. This mask is not necessarily !replacements, as replacements may pack values of different types (i.e. it is wrong to think of it as a bitset conceptually speaking).
    #[serde(serialize_with = "serialize_as_hex")]
    #[serde(deserialize_with = "deserialize_from_hex")]
    pub(in crate::x86_64) mask: u32,
}
impl CpuidOutputRegisterAdjustments {
    pub(in crate::x86_64) fn adjust(self, cpuid_output_register: &mut u32) {
        let temp_register_copy = *cpuid_output_register;
        let replacements_area_masked_in_temp_copy = temp_register_copy & self.mask;
        *cpuid_output_register = replacements_area_masked_in_temp_copy | self.replacements;
    }

    pub(in crate::x86_64) fn adjust_cpuid_entries(
        mut cpuid: Vec<CpuIdEntry>,
        adjustments: &[(Parameters, Self)],
    ) -> Result<Vec<CpuIdEntry>, MissingCpuidEntriesError> {
        for entry in &mut cpuid {
            for (reg, reg_value) in [
                (CpuidReg::EAX, &mut entry.eax),
                (CpuidReg::EBX, &mut entry.ebx),
                (CpuidReg::ECX, &mut entry.ecx),
                (CpuidReg::EDX, &mut entry.edx),
            ] {
                // Get the adjustment corresponding to the entry's function/leaf and index/sub-leaf for each of the register. If no such
                // adjustment is found we use the trivial adjustment (leading to the register being zeroed out entirely).
                let adjustment = adjustments
                    .iter()
                    .find_map(|(param, adjustment)| {
                        ((param.leaf == entry.function)
                            & param.sub_leaf.contains(&entry.index)
                            & (param.register == reg))
                            .then_some(*adjustment)
                    })
                    .unwrap_or(CpuidOutputRegisterAdjustments {
                        mask: 0,
                        replacements: 0,
                    });
                adjustment.adjust(reg_value);
            }
        }

        Self::expected_entries_found(&cpuid, adjustments).map(|_| cpuid)
    }

    /// Check that we found every value that was supposed to be replaced with something else than 0
    ///
    /// IMPORTANT: This function assumes that the given `cpuid` has already been adjusted with the
    /// provided `adjustments`.
    fn expected_entries_found(
        cpuid: &[CpuIdEntry],
        adjustments: &[(Parameters, Self)],
    ) -> Result<(), MissingCpuidEntriesError> {
        let mut missing_entry = false;

        // Invalid state components can be ignored. The next few lines obtain the relevant entries to
        // check for this.
        let eax_0xd_0 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 0))
            .map(|entry| entry.eax)
            .unwrap_or(0);
        let ecx_0xd_1 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 1))
            .map(|entry| entry.ecx)
            .unwrap_or(0);

        let edx_0xd_0 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 0))
            .map(|entry| entry.edx)
            .unwrap_or(0);
        let edx_0xd_1 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 1))
            .map(|entry| entry.edx)
            .unwrap_or(0);

        for (param, adjustment) in adjustments {
            if adjustment.replacements == 0 {
                continue;
            }
            let sub_start = *param.sub_leaf.start();
            let sub_end = *param.sub_leaf.end();

            let can_skip_lo = if (param.leaf == 0xd) && (2..32).contains(&sub_start) {
                let start = sub_start;
                let end = std::cmp::min(sub_end, 31);
                let mask = (start..=end).fold(0, |acc, next| acc | (1 << next));
                ((mask & eax_0xd_0) == 0) & ((mask & ecx_0xd_1) == 0)
            } else {
                false
            };

            let can_skip_hi = if (param.leaf == 0xd) && (32..64).contains(&sub_end) {
                let start = std::cmp::max(32, sub_start);
                let end = sub_end;
                let mask = (start..=end)
                    .map(|val| val - 32)
                    .fold(0, |acc, next| acc | (1 << next));
                ((mask & edx_0xd_0) == 0) & ((mask & edx_0xd_1) == 0)
            } else {
                false
            };

            if can_skip_lo && can_skip_hi {
                // This means that all state components referred to by the specified sub-leaf range are not valid
                // and may be skipped.
                continue;
            }
            if !cpuid.iter().any(|entry| {
                (entry.function == param.leaf) && (param.sub_leaf.contains(&entry.index))
            }) {
                error!(
                    "cannot adjust CPU profile. No entry found matching the required parameters: {:?}",
                    param
                );
                missing_entry = true;
            }
        }
        if missing_entry {
            Err(MissingCpuidEntriesError)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
#[error("Required CPUID entries not found")]
pub(in crate::x86_64) struct MissingCpuidEntriesError;
