// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module contains types associated with adjusting CPUID entries according
//! to a selected CPU profile.

use std::ops::RangeInclusive;

use hypervisor::arch::x86::CpuIdEntry;
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::x86_64::{CpuidReg, deserialize_u32_hex, serialize_u32_hex};

/// Parameters for inspecting CPUID definitions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CpuidParameters {
    /// The leaf (EAX) parameter used with the CPUID instruction
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    pub leaf: u32,
    /// The sub-leaf (ECX) parameter used with the CPUID instruction
    #[serde(
        serialize_with = "serialize_range_hex",
        deserialize_with = "deserialize_range_hex"
    )]
    pub sub_leaf: RangeInclusive<u32>,
    /// The register we are interested in inspecting which gets filled by the CPUID instruction
    pub register: CpuidReg,
}

// Only used for (de-)serialization
#[derive(Debug, Serialize, Deserialize)]
struct ProvisionalRangeInclusive {
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    start: u32,
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    end: u32,
}

fn serialize_range_hex<S: serde::Serializer>(
    input: &RangeInclusive<u32>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let provisional = ProvisionalRangeInclusive {
        start: *input.start(),
        end: *input.end(),
    };
    provisional.serialize(serializer)
}

fn deserialize_range_hex<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<RangeInclusive<u32>, D::Error> {
    let ProvisionalRangeInclusive { start, end } =
        ProvisionalRangeInclusive::deserialize(deserializer)?;
    Ok(start..=end)
}

/// Used for adjusting an entire cpuid output register (EAX, EBX, ECX or EDX).
///
/// Instances of this struct typically adjust CPUID according to the following
/// formula: `cpuid_reg_value = (self.mask & cpuid_reg_value) | self.replacements`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuidOutputRegisterAdjustments {
    /// Packs values to be placed into the given CPUID output register.
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    pub replacements: u32,
    /// Used to zero out the area `replacements` occupy. This mask is not necessarily !replacements, as replacements
    /// may pack values of different types that occupy varying ranges of bits.
    ///
    /// Bit ranges within a CPUID output register that are **not** supposed to be replaced/overwritten should be set in
    /// this mask.
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    pub mask: u32,
}

/// Error type indicating that expected CPUID entries could not be found.
///
/// This type does not record which entries could not be found as we do not
/// expect this to be actionable at runtime. Instead we encourage logging such
/// violations when and where they are detected.
#[derive(Debug, Error)]
#[error("Required CPUID entries not found")]
pub struct MissingCpuidEntriesError;

impl CpuidOutputRegisterAdjustments {
    /// Adjust the given `cpuid_output_register` by retaining and replacing values according to `self`.
    fn adjust(self, cpuid_output_register: &mut u32) {
        *cpuid_output_register &= self.mask;
        *cpuid_output_register |= self.replacements;
    }

    /// Adjust `cpuid` according to the given `adjustments`.
    ///
    /// The returned vector of cpuid entries covers the same CPUID (sub-) leaves as the given `cpuid` input,
    /// but values without matching [`CpuidParameters`] are zeroed out.
    ///
    /// # Errors
    ///
    /// An error is returned if an entry cannot be found for an adjustment describing non-zero replacements.
    pub(super) fn adjust_cpuid_entries(
        mut cpuid: Vec<CpuIdEntry>,
        adjustments: &[(CpuidParameters, Self)],
    ) -> Result<Vec<CpuIdEntry>, MissingCpuidEntriesError> {
        for entry in &mut cpuid {
            for (reg, reg_value) in [
                (CpuidReg::EAX, &mut entry.eax),
                (CpuidReg::EBX, &mut entry.ebx),
                (CpuidReg::ECX, &mut entry.ecx),
                (CpuidReg::EDX, &mut entry.edx),
            ] {
                // Lookup the adjustment corresponding to the entry's function/leaf and index/sub-leaf for each of the register.
                let register_adjustments: Option<CpuidOutputRegisterAdjustments> =
                    adjustments.iter().find_map(|(param, adjustment)| {
                        ((param.leaf == entry.function)
                            && param.sub_leaf.contains(&entry.index)
                            && (param.register == reg))
                            .then_some(*adjustment)
                    });

                match register_adjustments {
                    Some(adjustment) => adjustment.adjust(reg_value),
                    None => {
                        // No matching cpuid parameters were found. We thus set the value of the register to 0.
                        *reg_value = 0;
                    }
                }
            }
        }

        Self::expected_entries_found(&cpuid, adjustments)?;
        Ok(cpuid)
    }

    /// Check that we found every value that was supposed to be replaced with something else than 0
    ///
    /// IMPORTANT: This function assumes that the given `cpuid` has already been adjusted with the
    /// provided `adjustments`.
    fn expected_entries_found(
        cpuid: &[CpuIdEntry],
        adjustments: &[(CpuidParameters, Self)],
    ) -> Result<(), MissingCpuidEntriesError> {
        let mut missing_entry = false;

        for (param, adjustment) in adjustments {
            if adjustment.replacements == 0 {
                continue;
            }

            if !cpuid.iter().any(|entry| {
                (entry.function == param.leaf) && (param.sub_leaf.contains(&entry.index))
            }) {
                error!(
                    "cannot adjust CPU profile. No entry found matching the required parameters: {param:?}"
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
