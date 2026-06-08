// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use hypervisor::arch::x86::MsrEntry;
use log::error;
use serde::{Deserialize, Serialize};

use crate::x86_64::Error;
use crate::x86_64::helpers::{
    deserialize_u32_hex, deserialize_u64_hex, serialize_u32_hex, serialize_u64_hex,
};

/// The register address of an MSR
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterAddress(
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    pub u32,
);

/// Used to adjust the value of a Feature MSR.
///
/// Instances of this struct typically adjust MSR values according to the
/// following formula: `msr_value = (self.mask & msr_value) | self.replacements`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeatureMsrAdjustment {
    /// Packs values to be placed into the given feature MSR value.
    #[serde(
        serialize_with = "serialize_u64_hex",
        deserialize_with = "deserialize_u64_hex"
    )]
    pub replacements: u64,

    /// Used to zero out the area `replacements` occupy. This mask is not necessarily !replacements, as replacements
    /// may pack values of different types that occupy varying ranges of bits.
    ///
    /// Bit ranges within a feature MSR value that are **not** supposed to be replaced/overwritten should be set in
    /// this mask.
    #[serde(
        serialize_with = "serialize_u64_hex",
        deserialize_with = "deserialize_u64_hex"
    )]
    pub mask: u64,
}

impl FeatureMsrAdjustment {
    /// Adjusts the given `feature_msrs` according to `adjustments`.
    ///
    /// An error is returned if there exists an MSR register address in
    /// `adjustments` without a matching entry in `feature_msrs`.
    pub fn adjust_to(
        adjustments: &[(RegisterAddress, FeatureMsrAdjustment)],
        feature_msrs: &[MsrEntry],
    ) -> Result<Vec<MsrEntry>, Error> {
        let mut missing_msr = false;
        let mut output_feature_msrs = Vec::with_capacity(feature_msrs.len());
        for (reg_address, adjustment) in adjustments {
            let Some(entry) = feature_msrs
                .iter()
                .find(|entry| entry.index == reg_address.0)
            else {
                missing_msr = true;
                error!(
                    "Did not find feature based MSR entry for MSR:={:#x}",
                    reg_address.0
                );
                continue;
            };
            // Adjust the entry and push it to outputs
            {
                let mut entry = *entry;
                let data = entry.data;
                entry.data = (adjustment.mask & data) | adjustment.replacements;

                log::debug!(
                    "prepared adjusted MSR feature: register address:={:#x} value:={:#x}, previous value:={data:#x}",
                    entry.index,
                    entry.data
                );
                output_feature_msrs.push(entry);
            }
        }
        if missing_msr {
            Err(Error::CpuProfileMissingMsr)
        } else {
            Ok(output_feature_msrs)
        }
    }
}

/// Data describing MSR adjustments related to a CPU profile.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MsrProfileData {
    /// Describes feature MSR adjustments necessary to become compatible with
    /// the desired target.
    pub adjustments: Vec<(RegisterAddress, FeatureMsrAdjustment)>,
    /// List of all MSRs that the CPU profile permits. MSRs supported by the host that
    /// are outside of this list need to be denied by a filter.
    pub permitted_msrs: Vec<RegisterAddress>,
}

/// Computed MSR updates required to be compatible with a given CPU profile.
pub struct RequiredMsrUpdates {
    /// Feature MSRs to be set
    pub feature_msrs: Vec<MsrEntry>,
    /// MSRs that must be denied via a filter
    pub denied_msrs: Vec<u32>,
}
