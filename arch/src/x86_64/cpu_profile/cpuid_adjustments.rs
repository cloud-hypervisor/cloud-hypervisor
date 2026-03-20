// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module contains types associated with adjusting CPUID entries according
//! to a selected CPU profile.

use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

use crate::x86_64::{CpuidReg, deserialize_u32_hex, serialize_u32_hex};

/// Parameters for inspecting CPUID definitions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    // The leaf (EAX) parameter used with the CPUID instruction
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    pub leaf: u32,
    // The sub-leaf (ECX) parameter used with the CPUID instruction
    #[serde(
        serialize_with = "serialize_range_hex",
        deserialize_with = "deserialize_range_hex"
    )]
    pub sub_leaf: RangeInclusive<u32>,
    // The register we are interested in inspecting which gets filled by the CPUID instruction
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
