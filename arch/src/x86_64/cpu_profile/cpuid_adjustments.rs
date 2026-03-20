// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module contains types associated with adjusting CPUID entries according
//! to a selected CPU profile.

use std::io::Write;
use std::ops::RangeInclusive;

use serde::ser::SerializeStruct;
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

/// Used for adjusting an entire cpuid output register (EAX, EBX, ECX or EDX)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct CpuidOutputRegisterAdjustments {
    #[serde(deserialize_with = "deserialize_u32_hex")]
    pub replacements: u32,
    /// Used to zero out the area `replacements` occupy. This mask is not necessarily !replacements, as replacements may pack values of different types (i.e. it is wrong to think of it as a bitset conceptually speaking).
    #[serde(deserialize_with = "deserialize_u32_hex")]
    pub mask: u32,
}

/*
We want to serialize the values as 10 bytes, starting with 0x,
regardless of the value. This makes it easier for humans to compare different serialized values.
*/
impl Serialize for CpuidOutputRegisterAdjustments {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("CpuidOutputRegisterAdjustments", 2)?;
        let mut serialize_field = |key, value| {
            // two bytes for "0x" prefix and eight for the hex encoded number
            let mut buffer = [0_u8; 10];
            write!(&mut buffer[..], "{value:#010x}").expect("This write should be infallible");
            let str = core::str::from_utf8(&buffer[..])
                .expect("the buffer should be filled with valid UTF-8 bytes");
            s.serialize_field(key, str)
        };
        serialize_field("replacements", self.replacements)?;
        serialize_field("mask", self.mask)?;
        s.end()
    }
}

#[cfg(test)]
mod unit_tests {
    use proptest::prelude::*;

    use super::CpuidOutputRegisterAdjustments;

    // Check that serializing and then deserializing `CpuidOutputResiterAdjustments` results in the same value we started with.
    //
    // Also check that the serialized numeric values satisfy our expectations: They are 10-byte hex encoded strings
    proptest! {
        #[test]
        fn cpuid_output_register_adjustments_serialization_works(replacements in any::<u32>(), mask in any::<u32>()) {
            // Randomly generate these values. Several of the generated values will not represent anything that may be
            // produced in practice, but (de-)serialization does not take such domain knowledge into account (if that changes
            // then this test will need to be updated).
            let adjustments = CpuidOutputRegisterAdjustments {
                replacements,
                mask
            };
            let serialized = serde_json::to_string(&adjustments).unwrap();
            let deserialized: CpuidOutputRegisterAdjustments = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(&deserialized, &adjustments);
            let json = serde_json::to_value(adjustments).unwrap();
            let replacements_str = json.get("replacements").unwrap().as_str().unwrap();
            let mask_str = json.get("mask").unwrap().as_str().unwrap();
            let check_str_invariants = |value: &str| {
                prop_assert!(value.starts_with("0x"));
                prop_assert_eq!(value.len(),10);
                prop_assert!(value.as_bytes().iter().all(|byte| byte.is_ascii()));
                let is_hex_digit = |byte: &u8| -> bool {
                    byte.is_ascii_digit() | (*byte == b'a') | (*byte == b'b') | (*byte == b'c') | (*byte == b'd') | (*byte == b'e') | (*byte == b'f')
                };
                prop_assert!(
                    value.as_bytes()[2..].iter().all(is_hex_digit)
                );
                Ok(())
            };
            check_str_invariants(replacements_str)?;
            check_str_invariants(mask_str)?;
        }
    }
}
