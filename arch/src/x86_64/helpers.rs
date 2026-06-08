// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Deserializer, Serializer, de};

/// Serializes the given `input` as a hex string (starting with "0x").
///
/// As an example if `input:=5` then this function will feed the given
/// `serializer` the string "0x5".
pub(crate) fn serialize_u32_hex<S: Serializer>(
    input: &u32,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{input:#x}"))
}

/// Deserializes a u32 from a hex string representation.
pub(crate) fn deserialize_u32_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u32, D::Error> {
    let hex: &str = <&str>::deserialize(deserializer)?;
    u32::from_str_radix(hex.strip_prefix("0x").unwrap_or(""), 16).map_err(|_| {
        <D::Error as de::Error>::custom(format!("{hex} is not a hex encoded 32 bit integer"))
    })
}

/// 64-bit version of `serialize_u32_hex`
pub(crate) fn serialize_u64_hex<S: Serializer>(
    input: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{input:#x}"))
}

/// 64-bit version of `deserialize_u32_hex`
pub(crate) fn deserialize_u64_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let hex: &str = <&str>::deserialize(deserializer)?;
    u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(""), 16).map_err(|_| {
        <D::Error as de::Error>::custom(format!("{hex} is not a hex encoded 64 bit integer"))
    })
}

#[cfg(test)]
mod unit_tests {
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    struct TestStruct {
        #[serde(
            serialize_with = "serialize_u32_hex",
            deserialize_with = "deserialize_u32_hex"
        )]
        foo: u32,
        #[serde(
            serialize_with = "serialize_u32_hex",
            deserialize_with = "deserialize_u32_hex"
        )]
        bar: u32,
    }

    // Check that our hex serializers satisfy the two following invariants
    // 1. Serialization followed by deserialization is the identity.
    // 2. Values of type u32 are serialized to strings starting with "0x" and then
    // a sub-string where all characters are ascii hex digits (with the letters [a-f] always in lowercase).
    proptest! {
        #[test]
        fn hex_serialization_works(foo in any::<u32>(), bar in any::<u32>()) {
            let t = TestStruct { foo , bar };

            let t_string = serde_json::to_string(&t).unwrap();
            let t_deserialized = serde_json::from_str(&t_string).unwrap();
            prop_assert_eq!(t, t_deserialized);

            let t_json = serde_json::to_value(t).unwrap();

            let check_str_invariants = |value: &str| {
                prop_assert!(value.starts_with("0x"));
                prop_assert!(value.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit));
                prop_assert!(!value.as_bytes()[2..].iter().any(u8::is_ascii_uppercase));
                Ok(())
            };

            let foo_str = t_json.get("foo").unwrap().as_str().unwrap();
            let bar_str = t_json.get("bar").unwrap().as_str().unwrap();

            check_str_invariants(foo_str)?;
            check_str_invariants(bar_str)?;

        }
    }
}
