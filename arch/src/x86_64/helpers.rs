// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Write;

use serde::{Deserialize, Deserializer, Serializer};

// Introduce some helper functions to (de)-serialize u32's as hexadecimal
// strings

/// Serializes the given `input` as a hex string (starting with "0x").
///
/// As an example if `input:=5` then this function will feed the given
/// `serializer` the string "0x5".
pub(crate) fn serialize_u32_hex<S: Serializer>(
    input: &u32,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    // two bytes for "0x" prefix and at most eight for the hex encoded number
    let mut buffer = [0_u8; 10];
    let mut write_slice = &mut buffer[..];
    write!(write_slice, "{input:#x}").expect("This write should be infallible");
    let len = 10 - write_slice.len();
    let hex_str = core::str::from_utf8(&buffer[..len])
        .expect("the buffer should be filled with valid UTF-8 bytes");
    serializer.serialize_str(hex_str)
}

/// Deserializes a u32 from a hex string representation.
pub(crate) fn deserialize_u32_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u32, D::Error> {
    let hex = <&'de str as Deserialize>::deserialize(deserializer)?;
    u32::from_str_radix(hex.strip_prefix("0x").unwrap_or(""), 16).map_err(|_| {
        <D::Error as serde::de::Error>::custom(format!("{hex} is not a hex encoded 32 bit integer"))
    })
}
