// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::x86::bindings::*;

#[cfg(target_arch = "aarch")]
mod arm;
#[cfg(target_arch = "aarch")]
pub use self::arm::bindings::*;

#[cfg(target_arch = "aarch64")]
mod arm64;
#[cfg(target_arch = "aarch64")]
pub use self::arm64::bindings::*;
