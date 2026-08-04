// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes image type validation with an image of any format.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::fuzz_detect;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_detect(bytes) });
