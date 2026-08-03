// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the qcow2 parser. The input is the image.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2::Qcow2;
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Qcow2>(bytes) });
