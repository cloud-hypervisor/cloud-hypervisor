// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the VHDX parser. The input is the image.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhdx::{repair_checksums, Vhdx};
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_mutator, fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhdx>(bytes) });

// Repair the checksums, so structural mutations reach the parser.
fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        let new_size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
        repair_checksums(&mut data[..new_size]);
        new_size
    }
);
