// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the fixed VHD parser. The input is the image.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhd::{repair_footer_checksum, Vhd};
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_mutator, fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhd>(bytes) });

// Repair the footer checksum. One mutation in eight is left unrepaired, so
// the checksum rejection stays reachable.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let new_size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    if !seed.is_multiple_of(8) {
        repair_footer_checksum(&mut data[..new_size]);
    }
    new_size
});
