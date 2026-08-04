// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the VHDX parser. The input is the image.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhdx::{
    repair_checksums, restore_signatures, Vhdx,
};
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_mutator, fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhdx>(bytes) });

// Restore the signatures, then the checksums over them. One mutation in
// eight skips each repair, so both rejection branches stay reachable.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let new_size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    if !seed.is_multiple_of(8) {
        restore_signatures(&mut data[..new_size]);
    }
    if seed % 8 != 1 {
        repair_checksums(&mut data[..new_size]);
    }
    new_size
});
