// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the VHDX parser with the input as the disk image.
//!
//! Corpus entries are plain VHDX images, so `qemu-img` output can be used
//! as is:
//!
//! ```text
//! scripts/generate-fuzz-seeds.sh
//! cargo fuzz run disk_vhdx -j $(nproc) -- -max_len=16777216 \
//!     -dict=fuzz/dictionaries/vhdx.dict
//! ```
//!
//! Both VHDX headers and both region tables are CRC-32C protected and the
//! parser refuses an image whose checksums do not match, so a plain byte
//! mutation of any of them is rejected before the parser looks at anything
//! else. The custom mutator below runs the default libFuzzer mutator and then
//! repairs those four checksums, which lets structural mutations survive.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhdx::{repair_checksums, Vhdx};
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_mutator, fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhdx>(bytes) });

// The target itself still accepts arbitrary bytes: the corpus holds images
// this mutator never produced, and libFuzzer also feeds back inputs from the
// seed corpus and from other mutation sources unchanged.
fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        let new_size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
        repair_checksums(&mut data[..new_size]);
        new_size
    }
);
