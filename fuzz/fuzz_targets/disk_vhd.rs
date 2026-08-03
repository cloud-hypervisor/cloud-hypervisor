// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the fixed VHD parser with the input as the disk image.
//!
//! Corpus entries are plain VHD images, so `qemu-img` output can be used
//! as is:
//!
//! ```text
//! scripts/generate-fuzz-seeds.sh
//! cargo fuzz run disk_vhd -j $(nproc) -- -max_len=4194304 \
//!     -dict=fuzz/dictionaries/vhd.dict
//! ```
//!
//! The fixed VHD footer is checksum protected and the parser refuses an image
//! whose stored checksum does not match the one it computes, so a plain byte
//! mutation of the footer is rejected before the parser looks at anything
//! else. The custom mutator below runs the default libFuzzer mutator and then
//! repairs that checksum, which lets structural mutations of the footer
//! survive.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhd::{repair_footer_checksum, Vhd};
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_mutator, fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhd>(bytes) });

// The target itself still accepts arbitrary bytes: the corpus holds images
// this mutator never produced, and libFuzzer also feeds back inputs from the
// seed corpus and from other mutation sources unchanged.
//
// One mutation in eight is left unrepaired so the parser's checksum mismatch
// branch stays reachable.
//
// The footer is the last 512 bytes of the image, so it can only be located
// once `fuzzer_mutate` has returned the new size.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let new_size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    if seed % 8 != 0 {
        repair_footer_checksum(&mut data[..new_size]);
    }
    new_size
});
