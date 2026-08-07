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
//! The fixed VHD footer is checksum protected and carries the `conectix`
//! cookie, and the parser refuses an image whose cookie is wrong or whose
//! stored checksum does not match the one it computes, so a plain byte
//! mutation of the footer is rejected before the parser looks at anything
//! else. The custom mutator below runs the default libFuzzer mutator and then
//! restores the cookie and repairs the checksum, which lets structural
//! mutations of the footer survive.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhd::{
    repair_footer_checksum, restore_footer_cookie, Vhd,
};
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_mutator, fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhd>(bytes) });

// The target itself still accepts arbitrary bytes: the corpus holds images
// this mutator never produced, and libFuzzer also feeds back inputs from the
// seed corpus and from other mutation sources unchanged.
//
// Neither repair is unconditional, so both rejection branches stay reachable
// and stay separable. One mutation in eight keeps a mutated cookie, with the
// checksum repaired, which is the only way to reach the cookie branch with an
// otherwise valid footer. A different one in eight keeps the mutated
// checksum, with the cookie restored, which is the only way to reach the
// checksum branch at all: the cookie is tested first, so a mutation that
// broke both never gets that far. The remaining six in eight are fully
// repaired and reach the parser.
//
// Order matters: the cookie is inside the checksummed area, so it has to be
// written before the checksum is computed over it.
//
// The footer is the last 512 bytes of the image, so it can only be located
// once `fuzzer_mutate` has returned the new size.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let new_size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    if seed % 8 != 0 {
        restore_footer_cookie(&mut data[..new_size]);
    }
    if seed % 8 != 1 {
        repair_footer_checksum(&mut data[..new_size]);
    }
    new_size
});
