// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the image type sniffer with the input as the disk image.
//!
//! `block::detect_image_type` runs before any format specific parser, so it
//! sees every byte string a guest owner can point the VMM at. Its input space
//! is every format at once, which is why it is a target of its own rather
//! than a probe inside the per format image targets: an input that reaches a
//! new edge in the VHD sniffer says nothing about the VHDX parser, and
//! keeping it in the `disk_vhdx` corpus only spends that target's mutation
//! budget on images it can never open.
//!
//! The seed corpus is the union of the per format seeds, so a mutation starts
//! from a real image of one format and can drift towards another:
//!
//! ```text
//! scripts/generate-fuzz-seeds.sh
//! cargo fuzz run disk_detect -j $(nproc) -- -max_len=16777216
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::fuzz_detect;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_detect(bytes) });
