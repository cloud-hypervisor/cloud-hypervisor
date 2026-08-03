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

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhdx::Vhdx;
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhdx>(bytes) });
