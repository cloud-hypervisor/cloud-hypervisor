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

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhd::Vhd;
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vhd>(bytes) });
