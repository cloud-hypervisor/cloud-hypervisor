// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the flat VMDK descriptor parser and extent layout.
//!
//! The input is the descriptor, which is what `--disk path=` points at for a
//! VMDK image. The harness materializes it in a scratch directory holding the
//! extent files a descriptor may name, so corpus entries are the descriptors
//! `qemu-img` writes:
//!
//! ```text
//! scripts/generate-fuzz-seeds.sh
//! cargo fuzz run disk_vmdk -j $(nproc) -- -max_len=65536 \
//!     -dict=fuzz/dictionaries/vmdk.dict
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vmdk::Vmdk;
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Vmdk>(bytes) });
