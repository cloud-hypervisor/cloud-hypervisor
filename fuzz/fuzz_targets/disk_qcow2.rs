// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the QCOW2 parser with the input as the disk image.
//!
//! Corpus entries are plain qcow2 images, so `qemu-img` output can be used
//! as is:
//!
//! ```text
//! truncate -s 16M /tmp/source
//! qemu-img convert -O qcow2 /tmp/source fuzz/corpus/disk_qcow2/base.qcow2
//! cargo fuzz run disk_qcow2 -j $(nproc) -- -dict=fuzz/dictionaries/qcow2.dict
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2::Qcow2;
use cloud_hypervisor_fuzz::disk_engine::fuzz_image;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_image::<Qcow2>(bytes) });
