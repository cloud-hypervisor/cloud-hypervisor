// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the flat VMDK I/O path with op programs against a valid image.
//!
//! The image is a fixed two extent descriptor built by the adapter, so read
//! back data is checked against a shadow model of the disk contents. That is
//! what puts the extent selection, the `file_base_offset + (offset -
//! virtual_start)` arithmetic and `spanning_io`'s per segment byte accounting
//! under a data correctness oracle:
//!
//! ```text
//! cargo fuzz run disk_vmdk_ops -j $(nproc)
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vmdk::Vmdk;
use cloud_hypervisor_fuzz::disk_engine::{fuzz_program, Program};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|program: Program| -> Corpus { fuzz_program::<Vmdk>(&program) });
