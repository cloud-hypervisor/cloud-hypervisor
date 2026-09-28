// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the flat VMDK parser. The input is the descriptor.
//!
//! This bypasses the production `backing_files` gate, so the target admits
//! only relative extent names and runs under Landlock.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vmdk::{fuzz_vmdk, Vmdk};
use cloud_hypervisor_fuzz::disk_engine::{initialize_path_backed, DiskFormat};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(
    init: {
        if !initialize_path_backed(Vmdk::NAME) {
            std::process::exit(2);
        }
    },
    |bytes: &[u8]| -> Corpus { fuzz_vmdk(bytes) }
);
