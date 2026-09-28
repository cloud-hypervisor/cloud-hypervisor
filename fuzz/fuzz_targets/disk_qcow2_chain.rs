// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes qcow2 backing chains. The input is
//! `[u32 LE top_len][top image][backing image]`.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2_chain::{fuzz_chain, Qcow2Chain};
use cloud_hypervisor_fuzz::disk_engine::{initialize_path_backed, DiskFormat};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(
    init: {
        if !initialize_path_backed(Qcow2Chain::NAME) {
            std::process::exit(2);
        }
    },
    |bytes: &[u8]| -> Corpus { fuzz_chain(bytes) }
);
