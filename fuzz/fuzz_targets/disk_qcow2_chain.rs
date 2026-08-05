// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes qcow2 backing chains. The input is
//! `[u32 LE top_len][top image][backing image]`.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2_chain::fuzz_chain;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_chain(bytes) });
