// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes qcow2 I/O with op programs against a template image.

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2::Qcow2;
use cloud_hypervisor_fuzz::disk_engine::{fuzz_program, Program};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|program: Program| -> Corpus { fuzz_program::<Qcow2>(&program) });
