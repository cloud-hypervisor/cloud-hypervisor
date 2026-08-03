// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the QCOW2 I/O path with op programs against a valid image.
//!
//! The image is a freshly created qcow2 template, so read back data is
//! checked against a shadow model of the disk contents:
//!
//! ```text
//! cargo fuzz run disk_qcow2_ops -j $(nproc)
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2::Qcow2;
use cloud_hypervisor_fuzz::disk_engine::{fuzz_program, Program};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|program: Program| -> Corpus { fuzz_program::<Qcow2>(&program) });
