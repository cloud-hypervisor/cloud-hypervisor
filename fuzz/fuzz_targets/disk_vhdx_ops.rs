// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the VHDX I/O path with op programs against a valid image.
//!
//! The image is a blank 4 MiB dynamic VHDX built from a run table in the
//! adapter, so read back data is checked against a shadow model of the disk
//! contents:
//!
//! ```text
//! cargo fuzz run disk_vhdx_ops -j $(nproc)
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::vhdx::Vhdx;
use cloud_hypervisor_fuzz::disk_engine::{fuzz_program, Program};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|program: Program| -> Corpus { fuzz_program::<Vhdx>(&program) });
