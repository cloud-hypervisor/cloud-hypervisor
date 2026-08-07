// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the QCOW2 backing chain code with a fuzzer built chain.
//!
//! The input is a length prefixed pair of images, `[u32 LE top_len][top
//! image][backing image]`, which the harness materializes in a scratch
//! directory before opening the top image with backing files enabled. Both
//! halves are fuzzer controlled, so a malformed backing image is reachable,
//! and the harness refuses any backing name that is not a plain file name in
//! that directory:
//!
//! ```text
//! scripts/generate-fuzz-seeds.sh
//! cargo fuzz run disk_qcow2_chain -j $(nproc) -- -max_len=4194312 \
//!     -dict=fuzz/dictionaries/qcow2.dict
//! ```

#![no_main]

use cloud_hypervisor_fuzz::disk_engine::formats::qcow2_chain::fuzz_chain;
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|bytes: &[u8]| -> Corpus { fuzz_chain(bytes) });
