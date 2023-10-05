// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use vm_memory::{bitmap::AtomicBitmap, GuestAddress};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEM_SIZE: usize = 256 * 1024 * 1024;
// From 'arch::x86_64::layout::CMDLINE_START'
const CMDLINE_START: GuestAddress = GuestAddress(0x20000);

fuzz_target!(|bytes| {
    let payload_config = vmm::config::PayloadConfig {
        firmware: None,
        kernel: None,
        cmdline: Some(String::from_utf8_lossy(&bytes).to_string()),
        initramfs: None,
        #[cfg(feature = "igvm")]
        igvm: None,
    };
    let kernel_cmdline = match vmm::vm::Vm::generate_cmdline(&payload_config) {
        Ok(cmdline) => cmdline,
        _ => return,
    };
    let guest_memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]).unwrap();

    linux_loader::loader::load_cmdline(&guest_memory, CMDLINE_START, &kernel_cmdline).ok();
});
