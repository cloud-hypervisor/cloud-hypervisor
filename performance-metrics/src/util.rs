// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared benchmark helpers.

use std::io::ErrorKind;
use std::thread;
use std::time::Duration;

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::tempfile::TempFile;

pub const BLOCK_SIZE: u64 = 4096;

/// Create a temporary file pre sized to hold `num_blocks` blocks.
pub fn sized_tempfile(num_blocks: usize) -> TempFile {
    let tmp = TempFile::new().expect("failed to create tempfile");
    tmp.as_file()
        .set_len(BLOCK_SIZE * num_blocks as u64)
        .expect("failed to set file length");
    tmp
}

/// Spin and wait until the given eventfd becomes readable.
pub fn wait_for_eventfd(notifier: &EventFd) {
    loop {
        match notifier.read() {
            Ok(_) => return,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_micros(50));
            }
            Err(e) => panic!("eventfd read failed: {e}"),
        }
    }
}
