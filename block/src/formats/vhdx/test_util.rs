// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for VHDX image tests.

use std::process::Command;

use vmm_sys_util::tempfile::TempFile;

/// Generate a small dynamic VHDX with `qemu-img`. Returns `None` (and the
/// test is skipped) when `qemu-img` is unavailable, e.g. in minimal CI.
pub(crate) fn create_dynamic_vhdx(size_mib: u64) -> Option<TempFile> {
    let tf = TempFile::new().unwrap();
    let path = tf.as_path();
    let status = Command::new("qemu-img")
        .args(["create", "-f", "vhdx", "-o", "subformat=dynamic"])
        .arg(path)
        .arg(format!("{size_mib}M"))
        .status();
    match status {
        Ok(s) if s.success() => Some(tf),
        _ => None,
    }
}
