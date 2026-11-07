// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for VHDX image tests.

use vmm_sys_util::tempfile::TempFile;

use crate::test_util::qemu_img::QemuImg;

/// Generate a small dynamic VHDX with `qemu-img`.
pub(crate) fn create_dynamic_vhdx(size_mib: u64) -> TempFile {
    let tf = TempFile::new().unwrap();
    QemuImg::new()
        .args(["create", "-f", "vhdx", "-o", "subformat=dynamic"])
        .arg(tf.as_path())
        .arg(format!("{size_mib}M"))
        .run("Failed to create dynamic VHDX image");
    tf
}
