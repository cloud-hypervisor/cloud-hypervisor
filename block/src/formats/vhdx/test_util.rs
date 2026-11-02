// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for VHDX image tests.

use vmm_sys_util::tempfile::TempFile;

use crate::test_util::shared::QemuImgCommand;

/// Generate a small dynamic VHDX with `qemu-img`.
pub(crate) fn create_dynamic_vhdx(size_mib: u64) -> TempFile {
    let tf = TempFile::new().unwrap();
    QemuImgCommand::new()
        .create("vhdx", "subformat=dynamic")
        .args(&[tf.as_path().to_str().unwrap(), &format!("{size_mib}M")])
        .run("Failed to create dynamic VHDX image");
    tf
}
