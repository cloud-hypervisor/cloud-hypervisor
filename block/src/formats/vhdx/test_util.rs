// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for VHDX image tests.

use std::fs::OpenOptions;
use std::path::Path;

use vmm_sys_util::tempfile::TempFile;

use super::dynamic::{Result, Vhdx};
use crate::test_util::shared::QemuImgCommand;

/// Generate a dynamic VHDX with `qemu-img`.
pub(crate) fn create_dynamic_vhdx(size_mib: u64, block_size_mib: Option<u32>) -> TempFile {
    let tf = TempFile::new().unwrap();
    let options = match block_size_mib {
        Some(size) => format!("subformat=dynamic,block_size={size}M"),
        None => "subformat=dynamic".to_owned(),
    };
    QemuImgCommand::new()
        .create("vhdx", &options)
        .args(&[tf.as_path().to_str().unwrap(), &format!("{size_mib}M")])
        .run("Failed to create dynamic VHDX image");
    tf
}

/// Open an image read-write without consuming its temporary file.
pub(super) fn open_vhdx(path: &Path) -> Result<Vhdx> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    Vhdx::new(file, false)
}
