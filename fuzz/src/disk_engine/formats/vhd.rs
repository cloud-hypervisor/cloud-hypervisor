// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed VHD adapter.

use std::fs::File;
use std::path::Path;

use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;
use block::formats::vhd::VhdDisk;

use crate::disk_engine::format::{DiskFormat, OpenConfig};

/// Fixed VHD images, as opened by [`VhdDisk`].
///
/// The io_uring backend is not selected: the `block` crate only builds it
/// with its `io_uring` feature, which the fuzz crate does not enable, and a
/// kernel ring per iteration would dominate the run time anyway.
///
/// There is no template image because the `block` crate parses a VHD footer
/// but never writes one, and a footer built inside the fuzzer would encode
/// the harness author's reading of the format rather than the code under
/// test. The parser is fuzzed through the image target instead.
pub struct Vhd;

impl DiskFormat for Vhd {
    const NAME: &'static str = "vhd";

    fn open(
        file: File,
        _path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let disk = VhdDisk::new(file, false, config.direct)?;
        Ok(Box::new(disk))
    }
}
