// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for VHDX image tests.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;

use vmm_sys_util::tempfile::TempFile;

use super::dynamic::{Result, Vhdx};
use super::header::REGION_TABLE_1_START;
use crate::aligned_file::AlignedFile;
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

/// Edit a header or region table and recalculate its CRC32C checksum.
/// Flushing the resulting write is left to the caller.
pub(super) fn edit_header(
    file: &impl FileExt,
    offset: u64,
    length: usize,
    edit: impl FnOnce(&mut [u8]),
) {
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, offset).unwrap();
    edit(&mut bytes);
    bytes[4..8].fill(0);
    let mut crc = crc_any::CRC::crc32c();
    crc.digest(&bytes);
    bytes[4..8].copy_from_slice(&(crc.get_crc() as u32).to_le_bytes());
    file.write_all_at(&bytes, offset).unwrap();
}

/// Builds the 32-byte on-disk region table entry for `guid` describing
/// the region `[file_offset, file_offset + length)`.
pub(super) fn region_entry(guid: [u8; 16], file_offset: u64, length: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..16].copy_from_slice(&guid);
    e[16..24].copy_from_slice(&file_offset.to_le_bytes());
    e[24..28].copy_from_slice(&length.to_le_bytes());
    // `required` (e[28..32]) left zero.
    e
}

/// Write raw region entries without constructing or parsing a VHDX header.
pub(super) fn region_file(file_len: u64, entries: &[[u8; 32]]) -> AlignedFile {
    let file = TempFile::new().unwrap().into_file();
    file.set_len(file_len).unwrap();
    let entries_at = REGION_TABLE_1_START + 16; // Skip the region table header.
    for (index, entry) in entries.iter().enumerate() {
        file.write_all_at(entry, entries_at + (index * 32) as u64)
            .unwrap();
    }
    AlignedFile::new(file, false)
}
