// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared test helpers for [`AsyncIo`] backends.
//!
//! Each helper takes a `&mut dyn AsyncIo` together with the [`File`] handle
//! that backs the I/O object, so the same logic exercises every backend with
//! only the constructor differing.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::async_io::{AsyncIo, AsyncIoError};

/// Tests punching a hole in the middle of a 4 MB file and verifying data
/// integrity around the hole.
pub fn test_punch_hole(async_io: &mut dyn AsyncIo, file: &mut File) {
    // Write 4MB of data
    let data = vec![0xAA; 4 * 1024 * 1024];
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();

    // Punch hole in the middle (1MB at offset 1MB)
    let offset = 1024 * 1024;
    let length = 1024 * 1024;
    async_io.punch_hole(offset, length, 1).unwrap();

    // Check completion
    let (user_data, result) = async_io.next_completed_request().unwrap();
    assert_eq!(user_data, 1);
    assert_eq!(result, 0);

    // Verify the hole reads as zeros
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut read_buf = vec![0; length as usize];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0),
        "Punched hole should read as zeros"
    );

    // Verify data before hole is intact
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xAA),
        "Data before hole should be intact"
    );

    // Verify data after hole is intact
    file.seek(SeekFrom::Start(offset + length)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xAA),
        "Data after hole should be intact"
    );
}

/// Tests writing zeroes to a 512 KB region inside a 4 MB file and verifying
/// surrounding data is preserved.  Gracefully skips when the filesystem does
/// not support `FALLOC_FL_ZERO_RANGE`.
pub fn test_write_zeroes(async_io: &mut dyn AsyncIo, file: &mut File) {
    // Write 4MB of data
    let data = vec![0xBB; 4 * 1024 * 1024];
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();

    // Write zeros in the middle (512KB at offset 2MB)
    let offset = 2 * 1024 * 1024;
    let length = 512 * 1024;
    let write_zeroes_result = async_io.write_zeroes(offset, length, 2);

    // FALLOC_FL_ZERO_RANGE might not be supported on all filesystems (e.g., tmpfs)
    // If it fails with ENOTSUP, skip the test
    if let Err(AsyncIoError::WriteZeroes(ref e)) = write_zeroes_result
        && (e.raw_os_error() == Some(libc::EOPNOTSUPP) || e.raw_os_error() == Some(libc::ENOTSUP))
    {
        eprintln!("Skipping test_write_zeroes: filesystem doesn't support FALLOC_FL_ZERO_RANGE");
        return;
    }
    write_zeroes_result.unwrap();

    // Check completion
    let (user_data, result) = async_io.next_completed_request().unwrap();
    assert_eq!(user_data, 2);
    assert_eq!(result, 0);

    // Verify the zeroed region reads as zeros
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut read_buf = vec![0; length as usize];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0),
        "Zeroed region should read as zeros"
    );

    // Verify data before zeroed region is intact
    file.seek(SeekFrom::Start(offset - 1024)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xBB),
        "Data before zeroed region should be intact"
    );

    // Verify data after zeroed region is intact
    file.seek(SeekFrom::Start(offset + length)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xBB),
        "Data after zeroed region should be intact"
    );
}

/// Tests punching multiple holes in an 8 MB file and verifying each hole
/// independently reads as zeroes.
pub fn test_punch_hole_multiple_operations(async_io: &mut dyn AsyncIo, file: &mut File) {
    // Write 8MB of data
    let data = vec![0xCC; 8 * 1024 * 1024];
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();

    // Punch multiple holes
    async_io.punch_hole(1024 * 1024, 512 * 1024, 10).unwrap();
    async_io
        .punch_hole(3 * 1024 * 1024, 512 * 1024, 11)
        .unwrap();
    async_io
        .punch_hole(5 * 1024 * 1024, 512 * 1024, 12)
        .unwrap();

    // Check all completions
    let (user_data, result) = async_io.next_completed_request().unwrap();
    assert_eq!(user_data, 10);
    assert_eq!(result, 0);

    let (user_data, result) = async_io.next_completed_request().unwrap();
    assert_eq!(user_data, 11);
    assert_eq!(result, 0);

    let (user_data, result) = async_io.next_completed_request().unwrap();
    assert_eq!(user_data, 12);
    assert_eq!(result, 0);

    // Verify all holes read as zeros
    file.seek(SeekFrom::Start(1024 * 1024)).unwrap();
    let mut read_buf = vec![0; 512 * 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));

    file.seek(SeekFrom::Start(3 * 1024 * 1024)).unwrap();
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));

    file.seek(SeekFrom::Start(5 * 1024 * 1024)).unwrap();
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));
}
