// Copyright © 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2023 Crusoe Energy Systems LLC
use crate::engine::{IoUringEngine, RawFileDisk, Wrapper};

pub type RawDiskAsync = RawFileDisk<IoUringEngine>;
pub type RawFileAsync = Wrapper<IoUringEngine>;

#[cfg(test)]
mod unit_tests {

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::raw_async_io_tests;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsync::new(file.try_clone().unwrap(), 128).unwrap();
        raw_async_io_tests::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsync::new(file.try_clone().unwrap(), 128).unwrap();
        raw_async_io_tests::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsync::new(file.try_clone().unwrap(), 128).unwrap();
        raw_async_io_tests::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }
}
