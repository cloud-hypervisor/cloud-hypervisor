// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Template self test. A template that opens but has the wrong size or is
//! not blank would make its operation target silently check nothing, so
//! every template must open, have its pinned size, read back as zeroes and
//! run [`default_program`] under the model.

use block::async_io::{AsyncIoOperation, OwnedIoBuffer};

use crate::disk_engine::executor::Executor;
use crate::disk_engine::format::{DiskFormat, OpenConfig};
use crate::disk_engine::materialize_template;
use crate::disk_engine::program::default_program;

/// Chunk size of the whole disk read.
const READ_CHUNK: usize = 64 << 10;

/// Asserts that `F`'s template is a blank disk of `logical_size` bytes.
pub fn assert_template_is_sound<F: DiskFormat>(logical_size: u64) {
    let name = F::NAME;
    let template = F::template().unwrap_or_else(|| panic!("{name}: the format has no template"));

    // (a) It opens with the default configuration.
    let (file, path) = materialize_template::<F>(template).expect("materializing the template");
    let disk = F::open(file, path.as_deref(), &OpenConfig::default())
        .unwrap_or_else(|e| panic!("{name}: the template failed to open: {e}"));

    // (b) It has the pinned size.
    let reported = disk
        .logical_size()
        .unwrap_or_else(|e| panic!("{name}: the template reported no size: {e}"));
    assert_eq!(
        reported, logical_size,
        "{name}: the template is {reported} bytes, not the pinned {logical_size}"
    );

    // (c) It reads back as zeroes. The 0xff fill catches a read that does not
    // touch the buffer.
    let mut io = disk
        .create_async_io(1)
        .unwrap_or_else(|e| panic!("{name}: the template refused an I/O engine: {e}"));
    let mut offset = 0u64;
    while offset < logical_size {
        let len = READ_CHUNK.min((logical_size - offset) as usize);
        let op = AsyncIoOperation::read_to_vec(
            offset as libc::off_t,
            OwnedIoBuffer::from_vec(vec![0xffu8; len]),
            1,
        );
        io.submit_data_operation(op)
            .unwrap_or_else(|e| panic!("{name}: reading the template at {offset} failed: {e}"));
        let completion = io
            .next_completed_request()
            .unwrap_or_else(|| panic!("{name}: the read at {offset} produced no completion"));
        assert_eq!(
            completion.result, len as i32,
            "{name}: the read at {offset} returned {} of {len} bytes",
            completion.result
        );
        let buffer = completion
            .buffer
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: the read at {offset} returned no buffer"));
        if let Some(at) = buffer.as_slice()[..len].iter().position(|byte| *byte != 0) {
            panic!(
                "{name}: the template is not blank: byte {} is {:#04x}",
                offset + at as u64,
                buffer.as_slice()[at]
            );
        }
        offset += len as u64;
    }
    drop(io);
    drop(disk);

    // (d) The default program runs under the model.
    let (file, path) = materialize_template::<F>(template).expect("materializing the template");
    let disk = F::open(file, path.as_deref(), &OpenConfig::default())
        .unwrap_or_else(|e| panic!("{name}: the template failed to reopen: {e}"));
    let mut executor = Executor::<F>::new(disk, 1, true)
        .unwrap_or_else(|| panic!("{name}: the template refused an executor"));
    executor.run(&default_program());
}
