// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Self test for the template images the operation targets run against.
//!
//! # Why this exists
//!
//! The dangerous failure mode of a templated target is not a template that
//! fails to open: `fuzz_program` panics on that and the breakage is obvious
//! within one iteration. It is a template that opens but is subtly wrong -
//! the wrong size, or one that already holds data because it was extracted
//! from an image something had written to. The shadow model is initialised to
//! "all zeroes, this many bytes". If the image disagrees, either every single
//! read trips the oracle, which is loud, or, far worse, the disk is tiny or
//! the ops all land outside it and the target quietly checks nothing. It then
//! reports a hundred per cent pass rate forever, contributes no coverage that
//! anybody notices is missing, and produces no crashes. Nothing in CI, in the
//! coverage report or in the crash count can tell that state from a healthy
//! one.
//!
//! So every format that implements [`DiskFormat::template`] asserts four
//! things about it, and the assertions are what the target's value rests on:
//!
//! a. the template opens through the format adapter;
//! b. its `logical_size()` is exactly the pinned constant;
//! c. reading the whole disk returns nothing but zero bytes;
//! d. [`default_program`] runs through the [`Executor`] with the shadow model
//!    enabled without panicking.

use block::async_io::{AsyncIoOperation, OwnedIoBuffer};

use crate::disk_engine::executor::Executor;
use crate::disk_engine::format::{DiskFormat, OpenConfig};
use crate::disk_engine::materialize_template;
use crate::disk_engine::program::default_program;

/// Chunk size the whole disk read of assertion (c) uses.
const READ_CHUNK: usize = 64 << 10;

/// Asserts that `F`'s template is the image the shadow model assumes.
///
/// `logical_size` is the capacity the template must report, pinned by the
/// caller so that a template that silently changed size is caught rather than
/// accommodated.
pub fn assert_template_is_sound<F: DiskFormat>(logical_size: u64) {
    let name = F::NAME;
    let template = F::template().unwrap_or_else(|| panic!("{name}: the format has no template"));

    // (a) The template opens through the adapter, with the same default
    // configuration `fuzz_program` uses.
    let (file, path) = materialize_template::<F>(template).expect("materializing the template");
    let disk = F::open(file, path.as_deref(), &OpenConfig::default())
        .unwrap_or_else(|e| panic!("{name}: the template failed to open: {e}"));

    // (b) It is the disk it is supposed to be. A template of the wrong size
    // is the failure that hides: the model would be built for a disk that
    // does not exist.
    let reported = disk
        .logical_size()
        .unwrap_or_else(|e| panic!("{name}: the template reported no size: {e}"));
    assert_eq!(
        reported, logical_size,
        "{name}: the template is {reported} bytes, not the pinned {logical_size}"
    );

    // (c) It reads back as all zeroes, the shadow model's precondition. The
    // buffer is filled with 0xff first, so a read that reports success
    // without touching the buffer fails here instead of passing.
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

    // (d) A program runs against it under the model. This is the whole target
    // in miniature: a fresh copy of the template, the model enabled, and the
    // fixed program that touches every op the engine has. Any oracle
    // violation the default program can reach panics here rather than waiting
    // for a fuzzing campaign.
    let (file, path) = materialize_template::<F>(template).expect("materializing the template");
    let disk = F::open(file, path.as_deref(), &OpenConfig::default())
        .unwrap_or_else(|e| panic!("{name}: the template failed to reopen: {e}"));
    let mut executor = Executor::<F>::new(disk, 1, true)
        .unwrap_or_else(|| panic!("{name}: the template refused an executor"));
    executor.run(&default_program());
}
