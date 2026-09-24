// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_int, c_void};
use std::ptr::{NonNull, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

const QPL_PATH_AUTO: u32 = 0;
const QPL_PATH_HARDWARE: u32 = 1;
const QPL_STS_OK: c_int = 0;
const QPL_STS_BEING_PROCESSED: c_int = 1;
const QPL_STS_QUEUES_ARE_BUSY: c_int = 5;
const ASYNC_TIMEOUT: Duration = Duration::from_secs(60);
const COMPRESSION_BOUND_HEADROOM: u32 = 64 * 1024;

unsafe extern "C" {
    fn qpl_shim_create(execution_path: u32, result: *mut *mut c_void) -> c_int;
    fn qpl_shim_compression_bound(context: *mut c_void, input_size: u32) -> u32;
    fn qpl_shim_compress(
        context: *mut c_void,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        output_capacity: u32,
        output_size: *mut u32,
        dynamic_huffman: u32,
    ) -> c_int;
    fn qpl_shim_decompress(
        context: *mut c_void,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        output_capacity: u32,
        output_size: *mut u32,
    ) -> c_int;
    fn qpl_shim_submit_compress(
        context: *mut c_void,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        output_capacity: u32,
        dynamic_huffman: u32,
    ) -> c_int;
    fn qpl_shim_submit_decompress(
        context: *mut c_void,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        output_capacity: u32,
    ) -> c_int;
    fn qpl_shim_check(context: *mut c_void, output_size: *mut u32) -> c_int;
    fn qpl_shim_wait(context: *mut c_void) -> c_int;
    fn qpl_shim_destroy(context: *mut c_void);
}

#[derive(Clone, Copy)]
pub(crate) enum ExecutionPath {
    Auto,
    Hardware,
}

#[derive(Clone, Copy)]
pub(crate) enum HuffmanMode {
    Static,
    Dynamic,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("QPL initialization failed with status {0}")]
    Initialize(i32),
    #[error("QPL input is larger than 4 GiB")]
    InputTooLarge,
    #[error("QPL compression failed with status {0}")]
    Compress(i32),
    #[error("QPL decompression failed with status {0}")]
    Decompress(i32),
    #[error("QPL returned an invalid output size")]
    InvalidOutput,
    #[error("QPL asynchronous submission failed with status {0}")]
    Submit(i32),
    #[error("QPL asynchronous completion failed with status {0}")]
    Complete(i32),
    #[error("QPL asynchronous operation timed out")]
    Timeout,
}

pub(crate) struct Job {
    context: NonNull<c_void>,
    huffman_mode: HuffmanMode,
}

impl Job {
    pub(crate) fn new(path: ExecutionPath) -> Result<Self, Error> {
        Self::new_with_mode(path, HuffmanMode::Dynamic)
    }

    pub(crate) fn new_with_mode(
        path: ExecutionPath,
        huffman_mode: HuffmanMode,
    ) -> Result<Self, Error> {
        let execution_path = match path {
            ExecutionPath::Auto => QPL_PATH_AUTO,
            ExecutionPath::Hardware => QPL_PATH_HARDWARE,
        };
        let mut context = null_mut();
        // SAFETY: context points to writable storage for the newly allocated job.
        let status = unsafe { qpl_shim_create(execution_path, &mut context) };
        let context = NonNull::new(context).ok_or(Error::Initialize(status))?;
        if status != 0 {
            return Err(Error::Initialize(status));
        }
        Ok(Self {
            context,
            huffman_mode,
        })
    }

    pub(crate) fn compress_into(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let input_size = u32::try_from(input.len()).map_err(|_| Error::InputTooLarge)?;
        // SAFETY: context is owned and valid until Drop.
        let capacity = unsafe { qpl_shim_compression_bound(self.context.as_ptr(), input_size) }
            .checked_add(COMPRESSION_BOUND_HEADROOM)
            .ok_or(Error::InvalidOutput)?;
        if capacity == 0 {
            return Err(Error::InvalidOutput);
        }
        output.resize(capacity as usize, 0);
        let mut output_size = 0_u32;
        // SAFETY: all buffers remain valid and exclusively borrowed for the call.
        let status = unsafe {
            qpl_shim_compress(
                self.context.as_ptr(),
                input.as_ptr(),
                input_size,
                output.as_mut_ptr(),
                capacity,
                &mut output_size,
                matches!(self.huffman_mode, HuffmanMode::Dynamic).into(),
            )
        };
        if status != 0 {
            return Err(Error::Compress(status));
        }
        output.truncate(output_size as usize);
        Ok(())
    }

    pub(crate) fn decompress_into(
        &mut self,
        input: &[u8],
        expected_length: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let input_size = u32::try_from(input.len()).map_err(|_| Error::InputTooLarge)?;
        let output_capacity = u32::try_from(expected_length).map_err(|_| Error::InputTooLarge)?;
        output.resize(expected_length, 0);
        let mut output_size = 0_u32;
        // SAFETY: all buffers remain valid and exclusively borrowed for the call.
        let status = unsafe {
            qpl_shim_decompress(
                self.context.as_ptr(),
                input.as_ptr(),
                input_size,
                output.as_mut_ptr(),
                output_capacity,
                &mut output_size,
            )
        };
        if status != 0 {
            return Err(Error::Decompress(status));
        }
        if output_size as usize != expected_length {
            return Err(Error::InvalidOutput);
        }
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: this Job uniquely owns the context and drops it exactly once.
        unsafe { qpl_shim_destroy(self.context.as_ptr()) };
    }
}

struct PoolSlot {
    job: Job,
    input: Vec<u8>,
    output: Vec<u8>,
    submitted: bool,
    submitted_at: Option<Instant>,
}

pub(crate) struct JobPool {
    slots: Vec<PoolSlot>,
}

impl JobPool {
    pub(crate) fn new(
        path: ExecutionPath,
        huffman_mode: HuffmanMode,
        size: usize,
    ) -> Result<Self, Error> {
        let slots = (0..size.max(1))
            .map(|_| {
                Ok(PoolSlot {
                    job: Job::new_with_mode(path, huffman_mode)?,
                    input: Vec::new(),
                    output: Vec::new(),
                    submitted: false,
                    submitted_at: None,
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self { slots })
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn input_mut(&mut self, index: usize, size: usize) -> &mut [u8] {
        let slot = &mut self.slots[index];
        debug_assert!(!slot.submitted);
        slot.input.resize(size, 0);
        &mut slot.input
    }

    pub(crate) fn submit_compress(&mut self, index: usize) -> Result<(), Error> {
        let slot = &mut self.slots[index];
        debug_assert!(!slot.submitted);
        let input_size = u32::try_from(slot.input.len()).map_err(|_| Error::InputTooLarge)?;
        // SAFETY: the context is valid and exclusively owned by this slot.
        let output_capacity =
            unsafe { qpl_shim_compression_bound(slot.job.context.as_ptr(), input_size) }
                .checked_add(COMPRESSION_BOUND_HEADROOM)
                .ok_or(Error::InvalidOutput)?;
        if output_capacity == 0 {
            return Err(Error::InvalidOutput);
        }
        slot.output.resize(output_capacity as usize, 0);
        let deadline = Instant::now() + ASYNC_TIMEOUT;
        loop {
            // SAFETY: slot buffers cannot be resized again until this job completes.
            let status = unsafe {
                qpl_shim_submit_compress(
                    slot.job.context.as_ptr(),
                    slot.input.as_ptr(),
                    input_size,
                    slot.output.as_mut_ptr(),
                    output_capacity,
                    matches!(slot.job.huffman_mode, HuffmanMode::Dynamic).into(),
                )
            };
            if status == QPL_STS_OK {
                slot.submitted = true;
                slot.submitted_at = Some(Instant::now());
                return Ok(());
            }
            if status != QPL_STS_QUEUES_ARE_BUSY {
                return Err(Error::Submit(status));
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            thread::yield_now();
        }
    }

    pub(crate) fn submit_decompress(
        &mut self,
        index: usize,
        output_size: usize,
    ) -> Result<(), Error> {
        let slot = &mut self.slots[index];
        debug_assert!(!slot.submitted);
        let input_size = u32::try_from(slot.input.len()).map_err(|_| Error::InputTooLarge)?;
        let output_capacity = u32::try_from(output_size).map_err(|_| Error::InputTooLarge)?;
        slot.output.resize(output_size, 0);
        let deadline = Instant::now() + ASYNC_TIMEOUT;
        loop {
            // SAFETY: slot buffers cannot be resized again until this job completes.
            let status = unsafe {
                qpl_shim_submit_decompress(
                    slot.job.context.as_ptr(),
                    slot.input.as_ptr(),
                    input_size,
                    slot.output.as_mut_ptr(),
                    output_capacity,
                )
            };
            if status == QPL_STS_OK {
                slot.submitted = true;
                slot.submitted_at = Some(Instant::now());
                return Ok(());
            }
            if status != QPL_STS_QUEUES_ARE_BUSY {
                return Err(Error::Submit(status));
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            thread::yield_now();
        }
    }

    pub(crate) fn poll(&mut self, index: usize) -> Result<Option<usize>, Error> {
        let slot = &mut self.slots[index];
        debug_assert!(slot.submitted);
        let mut output_size = 0_u32;
        // SAFETY: the submitted job and both slot buffers remain valid.
        let status = unsafe { qpl_shim_check(slot.job.context.as_ptr(), &mut output_size) };
        match status {
            QPL_STS_OK => {
                slot.submitted = false;
                slot.submitted_at = None;
                if output_size as usize > slot.output.len() {
                    return Err(Error::InvalidOutput);
                }
                Ok(Some(output_size as usize))
            }
            QPL_STS_BEING_PROCESSED | QPL_STS_QUEUES_ARE_BUSY => {
                if slot
                    .submitted_at
                    .is_some_and(|submitted_at| submitted_at.elapsed() >= ASYNC_TIMEOUT)
                {
                    return Err(Error::Timeout);
                }
                Ok(None)
            }
            _ => {
                slot.submitted = false;
                slot.submitted_at = None;
                Err(Error::Complete(status))
            }
        }
    }

    pub(crate) fn output(&self, index: usize, size: usize) -> &[u8] {
        &self.slots[index].output[..size]
    }
}

impl Drop for JobPool {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            if slot.submitted {
                // SAFETY: the job and its buffers remain valid for the duration of Drop.
                unsafe { qpl_shim_wait(slot.job.context.as_ptr()) };
                slot.submitted = false;
                slot.submitted_at = None;
            }
        }
    }
}
