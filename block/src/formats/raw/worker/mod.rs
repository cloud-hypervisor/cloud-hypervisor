// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Sync/async I/O workers for raw images.
//!
//! Each backend implements the [`AsyncIo`](crate::async_io::AsyncIo)
//! trait.

pub(crate) mod async_aio;
#[cfg(feature = "io_uring")]
pub(crate) mod async_uring;
pub(crate) mod sync;
#[cfg(test)]
pub(crate) mod tests;
