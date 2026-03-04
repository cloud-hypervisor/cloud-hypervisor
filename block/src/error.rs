// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Unified error handling for the block crate.
//!
//! # Architecture
//!
//! ```text
//! BlockError                 -- single public error type
//!  |-- BlockErrorKind        -- small, stable, matchable classification
//!  |-- ErrorContext          -- optional diagnostic metadata (path, offset, op)
//!  +-- source                -- format-specific error (boxed)
//!         |-- QcowError
//!         |-- VhdError / RawError / ...
//!         +-- io::Error / etc.
//! ```
