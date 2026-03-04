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

use std::fmt::{self, Display, Formatter};

/// Small, stable classification of block errors.
///
/// Callers match on this for control flow. Adding new format specific
/// errors does not require new variants here.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum BlockErrorKind {
    /// An underlying I/O operation failed.
    Io,
    /// The disk image format is structurally invalid.
    InvalidFormat,
    /// The disk image requires a feature that is not implemented.
    UnsupportedFeature,
    /// The image is marked or detected as corrupt.
    CorruptImage,
    /// An address, offset, or index is outside the valid range.
    OutOfBounds,
    /// A file or required internal structure could not be found.
    NotFound,
    /// An internal counter or limit was exceeded.
    Overflow,
}

impl Display for BlockErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => write!(f, "I/O error"),
            Self::InvalidFormat => write!(f, "invalid format"),
            Self::UnsupportedFeature => write!(f, "unsupported feature"),
            Self::CorruptImage => write!(f, "corrupt image"),
            Self::OutOfBounds => write!(f, "out of bounds"),
            Self::NotFound => write!(f, "not found"),
            Self::Overflow => write!(f, "overflow"),
        }
    }
}
