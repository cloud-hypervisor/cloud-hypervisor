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
use std::path::PathBuf;

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

/// Classification of the operation that was in progress when an error occurred.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorOp {
    /// Opening a disk image file.
    Open,
    /// Detecting the image format.
    DetectImageType,
    /// Duplicating a backing-file descriptor.
    DupBackingFd,
}

impl Display for ErrorOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::DetectImageType => write!(f, "detect_image_type"),
            Self::DupBackingFd => write!(f, "dup_backing_fd"),
        }
    }
}

/// Optional diagnostic context attached to a [`BlockError`].
#[derive(Debug, Default, Clone)]
pub struct ErrorContext {
    pub path: Option<PathBuf>,
    pub offset: Option<u64>,
    pub op: Option<ErrorOp>,
}

impl Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut first = true;
        if let Some(path) = &self.path {
            write!(f, "path={}", path.display())?;
            first = false;
        }
        if let Some(offset) = self.offset {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "offset={offset:#x}")?;
            first = false;
        }
        if let Some(op) = self.op {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "op={op}")?;
        }
        Ok(())
    }
}
