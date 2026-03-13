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

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::io;
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
            Self::InvalidFormat => write!(f, "Invalid format"),
            Self::UnsupportedFeature => write!(f, "Unsupported feature"),
            Self::CorruptImage => write!(f, "Corrupt image"),
            Self::OutOfBounds => write!(f, "Out of bounds"),
            Self::NotFound => write!(f, "Not found"),
            Self::Overflow => write!(f, "Overflow"),
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
    /// Resizing a disk image.
    Resize,
}

impl Display for ErrorOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::DetectImageType => write!(f, "detect_image_type"),
            Self::DupBackingFd => write!(f, "dup_backing_fd"),
            Self::Resize => write!(f, "resize"),
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

/// Unified error type for the block crate.
///
/// Pairs a stable [`BlockErrorKind`] classification with an optional
/// boxed source error (format-specific) and optional [`ErrorContext`].
///
/// Display renders kind + context only; the underlying cause is
/// exposed via [`std::error::Error::source()`] for reporters that
/// walk the chain.
#[derive(Debug)]
pub struct BlockError {
    kind: BlockErrorKind,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    ctx: Option<ErrorContext>,
}

impl BlockError {
    /// Create a new `BlockError` from a kind and a source error.
    pub fn new<E>(kind: BlockErrorKind, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            kind,
            source: Some(Box::new(source)),
            ctx: None,
        }
    }

    /// Create a `BlockError` from just a kind, with no underlying cause.
    pub fn from_kind(kind: BlockErrorKind) -> Self {
        Self {
            kind,
            source: None,
            ctx: None,
        }
    }

    /// Attach or replace the source error (builder-style).
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Attach diagnostic context.
    pub fn with_ctx(mut self, ctx: ErrorContext) -> Self {
        self.ctx = Some(ctx);
        self
    }

    /// Replace the error classification (builder-style).
    pub fn with_kind(mut self, kind: BlockErrorKind) -> Self {
        self.kind = kind;
        self
    }

    /// Shorthand: attach an operation name.
    pub fn with_op(mut self, op: ErrorOp) -> Self {
        self.ctx.get_or_insert_with(ErrorContext::default).op = Some(op);
        self
    }

    /// Shorthand: attach a file path.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ctx.get_or_insert_with(ErrorContext::default).path = Some(path.into());
        self
    }

    /// Shorthand: attach a byte offset.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.ctx.get_or_insert_with(ErrorContext::default).offset = Some(offset);
        self
    }

    /// The error classification.
    pub fn kind(&self) -> BlockErrorKind {
        self.kind
    }

    /// The diagnostic context, if any.
    pub fn context(&self) -> Option<&ErrorContext> {
        self.ctx.as_ref()
    }

    /// Access the underlying source error, if any.
    pub fn source_ref(&self) -> Option<&(dyn StdError + Send + Sync + 'static)> {
        self.source.as_deref()
    }

    /// Try to downcast the source to a concrete type.
    pub fn downcast_ref<T: StdError + 'static>(&self) -> Option<&T> {
        self.source.as_ref()?.downcast_ref::<T>()
    }

    /// Consume the error and return the boxed source, if any.
    pub fn into_source(self) -> Option<Box<dyn StdError + Send + Sync + 'static>> {
        self.source
    }
}

impl Display for BlockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ctx) = &self.ctx {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

impl StdError for BlockError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn StdError + 'static))
    }
}

/// Convenience: wrap an `io::Error` as `BlockErrorKind::Io`.
impl From<io::Error> for BlockError {
    fn from(e: io::Error) -> Self {
        Self::new(BlockErrorKind::Io, e)
    }
}

/// Temporary scaffolding: classify a `qcow::Error` into the appropriate
/// `BlockErrorKind`.
///
/// This impl exists only to allow an incremental migration of the qcow
/// parse/construct chain from `qcow::Result` to `BlockResult`. Each
/// subsequent commit replaces bare `?` sites with explicit
/// `BlockError::new(kind, e)` calls. Once every site is migrated this
/// impl will be removed.
impl From<crate::qcow::Error> for BlockError {
    fn from(e: crate::qcow::Error) -> Self {
        use crate::qcow::Error as E;
        let kind = match &e {
            // Structural / format violations
            E::InvalidMagic
            | E::BackingFileTooLong(_)
            | E::InvalidBackingFileName(_)
            | E::InvalidClusterSize
            | E::InvalidL1TableSize(_)
            | E::InvalidL1TableOffset
            | E::InvalidOffset(_)
            | E::InvalidRefcountTableOffset
            | E::InvalidRefcountTableSize(_)
            | E::FileTooBig(_)
            | E::NoRefcountClusters
            | E::RefcountTableOffEnd
            | E::RefcountTableTooLarge
            | E::TooManyL1Entries(_)
            | E::TooManyRefcounts(_)
            | E::SizeTooSmallForNumberOfClusters => BlockErrorKind::InvalidFormat,

            // Unsupported features / versions
            E::UnsupportedVersion(_)
            | E::UnsupportedFeature(_)
            | E::UnsupportedCompressionType
            | E::UnsupportedBackingFileFormat(_)
            | E::UnsupportedRefcountOrder
            | E::BackingFilesDisabled
            | E::ShrinkNotSupported => BlockErrorKind::UnsupportedFeature,

            // Corrupt image
            E::CorruptImage => BlockErrorKind::CorruptImage,

            // Nesting depth overflow
            E::MaxNestingDepthExceeded => BlockErrorKind::Overflow,

            // Everything else is I/O
            _ => BlockErrorKind::Io,
        };
        Self::new(kind, e)
    }
}

pub type BlockResult<T> = Result<T, BlockError>;
