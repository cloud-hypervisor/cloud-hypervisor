// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#[macro_use]
extern crate log;

pub mod descriptor_utils;
pub mod file_traits;
pub mod filesystem;
pub mod fs_cache_req_handler;
pub mod fuse;
pub mod multikey;
pub mod passthrough;
pub mod sandbox;
pub mod server;

use std::ffi::FromBytesWithNulError;
use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    /// Failed to decode protocol messages.
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    EncodeMessage(io::Error),
    /// One or more parameters are missing.
    MissingParameter,
    /// A C string parameter is invalid.
    InvalidCString(FromBytesWithNulError),
    /// The `len` field of the header is too small.
    InvalidHeaderLength,
    /// The `size` field of the `SetxattrIn` message does not match the length
    /// of the decoded value.
    InvalidXattrSize((u32, usize)),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            DecodeMessage(err) => write!(f, "failed to decode fuse message: {}", err),
            EncodeMessage(err) => write!(f, "failed to encode fuse message: {}", err),
            MissingParameter => write!(f, "one or more parameters are missing"),
            InvalidHeaderLength => write!(f, "the `len` field of the header is too small"),
            InvalidCString(err) => write!(f, "a c string parameter is invalid: {}", err),
            InvalidXattrSize((size, len)) => write!(
                f,
                "The `size` field of the `SetxattrIn` message does not match the length of the\
                 decoded value: size = {}, value.len() = {}",
                size, len
            ),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
