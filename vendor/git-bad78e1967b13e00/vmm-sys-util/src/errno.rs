// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::fmt::{Display, Formatter};
use std::io;
use std::result;

use libc::__errno_location;

/// An error number, retrieved from [`errno`](http://man7.org/linux/man-pages/man3/errno.3.html),
/// set by a libc function that returned an error.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Error(i32);
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Constructs a new error with the given `errno`.
    pub fn new(e: i32) -> Error {
        Error(e)
    }

    /// Constructs an error from the current `errno`.
    ///
    /// The result of this only has any meaning just after a libc call that returned a value
    /// indicating `errno` was set.
    pub fn last() -> Error {
        Error(unsafe { *__errno_location() })
    }

    /// Gets the `errno` for this error.
    pub fn errno(self) -> i32 {
        self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        io::Error::from_raw_os_error(self.0).fmt(f)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::new(e.raw_os_error().unwrap_or_default())
    }
}

/// Returns the last `errno` as a [`Result`] that is always an error.
///
/// [`Result`]: type.Result.html
pub fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc;
    use std::fs::File;
    use std::io::{self, Write};
    use std::os::unix::io::FromRawFd;

    #[test]
    pub fn test_invalid_fd() {
        let mut file = unsafe { File::from_raw_fd(-1) };
        assert!(file.write(b"test").is_err());
        let last_err = errno_result::<i32>().unwrap_err();
        assert_eq!(last_err, Error::new(libc::EBADF));
        assert_eq!(last_err.errno(), libc::EBADF);
        assert_eq!(last_err, Error::from(io::Error::last_os_error()));
        assert_eq!(last_err, Error::last());
    }
}
