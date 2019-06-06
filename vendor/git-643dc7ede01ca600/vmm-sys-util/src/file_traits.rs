// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: BSD-3-Clause

use std::fs::File;
use std::io::Result;

/// A trait for flushing the contents of a file to disk.
/// This is equivalent to File's `sync_all` method, but
/// wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileSync {
    // Flush buffers related to this file to disk.
    fn fsync(&mut self) -> Result<()>;
}

impl FileSync for File {
    fn fsync(&mut self) -> Result<()> {
        self.sync_all()
    }
}

/// A trait for setting the size of a file.
/// This is equivalent to File's `set_len` method, but
/// wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileSetLen {
    // Set the size of this file.
    // This is the moral equivalent of `ftruncate()`.
    fn set_len(&self, _len: u64) -> Result<()>;
}

impl FileSetLen for File {
    fn set_len(&self, len: u64) -> Result<()> {
        File::set_len(self, len)
    }
}
