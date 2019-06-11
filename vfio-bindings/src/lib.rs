// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// generated with bindgen linux/uapi/linux/vfio.h --constified-enum '*' --with-derive-default
#[cfg(feature = "v5_0_0")]
mod v5_0_0;

pub mod bindings {
    #[cfg(feature = "v5_0_0")]
    pub use super::v5_0_0::*;
}
