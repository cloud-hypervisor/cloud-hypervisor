// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

#[cfg(feature = "cmos")]
mod cmos;
#[cfg(feature = "fwdebug")]
mod fwdebug;
mod i8042;
mod serial;

#[cfg(feature = "cmos")]
pub use self::cmos::Cmos;
#[cfg(feature = "fwdebug")]
pub use self::fwdebug::FwDebugDevice;
pub use self::i8042::I8042Device;
pub use self::serial::Serial;
