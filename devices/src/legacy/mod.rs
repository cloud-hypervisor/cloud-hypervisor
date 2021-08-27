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
#[cfg(target_arch = "aarch64")]
mod gpio_pl061;
mod i8042;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
mod serial;
mod serial_buffer;
#[cfg(target_arch = "aarch64")]
mod uart_pl011;

#[cfg(feature = "cmos")]
pub use self::cmos::Cmos;
#[cfg(feature = "fwdebug")]
pub use self::fwdebug::FwDebugDevice;
pub use self::i8042::I8042Device;
pub use self::serial::Serial;

#[cfg(target_arch = "aarch64")]
pub use self::gpio_pl061::Error as GpioDeviceError;
#[cfg(target_arch = "aarch64")]
pub use self::gpio_pl061::Gpio;
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::Rtc;
#[cfg(target_arch = "aarch64")]
pub use self::uart_pl011::Pl011;
