// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARM PL031 Real Time Clock
//!
//! This module implements part of a PL031 Real Time Clock (RTC):
//! * provide a clock value via RTCDR
//! * no alarm is implemented through the match register
//! * no interrupt is generated
//! * RTC cannot be disabled via RTCCR
//! * no test registers
use std::result;
use std::sync::{Arc, Barrier};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use log::{debug, warn};
use thiserror::Error;
use vm_device::BusDevice;

use crate::{read_le_u32, write_le_u32};

// As you can see in https://developer.arm.com/documentation/ddi0224/c/
// at section 3.2 Summary of RTC registers, the total size occupied by this device is 0x000 -> 0xFFC + 4 = 0x1000.
// From 0x0 to 0x1C we have following registers:
const RTCDR: u64 = 0x0; // Data Register.
const RTCMR: u64 = 0x4; // Match Register.
const RTCLR: u64 = 0x8; // Load Register.
const RTCCR: u64 = 0xc; // Control Register.
const RTCIMSC: u64 = 0x10; // Interrupt Mask Set or Clear Register.
const RTCRIS: u64 = 0x14; // Raw Interrupt Status.
const RTCMIS: u64 = 0x18; // Masked Interrupt Status.
const RTCICR: u64 = 0x1c; // Interrupt Clear Register.
// From 0x020 to 0xFDC => reserved space.
// From 0xFE0 to 0x1000 => Peripheral and PrimeCell Identification Registers which are Read Only registers.
// AMBA standard devices have CIDs (Cell IDs) and PIDs (Peripheral IDs). The linux kernel will look for these in order to assert the identity
// of these devices (i.e look at the `amba_device_try_add` function).
// We are putting the expected values (look at 'Reset value' column from above mentioned document) in an array.
const PL031_ID: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];
// We are only interested in the margins.
const AMBA_ID_LOW: u64 = 0xFE0;
const AMBA_ID_HIGH: u64 = 0x1000;
/// Constant to convert seconds to nanoseconds.
pub(super) const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Debug, Error)]
pub(super) enum Error {
    #[error("Bad Write Offset: {0}")]
    BadWriteOffset(u64),
}

type Result<T> = result::Result<T, Error>;

/// Converts a timestamp in seconds to an equivalent one in nanoseconds.
/// Returns `None` if the conversion overflows.
///
/// # Arguments
///
/// * `value` - Timestamp in seconds.
pub(super) fn seconds_to_nanoseconds(value: i64) -> Option<i64> {
    value.checked_mul(NANOS_PER_SECOND as i64)
}

/// A RTC device following the PL031 specification..
pub struct Rtc {
    previous_now: Instant,
    tick_offset: i64,
    // This is used for implementing the RTC alarm. However, in Firecracker we do not need it.
    match_value: u32,
    // Writes to this register load an update value into the RTC.
    load: u32,
}

impl Rtc {
    /// Constructs an AMBA PL031 RTC device.
    pub fn new() -> Self {
        Self {
            // This is used only for duration measuring purposes.
            previous_now: Instant::now(),
            tick_offset: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64,
            match_value: 0,
            load: 0,
        }
    }

    fn get_time(&self) -> u32 {
        let ts = (self.tick_offset as i128)
            + (Instant::now().duration_since(self.previous_now).as_nanos() as i128);
        (ts / NANOS_PER_SECOND as i128) as u32
    }

    fn handle_write(&mut self, offset: u64, val: u32) -> Result<()> {
        match offset {
            RTCMR => {
                // The MR register is used for implementing the RTC alarm. A real time clock alarm is
                // a feature that can be used to allow a computer to 'wake up' after shut down to execute
                // tasks every day or on a certain day. It can sometimes be found in the 'Power Management'
                // section of a motherboard's BIOS setup. This is functionality that extends beyond
                // Firecracker intended use. However, we increment a metric just in case.
                self.match_value = val;
            }
            RTCLR => {
                self.load = val;
                self.previous_now = Instant::now();
                // If the unwrap fails, then the internal value of the clock has been corrupted and
                // we want to terminate the execution of the process.
                self.tick_offset = seconds_to_nanoseconds(i64::from(val)).unwrap();
            }
            RTCIMSC => (),
            RTCICR => (),
            RTCCR => (), // ignore attempts to turn off the timer.
            o => {
                return Err(Error::BadWriteOffset(o));
            }
        }
        Ok(())
    }
}

impl Default for Rtc {
    fn default() -> Self {
        Self::new()
    }
}

impl BusDevice for Rtc {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let mut read_ok = true;

        let v = if (AMBA_ID_LOW..AMBA_ID_HIGH).contains(&offset) {
            let index = ((offset - AMBA_ID_LOW) >> 2) as usize;
            u32::from(PL031_ID[index])
        } else {
            match offset {
                RTCDR => self.get_time(),
                RTCMR => {
                    // Even though we are not implementing RTC alarm we return the last value
                    self.match_value
                }
                RTCLR => self.load,
                RTCCR => 1,   // RTC is always enabled.
                RTCIMSC => 0, // Interrupt is always disabled.
                RTCRIS => 0,
                RTCMIS => 0,
                _ => {
                    read_ok = false;
                    0
                }
            }
        };
        if read_ok && data.len() <= 4 {
            write_le_u32(data, v);
        } else {
            debug!(
                "Invalid RTC PL031 read: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() <= 4 {
            let v = read_le_u32(data);
            if let Err(e) = self.handle_write(offset, v) {
                warn!("Failed to write to RTC PL031 device: {e}");
            }
        } else {
            debug!(
                "Invalid RTC PL031 write: offset {offset}, data length {}",
                data.len()
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        read_be_u16, read_be_u32, read_le_i32, read_le_u16, read_le_u64, write_be_u16,
        write_be_u32, write_le_i32, write_le_u16, write_le_u64,
    };

    const LEGACY_RTC_MAPPED_IO_START: u64 = 0x0901_0000;

    #[test]
    fn test_seconds_to_nanoseconds() {
        assert_eq!(
            seconds_to_nanoseconds(100).unwrap() as u64,
            100 * NANOS_PER_SECOND
        );

        assert!(seconds_to_nanoseconds(9_223_372_037).is_none());
    }

    #[test]
    fn test_rtc_read_write_and_event() {
        let mut rtc = Rtc::new();
        let mut data = [0; 4];

        // Read and write to the MR register.
        write_le_u32(&mut data, 123);
        rtc.write(LEGACY_RTC_MAPPED_IO_START, RTCMR, &data);
        rtc.read(LEGACY_RTC_MAPPED_IO_START, RTCMR, &mut data);
        let v = read_le_u32(&data);
        assert_eq!(v, 123);

        // Read and write to the LR register.
        let v = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("host clock should be after the Unix epoch")
            .as_secs() as u32;
        write_le_u32(&mut data, v);
        let previous_now_before = rtc.previous_now;
        rtc.write(LEGACY_RTC_MAPPED_IO_START, RTCLR, &data);

        assert!(rtc.previous_now > previous_now_before);

        rtc.read(LEGACY_RTC_MAPPED_IO_START, RTCLR, &mut data);
        let v_read = read_le_u32(&data);
        assert_eq!(v, v_read);

        // Read and write to IMSC register.
        // Test with non zero value. Our device ignores the write.
        let non_zero = 1;
        write_le_u32(&mut data, non_zero);
        rtc.write(LEGACY_RTC_MAPPED_IO_START, RTCIMSC, &data);
        rtc.read(LEGACY_RTC_MAPPED_IO_START, RTCIMSC, &mut data);
        let v = read_le_u32(&data);
        assert_eq!(0, v);

        // Now test with 0.
        write_le_u32(&mut data, 0);
        rtc.write(LEGACY_RTC_MAPPED_IO_START, RTCIMSC, &data);
        rtc.read(LEGACY_RTC_MAPPED_IO_START, RTCIMSC, &mut data);
        let v = read_le_u32(&data);
        assert_eq!(0, v);

        // Read and write to the ICR register.
        write_le_u32(&mut data, 1);
        rtc.write(LEGACY_RTC_MAPPED_IO_START, RTCICR, &data);
        let v_before = read_le_u32(&data);

        rtc.read(LEGACY_RTC_MAPPED_IO_START, RTCICR, &mut data);
        let v = read_le_u32(&data);
        // ICR is a  write only register. Data received should stay equal to data sent.
        assert_eq!(v, v_before);

        // Attempts to turn off the RTC should not go through.
        write_le_u32(&mut data, 0);
        rtc.write(LEGACY_RTC_MAPPED_IO_START, RTCCR, &data);
        rtc.read(LEGACY_RTC_MAPPED_IO_START, RTCCR, &mut data);
        let v = read_le_u32(&data);
        assert_eq!(v, 1);

        // Attempts to write beyond the writable space. Using here the space used to read
        // the CID and PID from.
        write_le_u32(&mut data, 0);
        rtc.write(LEGACY_RTC_MAPPED_IO_START, AMBA_ID_LOW, &data);
        // However, reading from the AMBA_ID_LOW should succeed upon read.

        let mut data = [0; 4];
        rtc.read(LEGACY_RTC_MAPPED_IO_START, AMBA_ID_LOW, &mut data);
        let index = AMBA_ID_LOW + 3;
        assert_eq!(data[0], PL031_ID[((index - AMBA_ID_LOW) >> 2) as usize]);
    }

    macro_rules! byte_order_test_read_write {
        ($test_name: ident, $write_fn_name: ident, $read_fn_name: ident, $is_be: expr, $data_type: ty) => {
            #[test]
            fn $test_name() {
                let test_cases = [
                    (
                        0x0123_4567_89AB_CDEF as u64,
                        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
                    ),
                    (
                        0x0000_0000_0000_0000 as u64,
                        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    ),
                    (
                        0x1923_2345_ABF3_CCD4 as u64,
                        [0x19, 0x23, 0x23, 0x45, 0xAB, 0xF3, 0xCC, 0xD4],
                    ),
                    (
                        0x0FF0_0FF0_0FF0_0FF0 as u64,
                        [0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0],
                    ),
                    (
                        0xFFFF_FFFF_FFFF_FFFF as u64,
                        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    ),
                    (
                        0x89AB_12D4_C2D2_09BB as u64,
                        [0x89, 0xAB, 0x12, 0xD4, 0xC2, 0xD2, 0x09, 0xBB],
                    ),
                ];

                let type_size = size_of::<$data_type>();
                for (test_val, v_arr) in &test_cases {
                    let v = *test_val as $data_type;
                    let cmp_iter: Box<dyn Iterator<Item = _>> = if $is_be {
                        Box::new(v_arr[(8 - type_size)..].iter())
                    } else {
                        Box::new(v_arr.iter().rev())
                    };
                    // test write
                    let mut write_arr = vec![Default::default(); type_size];
                    $write_fn_name(&mut write_arr, v);
                    for (cmp, cur) in cmp_iter.zip(write_arr.iter()) {
                        assert_eq!(*cmp, *cur as u8)
                    }
                    // test read
                    let read_val = $read_fn_name(&write_arr);
                    assert_eq!(v, read_val);
                }
            }
        };
    }

    byte_order_test_read_write!(test_le_u16, write_le_u16, read_le_u16, false, u16);
    byte_order_test_read_write!(test_le_u32, write_le_u32, read_le_u32, false, u32);
    byte_order_test_read_write!(test_le_u64, write_le_u64, read_le_u64, false, u64);
    byte_order_test_read_write!(test_le_i32, write_le_i32, read_le_i32, false, i32);
    byte_order_test_read_write!(test_be_u16, write_be_u16, read_be_u16, true, u16);
    byte_order_test_read_write!(test_be_u32, write_be_u32, read_be_u32, true, u32);
}
