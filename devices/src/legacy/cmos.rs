// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{gmtime_r, time, time_t, tm};
use std::cmp::min;
use std::mem;

use crate::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

/// A CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71.
pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    /// Constructs a CMOS/RTC device with initial data.
    /// `mem_below_4g` is the size of memory in bytes below the 32-bit gap.
    /// `mem_above_4g` is the size of memory in bytes above the 32-bit gap.
    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Cmos {
        let mut data = [0u8; DATA_LEN];

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem as u8;
        data[0x35] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0x00FF_FFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem as u8;
        data[0x5c] = (high_mem >> 8) as u8;
        data[0x5d] = (high_mem >> 16) as u8;

        Cmos { index: 0, data }
    }
}

impl BusDevice for Cmos {
    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        match offset {
            INDEX_OFFSET => self.index = data[0] & INDEX_MASK,
            DATA_OFFSET => self.data[self.index as usize] = data[0],
            o => panic!("bad write offset on CMOS device: {}", o),
        }
    }

    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        fn to_bcd(v: u8) -> u8 {
            assert!(v < 100);
            ((v / 10) << 4) | (v % 10)
        }

        if data.len() != 1 {
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => self.index,
            DATA_OFFSET => {
                let seconds;
                let minutes;
                let hours;
                let week_day;
                let day;
                let month;
                let year;
                // The time and gmtime_r calls are safe as long as the structs they are given are
                // large enough, and neither of them fail. It is safe to zero initialize the tm
                // struct because it contains only plain data.
                unsafe {
                    let mut tm: tm = mem::zeroed();
                    let mut now: time_t = 0;
                    time(&mut now as *mut _);
                    gmtime_r(&now, &mut tm as *mut _);
                    // The following lines of code are safe but depend on tm being in scope.
                    seconds = tm.tm_sec;
                    minutes = tm.tm_min;
                    hours = tm.tm_hour;
                    week_day = tm.tm_wday + 1;
                    day = tm.tm_mday;
                    month = tm.tm_mon + 1;
                    year = tm.tm_year;
                };
                match self.index {
                    0x00 => to_bcd(seconds as u8),
                    0x02 => to_bcd(minutes as u8),
                    0x04 => to_bcd(hours as u8),
                    0x06 => to_bcd(week_day as u8),
                    0x07 => to_bcd(day as u8),
                    0x08 => to_bcd(month as u8),
                    0x09 => to_bcd((year % 100) as u8),
                    0x32 => to_bcd(((year + 1900) / 100) as u8),
                    _ => {
                        // self.index is always guaranteed to be in range via INDEX_MASK.
                        self.data[(self.index & INDEX_MASK) as usize]
                    }
                }
            }
            o => panic!("bad read offset on CMOS device: {}", o),
        }
    }
}
