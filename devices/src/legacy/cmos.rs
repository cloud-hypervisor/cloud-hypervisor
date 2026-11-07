// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::min;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;
use std::{mem, thread};

// https://github.com/rust-lang/libc/issues/1848
#[cfg_attr(target_env = "musl", allow(deprecated))]
use libc::time_t;
use libc::{CLOCK_REALTIME, clock_gettime, gmtime_r, timespec, tm};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use vm_device::BusDevice;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;
pub const CMOS_SNAPSHOT_ID: &str = "__cmos";

#[derive(Serialize, Deserialize)]
pub struct CmosState {
    index: u8,
    data: Vec<u8>,
}

/// A CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71.
pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
    reset_evt: EventFd,
    vcpus_kill_signalled: Arc<AtomicBool>,
}

impl Cmos {
    /// Constructs a CMOS/RTC device with initial data.
    /// `mem_below_4g` is the size of memory in bytes below the 32-bit gap.
    /// `mem_above_4g` is the size of memory in bytes above the 32-bit gap.
    pub fn new(
        mem_below_4g: u64,
        mem_above_4g: u64,
        reset_evt: EventFd,
        vcpus_kill_signalled: Arc<AtomicBool>,
        state: Option<CmosState>,
    ) -> Cmos {
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

        let index = if let Some(state) = state {
            data.copy_from_slice(&state.data);
            state.index
        } else {
            0
        };

        Cmos {
            index,
            data,
            reset_evt,
            vcpus_kill_signalled,
        }
    }
}

impl Snapshottable for Cmos {
    fn id(&self) -> String {
        CMOS_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&CmosState {
            index: self.index,
            data: self.data.to_vec(),
        })
    }
}

impl Pausable for Cmos {}
impl Transportable for Cmos {}
impl Migratable for Cmos {}

impl BusDevice for Cmos {
    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 1 {
            debug!("Invalid write size on CMOS device: {}", data.len());
            return None;
        }

        match offset {
            INDEX_OFFSET => self.index = data[0],
            DATA_OFFSET => {
                if self.index == 0x8f && data[0] == 0 {
                    info!("CMOS reset");
                    self.reset_evt.write(1).unwrap();
                    // Spin until we are sure the reset_evt has been handled and that when
                    // we return from the KVM_RUN we will exit rather than re-enter the guest.
                    while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                        // This is more effective than thread::yield_now() at
                        // avoiding a priority inversion with the VMM thread
                        thread::sleep(Duration::from_millis(1));
                    }
                } else {
                    self.data[(self.index & INDEX_MASK) as usize] = data[0];
                }
            }
            o => debug!("bad write offset on CMOS device: {o}"),
        }
        None
    }

    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        fn to_bcd(v: u8) -> u8 {
            assert!(v < 100);
            ((v / 10) << 4) | (v % 10)
        }

        if data.len() != 1 {
            debug!("Invalid read size on CMOS device: {}", data.len());
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
                // SAFETY: The clock_gettime and gmtime_r calls are safe as long as the structs they are
                // given are large enough, and neither of them fail. It is safe to zero initialize
                // the tm and timespec struct because it contains only plain data.
                let update_in_progress = unsafe {
                    let mut timespec: timespec = mem::zeroed();
                    clock_gettime(CLOCK_REALTIME, &raw mut timespec);

                    // https://github.com/rust-lang/libc/issues/1848
                    #[cfg_attr(target_env = "musl", allow(deprecated))]
                    let now: time_t = timespec.tv_sec;
                    let mut tm: tm = mem::zeroed();
                    gmtime_r(&now, &raw mut tm);

                    // The following lines of code are safe but depend on tm being in scope.
                    seconds = tm.tm_sec;
                    minutes = tm.tm_min;
                    hours = tm.tm_hour;
                    week_day = tm.tm_wday + 1;
                    day = tm.tm_mday;
                    month = tm.tm_mon + 1;
                    year = tm.tm_year;

                    // Update in Progress bit held for last 224us of each second
                    const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;
                    const UIP_HOLD_LENGTH: i64 = 8 * NANOSECONDS_PER_SECOND / 32768;
                    timespec.tv_nsec >= (NANOSECONDS_PER_SECOND - UIP_HOLD_LENGTH)
                };
                match self.index {
                    0x00 => to_bcd(seconds as u8),
                    0x02 => to_bcd(minutes as u8),
                    0x04 => to_bcd(hours as u8),
                    0x06 => to_bcd(week_day as u8),
                    0x07 => to_bcd(day as u8),
                    0x08 => to_bcd(month as u8),
                    0x09 => to_bcd((year % 100) as u8),
                    // Bit 5 for 32kHz clock. Bit 7 for Update in Progress
                    0x0a => (1 << 5) | ((update_in_progress as u8) << 7),
                    // Bit 0-6 are reserved and must be 0.
                    // Bit 7 must be 1 (CMOS has power)
                    0x0d => 1 << 7,
                    0x32 => to_bcd(((year + 1900) / 100) as u8),
                    _ => {
                        // self.index is always guaranteed to be in range via INDEX_MASK.
                        self.data[(self.index & INDEX_MASK) as usize]
                    }
                }
            }
            o => {
                debug!("bad read offset on CMOS device: {o}");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_preserves_selected_register_and_data() {
        let kill = Arc::new(AtomicBool::new(false));
        let reset = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut cmos = Cmos::new(0, 0, reset.try_clone().unwrap(), Arc::clone(&kill), None);
        cmos.write(0, INDEX_OFFSET, &[0x41]);
        cmos.write(0, DATA_OFFSET, &[0xab]);

        let state = cmos.snapshot().unwrap().to_state().unwrap();
        let mut restored = Cmos::new(0, 0, reset, kill, Some(state));
        let mut data = [0];
        restored.read(0, DATA_OFFSET, &mut data);
        assert_eq!(data, [0xab]);
        restored.write(0, DATA_OFFSET, &[0xcd]);
        restored.read(0, INDEX_OFFSET, &mut data);
        assert_eq!(data, [0x41]);
        restored.read(0, DATA_OFFSET, &mut data);
        assert_eq!(data, [0xcd]);
    }
}
