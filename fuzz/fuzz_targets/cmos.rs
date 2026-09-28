// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use devices::legacy::Cmos;
use libc::EFD_NONBLOCK;
use libfuzzer_sys::{fuzz_target, Corpus};
use vm_device::BusDevice;
use vmm_sys_util::eventfd::EventFd;

fn next_byte(bytes: &[u8], index: &mut usize) -> u8 {
    let value = bytes.get(*index).copied().unwrap_or(0);
    *index += 1;
    value
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    // Need at least 16 bytes for the test
    if bytes.len() < 16 {
        return Corpus::Reject;
    }

    let mut below_4g = [0u8; 8];
    let mut above_4g = [0u8; 8];

    below_4g.copy_from_slice(&bytes[0..8]);
    above_4g.copy_from_slice(&bytes[8..16]);

    let vcpus_kill_signalled = Arc::new(AtomicBool::new(false));
    let mut cmos = Cmos::new(
        u64::from_le_bytes(below_4g),
        u64::from_le_bytes(above_4g),
        EventFd::new(EFD_NONBLOCK).unwrap(),
        Arc::clone(&vcpus_kill_signalled),
    );

    // Exercise all RTC special register read paths and read-index path.
    for register in [0x00, 0x02, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0d, 0x32] {
        cmos.write(0, 0, &[register]);
        let mut out = [0];
        cmos.read(0, 0, &mut out);
        cmos.read(0, 1, &mut out);
    }

    // Exercise default data array read path.
    cmos.write(0, 0, &[0x34]);
    cmos.write(0, 1, &[0x5a]);
    let mut out = [0];
    cmos.read(0, 1, &mut out);

    // Exercise reset path. Signal the flag up front so the device's spin loop
    // exits on its first check instead of sleeping.
    vcpus_kill_signalled.store(true, Ordering::SeqCst);
    cmos.write(0, 0, &[0x8f]);
    cmos.write(0, 1, &[0]);

    // Exercise invalid-size and bad-offset paths.
    cmos.write(0, 0, &[]);
    cmos.write(0, 0, &[1, 2]);
    cmos.write(0, 2, &[0xff]);
    let mut out_zero = [0u8; 0];
    let mut out_two = [0u8; 2];
    cmos.read(0, 1, &mut out_zero);
    cmos.read(0, 1, &mut out_two);
    cmos.read(0, 2, &mut out);

    let mut i = 16;
    while i < bytes.len() {
        let op = next_byte(bytes, &mut i);
        let offset = (next_byte(bytes, &mut i) % 4) as u64;
        let len = (next_byte(bytes, &mut i) % 3) as usize;

        if op & 1 == 0 {
            let mut out_bytes = vec![0; len];
            cmos.read(0, offset, &mut out_bytes);
            continue;
        }

        let mut data = vec![0; len];
        for value in data.iter_mut() {
            *value = next_byte(bytes, &mut i);
        }
        cmos.write(0, offset, &data);
    }

    Corpus::Keep
});
