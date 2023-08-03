// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Barrier,
};
use std::thread;
use vm_device::BusDevice;
use vmm_sys_util::eventfd::EventFd;

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    reset_evt: EventFd,
    vcpus_kill_signalled: Arc<AtomicBool>,
}

impl I8042Device {
    /// Constructs a i8042 device that will signal the given event when the guest requests it.
    pub fn new(reset_evt: EventFd, vcpus_kill_signalled: Arc<AtomicBool>) -> I8042Device {
        I8042Device {
            reset_evt,
            vcpus_kill_signalled,
        }
    }
}

// i8042 device is located at I/O port 0x61. We partially implement two 8-bit
// registers: port 0x61 (I8042_PORT_B_REG, offset 0 from base of 0x61), and
// port 0x64 (I8042_COMMAND_REG, offset 3 from base of 0x61).
impl BusDevice for I8042Device {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if data.len() == 1 && offset == 3 {
            data[0] = 0x0;
        } else if data.len() == 1 && offset == 0 {
            // Like kvmtool, we return bit 5 set in I8042_PORT_B_REG to
            // avoid hang in pit_calibrate_tsc() in Linux kernel.
            data[0] = 0x20;
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() == 1 && data[0] == 0xfe && offset == 3 {
            info!("i8042 reset signalled");
            if let Err(e) = self.reset_evt.write(1) {
                error!("Error triggering i8042 reset event: {}", e);
            }
            // Spin until we are sure the reset_evt has been handled and that when
            // we return from the KVM_RUN we will exit rather than re-enter the guest.
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                // This is more effective than thread::yield_now() at
                // avoiding a priority inversion with the VMM thread
                thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        None
    }
}
