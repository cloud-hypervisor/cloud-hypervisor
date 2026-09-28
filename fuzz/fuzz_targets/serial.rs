// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]
use std::io;
use std::sync::Arc;

use devices::legacy::Serial;
use libc::EFD_NONBLOCK;
use libfuzzer_sys::fuzz_target;
use vm_device::interrupt::{InterruptIndex, InterruptSourceConfig, InterruptSourceGroup};
use vm_device::BusDevice;
use vm_migration::Snapshottable;
use vmm_sys_util::eventfd::EventFd;

const LOOP_SIZE: usize = 0x40;

fuzz_target!(|bytes: &[u8]| -> libfuzzer_sys::Corpus {
    let mut cursor = FuzzCursor::new(bytes);
    let Some(event_fd) = eventfd() else {
        return libfuzzer_sys::Corpus::Reject;
    };
    let mut serial = Serial::new_sink(
        "serial".into(),
        Arc::new(TestInterrupt::new(event_fd)),
        None,
    );

    let iterations = usize::from(cursor.next_u8() % 64) + 32;
    for _ in 0..iterations {
        match cursor.next_u8() % 8 {
            0 => {
                let mut out = [0u8; 1];
                serial.read(0, u64::from(cursor.next_u8()), &mut out);
            }
            1 => {
                let mut out = [0u8; 2];
                if cursor.next_bool() {
                    let mut empty: [u8; 0] = [];
                    serial.read(0, u64::from(cursor.next_u8()), &mut empty);
                } else {
                    serial.read(0, u64::from(cursor.next_u8()), &mut out);
                }
            }
            2 => {
                serial.write(0, u64::from(cursor.next_u8()), &[cursor.next_u8()]);
            }
            3 => {
                if cursor.next_bool() {
                    serial.write(0, u64::from(cursor.next_u8()), &[]);
                } else {
                    serial.write(
                        0,
                        u64::from(cursor.next_u8()),
                        &[cursor.next_u8(), cursor.next_u8()],
                    );
                }
            }
            4 => {
                let mut chunk = [0u8; 4];
                for byte in chunk.iter_mut() {
                    *byte = cursor.next_u8();
                }
                let len = usize::from(cursor.next_u8() % (chunk.len() as u8 + 1));
                let _ = serial.queue_input_bytes(&chunk[..len]);
            }
            5 => {
                serial.write(0, 1, &[cursor.next_u8() & 0x0f]);
                serial.write(0, 3, &[cursor.next_u8()]);
                serial.write(0, 4, &[cursor.next_u8()]);
                serial.write(0, 7, &[cursor.next_u8()]);
            }
            6 => {
                serial.write(0, 4, &[0x10]);
                for _ in 0..(LOOP_SIZE + 2) {
                    serial.write(0, 0, &[cursor.next_u8()]);
                }
            }
            _ => {
                let mut out = [0u8; 1];
                serial.read(0, 2, &mut out);
                serial.read(0, 0xff, &mut out);
            }
        }
    }

    let Some(event_fd) = eventfd() else {
        return libfuzzer_sys::Corpus::Reject;
    };
    let mut serial_out = Serial::new_out(
        "serial_out".into(),
        Arc::new(TestInterrupt::new(event_fd)),
        Box::new(io::sink()),
        None,
    );
    serial_out.write(0, 1, &[0x03]);
    serial_out.write(0, 0, &[cursor.next_u8()]);
    serial_out.write(0, 3, &[0x80]);
    serial_out.write(0, 0, &[cursor.next_u8()]);
    serial_out.write(0, 1, &[cursor.next_u8()]);

    let mut out = [0u8; 1];
    serial_out.read(0, 0, &mut out);
    serial_out.read(0, 1, &mut out);

    serial_out.set_out(None);
    serial_out.write(0, 0, &[cursor.next_u8()]);
    serial_out.set_out(Some(Box::new(io::sink())));
    let _ = serial_out.flush_output();

    serial_out.read(0, 0xfe, &mut out);
    let mut empty: [u8; 0] = [];
    serial_out.read(0, 0, &mut empty);
    serial_out.write(0, 0, &[]);
    serial_out.write(0, 0, &[cursor.next_u8(), cursor.next_u8()]);

    let _ = serial_out.queue_input_bytes(&[cursor.next_u8(), cursor.next_u8()]);
    serial_out.write(0, 4, &[0x10]);
    let _ = serial_out.queue_input_bytes(&[cursor.next_u8()]);

    let _ = Snapshottable::id(&serial_out);
    if let Ok(snapshot) = serial_out.snapshot() {
        let restored_state = snapshot.to_state().ok();
        let Some(event_fd) = eventfd() else {
            return libfuzzer_sys::Corpus::Reject;
        };
        let mut restored = Serial::new_sink(
            "serial_restored".into(),
            Arc::new(TestInterrupt::new(event_fd)),
            restored_state,
        );
        restored.write(0, 0, &[cursor.next_u8()]);
        restored.read(0, 2, &mut out);
        let _ = Snapshottable::id(&restored);
        let _ = restored.snapshot();
    }
    libfuzzer_sys::Corpus::Keep
});

fn eventfd() -> Option<EventFd> {
    EventFd::new(EFD_NONBLOCK).ok()
}

struct FuzzCursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> FuzzCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let value = self.bytes[self.index % self.bytes.len()];
        self.index = self.index.wrapping_add(1);
        value
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }
}

struct TestInterrupt {
    event_fd: EventFd,
}

impl InterruptSourceGroup for TestInterrupt {
    fn trigger(&self, _index: InterruptIndex) -> Result<(), std::io::Error> {
        self.event_fd.write(1)
    }
    fn update(
        &self,
        _index: InterruptIndex,
        _config: InterruptSourceConfig,
        _masked: bool,
        _set_gsi: bool,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }
    fn set_gsi(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
    fn notifier(&self, _index: InterruptIndex) -> Option<EventFd> {
        self.event_fd.try_clone().ok()
    }
}

impl TestInterrupt {
    fn new(event_fd: EventFd) -> Self {
        TestInterrupt { event_fd }
    }
}
