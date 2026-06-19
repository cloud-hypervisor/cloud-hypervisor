// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{Arc, Barrier};
use event_monitor::event;
use vm_device::BusDevice;

const EVENT_START: u8 = 0x01;
const EVENT_PANIC: u8 = 0x04;
const EVENT_INIT_READY: u8 = 0x08;

#[derive(Default)]
pub struct GuestEventDevice;

impl GuestEventDevice {
    pub fn new() -> Self {
        Self
    }
}

impl BusDevice for GuestEventDevice {
    fn read(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {}

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            EVENT_START => event!("guest", "sys_start", "source", "guest_event_device"),
            EVENT_INIT_READY => event!("guest", "init_ready", "source", "guest_event_device"),
            EVENT_PANIC => event!("guest", "panic", "source", "guest_event_device"),
            _ => {} // Ignore unknown signals
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    static MONITOR_RX: OnceLock<Mutex<flume::Receiver<String>>> = OnceLock::new();

    fn get_monitor_rx() -> &'static Mutex<flume::Receiver<String>> {
        MONITOR_RX.get_or_init(|| {
            let monitor = event_monitor::set_monitor(None).unwrap();
            Mutex::new(monitor.rx)
        })
    }

    #[test]
    fn test_guest_event_device() {
        let rx_lock = get_monitor_rx();
        let rx = rx_lock.lock().unwrap();
        let mut device = GuestEventDevice::new();

        // Write EVENT_START
        device.write(0, 0, &[EVENT_START]);
        if let Ok(msg) = rx.recv() {
            assert!(msg.contains(r#""source":"guest""#) || msg.contains(r#""source": "guest""#), "msg was: {msg}");
            assert!(msg.contains(r#""event":"sys_start""#) || msg.contains(r#""event": "sys_start""#), "msg was: {msg}");
        }

        // Write EVENT_INIT_READY
        device.write(0, 0, &[EVENT_INIT_READY]);
        if let Ok(msg) = rx.recv() {
            assert!(msg.contains(r#""source":"guest""#) || msg.contains(r#""source": "guest""#), "msg was: {msg}");
            assert!(msg.contains(r#""event":"init_ready""#) || msg.contains(r#""event": "init_ready""#), "msg was: {msg}");
        }

        // Write EVENT_PANIC
        device.write(0, 0, &[EVENT_PANIC]);
        if let Ok(msg) = rx.recv() {
            assert!(msg.contains(r#""source":"guest""#) || msg.contains(r#""source": "guest""#), "msg was: {msg}");
            assert!(msg.contains(r#""event":"panic""#) || msg.contains(r#""event": "panic""#), "msg was: {msg}");
        }
    }
}
