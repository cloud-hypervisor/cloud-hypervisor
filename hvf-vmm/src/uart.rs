//! Minimal PL011-style UART MMIO device model.
//!
//! Transport-neutral device state — the analogue of a cloud-hypervisor virtio
//! device's serializable state. Writes to the data register go to host stdout.

use std::io::Write;

pub const UART_BASE: u64 = 0x0900_0000;
pub const UART_SIZE: u64 = 0x1000;

const UARTDR: u64 = 0x000; // data register
const UARTFR: u64 = 0x018; // flag register

pub struct Uart {
    /// Number of bytes transmitted — part of the device's snapshot state.
    pub tx_count: u64,
}

impl Uart {
    pub fn new() -> Self {
        Uart { tx_count: 0 }
    }

    pub fn contains(addr: u64) -> bool {
        (UART_BASE..UART_BASE + UART_SIZE).contains(&addr)
    }

    /// MMIO write of `value` (low byte significant for DR).
    pub fn write(&mut self, offset: u64, value: u64) {
        if offset == UARTDR {
            let byte = (value & 0xff) as u8;
            let out = std::io::stdout();
            let mut h = out.lock();
            let _ = h.write_all(&[byte]);
            let _ = h.flush();
            self.tx_count += 1;
        }
        // Other registers (control/baud) are accepted and ignored.
    }

    /// MMIO read — report "transmit ready, nothing to receive".
    pub fn read(&self, offset: u64) -> u64 {
        match offset {
            UARTFR => 0, // TXFF=0 (not full), RXFE handled by guest as needed
            _ => 0,
        }
    }
}
