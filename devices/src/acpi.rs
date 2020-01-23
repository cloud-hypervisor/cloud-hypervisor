// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;
use vm_device::interrupt::InterruptSourceGroup;
use vm_memory::GuestAddress;
use vmm_sys_util::eventfd::EventFd;
use BusDevice;
use HotPlugNotificationFlags;

/// A device for handling ACPI shutdown and reboot
pub struct AcpiShutdownDevice {
    exit_evt: EventFd,
    reset_evt: EventFd,
}

impl AcpiShutdownDevice {
    /// Constructs a device that will signal the given event when the guest requests it.
    pub fn new(exit_evt: EventFd, reset_evt: EventFd) -> AcpiShutdownDevice {
        AcpiShutdownDevice {
            exit_evt,
            reset_evt,
        }
    }
}

// Same I/O port used for shutdown and reboot
impl BusDevice for AcpiShutdownDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        for i in data.iter_mut() {
            *i = 0;
        }
    }

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) {
        if data[0] == 1 {
            debug!("ACPI Reboot signalled");
            if let Err(e) = self.reset_evt.write(1) {
                error!("Error triggering ACPI reset event: {}", e);
            }
        }
        // The ACPI DSDT table specifies the S5 sleep state (shutdown) as value 5
        const S5_SLEEP_VALUE: u8 = 5;
        const SLEEP_STATUS_EN_BIT: u8 = 5;
        const SLEEP_VALUE_BIT: u8 = 2;
        if data[0] == (S5_SLEEP_VALUE << SLEEP_VALUE_BIT) | (1 << SLEEP_STATUS_EN_BIT) {
            debug!("ACPI Shutdown signalled");
            extern crate bitflags;
            if let Err(e) = self.exit_evt.write(1) {
                error!("Error triggering ACPI shutdown event: {}", e);
            }
        }
    }
}

/// A device for handling ACPI GED event generation
pub struct AcpiGEDDevice {
    interrupt: Arc<Box<dyn InterruptSourceGroup>>,
    notification_type: HotPlugNotificationFlags,
    ged_irq: u32,
    device_base: GuestAddress,
}

impl AcpiGEDDevice {
    pub const DEVICE_SIZE: u64 = 1;

    pub fn new(
        interrupt: Arc<Box<dyn InterruptSourceGroup>>,
        ged_irq: u32,
        device_base: GuestAddress,
    ) -> AcpiGEDDevice {
        AcpiGEDDevice {
            interrupt,
            notification_type: HotPlugNotificationFlags::NO_DEVICES_CHANGED,
            ged_irq,
            device_base,
        }
    }

    pub fn notify(
        &mut self,
        notification_type: HotPlugNotificationFlags,
    ) -> Result<(), std::io::Error> {
        self.notification_type |= notification_type;
        self.interrupt.trigger(0)
    }

    pub fn irq(&self) -> u32 {
        self.ged_irq
    }

    pub fn device_base(&self) -> GuestAddress {
        self.device_base
    }
}

// MMIO region reports what type of notification was made
impl BusDevice for AcpiGEDDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        data[0] = self.notification_type.bits();
        self.notification_type = HotPlugNotificationFlags::NO_DEVICES_CHANGED;
    }

    fn write(&mut self, _base: u64, _offset: u64, _data: &[u8]) {}
}
