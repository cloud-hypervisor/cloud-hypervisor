// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use vmm_sys_util::eventfd::EventFd;
use BusDevice;
use HotPlugNotificationType;
use Interrupt;

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
            if let Err(e) = self.exit_evt.write(1) {
                error!("Error triggering ACPI shutdown event: {}", e);
            }
        }
    }
}

/// A device for handling ACPI GED event generation
pub struct AcpiGEDDevice {
    interrupt: Box<dyn Interrupt>,
    notification_type: HotPlugNotificationType,
    ged_irq: u32,
}

impl AcpiGEDDevice {
    pub fn new(interrupt: Box<dyn Interrupt>, ged_irq: u32) -> AcpiGEDDevice {
        AcpiGEDDevice {
            interrupt,
            notification_type: HotPlugNotificationType::NoDevicesChanged,
            ged_irq,
        }
    }

    pub fn notify(
        &mut self,
        notification_type: HotPlugNotificationType,
    ) -> Result<(), std::io::Error> {
        self.notification_type = notification_type;
        self.interrupt.deliver()
    }

    pub fn irq(&self) -> u32 {
        self.ged_irq
    }
}

// I/O port reports what type of notification was made
impl BusDevice for AcpiGEDDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        data[0] = self.notification_type as u8;
        self.notification_type = HotPlugNotificationType::NoDevicesChanged;
    }

    fn write(&mut self, _base: u64, _offset: u64, _data: &[u8]) {}
}
