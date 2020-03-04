// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use acpi_tables::{aml, aml::Aml};
use std::sync::Arc;
use vm_device::interrupt::InterruptSourceGroup;
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
}

impl AcpiGEDDevice {
    pub fn new(interrupt: Arc<Box<dyn InterruptSourceGroup>>, ged_irq: u32) -> AcpiGEDDevice {
        AcpiGEDDevice {
            interrupt,
            notification_type: HotPlugNotificationFlags::NO_DEVICES_CHANGED,
            ged_irq,
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
}

// I/O port reports what type of notification was made
impl BusDevice for AcpiGEDDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        data[0] = self.notification_type.bits();
        self.notification_type = HotPlugNotificationFlags::NO_DEVICES_CHANGED;
    }

    fn write(&mut self, _base: u64, _offset: u64, _data: &[u8]) {}
}

#[cfg(feature = "acpi")]
impl Aml for AcpiGEDDevice {
    fn to_aml_bytes(&self) -> Vec<u8> {
        aml::Device::new(
            "_SB_.GED_".into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0013"),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                        true,
                        true,
                        false,
                        false,
                        self.ged_irq,
                    )]),
                ),
                &aml::OpRegion::new("GDST".into(), aml::OpRegionSpace::SystemIO, 0xb000, 0x1),
                &aml::Field::new(
                    "GDST".into(),
                    aml::FieldAccessType::Byte,
                    aml::FieldUpdateRule::WriteAsZeroes,
                    vec![aml::FieldEntry::Named(*b"GDAT", 8)],
                ),
                &aml::Method::new(
                    "_EVT".into(),
                    1,
                    true,
                    vec![
                        &aml::Store::new(&aml::Local(0), &aml::Path::new("GDAT")),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &aml::ONE),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &aml::ONE),
                            vec![&aml::MethodCall::new("\\_SB_.CPUS.CSCN".into(), vec![])],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &2usize),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &2usize),
                            vec![&aml::MethodCall::new("\\_SB_.MHPC.MSCN".into(), vec![])],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &4usize),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &4usize),
                            vec![&aml::MethodCall::new("\\_SB_.PCI0.PCNT".into(), vec![])],
                        ),
                    ],
                ),
            ],
        )
        .to_aml_bytes()
    }
}
