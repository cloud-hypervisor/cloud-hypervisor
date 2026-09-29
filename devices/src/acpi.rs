// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use std::{io, thread};

use acpi_tables::{Aml, AmlSink, aml};
use log::{error, info, warn};
#[cfg(not(target_arch = "riscv64"))]
use thiserror::Error;
use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
#[cfg(not(target_arch = "riscv64"))]
use vm_memory::VolatileMemory;
#[cfg(not(target_arch = "riscv64"))]
use vm_memory::bitmap::AtomicBitmap;
#[cfg(not(target_arch = "riscv64"))]
use vm_memory::volatile_memory::Error as VolatileMemoryError;
use vm_memory::{GuestAddress, MmapRegion};
use vmm_sys_util::eventfd::EventFd;

use super::AcpiNotificationFlags;

pub const GED_DEVICE_ACPI_SIZE: usize = 0x1;

#[cfg(not(target_arch = "riscv64"))]
pub const VMGENID_SIZE: usize = 16;

// KVM requires a memory slot to be page sized.
#[cfg(not(target_arch = "riscv64"))]
pub const VMGENID_REGION_SIZE: u64 = 0x1000;

const VMGENID_GED_BIT: usize = AcpiNotificationFlags::VMGENID_CHANGED.bits() as usize;

/// A device for handling ACPI shutdown and reboot
pub struct AcpiShutdownDevice {
    guest_exit_evt: EventFd,
    reset_evt: EventFd,
    vcpus_kill_signalled: Arc<AtomicBool>,
}

impl AcpiShutdownDevice {
    /// Constructs a device that will signal the given event when the guest requests it.
    pub fn new(
        guest_exit_evt: EventFd,
        reset_evt: EventFd,
        vcpus_kill_signalled: Arc<AtomicBool>,
    ) -> AcpiShutdownDevice {
        AcpiShutdownDevice {
            guest_exit_evt,
            reset_evt,
            vcpus_kill_signalled,
        }
    }
}

// Same I/O port used for shutdown and reboot
impl BusDevice for AcpiShutdownDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            warn!("Invalid sized read of ACPI shutdown device: {}", data.len());
            return;
        }
        data.fill(0);
    }

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 1 {
            warn!(
                "Invalid sized write of ACPI shutdown device: {}",
                data.len()
            );
            return None;
        }
        if data[0] == 1 {
            info!("ACPI Reboot signalled");
            if let Err(e) = self.reset_evt.write(1) {
                error!("Error triggering ACPI reset event: {e}");
            }
            // Spin until we are sure the reset_evt has been handled and that when
            // we return from the KVM_RUN we will exit rather than re-enter the guest.
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                // This is more effective than thread::yield_now() at
                // avoiding a priority inversion with the VMM thread
                thread::sleep(Duration::from_millis(1));
            }
        }
        // The ACPI DSDT table specifies the S5 sleep state (shutdown) as value 5
        const S5_SLEEP_VALUE: u8 = 5;
        const SLEEP_STATUS_EN_BIT: u8 = 5;
        const SLEEP_VALUE_BIT: u8 = 2;
        if data[0] == (S5_SLEEP_VALUE << SLEEP_VALUE_BIT) | (1 << SLEEP_STATUS_EN_BIT) {
            info!("ACPI Shutdown signalled");
            if let Err(e) = self.guest_exit_evt.write(1) {
                error!("Error triggering ACPI shutdown event: {e}");
            }
            // Spin until we are sure the reset_evt has been handled and that when
            // we return from the KVM_RUN we will exit rather than re-enter the guest.
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                // This is more effective than thread::yield_now() at
                // avoiding a priority inversion with the VMM thread
                thread::sleep(Duration::from_millis(1));
            }
        }
        None
    }
}

/// A device for handling ACPI GED event generation
pub struct AcpiGedDevice {
    interrupt: Arc<dyn InterruptSourceGroup>,
    notification_type: AcpiNotificationFlags,
    ged_irq: u32,
    address: GuestAddress,
}

impl AcpiGedDevice {
    pub fn new(
        interrupt: Arc<dyn InterruptSourceGroup>,
        ged_irq: u32,
        address: GuestAddress,
    ) -> AcpiGedDevice {
        AcpiGedDevice {
            interrupt,
            notification_type: AcpiNotificationFlags::NO_DEVICES_CHANGED,
            ged_irq,
            address,
        }
    }

    pub fn notify(&mut self, notification_type: AcpiNotificationFlags) -> io::Result<()> {
        self.notification_type |= notification_type;
        self.interrupt.trigger(0)
    }

    pub fn irq(&self) -> u32 {
        self.ged_irq
    }
}

// I/O port reports what type of notification was made
impl BusDevice for AcpiGedDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            warn!("Invalid sized read of ACPI GED device: {}", data.len());
            return;
        }
        data[0] = self.notification_type.bits();
        self.notification_type = AcpiNotificationFlags::NO_DEVICES_CHANGED;
    }
}

impl Aml for AcpiGedDevice {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        aml::Device::new(
            "_SB_.GEC_".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                &aml::Name::new("_UID".into(), &"Generic Event Controller"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.address.0,
                        self.address.0 + GED_DEVICE_ACPI_SIZE as u64 - 1,
                        None,
                    )]),
                ),
                &aml::OpRegion::new(
                    "GDST".into(),
                    aml::OpRegionSpace::SystemMemory,
                    &(self.address.0 as usize),
                    &GED_DEVICE_ACPI_SIZE,
                ),
                &aml::Field::new(
                    "GDST".into(),
                    aml::FieldAccessType::Byte,
                    aml::FieldLockRule::NoLock,
                    aml::FieldUpdateRule::WriteAsZeroes,
                    vec![aml::FieldEntry::Named(*b"GDAT", 8)],
                ),
                &aml::Method::new(
                    "ESCN".into(),
                    0,
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
                            vec![&aml::MethodCall::new("\\_SB_.PHPR.PSCN".into(), vec![])],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &8usize),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &8usize),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.PWRB"),
                                &0x80usize,
                            )],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &VMGENID_GED_BIT),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &VMGENID_GED_BIT),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.VGEN"),
                                &0x80usize,
                            )],
                        ),
                    ],
                ),
            ],
        )
        .to_aml_bytes(sink);
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
                &aml::Method::new(
                    "_EVT".into(),
                    1,
                    true,
                    vec![&aml::MethodCall::new("\\_SB_.GEC_.ESCN".into(), vec![])],
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

/// A device exposing a VM Generation ID from its own memory region
#[cfg(not(target_arch = "riscv64"))]
pub struct VmGenIdDevice {
    address: GuestAddress,
    region: Arc<MmapRegion<AtomicBitmap>>,
}

#[cfg(not(target_arch = "riscv64"))]
#[derive(Debug, Error)]
pub enum VmGenIdError {
    #[error("Failed to read random bytes for the VM Generation ID")]
    Random(#[source] getrandom::Error),

    #[error("Failed to publish the VM Generation ID")]
    Publish(#[source] VolatileMemoryError),
}

#[cfg(not(target_arch = "riscv64"))]
impl VmGenIdDevice {
    pub fn new(
        address: GuestAddress,
        region: Arc<MmapRegion<AtomicBitmap>>,
    ) -> Result<VmGenIdDevice, VmGenIdError> {
        let device = VmGenIdDevice { address, region };
        device.regenerate()?;

        Ok(device)
    }

    pub fn regenerate(&self) -> Result<(), VmGenIdError> {
        let mut gen_id = [0u8; VMGENID_SIZE];
        getrandom::fill(&mut gen_id).map_err(VmGenIdError::Random)?;

        self.region
            .get_slice(0, VMGENID_SIZE)
            .map_err(VmGenIdError::Publish)?
            .copy_from(&gen_id);

        Ok(())
    }
}

#[cfg(not(target_arch = "riscv64"))]
impl Aml for VmGenIdDevice {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        let addr_low = self.address.0 as u32;
        let addr_high = (self.address.0 >> 32) as u32;

        aml::Device::new(
            "_SB_.VGEN".into(),
            vec![
                &aml::Name::new("_HID".into(), &"VMGENCTR"),
                &aml::Name::new("_CID".into(), &"VM_Gen_Counter"),
                &aml::Name::new("_DDN".into(), &"VM_Gen_Counter"),
                &aml::Name::new(
                    "ADDR".into(),
                    &aml::Package::new(vec![&addr_low, &addr_high]),
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

pub struct AcpiPmTimerDevice {
    start: Instant,
}

impl AcpiPmTimerDevice {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for AcpiPmTimerDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl BusDevice for AcpiPmTimerDevice {
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        if data.len() != size_of::<u32>() {
            warn!("Invalid sized read of PM timer: {}", data.len());
            return;
        }
        let now = Instant::now();
        let since = now.duration_since(self.start);
        let nanos = since.as_nanos();

        const PM_TIMER_FREQUENCY_HZ: u128 = 3_579_545;
        const NANOS_PER_SECOND: u128 = 1_000_000_000;

        let counter = (nanos * PM_TIMER_FREQUENCY_HZ) / NANOS_PER_SECOND;
        let counter: u32 = (counter & 0xffff_ffff) as u32;

        data.copy_from_slice(&counter.to_le_bytes());
    }
}

#[cfg(all(test, not(target_arch = "riscv64")))]
mod tests {
    use super::*;

    #[test]
    fn test_vmgenid_regenerate() {
        let region = Arc::new(MmapRegion::new(VMGENID_REGION_SIZE as usize).unwrap());
        let device = VmGenIdDevice::new(GuestAddress(0xa_0028), Arc::clone(&region)).unwrap();

        let mut first = [0u8; VMGENID_SIZE];
        region
            .get_slice(0, VMGENID_SIZE)
            .unwrap()
            .copy_to(&mut first);

        device.regenerate().unwrap();

        let mut second = [0u8; VMGENID_SIZE];
        region
            .get_slice(0, VMGENID_SIZE)
            .unwrap()
            .copy_to(&mut second);

        assert_ne!(first, second);
    }
}
