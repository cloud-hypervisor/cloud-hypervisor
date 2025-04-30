// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use std::mem::{offset_of, size_of};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use acpi_tables::rsdp::Rsdp;
use acpi_tables::{aml, Aml, AmlSink};
use vm_device::interrupt::InterruptSourceGroup;
use vm_device::BusDevice;
use vm_memory::GuestAddress;
use vmm_sys_util::eventfd::EventFd;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::AcpiNotificationFlags;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use crate::legacy::fw_cfg::{create_file_name, FwCfgContent, FwCfgItem, FILE_NAME_SIZE};

pub const GED_DEVICE_ACPI_SIZE: usize = 0x1;

/// A device for handling ACPI shutdown and reboot
pub struct AcpiShutdownDevice {
    exit_evt: EventFd,
    reset_evt: EventFd,
    vcpus_kill_signalled: Arc<AtomicBool>,
}

impl AcpiShutdownDevice {
    /// Constructs a device that will signal the given event when the guest requests it.
    pub fn new(
        exit_evt: EventFd,
        reset_evt: EventFd,
        vcpus_kill_signalled: Arc<AtomicBool>,
    ) -> AcpiShutdownDevice {
        AcpiShutdownDevice {
            exit_evt,
            reset_evt,
            vcpus_kill_signalled,
        }
    }
}

// Same I/O port used for shutdown and reboot
impl BusDevice for AcpiShutdownDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        data.fill(0)
    }

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data[0] == 1 {
            info!("ACPI Reboot signalled");
            if let Err(e) = self.reset_evt.write(1) {
                error!("Error triggering ACPI reset event: {}", e);
            }
            // Spin until we are sure the reset_evt has been handled and that when
            // we return from the KVM_RUN we will exit rather than re-enter the guest.
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                // This is more effective than thread::yield_now() at
                // avoiding a priority inversion with the VMM thread
                thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        // The ACPI DSDT table specifies the S5 sleep state (shutdown) as value 5
        const S5_SLEEP_VALUE: u8 = 5;
        const SLEEP_STATUS_EN_BIT: u8 = 5;
        const SLEEP_VALUE_BIT: u8 = 2;
        if data[0] == (S5_SLEEP_VALUE << SLEEP_VALUE_BIT) | (1 << SLEEP_STATUS_EN_BIT) {
            info!("ACPI Shutdown signalled");
            if let Err(e) = self.exit_evt.write(1) {
                error!("Error triggering ACPI shutdown event: {}", e);
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

    pub fn notify(
        &mut self,
        notification_type: AcpiNotificationFlags,
    ) -> Result<(), std::io::Error> {
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
        .to_aml_bytes(sink)
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
        if data.len() != std::mem::size_of::<u32>() {
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

pub const COMMAND_ALLOCATE: u32 = 0x1;
pub const COMMAND_ADD_POINTER: u32 = 0x2;
pub const COMMAND_ADD_CHECKSUM: u32 = 0x3;

pub const ALLOC_ZONE_HIGH: u8 = 0x1;
pub const ALLOC_ZONE_FSEG: u8 = 0x2;

pub const FW_CFG_FILENAME_TABLE_LOADER: &str = "etc/table-loader";
pub const FW_CFG_FILENAME_RSDP: &str = "acpi/rsdp";
pub const FW_CFG_FILENAME_ACPI_TABLES: &str = "acpi/tables";

pub const SIGNATURE: [u8; 4] = *b"XSDT";
pub const COMPILER_ID: [u8; 4] = *b"RVAT";

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
pub struct Allocate {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    align: u32,
    zone: u8,
    _pad: [u8; 63],
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
pub struct AddPointer {
    command: u32,
    dst: [u8; FILE_NAME_SIZE],
    src: [u8; FILE_NAME_SIZE],
    offset: u32,
    size: u8,
    _pad: [u8; 7],
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
pub struct AddChecksum {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    offset: u32,
    start: u32,
    len: u32,
    _pad: [u8; 56],
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn create_intra_pointer(name: &str, offset: usize, size: u8) -> AddPointer {
    AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(name),
        src: create_file_name(name),
        offset: offset as u32,
        size,
        _pad: [0; 7],
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn create_acpi_table_checksum(offset: usize, len: usize) -> AddChecksum {
    AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: (offset + offset_of!(AcpiTableHeader, checksum)) as u32,
        start: offset as u32,
        len: len as u32,
        _pad: [0; 56],
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[inline]
pub fn wrapping_sum<'a, T>(data: T) -> u8
where
    T: IntoIterator<Item = &'a u8>,
{
    data.into_iter().fold(0u8, |accu, e| accu.wrapping_add(*e))
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, IntoBytes)]
pub struct AcpiTableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub asl_compiler_id: [u8; 4],
    pub asl_compiler_revision: u32,
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub struct AcpiTable {
    pub rsdp: Rsdp,
    pub tables: Vec<u8>,
    pub table_pointers: Vec<usize>,
    pub table_checksums: Vec<(usize, usize)>,
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl AcpiTable {
    pub fn rsdp(&self) -> &Rsdp {
        &self.rsdp
    }

    pub fn tables(&self) -> &[u8] {
        &self.tables
    }

    pub fn pointers(&self) -> &[usize] {
        &self.table_pointers
    }

    pub fn checksums(&self) -> &[(usize, usize)] {
        &self.table_checksums
    }

    pub fn take(self) -> (Rsdp, Vec<u8>) {
        (self.rsdp, self.tables)
    }
}

pub fn create_acpi_loader(acpi_table: AcpiTable) -> [FwCfgItem; 3] {
    let mut table_loader_bytes: Vec<u8> = Vec::new();
    let allocate_rsdp = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        align: 4,
        zone: ALLOC_ZONE_FSEG,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_rsdp.as_bytes());

    let allocate_tables = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        align: 4,
        zone: ALLOC_ZONE_HIGH,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_tables.as_bytes());

    for pointer_offset in acpi_table.pointers().iter() {
        let pointer = create_intra_pointer(FW_CFG_FILENAME_ACPI_TABLES, *pointer_offset, 8);
        table_loader_bytes.extend(pointer.as_bytes());
    }
    for (offset, len) in acpi_table.checksums().iter() {
        let checksum = create_acpi_table_checksum(*offset, *len);
        table_loader_bytes.extend(checksum.as_bytes());
    }
    let pointer_rsdp_to_xsdt = AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(FW_CFG_FILENAME_RSDP),
        src: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: offset_of!(Rsdp, xsdt_addr) as u32,
        size: 8,
        _pad: [0; 7],
    };
    table_loader_bytes.extend(pointer_rsdp_to_xsdt.as_bytes());
    let checksum_rsdp = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(Rsdp, checksum) as u32,
        start: 0,
        len: offset_of!(Rsdp, length) as u32,
        _pad: [0; 56],
    };
    let checksum_rsdp_ext = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(Rsdp, extended_checksum) as u32,
        start: 0,
        len: size_of::<Rsdp>() as u32,
        _pad: [0; 56],
    };
    table_loader_bytes.extend(checksum_rsdp.as_bytes());
    table_loader_bytes.extend(checksum_rsdp_ext.as_bytes());

    let table_loader = FwCfgItem {
        name: FW_CFG_FILENAME_TABLE_LOADER.to_owned(),
        content: FwCfgContent::Bytes(table_loader_bytes),
    };
    let (rsdp, tables) = acpi_table.take();
    let acpi_rsdp = FwCfgItem {
        name: FW_CFG_FILENAME_RSDP.to_owned(),
        content: FwCfgContent::Bytes(rsdp.as_bytes().to_owned()),
    };
    let apci_tables = FwCfgItem {
        name: FW_CFG_FILENAME_ACPI_TABLES.to_owned(),
        content: FwCfgContent::Bytes(tables),
    };
    [table_loader, acpi_rsdp, apci_tables]
}
