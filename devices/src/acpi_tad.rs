// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{mem, ptr};

use acpi_tables::{Aml, AmlSink, aml};
use log::warn;
use serde::{Deserialize, Serialize};
use vm_device::BusDevice;
use vm_memory::{ByteValued, GuestAddress};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

pub const ACPI_TAD_MMIO_SIZE: u64 = 20;
pub const ACPI_TAD_SNAPSHOT_ID: &str = "__acpi_tad";
const STATUS_OFFSET: u64 = 16;

#[repr(C)]
#[derive(Clone, Copy, Default, Deserialize, Serialize)]
struct AcpiTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    valid: u8,
    millisecond: u16,
    timezone: i16,
    daylight: u8,
    reserved: [u8; 3],
}

// SAFETY: All fields are integers and the C layout has no implicit padding.
unsafe impl ByteValued for AcpiTime {}

#[derive(Default, Deserialize, Serialize)]
pub struct AcpiTadState {
    offset_seconds: i64,
    time: AcpiTime,
    status: u32,
}

pub struct AcpiTadDevice {
    address: GuestAddress,
    state: AcpiTadState,
}

impl AcpiTadDevice {
    pub fn new(address: GuestAddress, state: Option<AcpiTadState>) -> Self {
        Self {
            address,
            state: state.unwrap_or_default(),
        }
    }
}

impl BusDevice for AcpiTadDevice {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 4 || offset & 3 != 0 || offset > STATUS_OFFSET {
            warn!(
                "Invalid ACPI TAD read: offset {offset}, length {}",
                data.len()
            );
            return;
        }

        if offset == STATUS_OFFSET {
            data.copy_from_slice(&self.state.status.to_le_bytes());
            return;
        }

        if offset == 0 {
            let seconds = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64)
                .saturating_add(self.state.offset_seconds);
            // SAFETY: A zeroed tm is valid and both pointers remain valid during the call.
            let (tm, valid) = unsafe {
                let mut tm = mem::zeroed::<libc::tm>();
                let valid = !libc::gmtime_r(&seconds, &mut tm).is_null();
                (tm, valid)
            };
            self.state.time = AcpiTime {
                year: (tm.tm_year + 1900) as u16,
                month: (tm.tm_mon + 1) as u8,
                day: tm.tm_mday as u8,
                hour: tm.tm_hour as u8,
                minute: tm.tm_min as u8,
                second: tm.tm_sec as u8,
                valid: u8::from(valid),
                timezone: 2047,
                ..Default::default()
            };
        }

        let index = offset as usize;
        data.copy_from_slice(&self.state.time.as_slice()[index..index + 4]);
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 4 || offset & 3 != 0 || offset >= STATUS_OFFSET {
            warn!(
                "Invalid ACPI TAD write: offset {offset}, length {}",
                data.len()
            );
            return None;
        }

        let index = offset as usize;
        self.state.time.as_mut_slice()[index..index + 4].copy_from_slice(data);
        if offset != STATUS_OFFSET - 4 {
            return None;
        }

        self.state.status = 1;
        let time = self.state.time;
        if !(1900..=9999).contains(&time.year)
            || !(1..=12).contains(&time.month)
            || !(1..=31).contains(&time.day)
            || time.hour > 23
            || time.minute > 59
            || time.second > 59
            || time.millisecond != 0
            || !matches!(time.timezone, 0 | 2047)
            || time.daylight != 0
        {
            return None;
        }

        let mut tm = libc::tm {
            tm_sec: time.second.into(),
            tm_min: time.minute.into(),
            tm_hour: time.hour.into(),
            tm_mday: time.day.into(),
            tm_mon: i32::from(time.month) - 1,
            tm_year: i32::from(time.year) - 1900,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: ptr::null(),
        };
        // SAFETY: tm is initialized and writable for the duration of the call.
        let seconds = unsafe { libc::timegm(&mut tm) };
        if tm.tm_mon != i32::from(time.month) - 1 || tm.tm_mday != i32::from(time.day) {
            return None;
        }

        self.state.offset_seconds = seconds
            - SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
        self.state.status = 0;
        None
    }
}

impl Aml for AcpiTadDevice {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        aml::Device::new(
            "_SB_.RTC0".into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI000E"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Memory32Fixed::new(
                        true,
                        self.address.0 as u32,
                        ACPI_TAD_MMIO_SIZE as u32,
                    )]),
                ),
                &aml::OpRegion::new(
                    "RTCR".into(),
                    aml::OpRegionSpace::SystemMemory,
                    &self.address.0,
                    &ACPI_TAD_MMIO_SIZE,
                ),
                &aml::Field::new(
                    "RTCR".into(),
                    aml::FieldAccessType::DWord,
                    aml::FieldLockRule::NoLock,
                    aml::FieldUpdateRule::WriteAsZeroes,
                    vec![
                        aml::FieldEntry::Named(*b"RTIM", 128),
                        aml::FieldEntry::Named(*b"RSTA", 32),
                    ],
                ),
                &aml::Mutex::new("RTLK".into(), 0),
                &aml::Method::new("_GCP".into(), 0, false, vec![&aml::Return::new(&4usize)]),
                &aml::Method::new(
                    "_GRT".into(),
                    0,
                    true,
                    vec![
                        &aml::Acquire::new("RTLK".into(), 0xffff),
                        &aml::Store::new(&aml::Local(0), &aml::Path::new("RTIM")),
                        &aml::Release::new("RTLK".into()),
                        &aml::Return::new(&aml::Local(0)),
                    ],
                ),
                &aml::Method::new(
                    "_SRT".into(),
                    1,
                    true,
                    vec![
                        &aml::Acquire::new("RTLK".into(), 0xffff),
                        &aml::Store::new(&aml::Path::new("RTIM"), &aml::Arg(0)),
                        &aml::Store::new(&aml::Local(0), &aml::Path::new("RSTA")),
                        &aml::Release::new("RTLK".into()),
                        &aml::Return::new(&aml::Local(0)),
                    ],
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

impl Snapshottable for AcpiTadDevice {
    fn id(&self) -> String {
        ACPI_TAD_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state)
    }
}

impl Pausable for AcpiTadDevice {}
impl Transportable for AcpiTadDevice {}
impl Migratable for AcpiTadDevice {}
