// Copyright (c) 2026 Crusoe Energy Systems LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};
use std::{iter, result};

use acpi_tables::{Aml, AmlSink, aml};
use anyhow::anyhow;
use log::{debug, error, warn};
use thiserror::Error as ThisError;
use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

use crate::iommu::{HwQueueHandle, PhysicalIommu};
use crate::{read_le_u32, write_le_u32};

// VCMDQ page0, and its VI_VCMDQ alias, are where the host VINTF page is mapped.
pub const TEGRA241_CMDQV_MMIO_SIZE: u64 = 0x5_0000;
pub const VCMDQ_PAGE0: u64 = 0x1_0000;
pub const VCMDQ_PAGE0_SIZE: u64 = 0x1_0000;
const VCMDQ_PAGE1: u64 = 0x2_0000;
pub const VI_VCMDQ_PAGE0: u64 = 0x3_0000;
const VI_VCMDQ_PAGE1: u64 = 0x4_0000;

// config page registers
const CONFIG: u64 = 0x0000;
const PARAM: u64 = 0x0004;
const STATUS: u64 = 0x0008;
const VI_ERR_MAP: u64 = 0x0014;
const VI_ERR_MAP_1: u64 = 0x0018;
const VI_INT_MASK: u64 = 0x001c;
const VI_INT_MASK_1: u64 = 0x0020;
const CMDQ_ERR_MAP: u64 = 0x0024;
const CMDQ_ERR_MAP_3: u64 = 0x0030;
const CMDQ_ALLOC_MAP: u64 = 0x0200;
const CMDQ_ALLOC_MAP_127: u64 = 0x03fc;

// config page VINTF0 block
const VINTF0_CONFIG: u64 = 0x1000;
const VINTF0_STATUS: u64 = 0x1004;
const VINTF0_SID_MATCH: u64 = 0x1040;
const VINTF0_SID_REPLACE_15: u64 = 0x10bc;
const VINTF0_LVCMDQ_ERR_MAP: u64 = 0x10c0;
const VINTF0_LVCMDQ_ERR_MAP_3: u64 = 0x10cc;

// Per-VCMDQ register stride in page0 and page1
const VCMDQ_STRIDE: u64 = 0x80;

// vcmdq base registers of a VCMDQ in page 1
const VCMDQ_BASE: u64 = 0x00;
const VCMDQ_BASE_HI: u64 = 0x04;
const VCMDQ_CONS_INDX_BASE: u64 = 0x08;
const VCMDQ_CONS_INDX_BASE_HI: u64 = 0x0c;

const CONFIG_CMDQV_EN: u32 = 1 << 0;
const PARAM_VER: u32 = 1;
const PARAM_NUM_VCMDQ_LOG2_SHIFT: u32 = 4;
const PARAM_NUM_SID_PER_VM_LOG2_SHIFT: u32 = 12;
const STATUS_CMDQV_ENABLED: u32 = 1 << 0;
const VI_ERR_MAP_VINTF0: u32 = 1 << 0;
const CMDQ_ALLOC_MAP_ALLOC: u32 = 1 << 0;
const VINTF_EN: u32 = 1 << 0;
const VINTF_HYP_OWN: u32 = 1 << 17;
const VINTF_STATUS_ENABLE_OK: u32 = 1 << 0;
const VCMDQ_BASE_ADDR_MASK: u64 = 0x0000_ffff_ffff_ffe0;
const VCMDQ_BASE_LOG2SIZE_MASK: u64 = 0x1f;
const VCMDQ_ENTRY_SIZE: u64 = 16;

const MAX_VCMDQS_LOG2: u8 = 7;
// The VINTF has 16 SID_MATCH and SID_REPLACE registers.
const MAX_SIDS_LOG2: u8 = 4;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Unsupported access width: {0}")]
    AccessWidth(usize),
    #[error("Unknown register offset: {0:#x}")]
    UnknownOffset(u64),
    #[error("Write to read-only register at offset {0:#x}")]
    ReadOnly(u64),
}

pub struct Tegra241CmdqvConfig {
    pub base: u64,
    pub irq: u32,
    pub interrupt: Arc<dyn InterruptSourceGroup>,
    /// IORT identifier of the SMMUv3 this CMDQV extends.
    pub smmu_id: u32,
    pub num_vcmdqs_log2: u8,
    pub num_sids_log2: u8,
}

/// The hardware queue backing a VCMDQ, with the BASE it was set up from.
#[derive(Default)]
enum HwQueue {
    #[default]
    None,
    Allocated {
        base: u64,
        // Dropping it frees the queue.
        _handle: Box<dyn HwQueueHandle>,
    },
    /// Not retried until BASE changes or the VCMDQ is set up again.
    Failed(u64),
}

#[derive(Default)]
struct Vcmdq {
    alloc_map: u32,
    base: u64,
    cons_indx_base: u64,
    hw_queue: HwQueue,
}

/// NVIDIA Tegra241 CMDQV, an SMMUv3 extension with command queues the
/// hardware reads directly.
pub struct Tegra241Cmdqv {
    id: String,
    base: u64,
    irq: u32,
    smmu_id: u32,

    config: u32,
    param: u32,
    status: u32,
    vi_err_map: [u32; 2],
    vi_int_mask: [u32; 2],
    cmdq_err_map: [u32; 4],
    vintf_config: u32,
    vintf_status: u32,
    vintf_lvcmdq_err_map: [u32; 4],
    vcmdqs: Vec<Vcmdq>,

    interrupt: Arc<dyn InterruptSourceGroup>,
    backend: Arc<dyn PhysicalIommu>,
}

impl Tegra241Cmdqv {
    pub fn new(id: String, config: Tegra241CmdqvConfig, backend: Arc<dyn PhysicalIommu>) -> Self {
        let num_vcmdqs_log2 = config.num_vcmdqs_log2.min(MAX_VCMDQS_LOG2);
        let num_sids_log2 = config.num_sids_log2.min(MAX_SIDS_LOG2);

        Tegra241Cmdqv {
            id,
            base: config.base,
            irq: config.irq,
            smmu_id: config.smmu_id,
            config: CONFIG_CMDQV_EN,
            param: PARAM_VER
                | (u32::from(num_vcmdqs_log2) << PARAM_NUM_VCMDQ_LOG2_SHIFT)
                | (u32::from(num_sids_log2) << PARAM_NUM_SID_PER_VM_LOG2_SHIFT),
            status: STATUS_CMDQV_ENABLED,
            vi_err_map: [0; 2],
            vi_int_mask: [0; 2],
            cmdq_err_map: [0; 4],
            vintf_config: 0,
            vintf_status: 0,
            vintf_lvcmdq_err_map: [0; 4],
            vcmdqs: iter::repeat_with(Vcmdq::default)
                .take(1 << num_vcmdqs_log2)
                .collect(),
            interrupt: config.interrupt,
            backend,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn report_vcmdq_errors(&mut self, lvcmdq_err_map: [u64; 2]) {
        if lvcmdq_err_map == [0, 0] {
            return;
        }

        let words = [
            lvcmdq_err_map[0] as u32,
            (lvcmdq_err_map[0] >> 32) as u32,
            lvcmdq_err_map[1] as u32,
            (lvcmdq_err_map[1] >> 32) as u32,
        ];
        // The maps keep the last report. The guest tells live errors from
        // each VCMDQ's GERROR in the host page.
        self.vintf_lvcmdq_err_map = words;
        self.cmdq_err_map = words;
        self.vi_err_map[0] |= VI_ERR_MAP_VINTF0;
        warn!(
            "Tegra241 CMDQV {}: VCMDQ errors {:#x}_{:#x}",
            self.id, lvcmdq_err_map[1], lvcmdq_err_map[0]
        );

        if self.vi_int_mask[0] & VI_ERR_MAP_VINTF0 == 0
            && let Err(e) = self.interrupt.trigger(0)
        {
            error!("Tegra241 CMDQV {}: failed to raise interrupt: {e}", self.id);
        }
    }

    fn vcmdq_ready(&self, index: usize) -> bool {
        let vcmdq = &self.vcmdqs[index];
        vcmdq.base != 0
            && vcmdq.alloc_map & CMDQ_ALLOC_MAP_ALLOC != 0
            && self.config & CONFIG_CMDQV_EN != 0
            && self.vintf_config & VINTF_EN != 0
    }

    /// The host maps VCMDQs in order, so a VCMDQ needs all those below it.
    fn hw_queue_wanted(&self, index: usize) -> bool {
        (0..=index).all(|i| self.vcmdq_ready(i))
    }

    fn hw_queue_stale(&self, index: usize) -> bool {
        match &self.vcmdqs[index].hw_queue {
            HwQueue::Allocated { base, .. } | HwQueue::Failed(base) => {
                *base != self.vcmdqs[index].base || !self.hw_queue_wanted(index)
            }
            HwQueue::None => {
                self.hw_queue_wanted(index)
                    && (index == 0
                        || matches!(self.vcmdqs[index - 1].hw_queue, HwQueue::Allocated { .. }))
            }
        }
    }

    /// Each hardware queue depends on the one below it: free from the top,
    /// then allocate from the bottom.
    fn update_hw_queues(&mut self) {
        let Some(first) = (0..self.vcmdqs.len()).find(|&index| self.hw_queue_stale(index)) else {
            return;
        };

        for index in (first..self.vcmdqs.len()).rev() {
            if matches!(self.vcmdqs[index].hw_queue, HwQueue::Allocated { .. })
                || self.hw_queue_stale(index)
            {
                self.vcmdqs[index].hw_queue = HwQueue::None;
            }
        }
        for index in first..self.vcmdqs.len() {
            if !self.hw_queue_wanted(index)
                || matches!(self.vcmdqs[index].hw_queue, HwQueue::Failed(_))
                || !self.allocate_hw_queue(index)
            {
                break;
            }
        }
    }

    fn allocate_hw_queue(&mut self, index: usize) -> bool {
        let base = self.vcmdqs[index].base;
        let addr = base & VCMDQ_BASE_ADDR_MASK;
        let size = VCMDQ_ENTRY_SIZE << (base & VCMDQ_BASE_LOG2SIZE_MASK);
        match self.backend.allocate_hw_queue(index as u32, addr, size) {
            Ok(hw_queue) => {
                debug!(
                    "Tegra241 CMDQV {}: VCMDQ{index} at {addr:#x}, size {size:#x}",
                    self.id
                );
                self.vcmdqs[index].hw_queue = HwQueue::Allocated {
                    base,
                    _handle: hw_queue,
                };
                true
            }
            Err(e) => {
                warn!(
                    "Tegra241 CMDQV {}: failed to allocate VCMDQ{index}: {e}",
                    self.id
                );
                self.vcmdqs[index].hw_queue = HwQueue::Failed(base);
                false
            }
        }
    }

    /// Splits a page1 offset, or its VI_VCMDQ alias, into a VCMDQ and a register.
    fn vcmdq_page1_reg(&self, offset: u64) -> Option<(usize, u64)> {
        let offset = match offset {
            VCMDQ_PAGE1..VI_VCMDQ_PAGE0 => offset - VCMDQ_PAGE1,
            VI_VCMDQ_PAGE1..TEGRA241_CMDQV_MMIO_SIZE => offset - VI_VCMDQ_PAGE1,
            _ => return None,
        };
        let index = (offset / VCMDQ_STRIDE) as usize;

        (index < self.vcmdqs.len()).then_some((index, offset % VCMDQ_STRIDE))
    }

    fn read_reg(&self, offset: u64) -> Result<u32, Error> {
        let word = |start: u64| ((offset - start) / 4) as usize;

        let value = match offset {
            CONFIG => self.config,
            PARAM => self.param,
            STATUS => self.status,
            VI_ERR_MAP..=VI_ERR_MAP_1 => self.vi_err_map[word(VI_ERR_MAP)],
            VI_INT_MASK..=VI_INT_MASK_1 => self.vi_int_mask[word(VI_INT_MASK)],
            CMDQ_ERR_MAP..=CMDQ_ERR_MAP_3 => self.cmdq_err_map[word(CMDQ_ERR_MAP)],
            CMDQ_ALLOC_MAP..=CMDQ_ALLOC_MAP_127 => self
                .vcmdqs
                .get(word(CMDQ_ALLOC_MAP))
                .map_or(0, |vcmdq| vcmdq.alloc_map),
            VINTF0_CONFIG => self.vintf_config,
            VINTF0_STATUS => self.vintf_status,
            // The host maps the guest's StreamIDs; Linux only clears these.
            VINTF0_SID_MATCH..=VINTF0_SID_REPLACE_15 => 0,
            VINTF0_LVCMDQ_ERR_MAP..=VINTF0_LVCMDQ_ERR_MAP_3 => {
                self.vintf_lvcmdq_err_map[word(VINTF0_LVCMDQ_ERR_MAP)]
            }
            _ => {
                let (index, reg) = self
                    .vcmdq_page1_reg(offset)
                    .ok_or(Error::UnknownOffset(offset))?;
                let vcmdq = &self.vcmdqs[index];
                match reg {
                    VCMDQ_BASE => vcmdq.base as u32,
                    VCMDQ_BASE_HI => (vcmdq.base >> 32) as u32,
                    VCMDQ_CONS_INDX_BASE => vcmdq.cons_indx_base as u32,
                    VCMDQ_CONS_INDX_BASE_HI => (vcmdq.cons_indx_base >> 32) as u32,
                    _ => return Err(Error::UnknownOffset(offset)),
                }
            }
        };

        Ok(value)
    }

    fn write_reg(&mut self, offset: u64, value: u32) -> Result<(), Error> {
        fn set_low(reg: &mut u64, value: u32) {
            *reg = (*reg & 0xffff_ffff_0000_0000) | u64::from(value);
        }

        fn set_high(reg: &mut u64, value: u32) {
            *reg = (*reg & 0xffff_ffff) | (u64::from(value) << 32);
        }

        match offset {
            CONFIG => {
                self.config = value;
                if value & CONFIG_CMDQV_EN != 0 {
                    self.status |= STATUS_CMDQV_ENABLED;
                } else {
                    self.status &= !STATUS_CMDQV_ENABLED;
                }
            }
            VI_INT_MASK..=VI_INT_MASK_1 => {
                self.vi_int_mask[((offset - VI_INT_MASK) / 4) as usize] = value;
            }
            CMDQ_ALLOC_MAP..=CMDQ_ALLOC_MAP_127 => {
                let index = ((offset - CMDQ_ALLOC_MAP) / 4) as usize;
                self.vcmdqs
                    .get_mut(index)
                    .ok_or(Error::UnknownOffset(offset))?
                    .alloc_map = value;
            }
            VINTF0_CONFIG => {
                // The VINTF is owned by the host.
                self.vintf_config = value & !VINTF_HYP_OWN;
                if value & VINTF_EN != 0 {
                    self.vintf_status |= VINTF_STATUS_ENABLE_OK;
                } else {
                    self.vintf_status &= !VINTF_STATUS_ENABLE_OK;
                }
            }
            VINTF0_SID_MATCH..=VINTF0_SID_REPLACE_15 => {}
            PARAM
            | STATUS
            | VI_ERR_MAP..=VI_ERR_MAP_1
            | CMDQ_ERR_MAP..=CMDQ_ERR_MAP_3
            | VINTF0_STATUS
            | VINTF0_LVCMDQ_ERR_MAP..=VINTF0_LVCMDQ_ERR_MAP_3 => {
                return Err(Error::ReadOnly(offset));
            }
            _ => {
                let (index, reg) = self
                    .vcmdq_page1_reg(offset)
                    .ok_or(Error::UnknownOffset(offset))?;
                let vcmdq = &mut self.vcmdqs[index];
                match reg {
                    VCMDQ_BASE => set_low(&mut vcmdq.base, value),
                    VCMDQ_BASE_HI => set_high(&mut vcmdq.base, value),
                    VCMDQ_CONS_INDX_BASE => set_low(&mut vcmdq.cons_indx_base, value),
                    VCMDQ_CONS_INDX_BASE_HI => set_high(&mut vcmdq.cons_indx_base, value),
                    _ => return Err(Error::UnknownOffset(offset)),
                }
            }
        }

        Ok(())
    }
}

impl BusDevice for Tegra241Cmdqv {
    // A 64-bit access covers two consecutive 32-bit registers.
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 4 && data.len() != 8 {
            debug!(
                "Tegra241 CMDQV read at {offset:#x}: {}",
                Error::AccessWidth(data.len())
            );
            data.fill(0);
            return;
        }

        for (offset, chunk) in (offset..).step_by(4).zip(data.chunks_mut(4)) {
            let value = self.read_reg(offset).unwrap_or_else(|e| {
                debug!("Tegra241 CMDQV read at {offset:#x}: {e}");
                0
            });
            write_le_u32(chunk, value);
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 4 && data.len() != 8 {
            debug!(
                "Tegra241 CMDQV write at {offset:#x}: {}",
                Error::AccessWidth(data.len())
            );
            return None;
        }

        for (offset, chunk) in (offset..).step_by(4).zip(data.chunks(4)) {
            if let Err(e) = self.write_reg(offset, read_le_u32(chunk)) {
                debug!("Tegra241 CMDQV write at {offset:#x}: {e}");
            }
        }
        self.update_hw_queues();

        None
    }
}

impl Aml for Tegra241Cmdqv {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        aml::Device::new(
            format!("_SB_.CV{:02X}", self.smmu_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"NVDA200C"),
                // Linux pairs the CMDQV with the SMMUv3 whose IORT identifier is _UID.
                &aml::Name::new("_UID".into(), &self.smmu_id),
                &aml::Name::new("_CCA".into(), &aml::ONE),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::AddressSpace::new_memory(
                            aml::AddressSpaceCacheable::NotCacheable,
                            true,
                            self.base,
                            self.base + TEGRA241_CMDQV_MMIO_SIZE - 1,
                            None,
                        ),
                        &aml::Interrupt::new(true, true, false, false, self.irq),
                    ]),
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

impl Drop for Tegra241Cmdqv {
    fn drop(&mut self) {
        // Each hardware queue depends on the one below it.
        while self.vcmdqs.pop().is_some() {}
    }
}

impl Pausable for Tegra241Cmdqv {}

impl Snapshottable for Tegra241Cmdqv {
    fn id(&self) -> String {
        self.id.clone()
    }

    // The command queues are owned by the host.
    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Err(MigratableError::Snapshot(anyhow!(
            "Tegra241 CMDQV does not support snapshot"
        )))
    }
}

impl Transportable for Tegra241Cmdqv {}
impl Migratable for Tegra241Cmdqv {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::{io, mem};

    use vm_device::interrupt::{InterruptIndex, InterruptSourceConfig};
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::iommu::{Error as IommuError, HwInfo, Invalidation, TableEntry};
    use crate::{read_le_u64, write_le_u64};

    #[derive(Default)]
    struct CountingInterrupt(AtomicUsize);

    impl InterruptSourceGroup for CountingInterrupt {
        fn trigger(&self, _index: InterruptIndex) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn notifier(&self, _index: InterruptIndex) -> Option<EventFd> {
            None
        }

        fn update(
            &self,
            _index: InterruptIndex,
            _config: InterruptSourceConfig,
            _masked: bool,
            _set_gsi: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn set_gsi(&self) -> io::Result<()> {
            Ok(())
        }
    }

    type Calls = Arc<Mutex<Vec<(u32, Option<u64>)>>>;

    /// Records hardware queue calls as (index, Some(addr)) or (index, None),
    /// failing allocations of the queues from `fail_from` up.
    struct QueueBackend {
        calls: Calls,
        fail_from: AtomicU32,
    }

    struct Queue {
        index: u32,
        calls: Calls,
    }

    impl HwQueueHandle for Queue {}

    impl Drop for Queue {
        fn drop(&mut self) {
            self.calls.lock().unwrap().push((self.index, None));
        }
    }

    impl QueueBackend {
        fn take(&self) -> Vec<(u32, Option<u64>)> {
            mem::take(&mut self.calls.lock().unwrap())
        }
    }

    impl PhysicalIommu for QueueBackend {
        fn hw_info(&self) -> Result<HwInfo, IommuError> {
            Ok(HwInfo::Smmuv3 {
                idr: [0; 6],
                ats_supported: false,
            })
        }

        fn install_table_entry(
            &self,
            _device_id: u32,
            _entry: TableEntry,
        ) -> Result<(), IommuError> {
            Ok(())
        }

        fn set_passthrough(&self, _device_id: u32) -> Result<(), IommuError> {
            Ok(())
        }

        fn set_blocking(&self, _device_id: u32) -> Result<(), IommuError> {
            Ok(())
        }

        fn invalidate(&self, _invalidation: Invalidation) -> Result<(), IommuError> {
            Ok(())
        }

        fn allocate_hw_queue(
            &self,
            index: u32,
            addr: u64,
            _size: u64,
        ) -> Result<Box<dyn HwQueueHandle>, IommuError> {
            self.calls.lock().unwrap().push((index, Some(addr)));
            if index >= self.fail_from.load(Ordering::SeqCst) {
                return Err(IommuError::Backend(io::Error::other("busy")));
            }
            Ok(Box::new(Queue {
                index,
                calls: Arc::clone(&self.calls),
            }))
        }
    }

    // A 64 KiB queue at 0x8000_0000, and one at 0x8001_0000.
    const BASE0: u64 = 0x8000_0000 | 12;
    const BASE1: u64 = 0x8001_0000 | 12;

    fn cmdqv() -> (Tegra241Cmdqv, Arc<CountingInterrupt>, Arc<QueueBackend>) {
        let interrupt = Arc::new(CountingInterrupt::default());
        let backend = Arc::new(QueueBackend {
            calls: Arc::default(),
            fail_from: AtomicU32::new(u32::MAX),
        });
        let config = Tegra241CmdqvConfig {
            base: 0x1000_0000,
            irq: 40,
            interrupt: Arc::clone(&interrupt) as Arc<dyn InterruptSourceGroup>,
            smmu_id: 1,
            num_vcmdqs_log2: 1,
            num_sids_log2: 5,
        };
        let cmdqv = Tegra241Cmdqv::new(
            "cmdqv".to_string(),
            config,
            Arc::clone(&backend) as Arc<dyn PhysicalIommu>,
        );
        (cmdqv, interrupt, backend)
    }

    fn read(cmdqv: &mut Tegra241Cmdqv, offset: u64, len: usize) -> u64 {
        let mut data = [0u8; 8];
        cmdqv.read(0, offset, &mut data[..len]);
        read_le_u64(&data)
    }

    fn write(cmdqv: &mut Tegra241Cmdqv, offset: u64, value: u64, len: usize) {
        let mut data = [0u8; 8];
        write_le_u64(&mut data, value);
        cmdqv.write(0, offset, &data[..len]);
    }

    fn enable(cmdqv: &mut Tegra241Cmdqv) {
        write(cmdqv, VINTF0_CONFIG, u64::from(VINTF_EN), 4);
        for index in 0..2 {
            write(cmdqv, CMDQ_ALLOC_MAP + index * 4, 1, 4);
        }
    }

    #[test]
    fn test_param_reports_host_queues_and_sids() {
        let (mut cmdqv, _, _) = cmdqv();
        assert_eq!(read(&mut cmdqv, PARAM, 4), 0x4011);
        assert_eq!(read(&mut cmdqv, STATUS, 4), u64::from(STATUS_CMDQV_ENABLED));

        write(&mut cmdqv, CONFIG, 0, 4);
        assert_eq!(read(&mut cmdqv, STATUS, 4), 0);
        write(&mut cmdqv, PARAM, 0, 4);
        assert_eq!(read(&mut cmdqv, PARAM, 4), 0x4011);
    }

    #[test]
    fn test_vintf_stays_host_owned() {
        let (mut cmdqv, _, _) = cmdqv();
        write(
            &mut cmdqv,
            VINTF0_CONFIG,
            u64::from(VINTF_EN | VINTF_HYP_OWN),
            4,
        );
        assert_eq!(read(&mut cmdqv, VINTF0_CONFIG, 4), u64::from(VINTF_EN));
        assert_eq!(
            read(&mut cmdqv, VINTF0_STATUS, 4),
            u64::from(VINTF_STATUS_ENABLE_OK)
        );
    }

    #[test]
    fn test_page1_halves_and_alias() {
        let (mut cmdqv, _, _) = cmdqv();
        let base1 = VCMDQ_PAGE1 + VCMDQ_STRIDE;
        write(&mut cmdqv, base1 + VCMDQ_BASE, 0x2345_6789, 4);
        write(&mut cmdqv, base1 + VCMDQ_BASE_HI, 0x1, 4);
        assert_eq!(read(&mut cmdqv, base1 + VCMDQ_BASE, 8), 0x1_2345_6789);

        let alias = VI_VCMDQ_PAGE1 + VCMDQ_STRIDE;
        write(&mut cmdqv, alias + VCMDQ_CONS_INDX_BASE, 0xab_cdef_0000, 8);
        assert_eq!(
            read(&mut cmdqv, base1 + VCMDQ_CONS_INDX_BASE, 8),
            0xab_cdef_0000
        );

        // Only two VCMDQs exist.
        let base2 = VCMDQ_PAGE1 + 2 * VCMDQ_STRIDE;
        write(&mut cmdqv, base2 + VCMDQ_BASE, 0x1000, 4);
        assert_eq!(read(&mut cmdqv, base2 + VCMDQ_BASE, 4), 0);
    }

    #[test]
    fn test_hw_queues_are_allocated_in_order() {
        let (mut cmdqv, _, backend) = cmdqv();
        enable(&mut cmdqv);

        // VCMDQ1 waits for VCMDQ0.
        write(&mut cmdqv, VCMDQ_PAGE1 + VCMDQ_STRIDE, BASE1, 8);
        assert_eq!(backend.take(), []);
        write(&mut cmdqv, VCMDQ_PAGE1, BASE0, 8);
        assert_eq!(
            backend.take(),
            [(0, Some(0x8000_0000)), (1, Some(0x8001_0000))]
        );

        // Moving VCMDQ0 frees both from the top before reallocating.
        write(&mut cmdqv, VCMDQ_PAGE1, BASE0 + 0x2_0000, 8);
        assert_eq!(
            backend.take(),
            [
                (1, None),
                (0, None),
                (0, Some(0x8002_0000)),
                (1, Some(0x8001_0000))
            ]
        );

        // Disabling the CMDQV frees them all.
        write(&mut cmdqv, CONFIG, 0, 4);
        assert_eq!(backend.take(), [(1, None), (0, None)]);
    }

    #[test]
    fn test_drop_frees_hw_queues_from_the_top() {
        let (mut cmdqv, _, backend) = cmdqv();
        enable(&mut cmdqv);
        write(&mut cmdqv, VCMDQ_PAGE1, BASE0, 8);
        write(&mut cmdqv, VCMDQ_PAGE1 + VCMDQ_STRIDE, BASE1, 8);
        backend.take();

        drop(cmdqv);
        assert_eq!(backend.take(), [(1, None), (0, None)]);
    }

    #[test]
    fn test_failed_allocation_waits_for_a_new_base() {
        let (mut cmdqv, _, backend) = cmdqv();
        enable(&mut cmdqv);
        backend.fail_from.store(1, Ordering::SeqCst);
        write(&mut cmdqv, VCMDQ_PAGE1, BASE0, 8);
        write(&mut cmdqv, VCMDQ_PAGE1 + VCMDQ_STRIDE, BASE1, 8);
        assert_eq!(
            backend.take(),
            [(0, Some(0x8000_0000)), (1, Some(0x8001_0000))]
        );

        // Neither other writes nor moving VCMDQ0 retry VCMDQ1.
        backend.fail_from.store(u32::MAX, Ordering::SeqCst);
        write(
            &mut cmdqv,
            VCMDQ_PAGE1 + VCMDQ_CONS_INDX_BASE,
            0x9000_0000,
            8,
        );
        write(&mut cmdqv, VCMDQ_PAGE1 + VCMDQ_STRIDE, BASE1, 8);
        assert_eq!(backend.take(), []);
        write(&mut cmdqv, VCMDQ_PAGE1, BASE0 + 0x2_0000, 8);
        assert_eq!(backend.take(), [(0, None), (0, Some(0x8002_0000))]);

        // A new BASE does, and so does setting the VINTF up again.
        write(&mut cmdqv, VCMDQ_PAGE1 + VCMDQ_STRIDE, BASE1 + 0x2_0000, 8);
        assert_eq!(backend.take(), [(1, Some(0x8003_0000))]);
        backend.fail_from.store(1, Ordering::SeqCst);
        write(&mut cmdqv, VCMDQ_PAGE1 + VCMDQ_STRIDE, BASE1, 8);
        assert_eq!(backend.take(), [(1, None), (1, Some(0x8001_0000))]);
        backend.fail_from.store(u32::MAX, Ordering::SeqCst);
        write(&mut cmdqv, VINTF0_CONFIG, 0, 4);
        write(&mut cmdqv, VINTF0_CONFIG, u64::from(VINTF_EN), 4);
        assert_eq!(
            backend.take(),
            [(0, None), (0, Some(0x8002_0000)), (1, Some(0x8001_0000))]
        );
    }

    #[test]
    fn test_sid_registers_and_split_accesses() {
        let (mut cmdqv, _, backend) = cmdqv();
        write(&mut cmdqv, VINTF0_SID_MATCH, 0x1234, 4);
        assert_eq!(read(&mut cmdqv, VINTF0_SID_MATCH, 4), 0);

        // The CONFIG half of a 64-bit write lands although PARAM is read-only.
        enable(&mut cmdqv);
        write(&mut cmdqv, VCMDQ_PAGE1, BASE0, 8);
        assert_eq!(backend.take(), [(0, Some(0x8000_0000))]);
        write(&mut cmdqv, CONFIG, 0, 8);
        assert_eq!(backend.take(), [(0, None)]);

        // A known register next to an unknown one still reads back.
        assert_eq!(
            read(&mut cmdqv, VINTF0_STATUS, 8),
            u64::from(VINTF_STATUS_ENABLE_OK)
        );
    }

    #[test]
    fn test_vcmdq_errors_reach_the_maps_and_interrupt() {
        let (mut cmdqv, interrupt, _) = cmdqv();
        cmdqv.report_vcmdq_errors([(1 << 33) | 1, 0]);
        assert_eq!(read(&mut cmdqv, VINTF0_LVCMDQ_ERR_MAP, 8), (1 << 33) | 1);
        assert_eq!(read(&mut cmdqv, CMDQ_ERR_MAP + 4, 4), 0x2);
        assert_eq!(
            read(&mut cmdqv, VI_ERR_MAP, 4),
            u64::from(VI_ERR_MAP_VINTF0)
        );
        assert_eq!(interrupt.0.load(Ordering::SeqCst), 1);

        write(&mut cmdqv, VI_INT_MASK, u64::from(VI_ERR_MAP_VINTF0), 4);
        cmdqv.report_vcmdq_errors([1, 0]);
        assert_eq!(interrupt.0.load(Ordering::SeqCst), 1);
    }
}
