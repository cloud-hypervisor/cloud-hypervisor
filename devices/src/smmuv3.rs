// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::result;
use std::sync::{Arc, Barrier};

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;
use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError, GuestMemoryMmap,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

use crate::iommu::{HwIommuBackend, Invalidation, TableEntry};
use crate::{read_le_u32, read_le_u64, write_le_u32, write_le_u64};

type GuestMemoryMmapAtomic = GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>;

pub const SMMU_V3_MMIO_SIZE: u64 = 0x2_0000;

const CMDQ_ENTRY_SIZE: u64 = 16;

// Page 0 registers
const IDR0: u64 = 0x0000;
const IDR1: u64 = 0x0004;
const IDR2: u64 = 0x0008;
const IDR3: u64 = 0x000c;
const IDR4: u64 = 0x0010;
const IDR5: u64 = 0x0014;
const IIDR: u64 = 0x0018;
const AIDR: u64 = 0x001c;
const CR0: u64 = 0x0020;
const CR0ACK: u64 = 0x0024;
const CR1: u64 = 0x0028;
const CR2: u64 = 0x002c;
const STATUSR: u64 = 0x0040;
const GBPA: u64 = 0x0044;
const IRQ_CTRL: u64 = 0x0050;
const IRQ_CTRLACK: u64 = 0x0054;
const GERROR: u64 = 0x0060;
const GERRORN: u64 = 0x0064;
const GERROR_IRQ_CFG0: u64 = 0x0068;
const GERROR_IRQ_CFG0_HI: u64 = 0x006c;
const GERROR_IRQ_CFG1: u64 = 0x0070;
const GERROR_IRQ_CFG2: u64 = 0x0074;
const STRTAB_BASE: u64 = 0x0080;
const STRTAB_BASE_HI: u64 = 0x0084;
const STRTAB_BASE_CFG: u64 = 0x0088;
const CMDQ_BASE: u64 = 0x0090;
const CMDQ_BASE_HI: u64 = 0x0094;
const CMDQ_PROD: u64 = 0x0098;
const CMDQ_CONS: u64 = 0x009c;
const EVENTQ_BASE: u64 = 0x00a0;
const EVENTQ_BASE_HI: u64 = 0x00a4;
const EVENTQ_IRQ_CFG0: u64 = 0x00b0;
const EVENTQ_IRQ_CFG0_HI: u64 = 0x00b4;
const EVENTQ_IRQ_CFG1: u64 = 0x00b8;
const EVENTQ_IRQ_CFG2: u64 = 0x00bc;

// Page 1 registers
const PAGE1_BASE: u64 = 0x1_0000;
const EVENTQ_PROD: u64 = PAGE1_BASE + 0x00a8;
const EVENTQ_CONS: u64 = PAGE1_BASE + 0x00ac;

// IDR0 fields
const IDR0_S1P: u32 = 1 << 1;
const IDR0_TTF_AARCH64: u32 = 0b10 << 2;
const IDR0_COHACC: u32 = 1 << 4;
const IDR0_ASID16: u32 = 1 << 12;
const IDR0_VMID16: u32 = 1 << 18;
const IDR0_CD2L: u32 = 1 << 19;
const IDR0_ATS: u32 = 1 << 10;
const IDR0_TTENDIAN_LE: u32 = 0b10 << 21;
const IDR0_STALL_MODEL_NONE: u32 = 0b01 << 24;
const IDR0_STLEVEL_2LVL: u32 = 0b01 << 27;
const IDR0_HOST_GATED: u32 =
    IDR0_COHACC | IDR0_ASID16 | IDR0_VMID16 | IDR0_CD2L | IDR0_STLEVEL_2LVL;
const IDR0_VALUE: u32 = IDR0_S1P
    | IDR0_TTF_AARCH64
    | IDR0_COHACC
    | IDR0_ASID16
    | IDR0_VMID16
    | IDR0_CD2L
    | IDR0_TTENDIAN_LE
    | IDR0_STALL_MODEL_NONE
    | IDR0_STLEVEL_2LVL;

// IDR1 fields
const IDR1_SIDSIZE: u32 = 16;
const IDR1_SSIDSIZE_SHIFT: u32 = 6;
const IDR1_SSIDSIZE_MASK: u32 = 0x1f << IDR1_SSIDSIZE_SHIFT;
const IDR1_CMDQS: u32 = Q_MAX_LOG2SIZE << 21;
const IDR1_EVENTQS: u32 = Q_MAX_LOG2SIZE << 16;
const IDR1_VALUE: u32 = IDR1_SIDSIZE | IDR1_CMDQS | IDR1_EVENTQS;

// IDR5 fields
const IDR5_OAS_MASK: u32 = 0b111;
const IDR5_OAS_48BIT: u32 = 0b101;
const IDR5_GRAN4K: u32 = 1 << 4;
const IDR5_GRAN16K: u32 = 1 << 5;
const IDR5_GRAN64K: u32 = 1 << 6;
const IDR5_GRAN_MASK: u32 = IDR5_GRAN4K | IDR5_GRAN16K | IDR5_GRAN64K;
const IDR5_VALUE: u32 = IDR5_OAS_48BIT | IDR5_GRAN4K | IDR5_GRAN64K;

// CR0 fields
const CR0_SMMUEN: u32 = 1 << 0;
const CR0_EVENTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;

// GBPA fields
const GBPA_UPDATE: u32 = 1 << 31;

// IRQ_CTRL fields
const IRQ_CTRL_GERROR_IRQEN: u32 = 1 << 0;
const IRQ_CTRL_EVENTQ_IRQEN: u32 = 1 << 2;

// GERROR fields
const GERROR_CMDQ_ERR: u32 = 1 << 0;
const GERROR_EVENTQ_ABT_ERR: u32 = 1 << 2;
const GERROR_MSI_CMDQ_ABT_ERR: u32 = 1 << 4;

// CMDQ_CONS fields
const CMDQ_CONS_ERR_SHIFT: u32 = 24;
const CMDQ_CONS_ERR_MASK: u32 = 0x7f << CMDQ_CONS_ERR_SHIFT;
const CERROR_ABT: u32 = 2;

// Event queue
const EVENTQ_ENTRY_SIZE: u64 = 32;
const EVENTQ_PROD_OVFLG: u32 = 1 << 31;

// Queue base field masks
const Q_BASE_LOG2SIZE_MASK: u64 = 0x1f;
const Q_BASE_ADDR_MASK: u64 = 0x00ff_ffff_ffff_ffe0;
/// Largest queue both IDR1.CMDQS and IDR1.EVENTQS advertise.
const Q_MAX_LOG2SIZE: u32 = 19;

// Stream table layout
const STRTAB_BASE_ADDR_MASK: u64 = 0x00ff_ffff_ffff_ffc0;
const STRTAB_CFG_FMT_SHIFT: u32 = 16;
const STRTAB_CFG_FMT_MASK: u32 = 0b11;
const STRTAB_CFG_SPLIT_SHIFT: u32 = 6;
const STRTAB_CFG_SPLIT_MASK: u32 = 0x1f;
const STRTAB_CFG_LOG2SIZE_MASK: u32 = 0x3f;
const STRTAB_FMT_2LEVEL: u32 = 0b01;

const STE_SIZE: u64 = 64;
const STE_WORDS: usize = 8;
const L1STD_SIZE: u64 = 8;
const L1STD_SPAN_MASK: u64 = 0x1f;
const L1STD_L2PTR_MASK: u64 = 0x00ff_ffff_ffff_ffc0;

const STE_V: u64 = 1 << 0;
const STE_CONFIG_SHIFT: u64 = 1;
const STE_CONFIG_MASK: u64 = 0b111;
const STE_CONFIG_BYPASS: u8 = 0b100;
const STE_CONFIG_S1_ONLY: u8 = 0b101;
const STE_CONFIG_S2_ONLY: u8 = 0b110;
const STE_CONFIG_NESTED: u8 = 0b111;

// Command opcodes
const CMD_OPCODE_MASK: u64 = 0xff;
const CMD_CFGI_STE: u8 = 0x03;
const CMD_CFGI_STE_RANGE: u8 = 0x04;
const CMD_CFGI_CD: u8 = 0x05;
const CMD_CFGI_CD_ALL: u8 = 0x06;
const CMD_TLBI_NH_ALL: u8 = 0x10;
const CMD_TLBI_NH_ASID: u8 = 0x11;
const CMD_TLBI_NH_VA: u8 = 0x12;
const CMD_TLBI_NH_VAA: u8 = 0x13;
const CMD_TLBI_NSNH_ALL: u8 = 0x30;
const CMD_ATC_INV: u8 = 0x40;
const CMD_SYNC: u8 = 0x46;

// CMD_SYNC fields
const CMD_SYNC_CS_MASK: u64 = 0b11 << 12;
const CMD_SYNC_CS_IRQ: u64 = 0b01 << 12;
const CMD_SYNC_MSIADDR_MASK: u64 = 0x000f_ffff_ffff_fffc;

#[derive(Clone, Copy, Debug)]
struct Command {
    opcode: u8,
    word0: u64,
    word1: u64,
}

impl Command {
    fn stream_id(&self) -> u32 {
        (self.word0 >> 32) as u32
    }
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("event queue is not enabled")]
    EventQueueDisabled,
    #[error("event queue is full")]
    EventQueueFull,
    #[error("invalid queue base register {0:#x}")]
    InvalidQueueBase(u64),
    #[error("guest memory access failed")]
    GuestMemory(#[source] GuestMemoryError),
}

/// SMMUv3 event record
#[derive(Clone, Copy, Debug)]
pub struct EventRecord(pub [u64; 4]);

const _: () = assert!(size_of::<EventRecord>() as u64 == EVENTQ_ENTRY_SIZE);

#[derive(Clone, Copy, Debug)]
struct SteConfig {
    config: u8,
    words: [u64; STE_WORDS],
}

/// Layout describing a CMDQ or EVENTQ
struct QueueLayout {
    base: u64,
    log2size: u32,
}

impl QueueLayout {
    fn new(base: u64) -> Option<Self> {
        let log2size = (base & Q_BASE_LOG2SIZE_MASK) as u32;
        if log2size > Q_MAX_LOG2SIZE {
            return None;
        }

        Some(QueueLayout {
            base: base & Q_BASE_ADDR_MASK,
            log2size,
        })
    }

    fn entries(&self) -> u32 {
        1 << self.log2size
    }

    fn entry_address(&self, pointer: u32, entry_size: u64) -> u64 {
        let index = u64::from(pointer & (self.entries() - 1));
        self.base + index * entry_size
    }

    fn wrapped_index(&self, pointer: u32) -> u32 {
        pointer & ((1 << (self.log2size + 1)) - 1)
    }

    fn next_pointer(&self, pointer: u32) -> u32 {
        let entries = self.entries();
        let index = pointer & (entries - 1);
        let wrap = pointer & entries;
        let status = pointer & !((entries << 1) - 1);

        if index + 1 == entries {
            status | (wrap ^ entries)
        } else {
            status | wrap | (index + 1)
        }
    }

    fn is_empty(&self, producer: u32, consumer: u32) -> bool {
        self.wrapped_index(producer) == self.wrapped_index(consumer)
    }

    fn is_full(&self, producer: u32, consumer: u32) -> bool {
        self.wrapped_index(self.next_pointer(producer)) == self.wrapped_index(consumer)
    }
}

pub struct Smmuv3Interrupts {
    pub event: Arc<dyn InterruptSourceGroup>,
    pub gerror: Arc<dyn InterruptSourceGroup>,
    pub sync: Arc<dyn InterruptSourceGroup>,
}

/// Information about the host SMMUv3
pub struct Smmuv3HostInfo {
    pub idr: [u32; 6],
    pub ats_supported: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Smmuv3State {
    idr0: u32,
    idr1: u32,
    idr5: u32,
    cr0: u32,
    cr0ack: u32,
    cr1: u32,
    cr2: u32,
    gbpa: u32,
    irq_ctrl: u32,
    irq_ctrlack: u32,
    gerror: u32,
    gerrorn: u32,
    strtab_base: u64,
    strtab_base_cfg: u32,
    cmdq_base: u64,
    cmdq_prod: u32,
    cmdq_cons: u32,
    eventq_base: u64,
    eventq_prod: u32,
    eventq_cons: u32,
    gerror_irq_cfg0: u64,
    eventq_irq_cfg0: u64,
}

/// ARM SMMUv3 device
pub struct Smmuv3 {
    id: String,

    idr0: u32,
    idr1: u32,
    idr5: u32,

    cr0: u32,
    cr0ack: u32,
    cr1: u32,
    cr2: u32,
    gbpa: u32,
    irq_ctrl: u32,
    irq_ctrlack: u32,
    gerror: u32,
    gerrorn: u32,

    strtab_base: u64,
    strtab_base_cfg: u32,

    cmdq_base: u64,
    cmdq_prod: u32,
    cmdq_cons: u32,

    eventq_base: u64,
    eventq_prod: u32,
    eventq_cons: u32,

    gerror_irq_cfg0: u64,
    eventq_irq_cfg0: u64,

    mem: GuestMemoryMmapAtomic,
    interrupts: Smmuv3Interrupts,
    backend: Arc<dyn HwIommuBackend>,
}

impl Smmuv3 {
    pub fn new(
        id: String,
        mem: GuestMemoryMmapAtomic,
        interrupts: Smmuv3Interrupts,
        backend: Arc<dyn HwIommuBackend>,
        state: Option<Smmuv3State>,
    ) -> Self {
        let state = state.unwrap_or(Smmuv3State {
            idr0: IDR0_VALUE,
            idr1: IDR1_VALUE,
            idr5: IDR5_VALUE,
            ..Default::default()
        });

        Smmuv3 {
            id,
            idr0: state.idr0,
            idr1: state.idr1,
            idr5: state.idr5,
            cr0: state.cr0,
            cr0ack: state.cr0ack,
            cr1: state.cr1,
            cr2: state.cr2,
            gbpa: state.gbpa,
            irq_ctrl: state.irq_ctrl,
            irq_ctrlack: state.irq_ctrlack,
            gerror: state.gerror,
            gerrorn: state.gerrorn,
            strtab_base: state.strtab_base,
            strtab_base_cfg: state.strtab_base_cfg,
            cmdq_base: state.cmdq_base,
            cmdq_prod: state.cmdq_prod,
            cmdq_cons: state.cmdq_cons,
            eventq_base: state.eventq_base,
            eventq_prod: state.eventq_prod,
            eventq_cons: state.eventq_cons,
            gerror_irq_cfg0: state.gerror_irq_cfg0,
            eventq_irq_cfg0: state.eventq_irq_cfg0,
            mem,
            interrupts,
            backend,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    fn state(&self) -> Smmuv3State {
        Smmuv3State {
            idr0: self.idr0,
            idr1: self.idr1,
            idr5: self.idr5,
            cr0: self.cr0,
            cr0ack: self.cr0ack,
            cr1: self.cr1,
            cr2: self.cr2,
            gbpa: self.gbpa,
            irq_ctrl: self.irq_ctrl,
            irq_ctrlack: self.irq_ctrlack,
            gerror: self.gerror,
            gerrorn: self.gerrorn,
            strtab_base: self.strtab_base,
            strtab_base_cfg: self.strtab_base_cfg,
            cmdq_base: self.cmdq_base,
            cmdq_prod: self.cmdq_prod,
            cmdq_cons: self.cmdq_cons,
            eventq_base: self.eventq_base,
            eventq_prod: self.eventq_prod,
            eventq_cons: self.eventq_cons,
            gerror_irq_cfg0: self.gerror_irq_cfg0,
            eventq_irq_cfg0: self.eventq_irq_cfg0,
        }
    }

    /// Refine ID registers exposed to the guest based on host information
    pub fn set_host_id_regs(&mut self, host_info: &Smmuv3HostInfo) {
        let (h0, h1, h5) = (host_info.idr[0], host_info.idr[1], host_info.idr[5]);

        self.idr0 = IDR0_VALUE & (h0 | !IDR0_HOST_GATED);
        if host_info.ats_supported {
            self.idr0 |= IDR0_ATS;
        }

        self.idr1 = (IDR1_VALUE & !IDR1_SSIDSIZE_MASK) | (h1 & IDR1_SSIDSIZE_MASK);

        let oas = (IDR5_VALUE & IDR5_OAS_MASK).min(h5 & IDR5_OAS_MASK);
        let mut granules = IDR5_VALUE & h5 & IDR5_GRAN_MASK;
        if granules == 0 {
            granules = IDR5_VALUE & IDR5_GRAN_MASK;
        }
        self.idr5 = (IDR5_VALUE & !(IDR5_OAS_MASK | IDR5_GRAN_MASK)) | oas | granules;
    }

    fn read_reg(&self, offset: u64) -> u64 {
        match offset {
            IDR0 => self.idr0 as u64,
            IDR1 => self.idr1 as u64,
            IDR2 | IDR3 | IDR4 => 0,
            IDR5 => self.idr5 as u64,
            IIDR => 0,
            AIDR => 0,
            CR0 => self.cr0 as u64,
            CR0ACK => self.cr0ack as u64,
            CR1 => self.cr1 as u64,
            CR2 => self.cr2 as u64,
            STATUSR => 0,
            GBPA => self.gbpa as u64,
            IRQ_CTRL => self.irq_ctrl as u64,
            IRQ_CTRLACK => self.irq_ctrlack as u64,
            GERROR => self.gerror as u64,
            GERRORN => self.gerrorn as u64,
            GERROR_IRQ_CFG0 => self.gerror_irq_cfg0,
            GERROR_IRQ_CFG0_HI => self.gerror_irq_cfg0 >> 32,
            STRTAB_BASE => self.strtab_base,
            STRTAB_BASE_HI => self.strtab_base >> 32,
            STRTAB_BASE_CFG => self.strtab_base_cfg as u64,
            CMDQ_BASE => self.cmdq_base,
            CMDQ_BASE_HI => self.cmdq_base >> 32,
            CMDQ_PROD => self.cmdq_prod as u64,
            CMDQ_CONS => self.cmdq_cons as u64,
            EVENTQ_BASE => self.eventq_base,
            EVENTQ_BASE_HI => self.eventq_base >> 32,
            EVENTQ_IRQ_CFG0 => self.eventq_irq_cfg0,
            EVENTQ_IRQ_CFG0_HI => self.eventq_irq_cfg0 >> 32,
            EVENTQ_PROD => self.eventq_prod as u64,
            EVENTQ_CONS => self.eventq_cons as u64,
            _ => {
                warn!("SMMUv3 read at unknown offset {offset:#x}");
                0
            }
        }
    }

    fn write_reg(&mut self, offset: u64, val: u64, len: usize) {
        fn merge_low(cur: u64, val: u64, len: usize) -> u64 {
            if len == 8 {
                return val;
            }
            (cur & 0xffff_ffff_0000_0000) | (val & 0xffff_ffff)
        }

        fn merge_high(cur: u64, val: u64, len: usize) -> u64 {
            if len == 8 {
                return val;
            }
            (cur & 0x0000_0000_ffff_ffff) | (val << 32)
        }

        match offset {
            CR0 => {
                self.cr0 = val as u32;
                self.cr0ack = self.cr0;
            }
            CR1 => self.cr1 = val as u32,
            CR2 => self.cr2 = val as u32,
            GBPA => self.gbpa = (val as u32) & !GBPA_UPDATE,
            IRQ_CTRL => {
                self.irq_ctrl = val as u32;
                self.irq_ctrlack = self.irq_ctrl;
            }
            GERRORN => self.gerrorn = val as u32,
            GERROR_IRQ_CFG0 => {
                self.gerror_irq_cfg0 = merge_low(self.gerror_irq_cfg0, val, len);
            }
            GERROR_IRQ_CFG0_HI => {
                self.gerror_irq_cfg0 = merge_high(self.gerror_irq_cfg0, val, len);
            }
            GERROR_IRQ_CFG1 | GERROR_IRQ_CFG2 => {}
            STRTAB_BASE => self.strtab_base = merge_low(self.strtab_base, val, len),
            STRTAB_BASE_HI => self.strtab_base = merge_high(self.strtab_base, val, len),
            STRTAB_BASE_CFG => self.strtab_base_cfg = val as u32,
            CMDQ_BASE => self.cmdq_base = merge_low(self.cmdq_base, val, len),
            CMDQ_BASE_HI => self.cmdq_base = merge_high(self.cmdq_base, val, len),
            CMDQ_PROD => {
                self.cmdq_prod = val as u32;
                self.consume_cmdq();
            }
            CMDQ_CONS => self.cmdq_cons = val as u32,
            EVENTQ_BASE => self.eventq_base = merge_low(self.eventq_base, val, len),
            EVENTQ_BASE_HI => self.eventq_base = merge_high(self.eventq_base, val, len),
            EVENTQ_IRQ_CFG0 => {
                self.eventq_irq_cfg0 = merge_low(self.eventq_irq_cfg0, val, len);
            }
            EVENTQ_IRQ_CFG0_HI => {
                self.eventq_irq_cfg0 = merge_high(self.eventq_irq_cfg0, val, len);
            }
            EVENTQ_IRQ_CFG1 | EVENTQ_IRQ_CFG2 => {}
            EVENTQ_PROD => self.eventq_prod = val as u32,
            EVENTQ_CONS => self.eventq_cons = val as u32,
            _ => warn!("SMMUv3 write at unknown offset {offset:#x}"),
        }
    }

    fn consume_cmdq(&mut self) {
        if self.cr0 & CR0_CMDQEN == 0 {
            return;
        }

        let Some(queue) = QueueLayout::new(self.cmdq_base) else {
            warn!("SMMUv3 invalid CMDQ_BASE {:#x}", self.cmdq_base);
            return;
        };

        let mem = self.mem.clone();
        let guard = mem.memory();

        let read_command = |addr: u64| -> Result<Command, Error> {
            let word0 = guard
                .read_obj::<u64>(GuestAddress(addr))
                .map_err(Error::GuestMemory)?;
            let word1 = guard
                .read_obj::<u64>(GuestAddress(addr + 8))
                .map_err(Error::GuestMemory)?;

            Ok(Command {
                opcode: (word0 & CMD_OPCODE_MASK) as u8,
                word0,
                word1,
            })
        };

        for _ in 0..queue.entries() {
            if queue.is_empty(self.cmdq_prod, self.cmdq_cons) {
                break;
            }

            let addr = queue.entry_address(self.cmdq_cons, CMDQ_ENTRY_SIZE);
            let cmd = match read_command(addr) {
                Ok(cmd) => cmd,
                Err(e) => {
                    warn!("SMMUv3 failed to read CMDQ entry at {addr:#x}: {e}");
                    self.set_cmdq_error(CERROR_ABT);
                    break;
                }
            };

            self.dispatch_command(&cmd);
            self.cmdq_cons = queue.next_pointer(self.cmdq_cons);
        }
    }

    fn fetch_ste(&self, sid: u32) -> Result<Option<SteConfig>, Error> {
        let Some(ste_addr) = self.ste_address(sid)? else {
            return Ok(None);
        };

        let mem = self.mem.clone();
        let guard = mem.memory();

        let mut words = [0u64; STE_WORDS];
        for (i, word) in words.iter_mut().enumerate() {
            *word = guard
                .read_obj::<u64>(GuestAddress(ste_addr + (i as u64) * 8))
                .map_err(Error::GuestMemory)?;
        }

        if words[0] & STE_V == 0 {
            return Ok(None);
        }

        let config = ((words[0] >> STE_CONFIG_SHIFT) & STE_CONFIG_MASK) as u8;
        Ok(Some(SteConfig { config, words }))
    }

    fn ste_address(&self, sid: u32) -> Result<Option<u64>, Error> {
        let cfg = self.strtab_base_cfg;
        let base = self.strtab_base & STRTAB_BASE_ADDR_MASK;

        let log2size = cfg & STRTAB_CFG_LOG2SIZE_MASK;
        if u64::from(sid) >= (1u64 << log2size) {
            return Ok(None);
        }

        let fmt = (cfg >> STRTAB_CFG_FMT_SHIFT) & STRTAB_CFG_FMT_MASK;
        if fmt != STRTAB_FMT_2LEVEL {
            return Ok(Some(base + u64::from(sid) * STE_SIZE));
        }

        let split = (cfg >> STRTAB_CFG_SPLIT_SHIFT) & STRTAB_CFG_SPLIT_MASK;
        if !matches!(split, 6 | 8 | 10) {
            warn!("SMMUv3 invalid stream table SPLIT {split}");
            return Ok(None);
        }

        let l1_index = u64::from(sid >> split);
        let l2_index = u64::from(sid & ((1 << split) - 1));

        let mem = self.mem.clone();
        let l1_desc = mem
            .memory()
            .read_obj::<u64>(GuestAddress(base + l1_index * L1STD_SIZE))
            .map_err(Error::GuestMemory)?;

        let span = (l1_desc & L1STD_SPAN_MASK) as u32;
        if span == 0 {
            return Ok(None);
        }

        let l2_entries = 1u64 << (span - 1);
        if l2_index >= l2_entries {
            return Ok(None);
        }

        Ok(Some((l1_desc & L1STD_L2PTR_MASK) + l2_index * STE_SIZE))
    }

    fn handle_cfgi_ste(&mut self, sid: u32) {
        let ste = match self.fetch_ste(sid) {
            Ok(ste) => ste,
            Err(e) => {
                warn!("SMMUv3 failed to fetch STE for SID {sid:#x}: {e}");
                self.set_cmdq_error(CERROR_ABT);
                return;
            }
        };

        let result = match ste {
            Some(SteConfig {
                config: STE_CONFIG_BYPASS,
                ..
            }) => self.backend.set_passthrough(sid),
            Some(SteConfig {
                config: STE_CONFIG_S1_ONLY | STE_CONFIG_S2_ONLY | STE_CONFIG_NESTED,
                words,
            }) => self
                .backend
                .install_table_entry(sid, TableEntry::Smmuv3Ste(words)),
            _ => self.backend.set_blocking(sid),
        };

        if let Err(e) = result {
            warn!("SMMUv3 backend error handling CFGI_STE for SID {sid:#x}: {e}");
            self.set_cmdq_error(CERROR_ABT);
        }
    }

    fn dispatch_command(&mut self, cmd: &Command) {
        let result = match cmd.opcode {
            CMD_CFGI_STE => {
                self.handle_cfgi_ste(cmd.stream_id());
                Ok(())
            }
            CMD_CFGI_STE_RANGE => {
                debug!(
                    "SMMUv3 CFGI_STE_RANGE (SID {:#x}): no cached STE state",
                    cmd.stream_id()
                );
                Ok(())
            }
            CMD_CFGI_CD | CMD_CFGI_CD_ALL | CMD_TLBI_NH_ALL | CMD_TLBI_NH_ASID | CMD_TLBI_NH_VA
            | CMD_TLBI_NH_VAA | CMD_TLBI_NSNH_ALL | CMD_ATC_INV => self
                .backend
                .invalidate(Invalidation::Smmuv3Cmd([cmd.word0, cmd.word1])),
            CMD_SYNC => {
                self.complete_sync(cmd);
                Ok(())
            }
            other => {
                debug!("SMMUv3 ignoring command opcode {other:#x}");
                Ok(())
            }
        };

        if let Err(e) = result {
            warn!("SMMUv3 backend error for opcode {:#x}: {e}", cmd.opcode);
            self.set_cmdq_error(CERROR_ABT);
        }
    }

    fn complete_sync(&mut self, cmd: &Command) {
        if cmd.word0 & CMD_SYNC_CS_MASK != CMD_SYNC_CS_IRQ {
            return;
        }

        let msi_addr = cmd.word1 & CMD_SYNC_MSIADDR_MASK;
        if msi_addr == 0 {
            if let Err(e) = self.interrupts.sync.trigger(0) {
                warn!("SMMUv3 failed to raise CMD_SYNC interrupt: {e}");
            }
            return;
        }

        let msi_data = (cmd.word0 >> 32) as u32;
        let mem = self.mem.clone();
        if let Err(e) = mem
            .memory()
            .write_obj::<u32>(msi_data, GuestAddress(msi_addr))
        {
            warn!("SMMUv3 failed to write CMD_SYNC MSI at {msi_addr:#x}: {e}");
            self.raise_gerror(GERROR_MSI_CMDQ_ABT_ERR);
        }
    }

    fn set_cmdq_error(&mut self, cerror: u32) {
        self.cmdq_cons = (self.cmdq_cons & !CMDQ_CONS_ERR_MASK) | (cerror << CMDQ_CONS_ERR_SHIFT);
        self.raise_gerror(GERROR_CMDQ_ERR);
    }

    fn raise_gerror(&mut self, mask: u32) {
        if (self.gerror ^ self.gerrorn) & mask != 0 {
            return;
        }
        self.gerror ^= mask;

        if self.irq_ctrl & IRQ_CTRL_GERROR_IRQEN == 0 {
            return;
        }
        if let Err(e) = self.interrupts.gerror.trigger(0) {
            warn!("SMMUv3 failed to raise GERROR interrupt: {e}");
        }
    }

    /// Set overflow on the EVENTQ
    pub fn set_event_overflow(&mut self) {
        self.eventq_prod |= EVENTQ_PROD_OVFLG;
    }

    /// Push an event to the EVENTQ
    pub fn push_event(&mut self, record: &EventRecord) -> Result<(), Error> {
        if self.cr0 & CR0_SMMUEN == 0 || self.cr0 & CR0_EVENTQEN == 0 {
            return Err(Error::EventQueueDisabled);
        }

        let Some(queue) = QueueLayout::new(self.eventq_base) else {
            return Err(Error::InvalidQueueBase(self.eventq_base));
        };

        if queue.is_full(self.eventq_prod, self.eventq_cons) {
            self.eventq_prod |= EVENTQ_PROD_OVFLG;
            return Err(Error::EventQueueFull);
        }

        let addr = queue.entry_address(self.eventq_prod, EVENTQ_ENTRY_SIZE);

        let mem = self.mem.clone();
        let guard = mem.memory();
        for (i, word) in record.0.iter().enumerate() {
            if let Err(e) = guard.write_obj::<u64>(*word, GuestAddress(addr + (i as u64) * 8)) {
                self.raise_gerror(GERROR_EVENTQ_ABT_ERR);
                return Err(Error::GuestMemory(e));
            }
        }

        self.eventq_prod = queue.next_pointer(self.eventq_prod);

        if self.irq_ctrl & IRQ_CTRL_EVENTQ_IRQEN != 0
            && let Err(e) = self.interrupts.event.trigger(0)
        {
            warn!("SMMUv3 failed to raise event interrupt: {e}");
        }

        Ok(())
    }
}

impl BusDevice for Smmuv3 {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let val = self.read_reg(offset);
        match data.len() {
            8 => write_le_u64(data, val),
            4 => write_le_u32(data, val as u32),
            _ => warn!("SMMUv3 unsupported read width {}", data.len()),
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let val = match data.len() {
            8 => read_le_u64(data),
            4 => read_le_u32(data) as u64,
            _ => {
                warn!("SMMUv3 unsupported write width {}", data.len());
                return None;
            }
        };
        self.write_reg(offset, val, data.len());
        None
    }
}

impl Pausable for Smmuv3 {}

impl Snapshottable for Smmuv3 {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for Smmuv3 {}
impl Migratable for Smmuv3 {}

#[cfg(test)]
mod tests {
    use std::io;

    use vm_device::interrupt::{InterruptIndex, InterruptSourceConfig};
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::iommu::Error as IommuError;

    struct NoopInterrupts;

    impl InterruptSourceGroup for NoopInterrupts {
        fn trigger(&self, _index: InterruptIndex) -> io::Result<()> {
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

    struct NoopBackend;

    impl HwIommuBackend for NoopBackend {
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
    }

    fn test_smmuv3() -> Smmuv3 {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1_0000)]).unwrap(),
        );
        let group = || Arc::new(NoopInterrupts) as Arc<dyn InterruptSourceGroup>;

        Smmuv3::new(
            "smmuv3".to_string(),
            mem,
            Smmuv3Interrupts {
                event: group(),
                gerror: group(),
                sync: group(),
            },
            Arc::new(NoopBackend),
            None,
        )
    }

    fn test_queue() -> QueueLayout {
        QueueLayout::new(2).unwrap()
    }

    #[test]
    fn test_queue_next_pointer_wraps() {
        let queue = test_queue();

        assert_eq!(queue.next_pointer(0b000), 0b001);
        assert_eq!(queue.next_pointer(0b011), 0b100); // last index => index 0, wrap set
        assert_eq!(queue.next_pointer(0b111), 0b000); // last index => index 0, wrap cleared
    }

    #[test]
    fn test_queue_next_pointer_preserves_other_bits() {
        let queue = test_queue();

        assert_eq!(
            queue.next_pointer(EVENTQ_PROD_OVFLG),
            EVENTQ_PROD_OVFLG | 0b001
        );
        assert_eq!(
            queue.next_pointer(EVENTQ_PROD_OVFLG | 0b011),
            EVENTQ_PROD_OVFLG | 0b100
        );
        assert_eq!(
            queue.next_pointer(EVENTQ_PROD_OVFLG | 0b111),
            EVENTQ_PROD_OVFLG
        );

        let err = CERROR_ABT << CMDQ_CONS_ERR_SHIFT;
        assert_eq!(queue.next_pointer(err), err | 0b001);
    }

    #[test]
    fn test_queue_empty_and_full() {
        let queue = test_queue();

        assert!(queue.is_empty(0b000, 0b000));
        assert!(!queue.is_full(0b000, 0b000));

        assert!(!queue.is_empty(0b100, 0b000));

        assert!(queue.is_full(0b011, 0b100));
        assert!(!queue.is_empty(0b011, 0b100));
    }

    #[test]
    fn test_queue_rejects_oversized() {
        assert!(QueueLayout::new(u64::from(Q_MAX_LOG2SIZE)).is_some());
        assert!(QueueLayout::new(u64::from(Q_MAX_LOG2SIZE) + 1).is_none());
    }

    #[test]
    fn test_set_host_id_regs_ats_and_ssidsize() {
        let mut host = Smmuv3HostInfo {
            idr: [0u32; 6],
            ats_supported: true,
        };
        host.idr[0] = IDR0_COHACC | IDR0_ASID16 | IDR0_VMID16 | IDR0_CD2L | IDR0_STLEVEL_2LVL;
        host.idr[1] = 20 << IDR1_SSIDSIZE_SHIFT;
        host.idr[5] = IDR5_OAS_48BIT | IDR5_GRAN4K | IDR5_GRAN64K;

        let mut smmuv3 = test_smmuv3();
        smmuv3.set_host_id_regs(&host);
        assert_ne!(
            smmuv3.idr0 & IDR0_ATS,
            0,
            "ATS must be advertised when supported"
        );
        assert_eq!(smmuv3.idr1 & IDR1_SSIDSIZE_MASK, 20 << IDR1_SSIDSIZE_SHIFT);
        assert_eq!(smmuv3.idr1 & IDR1_CMDQS, IDR1_CMDQS);
        assert_eq!(smmuv3.idr1 & IDR1_EVENTQS, IDR1_EVENTQS);
        assert_eq!(smmuv3.idr1 & 0x3f, IDR1_SIDSIZE);

        host.ats_supported = false;
        smmuv3.set_host_id_regs(&host);
        assert_eq!(smmuv3.idr0 & IDR0_ATS, 0);

        host.idr[1] = 0;
        smmuv3.set_host_id_regs(&host);
        assert_eq!(smmuv3.idr1 & IDR1_SSIDSIZE_MASK, 0);
    }

    #[test]
    fn test_set_host_id_regs_drops_features_the_host_lacks() {
        let host = Smmuv3HostInfo {
            idr: [0u32; 6],
            ats_supported: false,
        };

        let mut smmuv3 = test_smmuv3();
        smmuv3.set_host_id_regs(&host);
        assert_eq!(smmuv3.idr0 & IDR0_HOST_GATED, 0);
        assert_eq!(smmuv3.idr0, IDR0_VALUE & !IDR0_HOST_GATED);
    }

    #[test]
    fn test_new_advertises_conservative_defaults() {
        let smmuv3 = test_smmuv3();
        assert_eq!(smmuv3.idr0, IDR0_VALUE);
        assert_eq!(smmuv3.idr1, IDR1_VALUE);
        assert_eq!(smmuv3.idr5, IDR5_VALUE);
    }

    #[test]
    fn test_default_id_regs_omit_ats_and_ssidsize() {
        assert_eq!(IDR0_VALUE & IDR0_ATS, 0);
        assert_eq!(IDR1_VALUE & IDR1_SSIDSIZE_MASK, 0);
    }

    #[test]
    fn test_partial_writes_merge_into_64bit_registers() {
        let mut smmuv3 = test_smmuv3();

        smmuv3.write_reg(CMDQ_BASE, 0xdead_beef, 4);
        assert_eq!(smmuv3.read_reg(CMDQ_BASE), 0x0000_0000_dead_beef);
        smmuv3.write_reg(CMDQ_BASE_HI, 0xcafe, 4);
        assert_eq!(smmuv3.read_reg(CMDQ_BASE), 0x0000_cafe_dead_beef);
        assert_eq!(smmuv3.read_reg(CMDQ_BASE_HI), 0xcafe);

        smmuv3.write_reg(CMDQ_BASE, 0xffff_0000_1111, 8);
        assert_eq!(smmuv3.read_reg(CMDQ_BASE), 0xffff_0000_1111);
    }
}
