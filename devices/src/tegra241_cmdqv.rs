// Copyright (c) 2026 Crusoe Energy Systems LLC
//
// SPDX-License-Identifier: Apache-2.0
//
// NVIDIA Tegra241 CMDQV, following QEMU's hw/arm/tegra241-cmdqv.c.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;
use std::sync::{Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};

use acpi_tables::{Aml, AmlSink, aml};
use anyhow::anyhow;
use iommufd_ioctls::{
    IommuFd, IommufdError, IommufdHwQueue, IommufdVEventData, IommufdVEventQ, IommufdVIommu,
    IommufdViommuData,
};
use log::{debug, error, info, trace, warn};
use pci::mmap::MmapRegion;
use thiserror::Error;
use vm_allocator::page_size::get_page_size;
use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::{read_le_u32, read_le_u64, write_le_u32, write_le_u64};

/// MMIO span the device decodes.
pub const MMIO_SIZE: u64 = 0x50000;
/// Offsets of the VCMDQ and VI_VCMDQ page0s, where the host VINTF page0 may be mapped.
pub const VCMDQ_PAGE0_OFFSET: u64 = offset::VCMDQ_PAGE0_BASE;
pub const VI_VCMDQ_PAGE0_OFFSET: u64 = offset::VI_VCMDQ_PAGE0_BASE;

/// The guest is given two VCMDQs, as in QEMU.
const NUM_VCMDQ_LOG2: u32 = 1;
const NUM_VCMDQ: usize = 1 << NUM_VCMDQ_LOG2;

/// MMIO register offsets.
mod offset {
    pub(super) const CONFIG: u64 = 0x0000;
    pub(super) const PARAM: u64 = 0x0004;
    pub(super) const STATUS: u64 = 0x0008;

    pub(super) const VI_ERR_MAP: u64 = 0x0014;
    pub(super) const VI_ERR_MAP_1: u64 = 0x0018;

    pub(super) const VI_INT_MASK: u64 = 0x001c;
    pub(super) const VI_INT_MASK_1: u64 = 0x0020;

    pub(super) const CMDQ_ERR_MAP: u64 = 0x0024;
    pub(super) const CMDQ_ERR_MAP_3: u64 = 0x0030;

    pub(super) const CMDQ_ALLOC_MAP_0: u64 = 0x0200;
    pub(super) const CMDQ_ALLOC_MAP_127: u64 = 0x0200 + 127 * 4; // 0x03fc

    pub(super) const VINTF0_CONFIG: u64 = 0x1000;
    pub(super) const VINTF0_STATUS: u64 = 0x1004;
    pub(super) const VINTF0_LVCMDQ_ERR_MAP_0: u64 = 0x10c0;
    pub(super) const VINTF0_LVCMDQ_ERR_MAP_3: u64 = 0x10c0 + 3 * 4; // 0x10cc

    pub(super) const VCMDQ_PAGE0_BASE: u64 = 0x10000;
    pub(super) const VCMDQ_PAGE1_BASE: u64 = 0x20000;
    // The VI_VCMDQ pages alias the VCMDQ pages, 0x20000 above them.
    pub(super) const VI_VCMDQ_PAGE0_BASE: u64 = 0x30000;
    pub(super) const VCMDQ_STRIDE: u64 = 0x80;
    pub(super) const FOLD: u64 = 0x20000;

    // Within a page0 stride.
    pub(super) const VCMDQ_CONS_INDX: u64 = 0x00;
    pub(super) const VCMDQ_PROD_INDX: u64 = 0x04;
    pub(super) const VCMDQ_CONFIG: u64 = 0x08;
    pub(super) const VCMDQ_STATUS: u64 = 0x0c;
    pub(super) const VCMDQ_GERROR: u64 = 0x10;
    pub(super) const VCMDQ_GERRORN: u64 = 0x14;

    // Within a page1 stride.
    pub(super) const VCMDQ_BASE_L: u64 = 0x00;
    pub(super) const VCMDQ_BASE_H: u64 = 0x04;
    pub(super) const VCMDQ_CONS_INDX_BASE_DRAM_L: u64 = 0x08;
    pub(super) const VCMDQ_CONS_INDX_BASE_DRAM_H: u64 = 0x0c;
}

// QEMU's reset values: CMDQV enabled; 2 VCMDQs, 1 VINTF, 16 SIDs.
const CONFIG_RESET: u32 = 0x0002_0083;
const PARAM_RESET: u32 = 0x0000_4011;
const _: () = assert!((PARAM_RESET >> 4) & 0xf == NUM_VCMDQ_LOG2);
const STATUS_RESET: u32 = 0x1;

const CONFIG_CMDQV_EN_MASK: u32 = 1 << 0;
const STATUS_CMDQV_ENABLED_MASK: u32 = 1 << 0;
const VI_ERR_MAP_VINTF0: u32 = 1 << 0;
const VINTF_ENABLE_MASK: u32 = 1 << 0;
const VINTF_HYP_OWN_MASK: u32 = 1 << 17;
const VINTF_STATUS_ENABLE_OK_MASK: u32 = 1 << 0;
const VCMDQ_CONFIG_CMDQ_EN_MASK: u32 = 1 << 0;
const VCMDQ_STATUS_CMDQ_EN_OK_MASK: u32 = 1 << 0;
const CMDQ_ALLOC_MAP_ALLOC_MASK: u32 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reg {
    Config,
    Param,
    Status,
    ViErrMap(usize),
    ViIntMask(usize),
    CmdqErrMap(usize),
    CmdqAllocMap(usize),
    Vintf0Config,
    Vintf0Status,
    Vintf0LvcmdqErrMap(usize),
    VcmdqPage0 { index: usize, reg: u64 },
    VcmdqPage1 { index: usize, reg: u64 },
}

fn decode(raw_offset: u64) -> Option<Reg> {
    let offset = if (offset::VI_VCMDQ_PAGE0_BASE..MMIO_SIZE).contains(&raw_offset) {
        raw_offset - offset::FOLD
    } else {
        raw_offset
    };

    match offset {
        offset::CONFIG => Some(Reg::Config),
        offset::PARAM => Some(Reg::Param),
        offset::STATUS => Some(Reg::Status),
        offset::VI_ERR_MAP..=offset::VI_ERR_MAP_1 => {
            Some(Reg::ViErrMap(((offset - offset::VI_ERR_MAP) / 4) as usize))
        }
        offset::VI_INT_MASK..=offset::VI_INT_MASK_1 => Some(Reg::ViIntMask(
            ((offset - offset::VI_INT_MASK) / 4) as usize,
        )),
        offset::CMDQ_ERR_MAP..=offset::CMDQ_ERR_MAP_3 => Some(Reg::CmdqErrMap(
            ((offset - offset::CMDQ_ERR_MAP) / 4) as usize,
        )),
        offset::CMDQ_ALLOC_MAP_0..=offset::CMDQ_ALLOC_MAP_127 => {
            let index = ((offset - offset::CMDQ_ALLOC_MAP_0) / 4) as usize;
            (index < NUM_VCMDQ).then_some(Reg::CmdqAllocMap(index))
        }
        offset::VINTF0_CONFIG => Some(Reg::Vintf0Config),
        offset::VINTF0_STATUS => Some(Reg::Vintf0Status),
        offset::VINTF0_LVCMDQ_ERR_MAP_0..=offset::VINTF0_LVCMDQ_ERR_MAP_3 => Some(
            Reg::Vintf0LvcmdqErrMap(((offset - offset::VINTF0_LVCMDQ_ERR_MAP_0) / 4) as usize),
        ),
        _ if (offset::VCMDQ_PAGE0_BASE..offset::VCMDQ_PAGE1_BASE).contains(&offset) => {
            let rel = offset - offset::VCMDQ_PAGE0_BASE;
            let index = (rel / offset::VCMDQ_STRIDE) as usize;
            (index < NUM_VCMDQ).then_some(Reg::VcmdqPage0 {
                index,
                reg: rel % offset::VCMDQ_STRIDE,
            })
        }
        _ if (offset::VCMDQ_PAGE1_BASE..offset::VI_VCMDQ_PAGE0_BASE).contains(&offset) => {
            let rel = offset - offset::VCMDQ_PAGE1_BASE;
            let index = (rel / offset::VCMDQ_STRIDE) as usize;
            (index < NUM_VCMDQ).then_some(Reg::VcmdqPage1 {
                index,
                reg: rel % offset::VCMDQ_STRIDE,
            })
        }
        _ => None,
    }
}

/// The host VINTF page0, whose registers are little-endian. Trapped page0
/// accesses reach it when memslots cannot map it into the guest.
struct VintfPage {
    mapping: MmapRegion,
}

impl VintfPage {
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the mapping is page-aligned and the offset a multiple of 4, as asserted"
    )]
    fn read_u32(&self, byte_offset: usize) -> u32 {
        assert!(byte_offset.is_multiple_of(4) && byte_offset + 4 <= self.mapping.len());
        // SAFETY: in bounds of the mapping, checked above.
        let value =
            unsafe { ptr::read_volatile(self.mapping.addr().add(byte_offset).cast::<u32>()) };
        u32::from_le(value)
    }

    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the mapping is page-aligned and the offset a multiple of 4, as asserted"
    )]
    fn write_u32(&self, byte_offset: usize, value: u32) {
        assert!(byte_offset.is_multiple_of(4) && byte_offset + 4 <= self.mapping.len());
        // SAFETY: see `read_u32`.
        unsafe {
            ptr::write_volatile(
                self.mapping.addr().add(byte_offset).cast::<u32>(),
                value.to_le(),
            );
        }
    }
}

/// A hardware queue and the BASE it was allocated from.
struct HwQueue {
    base: u64,
    _queue: IommufdHwQueue,
}

pub struct Tegra241Cmdqv {
    name: String,
    instance_id: u32,
    irq: u32,
    /// The host VINTF page0, once the vIOMMU provides it.
    vintf_page: Option<VintfPage>,
    irq_group: Option<Arc<dyn InterruptSourceGroup>>,

    config: u32,
    param: u32,
    status: u32,
    vi_err_map: [u32; 2],
    vi_int_mask: [u32; 2],
    cmdq_err_map: [u32; 4],
    cmdq_alloc_map: [u32; NUM_VCMDQ],
    vintf_config: u32,
    vintf_status: u32,
    vintf_lvcmdq_err_map: [u32; 4],
    vcmdq_cons_indx: [u32; NUM_VCMDQ],
    vcmdq_prod_indx: [u32; NUM_VCMDQ],
    vcmdq_config: [u32; NUM_VCMDQ],
    vcmdq_status: [u32; NUM_VCMDQ],
    vcmdq_gerror: [u32; NUM_VCMDQ],
    vcmdq_gerrorn: [u32; NUM_VCMDQ],
    vcmdq_base: [u64; NUM_VCMDQ],
    vcmdq_cons_indx_base: [u64; NUM_VCMDQ],

    viommu: Option<Arc<IommufdVIommu>>,
    vcmdq: [Option<HwQueue>; NUM_VCMDQ],
    /// Largest VCMDQ, in bytes: VCMDQs must be physically contiguous.
    max_vcmdq_size: u64,
}

impl Tegra241Cmdqv {
    pub fn new(name: String, instance_id: u32, irq: u32) -> Self {
        Tegra241Cmdqv {
            name,
            instance_id,
            irq,
            vintf_page: None,
            irq_group: None,
            config: CONFIG_RESET,
            param: PARAM_RESET,
            status: STATUS_RESET,
            vi_err_map: [0; 2],
            vi_int_mask: [0; 2],
            cmdq_err_map: [0; 4],
            cmdq_alloc_map: [0; NUM_VCMDQ],
            vintf_config: 0,
            vintf_status: 0,
            vintf_lvcmdq_err_map: [0; 4],
            vcmdq_cons_indx: [0; NUM_VCMDQ],
            vcmdq_prod_indx: [0; NUM_VCMDQ],
            vcmdq_config: [0; NUM_VCMDQ],
            vcmdq_status: [0; NUM_VCMDQ],
            vcmdq_gerror: [0; NUM_VCMDQ],
            vcmdq_gerrorn: [0; NUM_VCMDQ],
            vcmdq_base: [0; NUM_VCMDQ],
            vcmdq_cons_indx_base: [0; NUM_VCMDQ],
            viommu: None,
            vcmdq: [const { None }; NUM_VCMDQ],
            max_vcmdq_size: get_page_size(),
        }
    }

    pub fn instance_id(&self) -> u32 {
        self.instance_id
    }

    pub fn irq(&self) -> u32 {
        self.irq
    }

    /// Reflects host-reported VCMDQ errors, as QEMU does.
    fn report_vcmdq_errors(&mut self, lvcmdq_err_map: [u64; 2]) {
        if lvcmdq_err_map == [0, 0] {
            return;
        }
        let words = [
            lvcmdq_err_map[0] as u32,
            (lvcmdq_err_map[0] >> 32) as u32,
            lvcmdq_err_map[1] as u32,
            (lvcmdq_err_map[1] >> 32) as u32,
        ];
        self.vintf_lvcmdq_err_map = words;
        self.cmdq_err_map = words;
        self.vi_err_map[0] |= VI_ERR_MAP_VINTF0;
        warn!(
            "Tegra241 CMDQV {}: host reported VCMDQ errors {:#x}_{:#x}",
            self.name, lvcmdq_err_map[1], lvcmdq_err_map[0]
        );
        if self.vi_int_mask[0] & VI_ERR_MAP_VINTF0 != 0 {
            return;
        }
        if let Some(irq_group) = &self.irq_group
            && let Err(e) = irq_group.trigger(0)
        {
            error!(
                "Tegra241 CMDQV {}: failed to raise the error interrupt: {e}",
                self.name
            );
        }
    }

    /// Each queue depends on the one below it, so destroy from the top.
    fn destroy_hw_queues(&mut self) {
        for index in (0..self.vcmdq.len()).rev() {
            self.vcmdq[index] = None;
        }
    }

    /// Whether VCMDQ `index` is ready for a hardware queue, as in QEMU.
    fn vcmdq_ready(&self, index: usize) -> bool {
        self.vcmdq_base[index] != 0
            && self.cmdq_alloc_map[index] & CMDQ_ALLOC_MAP_ALLOC_MASK != 0
            && self.config & CONFIG_CMDQV_EN_MASK != 0
            && self.vintf_config & VINTF_ENABLE_MASK != 0
    }

    /// Whether VCMDQ `index` and all below it are ready: queues map in order.
    fn vcmdq_wanted(&self, index: usize) -> bool {
        (0..=index).all(|i| self.vcmdq_ready(i))
    }

    /// The lowest VCMDQ whose hardware queue must change.
    fn first_vcmdq_to_update(&self) -> Option<usize> {
        (0..NUM_VCMDQ).find(|&index| match &self.vcmdq[index] {
            Some(queue) => !self.vcmdq_wanted(index) || queue.base != self.vcmdq_base[index],
            None => self.vcmdq_wanted(index),
        })
    }

    /// Each queue depends on the one below it: release from the top, then
    /// allocate from the bottom.
    fn update_vcmdqs(&mut self) {
        let Some(first) = self.first_vcmdq_to_update() else {
            return;
        };
        for index in (first..NUM_VCMDQ).rev() {
            if self.vcmdq[index].take().is_some() {
                debug!("Tegra241 CMDQV {}: released VCMDQ{index}", self.name);
            }
        }
        for index in first..NUM_VCMDQ {
            if !self.vcmdq_wanted(index) {
                break;
            }
            self.setup_vcmdq(index);
            if self.vcmdq[index].is_none() {
                break;
            }
        }
    }

    /// Allocates a hardware queue for VCMDQ `index` from its BASE.
    fn setup_vcmdq(&mut self, index: usize) {
        const BASE_ADDR_MASK: u64 = 0x0000_ffff_ffff_ffe0;
        const BASE_LOG2SIZE_MASK: u64 = 0x1f;
        let base = self.vcmdq_base[index];
        let addr = base & BASE_ADDR_MASK;
        let size = 1u64 << ((base & BASE_LOG2SIZE_MASK) + 4);

        let Some(viommu) = self.viommu.clone() else {
            debug!(
                "Tegra241 CMDQV {}: VCMDQ{index} (addr={addr:#x}, size={size:#x}) ready, \
                 no vIOMMU attached",
                self.name
            );
            return;
        };

        if size > self.max_vcmdq_size {
            warn!(
                "Tegra241 CMDQV {}: VCMDQ{index} size {size:#x} exceeds {:#x}; not allocating",
                self.name, self.max_vcmdq_size
            );
            return;
        }

        match viommu.allocate_hw_queue(index as u32, addr, size) {
            Ok(hw_queue) => {
                info!(
                    "Tegra241 CMDQV {}: allocated VCMDQ{index} (addr={addr:#x}, size={size:#x})",
                    self.name
                );
                self.vcmdq[index] = Some(HwQueue {
                    base,
                    _queue: hw_queue,
                });
            }
            Err(e) => warn!(
                "Tegra241 CMDQV {}: failed to allocate VCMDQ{index} \
                 (addr={addr:#x}, size={size:#x}): {e:?}",
                self.name
            ),
        }
    }

    fn vintf_page_offset(index: usize, reg: u64) -> usize {
        (index as u64 * offset::VCMDQ_STRIDE + reg) as usize
    }

    fn read_vcmdq_page0(&mut self, index: usize, reg: u64) -> u64 {
        let cached = match reg {
            offset::VCMDQ_CONS_INDX => &mut self.vcmdq_cons_indx[index],
            offset::VCMDQ_PROD_INDX => &mut self.vcmdq_prod_indx[index],
            offset::VCMDQ_CONFIG => &mut self.vcmdq_config[index],
            offset::VCMDQ_STATUS => &mut self.vcmdq_status[index],
            offset::VCMDQ_GERROR => &mut self.vcmdq_gerror[index],
            offset::VCMDQ_GERRORN => &mut self.vcmdq_gerrorn[index],
            _ => {
                trace!(
                    "Tegra241 CMDQV {}: read from unknown VCMDQ{index} page0 register {reg:#x}",
                    self.name
                );
                return 0;
            }
        };
        // With the VINTF page mapped, the hardware is the source of truth.
        if let Some(page) = &self.vintf_page {
            *cached = page.read_u32(Self::vintf_page_offset(index, reg));
        }
        *cached as u64
    }

    fn mirror_vcmdq_page0_write(&self, index: usize, reg: u64, value: u32) {
        if let Some(page) = &self.vintf_page {
            page.write_u32(Self::vintf_page_offset(index, reg), value);
        }
    }

    fn write_vcmdq_page0(&mut self, index: usize, reg: u64, data: &[u8]) {
        let value = read_le_u32(data);
        match reg {
            offset::VCMDQ_CONS_INDX => {
                self.mirror_vcmdq_page0_write(index, reg, value);
                self.vcmdq_cons_indx[index] = value;
            }
            offset::VCMDQ_PROD_INDX => {
                self.mirror_vcmdq_page0_write(index, reg, value);
                self.vcmdq_prod_indx[index] = value;
            }
            offset::VCMDQ_CONFIG => {
                if self.vintf_page.is_some() {
                    // The hardware derives STATUS itself.
                    self.mirror_vcmdq_page0_write(index, reg, value);
                } else if value & VCMDQ_CONFIG_CMDQ_EN_MASK != 0 {
                    self.vcmdq_status[index] |= VCMDQ_STATUS_CMDQ_EN_OK_MASK;
                } else {
                    self.vcmdq_status[index] &= !VCMDQ_STATUS_CMDQ_EN_OK_MASK;
                }
                self.vcmdq_config[index] = value;
            }
            offset::VCMDQ_GERRORN => {
                self.mirror_vcmdq_page0_write(index, reg, value);
                self.vcmdq_gerrorn[index] = value;
            }
            // GERROR and STATUS are read-only.
            _ => trace!(
                "Tegra241 CMDQV {}: write to unknown or read-only VCMDQ{index} page0 register {reg:#x}",
                self.name
            ),
        }
    }

    fn read_vcmdq_page1(&self, index: usize, reg: u64) -> u64 {
        match reg {
            offset::VCMDQ_BASE_L => self.vcmdq_base[index],
            offset::VCMDQ_BASE_H => self.vcmdq_base[index] >> 32,
            offset::VCMDQ_CONS_INDX_BASE_DRAM_L => self.vcmdq_cons_indx_base[index],
            offset::VCMDQ_CONS_INDX_BASE_DRAM_H => self.vcmdq_cons_indx_base[index] >> 32,
            _ => {
                trace!(
                    "Tegra241 CMDQV {}: read from unknown VCMDQ{index} page1 register {reg:#x}",
                    self.name
                );
                0
            }
        }
    }

    fn write_vcmdq_page1(&mut self, index: usize, reg: u64, data: &[u8]) {
        // A 64-bit write to a low half sets the whole register at once.
        match reg {
            offset::VCMDQ_BASE_L => {
                if data.len() == 8 {
                    self.vcmdq_base[index] = read_le_u64(data);
                } else {
                    self.vcmdq_base[index] =
                        (self.vcmdq_base[index] & 0xffff_ffff_0000_0000) | read_le_u32(data) as u64;
                }
                self.update_vcmdqs();
            }
            offset::VCMDQ_BASE_H => {
                self.vcmdq_base[index] = (self.vcmdq_base[index] & 0x0000_0000_ffff_ffff)
                    | ((read_le_u32(data) as u64) << 32);
                self.update_vcmdqs();
            }
            offset::VCMDQ_CONS_INDX_BASE_DRAM_L => {
                if data.len() == 8 {
                    self.vcmdq_cons_indx_base[index] = read_le_u64(data);
                } else {
                    self.vcmdq_cons_indx_base[index] = (self.vcmdq_cons_indx_base[index]
                        & 0xffff_ffff_0000_0000)
                        | read_le_u32(data) as u64;
                }
            }
            offset::VCMDQ_CONS_INDX_BASE_DRAM_H => {
                self.vcmdq_cons_indx_base[index] = (self.vcmdq_cons_indx_base[index]
                    & 0x0000_0000_ffff_ffff)
                    | ((read_le_u32(data) as u64) << 32);
            }
            _ => trace!(
                "Tegra241 CMDQV {}: write to unknown VCMDQ{index} page1 register {reg:#x}",
                self.name
            ),
        }
    }

    fn read_value(&mut self, offset: u64) -> u64 {
        match decode(offset) {
            Some(Reg::Config) => self.config as u64,
            Some(Reg::Param) => self.param as u64,
            Some(Reg::Status) => self.status as u64,
            Some(Reg::ViErrMap(i)) => self.vi_err_map[i] as u64,
            Some(Reg::ViIntMask(i)) => self.vi_int_mask[i] as u64,
            Some(Reg::CmdqErrMap(i)) => self.cmdq_err_map[i] as u64,
            Some(Reg::CmdqAllocMap(i)) => self.cmdq_alloc_map[i] as u64,
            Some(Reg::Vintf0Config) => self.vintf_config as u64,
            Some(Reg::Vintf0Status) => self.vintf_status as u64,
            Some(Reg::Vintf0LvcmdqErrMap(i)) => self.vintf_lvcmdq_err_map[i] as u64,
            Some(Reg::VcmdqPage0 { index, reg }) => self.read_vcmdq_page0(index, reg),
            Some(Reg::VcmdqPage1 { index, reg }) => self.read_vcmdq_page1(index, reg),
            None => {
                self.log_unhandled(offset, "read");
                0
            }
        }
    }

    fn write_value(&mut self, offset: u64, data: &[u8]) {
        match decode(offset) {
            Some(Reg::Config) => {
                let value = read_le_u32(data);
                self.config = value;
                if value & CONFIG_CMDQV_EN_MASK != 0 {
                    self.status |= STATUS_CMDQV_ENABLED_MASK;
                } else {
                    self.status &= !STATUS_CMDQV_ENABLED_MASK;
                }
                self.update_vcmdqs();
            }
            Some(Reg::Param | Reg::Status | Reg::ViErrMap(_) | Reg::CmdqErrMap(_)) => {
                self.log_unhandled(offset, "write");
            }
            Some(Reg::ViIntMask(i)) => self.vi_int_mask[i] = read_le_u32(data),
            Some(Reg::CmdqAllocMap(i)) => {
                self.cmdq_alloc_map[i] = read_le_u32(data);
                self.update_vcmdqs();
            }
            Some(Reg::Vintf0Config) => {
                // The VMM owns the VINTF, never the guest.
                let value = read_le_u32(data) & !VINTF_HYP_OWN_MASK;
                self.vintf_config = value;
                if value & VINTF_ENABLE_MASK != 0 {
                    self.vintf_status |= VINTF_STATUS_ENABLE_OK_MASK;
                } else {
                    self.vintf_status &= !VINTF_STATUS_ENABLE_OK_MASK;
                }
                self.update_vcmdqs();
            }
            Some(Reg::Vintf0Status | Reg::Vintf0LvcmdqErrMap(_)) => {
                self.log_unhandled(offset, "write");
            }
            Some(Reg::VcmdqPage0 { index, reg }) => self.write_vcmdq_page0(index, reg, data),
            Some(Reg::VcmdqPage1 { index, reg }) => self.write_vcmdq_page1(index, reg, data),
            None => self.log_unhandled(offset, "write"),
        }
    }

    fn log_unhandled(&self, offset: u64, access: &str) {
        if offset >= MMIO_SIZE {
            warn!(
                "Tegra241 CMDQV {}: {access} offset {offset:#x} exceeds the {:#x} span",
                self.name, MMIO_SIZE
            );
        } else {
            trace!(
                "Tegra241 CMDQV {}: unhandled {access} access at offset {offset:#x}",
                self.name
            );
        }
    }
}

impl BusDevice for Tegra241Cmdqv {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match data.len() {
            8 => write_le_u64(data, self.read_value(offset)),
            4 => write_le_u32(data, self.read_value(offset) as u32),
            _ => warn!(
                "Tegra241 CMDQV {}: unsupported read size {} at offset {offset:#x}",
                self.name,
                data.len()
            ),
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match data.len() {
            4 | 8 => self.write_value(offset, data),
            _ => warn!(
                "Tegra241 CMDQV {}: unsupported write size {} at offset {offset:#x}",
                self.name,
                data.len()
            ),
        }
        None
    }
}

/// Forwards the CMDQV vEVENTQ, which reports VCMDQ errors, to the device.
pub struct EventForwarder {
    kill: EventFd,
    handle: Option<JoinHandle<()>>,
}

impl EventForwarder {
    pub fn new(mut veventq: IommufdVEventQ, device: Arc<Mutex<Tegra241Cmdqv>>) -> io::Result<Self> {
        let kill = EventFd::new(EFD_NONBLOCK)?;
        let kill_reader = kill.try_clone()?;
        let handle = thread::Builder::new()
            .name("cmdqv_veventq".to_string())
            .spawn(move || Self::run(&mut veventq, &device, &kill_reader))?;
        Ok(EventForwarder {
            kill,
            handle: Some(handle),
        })
    }

    fn run(veventq: &mut IommufdVEventQ, device: &Mutex<Tegra241Cmdqv>, kill: &EventFd) {
        const VEVENTQ_TOKEN: u64 = 0;
        const KILL_TOKEN: u64 = 1;

        let epoll = match Epoll::new() {
            Ok(epoll) => epoll,
            Err(e) => {
                error!("Tegra241 CMDQV vEVENTQ reader failed to create epoll: {e}");
                return;
            }
        };
        for (fd, token) in [
            (veventq.as_raw_fd(), VEVENTQ_TOKEN),
            (kill.as_raw_fd(), KILL_TOKEN),
        ] {
            if let Err(e) = epoll.ctl(
                ControlOperation::Add,
                fd,
                EpollEvent::new(EventSet::IN, token),
            ) {
                error!("Tegra241 CMDQV vEVENTQ reader failed to register fd {fd}: {e}");
                return;
            }
        }

        let mut events = [EpollEvent::default(); 2];
        loop {
            let count = match epoll.wait(-1, &mut events) {
                Ok(count) => count,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("Tegra241 CMDQV vEVENTQ reader epoll wait failed: {e}");
                    return;
                }
            };
            for event in events.iter().take(count) {
                match event.data() {
                    KILL_TOKEN => return,
                    VEVENTQ_TOKEN => match veventq.read_events() {
                        Ok(records) => {
                            let mut device = device.lock().unwrap();
                            for record in records {
                                if record.lost > 0 {
                                    warn!(
                                        "Tegra241 CMDQV {}: vEVENTQ lost {} events",
                                        device.name, record.lost
                                    );
                                }
                                match record.data {
                                    Some(IommufdVEventData::Tegra241Cmdqv(evt)) => {
                                        device.report_vcmdq_errors(evt.lvcmdq_err_map);
                                    }
                                    Some(_) => warn!(
                                        "Tegra241 CMDQV {}: unexpected vEVENTQ record",
                                        device.name
                                    ),
                                    None => {}
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => warn!("Tegra241 CMDQV vEVENTQ read failed: {e}"),
                    },
                    _ => unreachable!(),
                }
            }
        }
    }
}

impl Drop for EventForwarder {
    fn drop(&mut self) {
        if let Err(e) = self.kill.write(1) {
            error!("Tegra241 CMDQV failed to signal vEVENTQ reader shutdown: {e}");
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The Tegra241 CMDQV of the host SMMU behind a device.
#[derive(Debug)]
pub enum HostCmdqv {
    Compatible,
    Incompatible,
    Absent,
}

/// Queries the host SMMU's Tegra241 CMDQV for iommufd device `dev_id`.
pub fn probe_host_cmdqv(iommufd: &IommuFd, dev_id: u32) -> Result<HostCmdqv, IommufdError> {
    use iommufd_bindings::{
        iommu_hw_info, iommu_hw_info__bindgen_ty_1, iommu_hw_info_tegra241_cmdqv,
        iommu_hw_info_type_IOMMU_HW_INFO_TYPE_TEGRA241_CMDQV,
        iommufd_hw_info_flags_IOMMU_HW_INFO_FLAG_INPUT_TYPE,
    };

    let mut data = iommu_hw_info_tegra241_cmdqv::default();
    let mut hw_info = iommu_hw_info {
        size: size_of::<iommu_hw_info>() as u32,
        flags: iommufd_hw_info_flags_IOMMU_HW_INFO_FLAG_INPUT_TYPE,
        dev_id,
        data_len: size_of::<iommu_hw_info_tegra241_cmdqv>() as u32,
        data_uptr: &mut data as *mut iommu_hw_info_tegra241_cmdqv as u64,
        __bindgen_anon_1: iommu_hw_info__bindgen_ty_1 {
            in_data_type: iommu_hw_info_type_IOMMU_HW_INFO_TYPE_TEGRA241_CMDQV,
        },
        ..Default::default()
    };
    match iommufd.get_hw_info(&mut hw_info) {
        Ok(()) => {}
        // The SMMU has no CMDQV.
        Err(IommufdError::IommuGetHwInfo(e)) if e.errno() == libc::EOPNOTSUPP => {
            return Ok(HostCmdqv::Absent);
        }
        Err(e) => return Err(e),
    }
    // SAFETY: the union holds one __u32 under either name.
    let out_data_type = unsafe { hw_info.__bindgen_anon_1.out_data_type };
    Ok(
        if out_data_type != iommu_hw_info_type_IOMMU_HW_INFO_TYPE_TEGRA241_CMDQV {
            HostCmdqv::Absent
        } else if data.version != 1 || data.log2vcmdqs < 1 || data.log2vsids < 4 {
            // The guest is given 2 VCMDQs and 16 SIDs.
            HostCmdqv::Incompatible
        } else {
            HostCmdqv::Compatible
        },
    )
}

/// The host VINTF page0 the VCMDQ page0s map to.
pub const VINTF_PAGE_SIZE: u64 = 0x1_0000;
const VEVENTQ_DEPTH: u32 = 64;

#[derive(Debug, Error)]
pub enum Error {
    #[error("The vIOMMU reports no VINTF page0 mapping")]
    VintfPageMissing,
    #[error("Host VINTF page0 size {0:#x} is not 64 KiB")]
    VintfPageSize(u64),
    #[error("Failed to mmap the host VINTF page0")]
    MmapVintfPage(#[source] io::Error),
    #[error("Failed to allocate the vEVENTQ")]
    AllocateVeventq(#[source] IommufdError),
    #[error("Failed to start the vEVENTQ reader")]
    StartEventForwarder(#[source] io::Error),
}

/// A Tegra241 CMDQV backed by an iommufd vIOMMU; see `release`.
pub struct Tegra241CmdqvIommufd {
    device: Arc<Mutex<Tegra241Cmdqv>>,
    events: Option<EventForwarder>,
    /// (slot, guest address) of the memslots mapping the VINTF page.
    memslots: Vec<(u32, u64)>,
}

impl Tegra241CmdqvIommufd {
    pub fn new(
        id: String,
        instance_id: u32,
        irq: u32,
        interrupt: Arc<dyn InterruptSourceGroup>,
        viommu: Arc<IommufdVIommu>,
        max_vcmdq_size: u64,
    ) -> Result<Self, Error> {
        let IommufdViommuData::Tegra241Cmdqv {
            mmap_offset,
            mmap_length,
        } = viommu.data()
        else {
            return Err(Error::VintfPageMissing);
        };
        if mmap_length != VINTF_PAGE_SIZE {
            return Err(Error::VintfPageSize(mmap_length));
        }
        // SAFETY: the vIOMMU keeps the iommufd open.
        let fd = unsafe { BorrowedFd::borrow_raw(viommu.iommufd().as_raw_fd()) };
        let mapping = MmapRegion::mmap(
            VINTF_PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            fd,
            mmap_offset,
            0,
        )
        .map_err(Error::MmapVintfPage)?;
        let veventq = viommu
            .allocate_cmdqv_veventq(VEVENTQ_DEPTH)
            .map_err(Error::AllocateVeventq)?;

        let mut device = Tegra241Cmdqv::new(id, instance_id, irq);
        device.max_vcmdq_size = max_vcmdq_size;
        device.vintf_page = Some(VintfPage { mapping });
        device.viommu = Some(viommu);
        device.irq_group = Some(interrupt);
        let device = Arc::new(Mutex::new(device));
        let events = EventForwarder::new(veventq, Arc::clone(&device))
            .map_err(Error::StartEventForwarder)?;

        Ok(Self {
            device,
            events: Some(events),
            memslots: Vec::new(),
        })
    }

    pub fn device(&self) -> &Arc<Mutex<Tegra241Cmdqv>> {
        &self.device
    }

    /// The VINTF page's host address, valid until `release`.
    pub fn vintf_page_addr(&self) -> *mut u8 {
        let device = self.device.lock().unwrap();
        let page = device.vintf_page.as_ref().expect("CMDQV already released");
        page.mapping.addr()
    }

    /// Records the memslots mapping the VINTF page, for `release`.
    pub fn set_memslots(&mut self, memslots: Vec<(u32, u64)>) {
        self.memslots = memslots;
    }

    /// Stops the vEVENTQ reader, removes the memslots, then frees the queues,
    /// page and vIOMMU. The MMIO bus keeps the device, so Drop is too late.
    pub fn release(&mut self, mut remove_memslot: impl FnMut(u32, u64, *mut u8)) {
        self.events = None;
        let mut device = self.device.lock().unwrap();
        if let Some(addr) = device.vintf_page.as_ref().map(|page| page.mapping.addr()) {
            for (slot, guest_addr) in mem::take(&mut self.memslots) {
                remove_memslot(slot, guest_addr, addr);
            }
        }
        device.destroy_hw_queues();
        // The mapping holds a reference on the vIOMMU, so it goes first.
        device.vintf_page = None;
        device.viommu = None;
    }
}

impl Drop for Tegra241Cmdqv {
    fn drop(&mut self) {
        self.destroy_hw_queues();
    }
}

/// The DSDT description of a Tegra241 CMDQV.
pub struct Tegra241CmdqvAcpiDevice {
    pub instance_id: u32,
    /// The SMMUv3's IORT node identifier, which Linux pairs the CMDQV with.
    pub uid: u32,
    pub base: u64,
    pub len: u64,
    pub irq: u32,
}

impl Aml for Tegra241CmdqvAcpiDevice {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        aml::Device::new(
            format!("_SB_.CV{:02X}", self.instance_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"NVDA200C"),
                &aml::Name::new("_UID".into(), &self.uid),
                &aml::Name::new("_CCA".into(), &aml::ONE),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::AddressSpace::new_memory(
                            aml::AddressSpaceCacheable::Cacheable,
                            true,
                            self.base,
                            self.base + self.len - 1,
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

impl Snapshottable for Tegra241Cmdqv {
    fn id(&self) -> String {
        self.name.clone()
    }

    /// The queues live in the host kernel.
    fn snapshot(&mut self) -> Result<Snapshot, MigratableError> {
        Err(MigratableError::Snapshot(anyhow!(
            "Tegra241 CMDQV ({}) does not support snapshot, restore or live migration",
            self.name
        )))
    }
}
impl Pausable for Tegra241Cmdqv {}
impl Transportable for Tegra241Cmdqv {}
impl Migratable for Tegra241Cmdqv {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use vm_device::interrupt::{InterruptIndex, InterruptSourceConfig};

    use super::*;

    /// # Safety
    ///
    /// `base + byte_offset` must be a valid, 4-byte aligned address.
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the page is page-aligned and the offset a multiple of 4"
    )]
    unsafe fn poke_u32(base: *mut u8, byte_offset: usize, value: u32) {
        assert!(byte_offset.is_multiple_of(4));
        // SAFETY: the caller's contract.
        unsafe { ptr::write_volatile(base.add(byte_offset).cast::<u32>(), value) }
    }

    fn dev() -> Tegra241Cmdqv {
        Tegra241Cmdqv::new("vcmdqv_0".to_string(), 0, 100)
    }

    /// A memfd standing in for the VINTF page.
    fn test_vintf_mapping(len: u64) -> MmapRegion {
        use std::ffi::CString;
        use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

        // SAFETY: FFI call with a valid name.
        let raw_fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                CString::new("cmdqv-test-vintf").unwrap().as_ptr(),
                0,
            )
        };
        assert!(raw_fd >= 0, "memfd_create failed");
        // SAFETY: a new fd we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
        // SAFETY: FFI call with a valid, owned fd.
        let ret = unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) };
        assert_eq!(ret, 0, "ftruncate failed");
        MmapRegion::mmap(len, libc::PROT_READ | libc::PROT_WRITE, fd.as_fd(), 0, 0).unwrap()
    }

    #[test]
    fn test_resets() {
        let d = dev();
        assert_eq!(d.config, CONFIG_RESET);
        assert_eq!(d.config, 0x0002_0083);
        assert_eq!(d.param, PARAM_RESET);
        assert_eq!(d.param, 0x0000_4011);
        assert_eq!(d.status, STATUS_RESET);
        assert_eq!(
            d.status & STATUS_CMDQV_ENABLED_MASK,
            STATUS_CMDQV_ENABLED_MASK
        );
    }

    #[test]
    fn test_decode_scalar_registers() {
        assert_eq!(decode(0x0000), Some(Reg::Config));
        assert_eq!(decode(0x0004), Some(Reg::Param));
        assert_eq!(decode(0x0008), Some(Reg::Status));
        assert_eq!(decode(0x1000), Some(Reg::Vintf0Config));
        assert_eq!(decode(0x1004), Some(Reg::Vintf0Status));
    }

    #[test]
    fn test_decode_array_registers() {
        assert_eq!(decode(0x0014), Some(Reg::ViErrMap(0)));
        assert_eq!(decode(0x0018), Some(Reg::ViErrMap(1)));
        assert_eq!(decode(0x001c), Some(Reg::ViIntMask(0)));
        assert_eq!(decode(0x0020), Some(Reg::ViIntMask(1)));
        assert_eq!(decode(0x0024), Some(Reg::CmdqErrMap(0)));
        assert_eq!(decode(0x0030), Some(Reg::CmdqErrMap(3)));
        assert_eq!(decode(0x0200), Some(Reg::CmdqAllocMap(0)));
        assert_eq!(decode(0x0204), Some(Reg::CmdqAllocMap(1)));
        assert_eq!(decode(0x0208), None);
        assert_eq!(decode(0x03fc), None);
        assert_eq!(decode(0x10c0), Some(Reg::Vintf0LvcmdqErrMap(0)));
        assert_eq!(decode(0x10cc), Some(Reg::Vintf0LvcmdqErrMap(3)));
    }

    #[test]
    fn test_decode_vcmdq_pages() {
        // Index 0.
        assert_eq!(
            decode(0x10000),
            Some(Reg::VcmdqPage0 {
                index: 0,
                reg: offset::VCMDQ_CONS_INDX
            })
        );
        assert_eq!(
            decode(0x10014),
            Some(Reg::VcmdqPage0 {
                index: 0,
                reg: offset::VCMDQ_GERRORN
            })
        );
        assert_eq!(
            decode(0x20000),
            Some(Reg::VcmdqPage1 {
                index: 0,
                reg: offset::VCMDQ_BASE_L
            })
        );

        // Index 1: one 0x80 stride in.
        assert_eq!(
            decode(0x10080),
            Some(Reg::VcmdqPage0 {
                index: 1,
                reg: offset::VCMDQ_CONS_INDX
            })
        );
        assert_eq!(
            decode(0x20084),
            Some(Reg::VcmdqPage1 {
                index: 1,
                reg: offset::VCMDQ_BASE_H
            })
        );

        // The guest has no VCMDQ beyond index 1.
        assert_eq!(decode(0x10000 + 2 * 0x80), None);
        assert_eq!(decode(0x20000 + 2 * 0x80), None);
        assert_eq!(decode(0x30000 + 2 * 0x80), None);
    }

    #[test]
    fn test_decode_vi_vcmdq_fold() {
        assert_eq!(decode(0x30000), decode(0x10000));
        assert_eq!(decode(0x30014), decode(0x10014));
        assert_eq!(decode(0x40000), decode(0x20000));
        assert_eq!(decode(0x40084), decode(0x20084));
        assert_eq!(
            decode(0x30080),
            Some(Reg::VcmdqPage0 {
                index: 1,
                reg: offset::VCMDQ_CONS_INDX
            })
        );
    }

    #[test]
    fn test_decode_gaps_and_out_of_range() {
        // Gaps between defined registers.
        assert_eq!(decode(0x000c), None);
        assert_eq!(decode(0x0034), None);
        assert_eq!(decode(0x0400), None);
        // At and beyond the 0x50000 span limit.
        assert_eq!(decode(0x50000), None);
        assert_eq!(decode(0x50004), None);
        assert_eq!(decode(0xffff_ffff), None);
    }

    #[test]
    fn test_config_write_mirrors_status() {
        let mut d = dev();

        // Disable CMDQV_EN: STATUS.CMDQV_ENABLED must clear.
        d.write(0, offset::CONFIG, &0u32.to_le_bytes());
        assert_eq!(d.config, 0);
        assert_eq!(d.status & STATUS_CMDQV_ENABLED_MASK, 0);

        // Re-enable: STATUS.CMDQV_ENABLED must set again.
        d.write(0, offset::CONFIG, &CONFIG_CMDQV_EN_MASK.to_le_bytes());
        assert_eq!(
            d.status & STATUS_CMDQV_ENABLED_MASK,
            STATUS_CMDQV_ENABLED_MASK
        );
    }

    #[test]
    fn test_vintf_config_strips_hyp_own() {
        let mut d = dev();

        // The guest sets ENABLE and (incorrectly) HYP_OWN.
        let value = VINTF_ENABLE_MASK | VINTF_HYP_OWN_MASK;
        d.write(0, offset::VINTF0_CONFIG, &value.to_le_bytes());

        // HYP_OWN must never stick; ENABLE must, and STATUS.ENABLE_OK
        // mirrors it.
        assert_eq!(d.vintf_config, VINTF_ENABLE_MASK);
        assert_eq!(d.vintf_config & VINTF_HYP_OWN_MASK, 0);
        assert_eq!(
            d.vintf_status & VINTF_STATUS_ENABLE_OK_MASK,
            VINTF_STATUS_ENABLE_OK_MASK
        );

        // Disabling clears STATUS.ENABLE_OK.
        d.write(0, offset::VINTF0_CONFIG, &0u32.to_le_bytes());
        assert_eq!(d.vintf_status & VINTF_STATUS_ENABLE_OK_MASK, 0);
    }

    #[test]
    fn test_base_composition_4_byte_writes() {
        let mut d = dev();
        let base_l_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_L;
        let base_h_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_H;

        let base_l: u32 = (0x1234_5678 << 5) | 0xf;
        let base_h: u32 = 0xbeef;

        d.write(0, base_l_off, &base_l.to_le_bytes());
        d.write(0, base_h_off, &base_h.to_le_bytes());

        let expected = ((base_h as u64) << 32) | base_l as u64;
        assert_eq!(d.vcmdq_base[0], expected);

        // Reading back BASE_L/BASE_H recomposes the same value.
        let mut low = [0u8; 4];
        d.read(0, base_l_off, &mut low);
        assert_eq!(u32::from_le_bytes(low), base_l);
        let mut high = [0u8; 4];
        d.read(0, base_h_off, &mut high);
        assert_eq!(u32::from_le_bytes(high), base_h);
    }

    #[test]
    fn test_base_composition_8_byte_write_identical_to_4_byte() {
        let mut two_writes = dev();
        let base_l_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_L;
        let base_h_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_H;
        let base_l: u32 = (0x0abc_def0 << 5) | 0x1f;
        let base_h: u32 = 0x0007;
        two_writes.write(0, base_l_off, &base_l.to_le_bytes());
        two_writes.write(0, base_h_off, &base_h.to_le_bytes());

        let mut one_write = dev();
        let full: u64 = ((base_h as u64) << 32) | base_l as u64;
        one_write.write(0, base_l_off, &full.to_le_bytes());

        assert_eq!(one_write.vcmdq_base[0], two_writes.vcmdq_base[0]);
        assert_eq!(one_write.vcmdq_base[0], full);
    }

    #[test]
    fn test_base_l_4_byte_write_preserves_prior_high_half() {
        let mut d = dev();
        let base_l_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_L;
        let base_h_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_H;

        d.write(0, base_h_off, &0xdead_u32.to_le_bytes());
        d.write(0, base_l_off, &0x0000_0001_u32.to_le_bytes());

        assert_eq!(d.vcmdq_base[0], (0xdead_u64 << 32) | 1);
    }

    #[test]
    fn test_cons_indx_base_dram_composition() {
        let mut d = dev();
        let low_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_CONS_INDX_BASE_DRAM_L;
        let high_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_CONS_INDX_BASE_DRAM_H;
        let full: u64 = 0x0000_1234_5678_9000;

        d.write(0, low_off, &full.to_le_bytes());
        assert_eq!(d.vcmdq_cons_indx_base[0], full);

        let mut low = [0u8; 4];
        d.read(0, low_off, &mut low);
        assert_eq!(u32::from_le_bytes(low), full as u32);
        let mut high = [0u8; 4];
        d.read(0, high_off, &mut high);
        assert_eq!(u32::from_le_bytes(high), (full >> 32) as u32);
    }

    #[test]
    fn test_8_byte_write_to_32_bit_register_truncates() {
        let mut d = dev();
        let value: u64 = CONFIG_CMDQV_EN_MASK as u64 | (0xffff_ffffu64 << 32);
        d.write(0, offset::CONFIG, &value.to_le_bytes());
        assert_eq!(d.config, CONFIG_CMDQV_EN_MASK);
        assert_eq!(d.param, PARAM_RESET);
    }

    #[test]
    fn test_vcmdq_page0_config_mirrors_status() {
        let mut d = dev();
        let config_off = offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_CONFIG;
        let status_off = offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_STATUS;

        d.write(0, config_off, &VCMDQ_CONFIG_CMDQ_EN_MASK.to_le_bytes());
        let mut status = [0u8; 4];
        d.read(0, status_off, &mut status);
        assert_eq!(
            u32::from_le_bytes(status) & VCMDQ_STATUS_CMDQ_EN_OK_MASK,
            VCMDQ_STATUS_CMDQ_EN_OK_MASK
        );

        d.write(0, config_off, &0u32.to_le_bytes());
        d.read(0, status_off, &mut status);
        assert_eq!(u32::from_le_bytes(status) & VCMDQ_STATUS_CMDQ_EN_OK_MASK, 0);
    }

    #[test]
    fn test_bad_access_size_ignored() {
        let mut d = dev();
        let mut data = [0u8; 2];
        d.read(0, offset::CONFIG, &mut data);
        d.write(0, offset::CONFIG, &data);
        assert_eq!(d.config, CONFIG_RESET);
    }

    #[test]
    fn test_vintf_page_mirrors_writes() {
        let mut d = dev();
        d.vintf_page = Some(VintfPage {
            mapping: test_vintf_mapping(0x10000),
        });

        let cons_off = offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_CONS_INDX;
        d.write(0, cons_off, &0x1234u32.to_le_bytes());

        assert_eq!(
            d.vintf_page.as_ref().unwrap().read_u32(0),
            0x1234,
            "write must reach the mapped page, not just the register cache"
        );

        let mut data = [0u8; 4];
        d.read(0, cons_off, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0x1234);
    }

    #[test]
    fn test_vintf_page_read_refreshes_cache_from_hardware() {
        let mut d = dev();
        let mapping = test_vintf_mapping(0x10000);
        let base = mapping.addr();
        d.vintf_page = Some(VintfPage { mapping });

        // The hardware advances PROD_INDX behind the VMM's back.
        // SAFETY: within the mapping `d` owns.
        unsafe { poke_u32(base, offset::VCMDQ_PROD_INDX as usize, 0xabcd) };

        let mut data = [0u8; 4];
        d.read(
            0,
            offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_PROD_INDX,
            &mut data,
        );
        assert_eq!(
            u32::from_le_bytes(data),
            0xabcd,
            "a read must refresh the cache from the mapped page"
        );
    }

    #[test]
    fn test_vintf_page_shared_between_native_and_vi_alias() {
        let mut d = dev();
        d.vintf_page = Some(VintfPage {
            mapping: test_vintf_mapping(0x10000),
        });

        let native_off = offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_CONS_INDX;
        let alias_off = offset::VI_VCMDQ_PAGE0_BASE + offset::VCMDQ_CONS_INDX;

        d.write(0, native_off, &0x55aa_u32.to_le_bytes());

        let mut data = [0u8; 4];
        d.read(0, alias_off, &mut data);
        assert_eq!(
            u32::from_le_bytes(data),
            0x55aa,
            "the VI_VCMDQ alias must observe a write through the native VCMDQ page \
             (both fold to the same mapped page)"
        );
    }

    #[test]
    fn test_vintf_page_config_write_skips_local_status_derivation() {
        let mut d = dev();
        d.vintf_page = Some(VintfPage {
            mapping: test_vintf_mapping(0x10000),
        });

        let config_off = offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_CONFIG;
        d.write(0, config_off, &VCMDQ_CONFIG_CMDQ_EN_MASK.to_le_bytes());

        assert_eq!(
            d.vintf_page
                .as_ref()
                .unwrap()
                .read_u32(offset::VCMDQ_CONFIG as usize),
            VCMDQ_CONFIG_CMDQ_EN_MASK
        );

        // STATUS comes from the page, which the memfd leaves 0.
        let mut status = [0u8; 4];
        d.read(
            0,
            offset::VCMDQ_PAGE0_BASE + offset::VCMDQ_STATUS,
            &mut status,
        );
        assert_eq!(u32::from_le_bytes(status), 0);
    }

    #[test]
    fn test_vintf_page_read_of_undefined_reg_skips_device_access() {
        let mut d = dev();
        let mapping = test_vintf_mapping(0x10000);
        let base = mapping.addr();
        d.vintf_page = Some(VintfPage { mapping });

        let undefined_reg = 0x18u64;
        // SAFETY: within the mapping `d` owns.
        unsafe { poke_u32(base, undefined_reg as usize, 0xdead_beef) };

        let mut data = [0u8; 4];
        d.read(0, offset::VCMDQ_PAGE0_BASE + undefined_reg, &mut data);
        assert_eq!(
            u32::from_le_bytes(data),
            0,
            "an undefined VCMDQ page0 register must return the shadow (0), not the \
             live hardware value - proving the read never touched the mapped page"
        );
    }

    #[test]
    fn test_setup_vcmdq_without_viommu_only_latches() {
        let mut d = dev();
        let base_l_off = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_L;

        d.write(0, base_l_off, &0x1000_0000_u64.to_le_bytes());
        assert!(d.vcmdq[0].is_none());
        assert_eq!(d.vcmdq_base[0], 0x1000_0000);
    }

    #[test]
    fn test_vcmdq_is_ready_only_when_allocated_and_enabled() {
        let mut d = dev();
        let write = |d: &mut Tegra241Cmdqv, offset: u64, value: u32| {
            d.write(0, offset, &value.to_le_bytes());
        };
        let base_l = offset::VCMDQ_PAGE1_BASE + offset::VCMDQ_BASE_L;

        write(&mut d, base_l, 0x1000_0000);
        assert!(!d.vcmdq_ready(0), "not allocated to the VINTF");
        write(&mut d, offset::CMDQ_ALLOC_MAP_0, CMDQ_ALLOC_MAP_ALLOC_MASK);
        assert!(!d.vcmdq_ready(0), "VINTF disabled");
        write(&mut d, offset::VINTF0_CONFIG, VINTF_ENABLE_MASK);
        assert!(d.vcmdq_ready(0));
        assert!(!d.vcmdq_ready(1), "VCMDQ1 has no BASE");

        write(&mut d, offset::CONFIG, 0);
        assert!(!d.vcmdq_ready(0), "CMDQV disabled");
        write(&mut d, offset::CONFIG, CONFIG_CMDQV_EN_MASK);
        assert!(d.vcmdq_ready(0));
        write(&mut d, offset::CMDQ_ALLOC_MAP_0, 0);
        assert!(!d.vcmdq_ready(0), "unmapped from the VINTF");
        write(&mut d, offset::CMDQ_ALLOC_MAP_0, CMDQ_ALLOC_MAP_ALLOC_MASK);
        write(&mut d, base_l, 0);
        assert!(!d.vcmdq_ready(0), "BASE cleared");
    }

    #[test]
    fn test_vcmdq_waits_for_the_queues_below_it() {
        let mut d = dev();
        assert_eq!(d.first_vcmdq_to_update(), None);
        d.vintf_config = VINTF_ENABLE_MASK;
        d.vcmdq_base[1] = 0x1000_0000;
        d.cmdq_alloc_map[1] = CMDQ_ALLOC_MAP_ALLOC_MASK;
        assert!(d.vcmdq_ready(1));
        assert!(!d.vcmdq_wanted(1), "the hardware maps VCMDQ1 after VCMDQ0");
        assert_eq!(d.first_vcmdq_to_update(), None);
        d.vcmdq_base[0] = 0x2000_0000;
        d.cmdq_alloc_map[0] = CMDQ_ALLOC_MAP_ALLOC_MASK;
        assert!(d.vcmdq_wanted(1));
        assert_eq!(d.first_vcmdq_to_update(), Some(0));
    }

    #[test]
    fn test_max_vcmdq_size_defaults_to_the_host_page() {
        let mut d = Tegra241Cmdqv::new("cmdqv".to_string(), 0, 0);
        assert_eq!(d.max_vcmdq_size, get_page_size());
        d.max_vcmdq_size = 512 << 20;
        assert_eq!(d.max_vcmdq_size, 512 << 20);
    }

    #[test]
    fn test_drop_destroys_queues_descending() {
        drop(dev());
    }

    struct CountingIrq(AtomicUsize);

    impl InterruptSourceGroup for CountingIrq {
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

    #[test]
    fn test_vcmdq_errors_reach_the_error_maps_and_interrupt() {
        let mut d = dev();
        let irq = Arc::new(CountingIrq(AtomicUsize::new(0)));
        d.irq_group = Some(Arc::clone(&irq) as Arc<dyn InterruptSourceGroup>);
        let triggers = || irq.0.load(Ordering::SeqCst);

        d.report_vcmdq_errors([0, 0]);
        assert_eq!(triggers(), 0);
        assert_eq!(d.read_value(offset::VI_ERR_MAP), 0);

        d.report_vcmdq_errors([(1 << 1) | (1 << 33), 0]);
        assert_eq!(triggers(), 1);
        assert_eq!(d.read_value(offset::VI_ERR_MAP), 1);
        assert_eq!(d.read_value(offset::VINTF0_LVCMDQ_ERR_MAP_0), 1 << 1);
        assert_eq!(d.read_value(offset::VINTF0_LVCMDQ_ERR_MAP_0 + 4), 1 << 1);
        assert_eq!(d.read_value(offset::CMDQ_ERR_MAP), 1 << 1);
        assert_eq!(d.read_value(offset::CMDQ_ERR_MAP + 4), 1 << 1);

        d.write_value(offset::VI_INT_MASK, &1u32.to_le_bytes());
        d.report_vcmdq_errors([0, 1 << 32]);
        assert_eq!(triggers(), 1);
        assert_eq!(d.read_value(offset::VINTF0_LVCMDQ_ERR_MAP_3), 1);
    }

    #[test]
    fn test_snapshot_is_blocked() {
        let mut d = dev();
        assert!(matches!(d.snapshot(), Err(MigratableError::Snapshot(_))));
    }

    #[test]
    fn test_irq() {
        assert_eq!(dev().irq(), 100);
    }

    #[test]
    fn test_tegra241_cmdqv_acpi_device_bytes() {
        let dev = Tegra241CmdqvAcpiDevice {
            instance_id: 127,
            uid: 5,
            base: 0x0c00_0000,
            len: 0x5_0000,
            irq: 200,
        };
        let mut bytes = Vec::new();
        dev.to_aml_bytes(&mut bytes);

        assert!(
            bytes.windows(4).any(|w| w == b"CV7F"),
            "device name CV7F not found"
        );

        assert!(
            bytes.windows(8).any(|w| w == b"NVDA200C"),
            "_HID NVDA200C not found"
        );

        // _UID is a Byte: BYTEPREFIX, 5.
        let uid_name = bytes
            .windows(4)
            .position(|w| w == b"_UID")
            .expect("_UID name not found");
        assert_eq!(
            &bytes[uid_name + 4..uid_name + 6],
            &[0x0a, 0x05],
            "_UID must encode the IORT identifier 5 as a Byte"
        );

        // _CRS: one QWord address space descriptor.
        let qword_desc = 0x8au8;
        assert_eq!(
            bytes.iter().filter(|&&b| b == qword_desc).count(),
            1,
            "expected exactly one QWord address space descriptor"
        );
        let marker = bytes.iter().position(|&b| b == qword_desc).unwrap();
        let read_u64 =
            |off: usize| -> u64 { u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) };
        let field_base = marker + 6;
        assert_eq!(read_u64(field_base), 0, "granularity must be 0");
        assert_eq!(read_u64(field_base + 8), dev.base, "min must be base");
        assert_eq!(
            read_u64(field_base + 16),
            dev.base + dev.len - 1,
            "max must be base + len - 1"
        );
        assert_eq!(read_u64(field_base + 24), 0, "translation must be 0");
        assert_eq!(read_u64(field_base + 32), dev.len, "length must be len");

        // _CRS: one extended IRQ descriptor, edge-triggered consumer.
        let irq_desc = 0x89u8;
        assert_eq!(
            bytes.iter().filter(|&&b| b == irq_desc).count(),
            1,
            "expected exactly one extended IRQ descriptor"
        );
        let marker = bytes.iter().position(|&b| b == irq_desc).unwrap();
        assert_eq!(
            bytes[marker + 3],
            0x03,
            "expected consumer|edge-triggered, not active-low, not shared"
        );
        assert_eq!(bytes[marker + 4], 1, "expected a single interrupt number");
        let irq = u32::from_le_bytes(bytes[marker + 5..marker + 9].try_into().unwrap());
        assert_eq!(irq, dev.irq);
    }
}
