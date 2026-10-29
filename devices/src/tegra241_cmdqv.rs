// Copyright (c) 2026 Crusoe Energy Systems LLC
//
// SPDX-License-Identifier: Apache-2.0
//
// NVIDIA Tegra241 CMDQV, following QEMU's hw/arm/tegra241-cmdqv.c.

use std::sync::{Arc, Barrier};

use acpi_tables::{Aml, AmlSink, aml};
use anyhow::anyhow;
use log::{trace, warn};
use vm_device::BusDevice;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

use crate::{read_le_u32, read_le_u64, write_le_u32, write_le_u64};

/// MMIO span the device decodes.
pub const MMIO_SIZE: u64 = 0x50000;

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
const VINTF_ENABLE_MASK: u32 = 1 << 0;
const VINTF_HYP_OWN_MASK: u32 = 1 << 17;
const VINTF_STATUS_ENABLE_OK_MASK: u32 = 1 << 0;
const VCMDQ_CONFIG_CMDQ_EN_MASK: u32 = 1 << 0;
const VCMDQ_STATUS_CMDQ_EN_OK_MASK: u32 = 1 << 0;

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

pub struct Tegra241Cmdqv {
    name: String,
    instance_id: u32,
    irq: u32,

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
}

impl Tegra241Cmdqv {
    pub fn new(name: String, instance_id: u32, irq: u32) -> Self {
        Tegra241Cmdqv {
            name,
            instance_id,
            irq,
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
        }
    }

    pub fn instance_id(&self) -> u32 {
        self.instance_id
    }

    pub fn irq(&self) -> u32 {
        self.irq
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
        *cached as u64
    }

    fn write_vcmdq_page0(&mut self, index: usize, reg: u64, data: &[u8]) {
        let value = read_le_u32(data);
        match reg {
            offset::VCMDQ_CONS_INDX => {
                self.vcmdq_cons_indx[index] = value;
            }
            offset::VCMDQ_PROD_INDX => {
                self.vcmdq_prod_indx[index] = value;
            }
            offset::VCMDQ_CONFIG => {
                if value & VCMDQ_CONFIG_CMDQ_EN_MASK != 0 {
                    self.vcmdq_status[index] |= VCMDQ_STATUS_CMDQ_EN_OK_MASK;
                } else {
                    self.vcmdq_status[index] &= !VCMDQ_STATUS_CMDQ_EN_OK_MASK;
                }
                self.vcmdq_config[index] = value;
            }
            offset::VCMDQ_GERRORN => {
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
            }
            offset::VCMDQ_BASE_H => {
                self.vcmdq_base[index] = (self.vcmdq_base[index] & 0x0000_0000_ffff_ffff)
                    | ((read_le_u32(data) as u64) << 32);
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
            }
            Some(Reg::Param | Reg::Status | Reg::ViErrMap(_) | Reg::CmdqErrMap(_)) => {
                self.log_unhandled(offset, "write");
            }
            Some(Reg::ViIntMask(i)) => self.vi_int_mask[i] = read_le_u32(data),
            Some(Reg::CmdqAllocMap(i)) => self.cmdq_alloc_map[i] = read_le_u32(data),
            Some(Reg::Vintf0Config) => {
                // The VMM owns the VINTF, never the guest.
                let value = read_le_u32(data) & !VINTF_HYP_OWN_MASK;
                self.vintf_config = value;
                if value & VINTF_ENABLE_MASK != 0 {
                    self.vintf_status |= VINTF_STATUS_ENABLE_OK_MASK;
                } else {
                    self.vintf_status &= !VINTF_STATUS_ENABLE_OK_MASK;
                }
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
    use super::*;

    fn dev() -> Tegra241Cmdqv {
        Tegra241Cmdqv::new("vcmdqv_0".to_string(), 0, 100)
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
