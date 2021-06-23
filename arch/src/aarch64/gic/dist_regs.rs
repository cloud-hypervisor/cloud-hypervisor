// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{Error, Result};
use crate::layout::IRQ_BASE;
use hypervisor::kvm::kvm_bindings::{
    kvm_device_attr, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
};
use std::sync::Arc;

/*
 Distributor registers as detailed at page 456 from
 https://static.docs.arm.com/ihi0069/c/IHI0069C_gic_architecture_specification.pdf.
 Address offsets are relative to the Distributor base address defined
by the system memory map. Unless otherwise stated in the register description,
all GIC registers are 32-bits wide.
 */
const GICD_CTLR: u32 = 0x0;
const GICD_STATUSR: u32 = 0x0010;
const GICD_IGROUPR: u32 = 0x0080;
const GICD_ISENABLER: u32 = 0x0100;
const GICD_ICENABLER: u32 = 0x0180;
const GICD_ISPENDR: u32 = 0x0200;
const GICD_ICPENDR: u32 = 0x0280;
const GICD_ISACTIVER: u32 = 0x0300;
const GICD_ICACTIVER: u32 = 0x0380;
const GICD_IPRIORITYR: u32 = 0x0400;
const GICD_ICFGR: u32 = 0x0C00;
const GICD_IROUTER: u32 = 0x6000;

/// This is how we represent the registers of the vgic's distributor.
/// Some of the distributor register )(i.e GICD_STATUSR) are simple
/// registers (i.e they are associated to a 32 bit value).
/// However, there are other registers that have variable lengths since
/// they dedicate some of the 32 bits to some specific interrupt. So, their length
/// depends on the number of interrupts (i.e the ones that are represented as GICD_REG<n>)
/// in the documentation mentioned above.
struct DistReg {
    /// Offset from distributor address.
    base: u32,
    /// Bits per interrupt.
    /// Relevant for registers that DO share IRQs.
    bpi: u8,
    /// Length of the register.
    /// Relevant for registers that DO NOT share IRQs.
    length: u16,
}

// All or at least the registers we are interested in are 32 bit, so
// we use a constant for size(u32).
const REG_SIZE: u8 = 4;

// Creates a vgic distributor register.
macro_rules! VGIC_DIST_REG {
    ($base:expr, $bpi:expr, $length:expr) => {
        DistReg {
            base: $base,
            bpi: $bpi,
            length: $length,
        }
    };
}

// List with relevant distributor registers that we will be restoring.
// Order is taken from qemu.
static VGIC_DIST_REGS: &'static [DistReg] = &[
    VGIC_DIST_REG!(GICD_STATUSR, 0, 4),
    VGIC_DIST_REG!(GICD_ICENABLER, 1, 0),
    VGIC_DIST_REG!(GICD_ISENABLER, 1, 0),
    VGIC_DIST_REG!(GICD_IGROUPR, 1, 0),
    VGIC_DIST_REG!(GICD_IROUTER, 64, 0),
    VGIC_DIST_REG!(GICD_ICFGR, 2, 0),
    VGIC_DIST_REG!(GICD_ICPENDR, 1, 0),
    VGIC_DIST_REG!(GICD_ISPENDR, 1, 0),
    VGIC_DIST_REG!(GICD_ICACTIVER, 1, 0),
    VGIC_DIST_REG!(GICD_ISACTIVER, 1, 0),
    VGIC_DIST_REG!(GICD_IPRIORITYR, 8, 0),
];

fn dist_attr_access(
    gic: &Arc<dyn hypervisor::Device>,
    offset: u32,
    val: &u32,
    set: bool,
) -> Result<()> {
    let mut gic_dist_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        attr: offset as u64,
        addr: val as *const u32 as u64,
        flags: 0,
    };
    if set {
        gic.set_device_attr(&gic_dist_attr)
            .map_err(Error::SetDeviceAttribute)?;
    } else {
        gic.get_device_attr(&mut gic_dist_attr)
            .map_err(Error::GetDeviceAttribute)?;
    }
    Ok(())
}

/// Get the distributor control register.
pub fn read_ctlr(gic: &Arc<dyn hypervisor::Device>) -> Result<u32> {
    let val: u32 = 0;
    dist_attr_access(gic, GICD_CTLR, &val, false)?;
    Ok(val)
}

/// Set the distributor control register.
pub fn write_ctlr(gic: &Arc<dyn hypervisor::Device>, val: u32) -> Result<()> {
    dist_attr_access(gic, GICD_CTLR, &val, true)
}

fn get_interrupts_num(gic: &Arc<dyn hypervisor::Device>) -> Result<u32> {
    let num_irq = 0;

    let mut nr_irqs_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
        attr: 0,
        addr: &num_irq as *const u32 as u64,
        flags: 0,
    };
    gic.get_device_attr(&mut nr_irqs_attr)
        .map_err(Error::GetDeviceAttribute)?;
    Ok(num_irq)
}

fn compute_reg_len(gic: &Arc<dyn hypervisor::Device>, reg: &DistReg, base: u32) -> Result<u32> {
    let mut end = base;
    let num_irq = get_interrupts_num(gic)?;
    if reg.length > 0 {
        // This is the single type register (i.e one that is not DIST_X<n>) and for which
        // the bpi is 0.
        // Look in the kernel for REGISTER_DESC_WITH_LENGTH.
        end = base + reg.length as u32;
    }
    if reg.bpi > 0 {
        // This is the type of register that takes into account the number of interrupts
        // that the model has. It is also the type of register where
        // a register relates to multiple interrupts.
        end = base + (reg.bpi as u32 * (num_irq - IRQ_BASE) / 8);
        if reg.bpi as u32 * (num_irq - IRQ_BASE) % 8 > 0 {
            end += REG_SIZE as u32;
        }
    }
    Ok(end)
}

/// Set distributor registers of the GIC.
pub fn set_dist_regs(gic: &Arc<dyn hypervisor::Device>, state: &[u32]) -> Result<()> {
    let mut idx = 0;

    for dreg in VGIC_DIST_REGS {
        let mut base = dreg.base + REG_SIZE as u32 * dreg.bpi as u32;
        let end = compute_reg_len(gic, dreg, base)?;

        while base < end {
            let val = state[idx];
            dist_attr_access(gic, base, &val, true)?;
            idx += 1;
            base += REG_SIZE as u32;
        }
    }
    Ok(())
}
/// Get distributor registers of the GIC.
pub fn get_dist_regs(gic: &Arc<dyn hypervisor::Device>) -> Result<Vec<u32>> {
    let mut state = Vec::new();

    for dreg in VGIC_DIST_REGS {
        let mut base = dreg.base + REG_SIZE as u32 * dreg.bpi as u32;
        let end = compute_reg_len(gic, dreg, base)?;

        while base < end {
            let val: u32 = 0;
            dist_attr_access(gic, base, &val, false)?;
            state.push(val);
            base += REG_SIZE as u32;
        }
    }
    Ok(state)
}
