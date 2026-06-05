// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Managed GICv3 (`hv_gic`) support for the Apple Hypervisor.framework backend.
//!
//! Apple's framework provides an in-VM GICv3 distributor + redistributors whose
//! state can be saved and restored as an opaque blob (`hv_gic_state`). This
//! module wires that into the hypervisor-agnostic [`Vgic`] trait, including the
//! interrupt-controller state that snapshot/rehydration depends on.
//!
//! Ordering constraint (enforced by Apple): `hv_gic_create()` must be called
//! after the VM exists but **before** any vCPU is created.

use std::any::Any;
use std::ffi::c_void;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::ffi::*;
use crate::arch::aarch64::gic::{
    Error as GicError, GicState, Result as GicResult, Vgic, VgicConfig,
};
use crate::device::HypervisorDeviceError;
use crate::CpuState;

/// GICv3 maintenance interrupt (PPI), matching the value the VMM advertises.
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

/// `GICD_CTLR` distributor register offset.
pub const GICD_CTLR: u32 = HV_GIC_DIST_REG_GICD_CTLR;
/// `GICD_TYPER` distributor register offset.
pub const GICD_TYPER: u32 = HV_GIC_DIST_REG_GICD_TYPER;

/// Opaque, serializable snapshot of the managed GIC produced by `hv_gic`.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HvfGicState {
    pub data: Vec<u8>,
}

/// A managed GICv3 created through `hv_gic_create`.
pub struct HvfGicV3 {
    dist_addr: u64,
    dist_size: u64,
    redists_addr: u64,
    redists_size: u64,
    msi_addr: u64,
    msi_size: u64,
    vcpu_count: u64,
    gicr_typers: Vec<u64>,
}

fn dev_get(op: &'static str, code: i32) -> GicResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(GicError::GetDeviceAttribute(
            HypervisorDeviceError::GetDeviceAttribute(anyhow!(
                "{op} failed: {:#010x}",
                code as u32
            )),
        ))
    }
}

fn dev_set(op: &'static str, code: i32) -> GicResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(GicError::SetDeviceAttribute(
            HypervisorDeviceError::SetDeviceAttribute(anyhow!(
                "{op} failed: {:#010x}",
                code as u32
            )),
        ))
    }
}

impl HvfGicV3 {
    /// Create the managed GIC. Must run before any vCPU is created.
    pub fn new(config: &VgicConfig) -> GicResult<Self> {
        // SAFETY: FFI; the returned object is released below.
        let cfg = unsafe { hv_gic_config_create() };
        if cfg.is_null() {
            return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                anyhow!("hv_gic_config_create returned null"),
            )));
        }

        // NOTE: MSI/ITS is intentionally NOT configured yet. The irqfd/GSI
        // routing path that would deliver MSIs is not implemented, so we do not
        // advertise MSI to the guest (`msi_compatible()` returns false). Only
        // the distributor + redistributors are set up here.
        //
        // SAFETY: `cfg` is a valid configuration object for the calls below.
        let result = unsafe {
            let mut rc = hv_gic_config_set_distributor_base(cfg, config.dist_addr);
            if rc == 0 {
                rc = hv_gic_config_set_redistributor_base(cfg, config.redists_addr);
            }
            if rc == 0 {
                rc = hv_gic_create(cfg);
            }
            rc
        };
        // SAFETY: release the configuration object exactly once.
        unsafe { os_release(cfg) };

        if result != 0 {
            return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                anyhow!("hv_gic_create failed: {:#010x}", result as u32),
            )));
        }

        Ok(HvfGicV3 {
            dist_addr: config.dist_addr,
            dist_size: config.dist_size,
            redists_addr: config.redists_addr,
            redists_size: config.redists_size,
            msi_addr: config.msi_addr,
            msi_size: config.msi_size,
            vcpu_count: config.vcpu_count,
            gicr_typers: vec![0; config.vcpu_count as usize],
        })
    }

    /// Read a distributor register (e.g. `GICD_TYPER`); proves the GIC is live.
    pub fn distributor_reg(&self, reg: u32) -> GicResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI; out-param valid.
        dev_get("hv_gic_get_distributor_reg", unsafe {
            hv_gic_get_distributor_reg(reg, &mut v)
        })?;
        Ok(v)
    }

    /// Assert or deassert a shared peripheral interrupt by INTID.
    pub fn set_spi(&self, intid: u32, level: bool) -> GicResult<()> {
        // SAFETY: FFI.
        dev_set("hv_gic_set_spi", unsafe { hv_gic_set_spi(intid, level) })
    }
}

impl Vgic for HvfGicV3 {
    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn device_properties(&self) -> [u64; 4] {
        [
            self.dist_addr,
            self.dist_size,
            self.redists_addr,
            self.redists_size,
        ]
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn msi_compatible(&self) -> bool {
        // MSI/ITS delivery (irqfd + GSI routing) is not implemented yet, so we
        // do not advertise MSI support even if a region was reserved.
        false
    }

    fn msi_compatibility(&self) -> &str {
        "arm,gic-v3-its"
    }

    fn msi_properties(&self) -> [u64; 2] {
        [self.msi_addr, self.msi_size]
    }

    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]) {
        // The managed GIC owns redistributor state; we only track the count so
        // FDT generation and snapshot bookkeeping stay consistent.
        self.gicr_typers = vec![0; vcpu_states.len()];
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn state(&self) -> GicResult<GicState> {
        // SAFETY: FFI; the state object is released before returning.
        let state_obj = unsafe { hv_gic_state_create() };
        if state_obj.is_null() {
            return Err(GicError::GetDeviceAttribute(
                HypervisorDeviceError::GetDeviceAttribute(anyhow!(
                    "hv_gic_state_create returned null"
                )),
            ));
        }

        let mut size = 0usize;
        // SAFETY: FFI; out-param valid.
        let rc = unsafe { hv_gic_state_get_size(state_obj, &mut size) };
        if rc != 0 {
            // SAFETY: release before bailing out.
            unsafe { os_release(state_obj) };
            return dev_get("hv_gic_state_get_size", rc).map(|_| unreachable!());
        }
        if size == 0 {
            // SAFETY: release before bailing out.
            unsafe { os_release(state_obj) };
            return Err(GicError::GetDeviceAttribute(
                HypervisorDeviceError::GetDeviceAttribute(anyhow!(
                    "hv_gic_state_get_size reported zero bytes"
                )),
            ));
        }

        let mut data = vec![0u8; size];
        // SAFETY: `data` has room for `size` bytes.
        let rc = unsafe { hv_gic_state_get_data(state_obj, data.as_mut_ptr() as *mut c_void) };
        // SAFETY: release the state object exactly once.
        unsafe { os_release(state_obj) };
        dev_get("hv_gic_state_get_data", rc)?;

        Ok(GicState::Hvf(HvfGicState { data }))
    }

    fn set_state(&mut self, state: &GicState) -> GicResult<()> {
        #[allow(irrefutable_let_patterns)]
        let GicState::Hvf(s) = state else {
            return Err(GicError::SetDeviceAttribute(
                HypervisorDeviceError::SetDeviceAttribute(anyhow!("expected HVF GicState")),
            ));
        };
        if s.data.is_empty() {
            return Err(GicError::SetDeviceAttribute(
                HypervisorDeviceError::SetDeviceAttribute(anyhow!("empty HVF GIC state blob")),
            ));
        }
        // SAFETY: FFI; `s.data` is valid for `s.data.len()` bytes.
        dev_set("hv_gic_set_state", unsafe {
            hv_gic_set_state(s.data.as_ptr() as *const c_void, s.data.len())
        })
    }

    fn save_data_tables(&self) -> GicResult<()> {
        // The managed GIC keeps its tables internally; nothing to flush.
        Ok(())
    }
}

/// Inject the virtual-timer interrupt after an `HV_EXIT_REASON_VTIMER_ACTIVATED`
/// exit: assert the vCPU IRQ line and re-unmask the timer (auto-masked on exit).
///
/// UNVERIFIED end-to-end: this follows Apple's documented vtimer flow but is not
/// exercised by any test (no GIC-enabled guest programs CNTV here).
pub(super) fn inject_vtimer(vcpu_id: u64) -> Result<(), i32> {
    // SAFETY: FFI on the owning thread.
    let rc = unsafe { hv_vcpu_set_pending_interrupt(vcpu_id, HV_INTERRUPT_TYPE_IRQ, true) };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: FFI on the owning thread.
    let rc = unsafe { hv_vcpu_set_vtimer_mask(vcpu_id, false) };
    if rc != 0 {
        Err(rc)
    } else {
        Ok(())
    }
}
