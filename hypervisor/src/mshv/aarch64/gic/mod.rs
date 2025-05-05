// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2025, Microsoft Corporation
//
use std::any::Any;

use serde::{Deserialize, Serialize};

use crate::arch::aarch64::gic::{GicState, Result, Vgic, VgicConfig};
use crate::{CpuState, Vm};

pub struct MshvGicV2M {
    /// GIC distributor address
    pub dist_addr: u64,

    /// GIC distributor size
    pub dist_size: u64,

    /// GIC re-distributors address
    pub redists_addr: u64,

    /// GIC re-distributors size
    pub redists_size: u64,

    /// GITS translator address
    pub gits_addr: u64,

    /// GITS translator size
    pub gits_size: u64,

    /// Number of CPUs handled by the device
    pub vcpu_count: u64,
}

pub const BASE_SPI_IRQ: u32 = 32;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MshvGicV2MState {}

impl From<GicState> for MshvGicV2MState {
    fn from(state: GicState) -> Self {
        match state {
            GicState::MshvGicV2M(state) => state,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("GicState is not valid"),
        }
    }
}

impl From<MshvGicV2MState> for GicState {
    fn from(state: MshvGicV2MState) -> Self {
        GicState::MshvGicV2M(state)
    }
}

impl MshvGicV2M {
    /// Create a new GICv2m device
    pub fn new(_vm: &dyn Vm, config: VgicConfig) -> Result<MshvGicV2M> {
        let gic_device = MshvGicV2M {
            dist_addr: config.dist_addr,
            dist_size: config.dist_size,
            redists_addr: config.redists_addr,
            redists_size: config.redists_size,
            gits_addr: config.msi_addr,
            gits_size: config.msi_size,
            vcpu_count: config.vcpu_count,
        };
        Ok(gic_device)
    }
}

impl Vgic for MshvGicV2M {
    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn msi_compatible(&self) -> bool {
        true
    }

    fn msi_compatibility(&self) -> &str {
        "arm,gic-v2m-frame"
    }

    fn fdt_maint_irq(&self) -> u32 {
        0
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn msi_properties(&self) -> [u64; 2] {
        [self.gits_addr, self.gits_size]
    }

    fn device_properties(&self) -> [u64; 4] {
        [
            self.dist_addr,
            self.dist_size,
            self.redists_addr,
            self.redists_size,
        ]
    }

    fn set_gicr_typers(&mut self, _vcpu_states: &[CpuState]) {
        unimplemented!()
    }

    fn state(&self) -> Result<GicState> {
        unimplemented!()
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn set_state(&mut self, _state: &GicState) -> Result<()> {
        unimplemented!()
    }

    fn save_data_tables(&self) -> Result<()> {
        unimplemented!()
    }
}
