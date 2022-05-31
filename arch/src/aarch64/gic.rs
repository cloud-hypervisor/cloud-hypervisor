// Copyright 2021 Arm Limited (or its affiliates). All rights reserved.

use crate::layout;
use anyhow::anyhow;
use hypervisor::{arch::aarch64::gic::Vgic, CpuState};
use std::result;
use std::sync::Arc;
use vm_memory::Address;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

/// Errors thrown while setting up the GIC.
#[derive(Debug)]
pub enum Error {
    CreateGic(hypervisor::HypervisorVmError),
}
type Result<T> = result::Result<T, Error>;

/// A wrapper around creating and using a hypervisor-agnostic vgic.
pub struct GicDevice {
    // The hypervisor abstracted GIC.
    vgic: Box<dyn Vgic>,
}

impl GicDevice {
    pub fn new(vm: &Arc<dyn hypervisor::Vm>, vcpu_count: u64) -> Result<GicDevice> {
        let vgic = vm
            .create_vgic(
                vcpu_count,
                layout::GIC_V3_DIST_START.raw_value(),
                layout::GIC_V3_DIST_SIZE,
                layout::GIC_V3_REDIST_SIZE,
                layout::GIC_V3_ITS_SIZE,
                layout::IRQ_NUM,
            )
            .unwrap();
        Ok(GicDevice { vgic })
    }

    pub fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]) {
        self.vgic.set_gicr_typers(vcpu_states)
    }

    pub fn get_vgic(&self) -> &dyn Vgic {
        &*self.vgic
    }
}

pub const GIC_V3_ITS_SNAPSHOT_ID: &str = "gic-v3-its";
impl Snapshottable for GicDevice {
    fn id(&self) -> String {
        GIC_V3_ITS_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let state = self.vgic.state().unwrap();
        Snapshot::new_from_state(&self.id(), &state)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.vgic
            .set_state(&snapshot.to_state(&self.id())?)
            .map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore GICv3ITS state {:?}", e))
            })
    }
}

impl Pausable for GicDevice {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        // Flush tables to guest RAM
        self.vgic.save_data_tables().map_err(|e| {
            MigratableError::Pause(anyhow!(
                "Could not save GICv3ITS GIC pending tables {:?}",
                e
            ))
        })
    }
}
impl Transportable for GicDevice {}
impl Migratable for GicDevice {}
