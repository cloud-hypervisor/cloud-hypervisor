// Copyright © 2024 Institute of Software, CAS. All rights reserved.
// Copyright 2020, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::interrupt_controller::{Error, InterruptController};
extern crate arch;
use std::result;
use std::sync::{Arc, Mutex};

use arch::layout;
use hypervisor::arch::riscv64::aia::{Vaia, VaiaConfig};
use hypervisor::{AiaState, CpuState};
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceConfig, InterruptSourceGroup,
    LegacyIrqSourceConfig, MsiIrqGroupConfig,
};
use vm_memory::address::Address;
use vm_migration::{Migratable, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

type Result<T> = result::Result<T, Error>;

// Reserve 32 IRQs for legacy devices.
pub const IRQ_LEGACY_BASE: usize = layout::IRQ_BASE as usize;
pub const IRQ_LEGACY_COUNT: usize = 32;
// TODO: AIA snapshotting is not yet completed.
pub const _AIA_SNAPSHOT_ID: &str = "";

// Aia (Advance Interrupt Architecture) struct provides all the functionality of a
// AIA device. It wraps a hypervisor-emulated AIA device (Vaia) provided by the
// `hypervisor` crate.
// Aia struct also implements InterruptController to provide interrupt delivery
// service.
pub struct Aia {
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
    // The hypervisor agnostic virtual AIA
    vaia: Arc<Mutex<dyn Vaia>>,
}

impl Aia {
    pub fn new(
        vcpu_count: u8,
        interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        vm: Arc<dyn hypervisor::Vm>,
    ) -> Result<Aia> {
        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: IRQ_LEGACY_BASE as InterruptIndex,
                count: IRQ_LEGACY_COUNT as InterruptIndex,
            })
            .map_err(Error::CreateInterruptSourceGroup)?;

        let vaia = vm
            .create_vaia(Aia::create_default_config(vcpu_count as u64))
            .map_err(Error::CreateAia)?;

        let aia = Aia {
            interrupt_source_group,
            vaia,
        };
        aia.enable()?;

        Ok(aia)
    }

    pub fn restore_vaia(
        &mut self,
        state: Option<AiaState>,
        _saved_vcpu_states: &[CpuState],
    ) -> Result<()> {
        self.vaia
            .clone()
            .lock()
            .unwrap()
            .set_state(&state.unwrap())
            .map_err(Error::RestoreAia)
    }

    fn enable(&self) -> Result<()> {
        // Set irqfd for legacy interrupts
        self.interrupt_source_group
            .enable()
            .map_err(Error::EnableInterrupt)?;

        // Set irq_routing for legacy interrupts.
        //   irqchip: Hardcode to 0 as we support only 1 APLIC
        //   pin: Use irq number as pin
        for i in IRQ_LEGACY_BASE..(IRQ_LEGACY_BASE + IRQ_LEGACY_COUNT) {
            let config = LegacyIrqSourceConfig {
                irqchip: 0,
                pin: (i - IRQ_LEGACY_BASE) as u32,
            };
            self.interrupt_source_group
                .update(
                    i as InterruptIndex,
                    InterruptSourceConfig::LegacyIrq(config),
                    false,
                    false,
                )
                .map_err(Error::EnableInterrupt)?;
        }

        self.interrupt_source_group
            .set_gsi()
            .map_err(Error::EnableInterrupt)?;
        Ok(())
    }

    /// Default config implied by arch::layout
    pub fn create_default_config(vcpu_count: u64) -> VaiaConfig {
        VaiaConfig {
            vcpu_count: vcpu_count as u32,
            aplic_addr: layout::APLIC_START.raw_value(),
            imsic_addr: layout::IMSIC_START.raw_value(),
            nr_irqs: layout::IRQ_NUM,
        }
    }

    pub fn get_vaia(&mut self) -> Result<Arc<Mutex<dyn Vaia>>> {
        Ok(self.vaia.clone())
    }
}

impl InterruptController for Aia {
    // This should be called anytime an interrupt needs to be injected into the
    // running guest.
    fn service_irq(&mut self, irq: usize) -> Result<()> {
        self.interrupt_source_group
            .trigger(irq as InterruptIndex)
            .map_err(Error::TriggerInterrupt)?;

        Ok(())
    }

    fn notifier(&self, irq: usize) -> Option<EventFd> {
        self.interrupt_source_group.notifier(irq as InterruptIndex)
    }
}

impl Snapshottable for Aia {}
impl Pausable for Aia {}
impl Transportable for Aia {}
impl Migratable for Aia {}
