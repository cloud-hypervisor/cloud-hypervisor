// Copyright 2020, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::interrupt_controller::{Error, InterruptController};
extern crate arch;
use std::result;
use std::sync::Arc;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceConfig, InterruptSourceGroup,
    LegacyIrqSourceConfig, MsiIrqGroupConfig,
};
use vmm_sys_util::eventfd::EventFd;

type Result<T> = result::Result<T, Error>;

// Reserve 32 IRQs for legacy device.
pub const IRQ_LEGACY_BASE: usize = arch::layout::IRQ_BASE as usize;
pub const IRQ_LEGACY_COUNT: usize = 32;

// This Gic struct implements InterruptController to provide interrupt delivery service.
// The Gic source files in arch/ folder maintain the Aarch64 specific Gic device.
// The 2 Gic instances could be merged together.
// Leave this refactoring to future. Two options may be considered:
//   1. Move Gic*.rs from arch/ folder here.
//   2. Move this file and ioapic.rs to arch/, as they are architecture specific.
pub struct Gic {
    interrupt_source_group: Arc<Box<dyn InterruptSourceGroup>>,
}

impl Gic {
    pub fn new(
        _vcpu_count: u8,
        interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) -> Result<Gic> {
        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: IRQ_LEGACY_BASE as InterruptIndex,
                count: IRQ_LEGACY_COUNT as InterruptIndex,
            })
            .map_err(Error::CreateInterruptSourceGroup)?;

        Ok(Gic {
            interrupt_source_group,
        })
    }
}

impl InterruptController for Gic {
    fn enable(&self) -> Result<()> {
        // Set irqfd for legacy interrupts
        self.interrupt_source_group
            .enable()
            .map_err(Error::EnableInterrupt)?;

        // Set irq_routing for legacy interrupts.
        //   irqchip: Hardcode to 0 as we support only 1 GIC
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
                )
                .map_err(Error::EnableInterrupt)?;
        }
        Ok(())
    }

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
