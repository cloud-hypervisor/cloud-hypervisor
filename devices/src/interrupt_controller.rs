// Copyright © 2024 Institute of Software, CAS. All rights reserved.
// Copyright 2020, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::{io, result};

#[cfg(target_arch = "aarch64")]
use hypervisor::arch::aarch64::gic;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid trigger mode.
    #[error("Invalid trigger mode")]
    InvalidTriggerMode,
    /// Invalid delivery mode.
    #[error("Invalid delivery mode")]
    InvalidDeliveryMode,
    /// Failed creating the interrupt source group.
    #[error("Failed creating the interrupt source group")]
    CreateInterruptSourceGroup(#[source] io::Error),
    /// Failed triggering the interrupt.
    #[error("Failed triggering the interrupt")]
    TriggerInterrupt(#[source] io::Error),
    /// Failed masking the interrupt.
    #[error("Failed masking the interrupt")]
    MaskInterrupt(#[source] io::Error),
    /// Failed unmasking the interrupt.
    #[error("Failed unmasking the interrupt")]
    UnmaskInterrupt(#[source] io::Error),
    /// Failed updating the interrupt.
    #[error("Failed updating the interrupt")]
    UpdateInterrupt(#[source] io::Error),
    /// Failed enabling the interrupt.
    #[error("Failed enabling the interrupt")]
    EnableInterrupt(#[source] io::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed creating GIC device.
    #[error("Failed creating GIC device")]
    CreateGic(#[source] hypervisor::HypervisorVmError),
    #[cfg(target_arch = "aarch64")]
    /// Failed restoring GIC device.
    #[error("Failed restoring GIC device")]
    RestoreGic(#[source] gic::Error),
    #[cfg(target_arch = "riscv64")]
    /// Failed creating AIA device.
    #[error("Failed creating AIA device")]
    CreateAia(#[source] hypervisor::HypervisorVmError),
    #[cfg(target_arch = "riscv64")]
    /// Failed restoring AIA device.
    #[error("Failed restoring AIA device")]
    RestoreAia(#[source] hypervisor::arch::riscv64::aia::Error),
}

type Result<T> = result::Result<T, Error>;

// Introduce trait InterruptController to uniform the interrupt
// service provided for devices.
// Device manager uses this trait without caring whether it is a
// IOAPIC (X86), GIC (Arm) or AIA (RISC-V).
pub trait InterruptController: Send {
    fn service_irq(&mut self, irq: usize) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn end_of_interrupt(&mut self, vec: u8);
    fn notifier(&self, irq: usize) -> Option<EventFd>;
}
