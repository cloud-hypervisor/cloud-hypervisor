// Copyright © 2024 Institute of Software, CAS. All rights reserved.
// Copyright 2020, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::{io, result};

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
    #[error("Failed creating the interrupt source group: {0}")]
    CreateInterruptSourceGroup(#[source] io::Error),
    /// Failed triggering the interrupt.
    #[error("Failed triggering the interrupt: {0}")]
    TriggerInterrupt(#[source] io::Error),
    /// Failed masking the interrupt.
    #[error("Failed masking the interrupt: {0}")]
    MaskInterrupt(#[source] io::Error),
    /// Failed unmasking the interrupt.
    #[error("Failed unmasking the interrupt: {0}")]
    UnmaskInterrupt(#[source] io::Error),
    /// Failed updating the interrupt.
    #[error("Failed updating the interrupt: {0}")]
    UpdateInterrupt(#[source] io::Error),
    /// Failed enabling the interrupt.
    #[error("Failed enabling the interrupt: {0}")]
    EnableInterrupt(#[source] io::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed creating GIC device.
    #[error("Failed creating GIC device: {0}")]
    CreateGic(#[source] hypervisor::HypervisorVmError),
    #[cfg(target_arch = "aarch64")]
    /// Failed restoring GIC device.
    #[error("Failed restoring GIC device: {0}")]
    RestoreGic(#[source] hypervisor::arch::aarch64::gic::Error),
    #[cfg(target_arch = "riscv64")]
    /// Failed creating AIA device.
    #[error("Failed creating AIA device: {0}")]
    CreateAia(#[source] hypervisor::HypervisorVmError),
    #[cfg(target_arch = "riscv64")]
    /// Failed restoring AIA device.
    #[error("Failed restoring AIA device: {0}")]
    RestoreAia(#[source] hypervisor::arch::riscv64::aia::Error),
}

type Result<T> = result::Result<T, Error>;

pub struct MsiMessage {
    // Message Address Register
    //   31-20: Base address. Fixed value (0x0FEE)
    //   19-12: Destination ID
    //   11-4:  Reserved
    //   3:     Redirection Hint indication
    //   2:     Destination Mode
    //   1-0:   Reserved
    pub addr: u32,
    // Message Data Register
    //   32-16: Reserved
    //   15:    Trigger Mode. 0 = Edge, 1 = Level
    //   14:    Level. 0 = Deassert, 1 = Assert
    //   13-11: Reserved
    //   10-8:  Delivery Mode
    //   7-0:   Vector
    pub data: u32,
}

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
