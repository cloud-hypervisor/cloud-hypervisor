// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

#[cfg(target_arch = "aarch64")]
use crate::aarch64::VcpuInit;
use crate::cpu::Vcpu;
use crate::device::Device;
#[cfg(target_arch = "x86_64")]
use crate::ClockData;
use crate::KvmVmState as VmState;
use crate::{CreateDevice, IoEventAddress, IrqRoutingEntry, MemoryRegion};
use kvm_ioctls::Cap;
use std::sync::Arc;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

///
/// I/O events data matches (32 or 64 bits).
///
pub enum DataMatch {
    DataMatch32(u32),
    DataMatch64(u64),
}

impl Into<u64> for DataMatch {
    fn into(self) -> u64 {
        match self {
            DataMatch::DataMatch32(dm) => dm.into(),
            DataMatch::DataMatch64(dm) => dm,
        }
    }
}

#[derive(Error, Debug)]
///
/// Enum for VM error
pub enum HypervisorVmError {
    ///
    /// Create Vcpu error
    ///
    #[error("Failed to create Vcpu: {0}")]
    CreateVcpu(#[source] anyhow::Error),
    ///
    /// TSS address error
    ///
    #[error("Failed to set TSS address: {0}")]
    SetTssAddress(#[source] anyhow::Error),
    ///
    /// Create interrupt controller error
    ///
    #[error("Failed to create interrupt controller: {0}")]
    CreateIrq(#[source] anyhow::Error),
    ///
    /// Register interrupt event error
    ///
    #[error("Failed to register interrupt event: {0}")]
    RegisterIrqFd(#[source] anyhow::Error),
    ///
    /// Un register interrupt event error
    ///
    #[error("Failed to unregister interrupt event: {0}")]
    UnregisterIrqFd(#[source] anyhow::Error),
    ///
    /// Register IO event error
    ///
    #[error("Failed to register IO event: {0}")]
    RegisterIoEvent(#[source] anyhow::Error),
    ///
    /// Unregister IO event error
    ///
    #[error("Failed to unregister IO event: {0}")]
    UnregisterIoEvent(#[source] anyhow::Error),
    ///
    /// Set GSI routing error
    ///
    #[error("Failed to set GSI routing: {0}")]
    SetGsiRouting(#[source] anyhow::Error),
    ///
    /// Set user memory error
    ///
    #[error("Failed to set user memory: {0}")]
    SetUserMemory(#[source] anyhow::Error),
    ///
    /// Create device error
    ///
    #[error("Failed to set GSI routing: {0}")]
    CreateDevice(#[source] anyhow::Error),
    ///
    /// Get preferred target error
    ///
    #[error("Failed to get preferred target: {0}")]
    GetPreferredTarget(#[source] anyhow::Error),
    ///
    /// Enable split Irq error
    ///
    #[error("Failed to enable split Irq: {0}")]
    EnableSplitIrq(#[source] anyhow::Error),
    ///
    /// Get clock error
    ///
    #[error("Failed to get clock: {0}")]
    GetClock(#[source] anyhow::Error),
    ///
    /// Set clock error
    ///
    #[error("Failed to set clock: {0}")]
    SetClock(#[source] anyhow::Error),
    ///
    /// Create passthrough device
    ///
    #[error("Failed to create passthrough device: {0}")]
    CreatePassthroughDevice(#[source] anyhow::Error),
    ///
    /// Write to Guest memory
    ///
    #[error("Failed to write to guest memory: {0}")]
    GuestMemWrite(#[source] anyhow::Error),
    ///
    /// Read Guest memory
    ///
    #[error("Failed to read guest memory: {0}")]
    GuestMemRead(#[source] anyhow::Error),
    ///
    /// Read from MMIO Bus
    ///
    #[error("Failed to read from MMIO Bus: {0}")]
    MmioBusRead(#[source] anyhow::Error),
    ///
    /// Write to MMIO Bus
    ///
    #[error("Failed to write to MMIO Bus: {0}")]
    MmioBusWrite(#[source] anyhow::Error),
    ///
    /// Read from IO Bus
    ///
    #[error("Failed to read from IO Bus: {0}")]
    IoBusRead(#[source] anyhow::Error),
    ///
    /// Write to IO Bus
    ///
    #[error("Failed to write to IO Bus: {0}")]
    IoBusWrite(#[source] anyhow::Error),
}
///
/// Result type for returning from a function
///
pub type Result<T> = std::result::Result<T, HypervisorVmError>;

///
/// Trait to represent a Vm
///
/// This crate provides a hypervisor-agnostic interfaces for Vm
///
pub trait Vm: Send + Sync {
    #[cfg(target_arch = "x86_64")]
    /// Sets the address of the three-page region in the VM's address space.
    fn set_tss_address(&self, offset: usize) -> Result<()>;
    /// Creates an in-kernel interrupt controller.
    fn create_irq_chip(&self) -> Result<()>;
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()>;
    /// Unregister an event that will, when signaled, trigger the `gsi` IRQ.
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()>;
    /// Creates a new KVM vCPU file descriptor and maps the memory corresponding
    fn create_vcpu(&self, id: u8) -> Result<Arc<dyn Vcpu>>;
    /// Registers an event to be signaled whenever a certain address is written to.
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<DataMatch>,
    ) -> Result<()>;
    /// Unregister an event from a certain address it has been previously registered to.
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> Result<()>;
    /// Sets the GSI routing table entries, overwriting any previously set
    fn set_gsi_routing(&self, entries: &[IrqRoutingEntry]) -> Result<()>;
    /// Creates a memory region structure that can be used with set_user_memory_region
    fn make_user_memory_region(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
        log_dirty_pages: bool,
    ) -> MemoryRegion;
    /// Creates/modifies a guest physical memory slot.
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> Result<()>;
    /// Creates an emulated device in the kernel.
    fn create_device(&self, device: &mut CreateDevice) -> Result<Arc<dyn Device>>;
    /// Returns the preferred CPU target type which can be emulated by KVM on underlying host.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_preferred_target(&self, kvi: &mut VcpuInit) -> Result<()>;
    /// Enable split Irq capability
    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> Result<()>;
    /// Retrieve guest clock.
    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> Result<ClockData>;
    /// Set guest clock.
    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, data: &ClockData) -> Result<()>;
    /// Checks if a particular `Cap` is available.
    fn check_extension(&self, c: Cap) -> bool;
    /// Create a device that is used for passthrough
    fn create_passthrough_device(&self) -> Result<Arc<dyn Device>>;
    /// Get the Vm state. Return VM specific data
    fn state(&self) -> Result<VmState>;
    /// Set the VM state
    fn set_state(&self, state: VmState) -> Result<()>;
    /// Set VmmOps interface
    fn set_vmmops(&self, vmmops: Box<dyn VmmOps>) -> Result<()>;
}

pub trait VmmOps: Send + Sync {
    fn guest_mem_write(&self, buf: &[u8], gpa: u64) -> Result<usize>;
    fn guest_mem_read(&self, buf: &mut [u8], gpa: u64) -> Result<usize>;
    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> Result<()>;
    fn mmio_write(&self, addr: u64, data: &[u8]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, addr: u64, data: &mut [u8]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, addr: u64, data: &[u8]) -> Result<()>;
}
