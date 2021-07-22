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
#[cfg(feature = "tdx")]
use crate::x86_64::CpuId;
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use crate::ClockData;
#[cfg(feature = "kvm")]
use crate::CreateDevice;
#[cfg(feature = "mshv")]
use crate::HvState as VmState;
#[cfg(feature = "kvm")]
use crate::KvmVmState as VmState;
use crate::{IoEventAddress, IrqRoutingEntry, MemoryRegion};
#[cfg(feature = "kvm")]
use kvm_ioctls::Cap;
#[cfg(target_arch = "x86_64")]
use std::fs::File;
use std::sync::Arc;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

///
/// I/O events data matches (32 or 64 bits).
///
#[derive(Debug)]
pub enum DataMatch {
    DataMatch32(u32),
    DataMatch64(u64),
}

impl From<DataMatch> for u64 {
    fn from(dm: DataMatch) -> u64 {
        match dm {
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
    /// Create user memory error
    ///
    #[error("Failed to create user memory: {0}")]
    CreateUserMemory(#[source] anyhow::Error),
    ///
    /// Remove user memory region error
    ///
    #[error("Failed to remove user memory: {0}")]
    RemoveUserMemory(#[source] anyhow::Error),
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
    /// Enable SGX attribute error
    ///
    #[error("Failed to enable SGX attribute: {0}")]
    EnableSgxAttribute(#[source] anyhow::Error),
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
    ///
    /// Start dirty log error
    ///
    #[error("Failed to get dirty log: {0}")]
    StartDirtyLog(#[source] anyhow::Error),
    ///
    /// Stop dirty log error
    ///
    #[error("Failed to get dirty log: {0}")]
    StopDirtyLog(#[source] anyhow::Error),
    ///
    /// Get dirty log error
    ///
    #[error("Failed to get dirty log: {0}")]
    GetDirtyLog(#[source] anyhow::Error),
    ///
    /// Assert virtual interrupt error
    ///
    #[error("Failed to assert virtual Interrupt: {0}")]
    AsserttVirtualInterrupt(#[source] anyhow::Error),

    #[cfg(feature = "tdx")]
    ///
    /// Error initializing TDX on the VM
    ///
    #[error("Failed to initialize TDX: {0}")]
    InitializeTdx(#[source] std::io::Error),
    #[cfg(feature = "tdx")]
    ///
    /// Error finalizing the TDX configuration on the VM
    ///
    #[error("Failed to finalize TDX: {0}")]
    FinalizeTdx(#[source] std::io::Error),
    #[cfg(feature = "tdx")]
    ///
    /// Error initializing the TDX memory region
    ///
    #[error("Failed to initialize memory region TDX: {0}")]
    InitMemRegionTdx(#[source] std::io::Error),
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
    fn create_vcpu(&self, id: u8, vmmops: Option<Arc<Box<dyn VmmOps>>>) -> Result<Arc<dyn Vcpu>>;
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
    /// Creates a memory region structure that can be used with {create/remove}_user_memory_region
    fn make_user_memory_region(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
        log_dirty_pages: bool,
    ) -> MemoryRegion;
    /// Creates a guest physical memory slot.
    fn create_user_memory_region(&self, user_memory_region: MemoryRegion) -> Result<()>;
    /// Removes a guest physical memory slot.
    fn remove_user_memory_region(&self, user_memory_region: MemoryRegion) -> Result<()>;
    #[cfg(feature = "kvm")]
    /// Creates an emulated device in the kernel.
    fn create_device(&self, device: &mut CreateDevice) -> Result<Arc<dyn Device>>;
    /// Returns the preferred CPU target type which can be emulated by KVM on underlying host.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_preferred_target(&self, kvi: &mut VcpuInit) -> Result<()>;
    /// Enable split Irq capability
    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn enable_sgx_attribute(&self, file: File) -> Result<()>;
    /// Retrieve guest clock.
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn get_clock(&self) -> Result<ClockData>;
    /// Set guest clock.
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn set_clock(&self, data: &ClockData) -> Result<()>;
    #[cfg(feature = "kvm")]
    /// Checks if a particular `Cap` is available.
    fn check_extension(&self, c: Cap) -> bool;
    /// Create a device that is used for passthrough
    fn create_passthrough_device(&self) -> Result<Arc<dyn Device>>;
    /// Get the Vm state. Return VM specific data
    fn state(&self) -> Result<VmState>;
    /// Set the VM state
    fn set_state(&self, state: VmState) -> Result<()>;
    /// Start logging dirty pages
    fn start_dirty_log(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    ) -> Result<()>;
    /// Stop logging dirty pages
    fn stop_dirty_log(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    ) -> Result<()>;
    /// Get dirty pages bitmap
    fn get_dirty_log(&self, slot: u32, memory_size: u64) -> Result<Vec<u64>>;
    #[cfg(feature = "tdx")]
    /// Initalize TDX on this VM
    fn tdx_init(&self, cpuid: &CpuId, max_vcpus: u32) -> Result<()>;
    #[cfg(feature = "tdx")]
    /// Finalize the configuration of TDX on this VM
    fn tdx_finalize(&self) -> Result<()>;
    #[cfg(feature = "tdx")]
    /// Initalize a TDX memory region for this VM
    fn tdx_init_memory_region(
        &self,
        host_address: u64,
        guest_address: u64,
        size: u64,
        measure: bool,
    ) -> Result<()>;
}

pub trait VmmOps: Send + Sync {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> Result<usize>;
    fn guest_mem_read(&self, gpa: u64, buf: &mut [u8]) -> Result<usize>;
    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> Result<()>;
    fn mmio_write(&self, gpa: u64, data: &[u8]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, port: u64, data: &mut [u8]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, port: u64, data: &[u8]) -> Result<()>;
}
