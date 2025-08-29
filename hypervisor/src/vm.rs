// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use std::any::Any;
use std::sync::Arc;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use std::sync::Mutex;

#[cfg(feature = "sev_snp")]
use igvm_defs::IGVM_VHS_SNP_ID_BLOCK;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::{Vgic, VgicConfig};
#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::aia::{Vaia, VaiaConfig};
#[cfg(feature = "tdx")]
use crate::arch::x86::CpuIdEntry;
use crate::cpu::Vcpu;
#[cfg(target_arch = "x86_64")]
use crate::ClockData;
use crate::{IoEventAddress, IrqRoutingEntry, UserMemoryRegion};

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
    #[error("Failed to create Vcpu")]
    CreateVcpu(#[source] anyhow::Error),
    ///
    /// Identity map address error
    ///
    #[error("Failed to set identity map address")]
    SetIdentityMapAddress(#[source] anyhow::Error),
    ///
    /// TSS address error
    ///
    #[error("Failed to set TSS address")]
    SetTssAddress(#[source] anyhow::Error),
    ///
    /// Create interrupt controller error
    ///
    #[error("Failed to create interrupt controller")]
    CreateIrq(#[source] anyhow::Error),
    ///
    /// Register interrupt event error
    ///
    #[error("Failed to register interrupt event")]
    RegisterIrqFd(#[source] anyhow::Error),
    ///
    /// Un register interrupt event error
    ///
    #[error("Failed to unregister interrupt event")]
    UnregisterIrqFd(#[source] anyhow::Error),
    ///
    /// Register IO event error
    ///
    #[error("Failed to register IO event")]
    RegisterIoEvent(#[source] anyhow::Error),
    ///
    /// Unregister IO event error
    ///
    #[error("Failed to unregister IO event")]
    UnregisterIoEvent(#[source] anyhow::Error),
    ///
    /// Set GSI routing error
    ///
    #[error("Failed to set GSI routing")]
    SetGsiRouting(#[source] anyhow::Error),
    ///
    /// Create user memory error
    ///
    #[error("Failed to create user memory")]
    CreateUserMemory(#[source] anyhow::Error),
    ///
    /// Remove user memory region error
    ///
    #[error("Failed to remove user memory")]
    RemoveUserMemory(#[source] anyhow::Error),
    ///
    /// Create device error
    ///
    #[error("Failed to set GSI routing")]
    CreateDevice(#[source] anyhow::Error),
    ///
    /// Get preferred target error
    ///
    #[error("Failed to get preferred target")]
    GetPreferredTarget(#[source] anyhow::Error),
    ///
    /// Enable split Irq error
    ///
    #[error("Failed to enable split Irq")]
    EnableSplitIrq(#[source] anyhow::Error),
    ///
    /// Enable x2apic API error
    ///
    #[error("Failed to enable x2apic API")]
    EnableX2ApicApi(#[source] anyhow::Error),
    /// Get clock error
    ///
    #[error("Failed to get clock")]
    GetClock(#[source] anyhow::Error),
    ///
    /// Set clock error
    ///
    #[error("Failed to set clock")]
    SetClock(#[source] anyhow::Error),
    ///
    /// Create passthrough device
    ///
    #[error("Failed to create passthrough device")]
    CreatePassthroughDevice(#[source] anyhow::Error),
    /// Write to Guest memory
    ///
    #[error("Failed to write to guest memory")]
    GuestMemWrite(#[source] anyhow::Error),
    ///
    /// Read Guest memory
    ///
    #[error("Failed to read guest memory")]
    GuestMemRead(#[source] anyhow::Error),
    ///
    /// Read from MMIO Bus
    ///
    #[error("Failed to read from MMIO Bus")]
    MmioBusRead(#[source] anyhow::Error),
    ///
    /// Write to MMIO Bus
    ///
    #[error("Failed to write to MMIO Bus")]
    MmioBusWrite(#[source] anyhow::Error),
    ///
    /// Read from IO Bus
    ///
    #[error("Failed to read from IO Bus")]
    IoBusRead(#[source] anyhow::Error),
    ///
    /// Write to IO Bus
    ///
    #[error("Failed to write to IO Bus")]
    IoBusWrite(#[source] anyhow::Error),
    ///
    /// Start dirty log error
    ///
    #[error("Failed to get dirty log")]
    StartDirtyLog(#[source] anyhow::Error),
    ///
    /// Stop dirty log error
    ///
    #[error("Failed to get dirty log")]
    StopDirtyLog(#[source] anyhow::Error),
    ///
    /// Get dirty log error
    ///
    #[error("Failed to get dirty log")]
    GetDirtyLog(#[source] anyhow::Error),
    ///
    /// Assert virtual interrupt error
    ///
    #[error("Failed to assert virtual Interrupt")]
    AssertVirtualInterrupt(#[source] anyhow::Error),

    #[cfg(feature = "sev_snp")]
    ///
    /// Error initializing SEV-SNP on the VM
    ///
    #[error("Failed to initialize SEV-SNP")]
    InitializeSevSnp(#[source] std::io::Error),

    #[cfg(feature = "tdx")]
    ///
    /// Error initializing TDX on the VM
    ///
    #[error("Failed to initialize TDX")]
    InitializeTdx(#[source] std::io::Error),
    #[cfg(feature = "tdx")]
    ///
    /// Error finalizing the TDX configuration on the VM
    ///
    #[error("Failed to finalize TDX")]
    FinalizeTdx(#[source] std::io::Error),
    #[cfg(feature = "tdx")]
    ///
    /// Error initializing the TDX memory region
    ///
    #[error("Failed to initialize memory region TDX")]
    InitMemRegionTdx(#[source] std::io::Error),
    ///
    /// Create Vgic error
    ///
    #[error("Failed to create Vgic")]
    CreateVgic(#[source] anyhow::Error),
    ///
    /// Create Vaia error
    ///
    #[error("Failed to create Vaia")]
    CreateVaia(#[source] anyhow::Error),
    ///
    /// Import isolated pages error
    ///
    #[error("Failed to import isolated pages")]
    ImportIsolatedPages(#[source] anyhow::Error),
    /// Failed to complete isolated import
    ///
    #[error("Failed to complete isolated import")]
    CompleteIsolatedImport(#[source] anyhow::Error),
    /// Failed to set VM property
    ///
    #[error("Failed to set VM property")]
    SetVmProperty(#[source] anyhow::Error),
    ///
    /// Modify GPA host access error
    ///
    #[cfg(feature = "sev_snp")]
    #[error("Failed to modify GPA host access")]
    ModifyGpaHostAccess(#[source] anyhow::Error),
    ///
    /// Failed to mmap
    ///
    #[cfg(feature = "sev_snp")]
    #[error("Failed to mmap:")]
    MmapToRoot,
    ///
    /// Failed to initialize VM
    ///
    #[error("Failed to initialize VM")]
    InitializeVm(#[source] anyhow::Error),
}
///
/// Result type for returning from a function
///
pub type Result<T> = std::result::Result<T, HypervisorVmError>;

/// Configuration data for legacy interrupts.
///
/// On x86 platforms, legacy interrupts means those interrupts routed through PICs or IOAPICs.
#[derive(Copy, Clone, Debug)]
pub struct LegacyIrqSourceConfig {
    pub irqchip: u32,
    pub pin: u32,
}

/// Configuration data for MSI/MSI-X interrupts.
///
/// On x86 platforms, these interrupts are vectors delivered directly to the LAPIC.
#[derive(Copy, Clone, Debug, Default)]
pub struct MsiIrqSourceConfig {
    /// High address to delivery message signaled interrupt.
    pub high_addr: u32,
    /// Low address to delivery message signaled interrupt.
    pub low_addr: u32,
    /// Data to write to delivery message signaled interrupt.
    pub data: u32,
    /// Unique ID of the device to delivery message signaled interrupt.
    pub devid: u32,
}

/// Configuration data for an interrupt source.
#[derive(Copy, Clone, Debug)]
pub enum InterruptSourceConfig {
    /// Configuration data for Legacy interrupts.
    LegacyIrq(LegacyIrqSourceConfig),
    /// Configuration data for PciMsi, PciMsix and generic MSI interrupts.
    MsiIrq(MsiIrqSourceConfig),
}

///
/// Trait to represent a Vm
///
/// This crate provides a hypervisor-agnostic interfaces for Vm
///
pub trait Vm: Send + Sync + Any {
    #[cfg(target_arch = "x86_64")]
    /// Sets the address of the one-page region in the VM's address space.
    fn set_identity_map_address(&self, address: u64) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    /// Sets the address of the three-page region in the VM's address space.
    fn set_tss_address(&self, offset: usize) -> Result<()>;
    #[cfg(not(target_arch = "riscv64"))]
    /// Creates an in-kernel interrupt controller.
    fn create_irq_chip(&self) -> Result<()>;
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()>;
    /// Unregister an event that will, when signaled, trigger the `gsi` IRQ.
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()>;
    /// Creates a new KVM vCPU file descriptor and maps the memory corresponding
    fn create_vcpu(&self, id: u32, vm_ops: Option<Arc<dyn VmOps>>) -> Result<Arc<dyn Vcpu>>;
    #[cfg(target_arch = "aarch64")]
    fn create_vgic(&self, config: VgicConfig) -> Result<Arc<Mutex<dyn Vgic>>>;
    #[cfg(target_arch = "riscv64")]
    fn create_vaia(&self, config: VaiaConfig) -> Result<Arc<Mutex<dyn Vaia>>>;

    /// Registers an event to be signaled whenever a certain address is written to.
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<DataMatch>,
    ) -> Result<()>;
    /// Unregister an event from a certain address it has been previously registered to.
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> Result<()>;
    // Construct a routing entry
    fn make_routing_entry(&self, gsi: u32, config: &InterruptSourceConfig) -> IrqRoutingEntry;
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
    ) -> UserMemoryRegion;
    /// Creates a guest physical memory slot.
    fn create_user_memory_region(&self, user_memory_region: UserMemoryRegion) -> Result<()>;
    /// Removes a guest physical memory slot.
    fn remove_user_memory_region(&self, user_memory_region: UserMemoryRegion) -> Result<()>;
    /// Returns the preferred CPU target type which can be emulated by KVM on underlying host.
    #[cfg(target_arch = "aarch64")]
    fn get_preferred_target(&self, kvi: &mut crate::VcpuInit) -> Result<()>;
    /// Enable split Irq capability
    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> Result<()>;
    /// Retrieve guest clock.
    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> Result<ClockData>;
    /// Set guest clock.
    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, data: &ClockData) -> Result<()>;
    /// Create a device that is used for passthrough
    fn create_passthrough_device(&self) -> Result<vfio_ioctls::VfioDeviceFd>;
    /// Start logging dirty pages
    fn start_dirty_log(&self) -> Result<()>;
    /// Stop logging dirty pages
    fn stop_dirty_log(&self) -> Result<()>;
    /// Get dirty pages bitmap
    fn get_dirty_log(&self, slot: u32, base_gpa: u64, memory_size: u64) -> Result<Vec<u64>>;
    #[cfg(feature = "sev_snp")]
    /// Initialize SEV-SNP on this VM
    fn sev_snp_init(&self) -> Result<()> {
        unimplemented!()
    }
    #[cfg(feature = "tdx")]
    /// Initialize TDX on this VM
    fn tdx_init(&self, _cpuid: &[CpuIdEntry], _max_vcpus: u32) -> Result<()> {
        unimplemented!()
    }
    #[cfg(feature = "tdx")]
    /// Finalize the configuration of TDX on this VM
    fn tdx_finalize(&self) -> Result<()> {
        unimplemented!()
    }
    #[cfg(feature = "tdx")]
    /// Initialize a TDX memory region for this VM
    fn tdx_init_memory_region(
        &self,
        _host_address: u64,
        _guest_address: u64,
        _size: u64,
        _measure: bool,
    ) -> Result<()> {
        unimplemented!()
    }
    /// Downcast to the underlying hypervisor VM type
    fn as_any(&self) -> &dyn Any;
    /// Import the isolated pages
    #[cfg(feature = "sev_snp")]
    fn import_isolated_pages(
        &self,
        _page_type: u32,
        _page_size: u32,
        _pages: &[u64],
    ) -> Result<()> {
        unimplemented!()
    }
    /// Complete the isolated import
    #[cfg(feature = "sev_snp")]
    fn complete_isolated_import(
        &self,
        _snp_id_block: IGVM_VHS_SNP_ID_BLOCK,
        _host_data: [u8; 32],
        _id_block_enabled: u8,
    ) -> Result<()> {
        unimplemented!()
    }
    /// Initialize the VM
    fn init(&self) -> Result<()> {
        Ok(())
    }
    /// Pause the VM
    fn pause(&self) -> Result<()> {
        Ok(())
    }

    /// Resume the VM
    fn resume(&self) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "sev_snp")]
    fn gain_page_access(&self, _gpa: u64, _size: u32) -> Result<()> {
        Ok(())
    }

    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn enable_x2apic_api(&self) -> Result<()> {
        unimplemented!("x2Apic is only supported on KVM/Linux hosts")
    }
}

pub trait VmOps: Send + Sync {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> Result<usize>;
    fn guest_mem_read(&self, gpa: u64, buf: &mut [u8]) -> Result<usize>;
    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> Result<()>;
    fn mmio_write(&self, gpa: u64, data: &[u8]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, port: u64, data: &mut [u8]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, port: u64, data: &[u8]) -> Result<()>;
}
