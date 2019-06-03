// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::*;
use libc::EINVAL;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use ioctls::CpuId;
use ioctls::{KvmRunWrapper, Result};
use kvm_ioctls::*;
use sys_ioctl::*;

/// Reasons for vCPU exits.
///
/// The exit reasons are mapped to the `KVM_EXIT_*` defines in the
/// [Linux KVM header](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/kvm.h).
///
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16 /* port */, &'a [u8] /* data */),
    /// An in port instruction was run on the given port.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    /// A read instruction was run against the given MMIO address.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    MmioRead(u64 /* address */, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64 /* address */, &'a [u8]),
    /// Corresponds to KVM_EXIT_UNKNOWN.
    Unknown,
    /// Corresponds to KVM_EXIT_EXCEPTION.
    Exception,
    /// Corresponds to KVM_EXIT_HYPERCALL.
    Hypercall,
    /// Corresponds to KVM_EXIT_DEBUG.
    Debug,
    /// Corresponds to KVM_EXIT_HLT.
    Hlt,
    /// Corresponds to KVM_EXIT_IRQ_WINDOW_OPEN.
    IrqWindowOpen,
    /// Corresponds to KVM_EXIT_SHUTDOWN.
    Shutdown,
    /// Corresponds to KVM_EXIT_FAIL_ENTRY.
    FailEntry,
    /// Corresponds to KVM_EXIT_INTR.
    Intr,
    /// Corresponds to KVM_EXIT_SET_TPR.
    SetTpr,
    /// Corresponds to KVM_EXIT_TPR_ACCESS.
    TprAccess,
    /// Corresponds to KVM_EXIT_S390_SIEIC.
    S390Sieic,
    /// Corresponds to KVM_EXIT_S390_RESET.
    S390Reset,
    /// Corresponds to KVM_EXIT_DCR.
    Dcr,
    /// Corresponds to KVM_EXIT_NMI.
    Nmi,
    /// Corresponds to KVM_EXIT_INTERNAL_ERROR.
    InternalError,
    /// Corresponds to KVM_EXIT_OSI.
    Osi,
    /// Corresponds to KVM_EXIT_PAPR_HCALL.
    PaprHcall,
    /// Corresponds to KVM_EXIT_S390_UCONTROL.
    S390Ucontrol,
    /// Corresponds to KVM_EXIT_WATCHDOG.
    Watchdog,
    /// Corresponds to KVM_EXIT_S390_TSCH.
    S390Tsch,
    /// Corresponds to KVM_EXIT_EPR.
    Epr,
    /// Corresponds to KVM_EXIT_SYSTEM_EVENT.
    SystemEvent,
    /// Corresponds to KVM_EXIT_S390_STSI.
    S390Stsi,
    /// Corresponds to KVM_EXIT_IOAPIC_EOI.
    IoapicEoi,
    /// Corresponds to KVM_EXIT_HYPERV.
    Hyperv,
}

/// Wrapper over KVM vCPU ioctls.
pub struct VcpuFd {
    vcpu: File,
    kvm_run_ptr: KvmRunWrapper,
}

impl VcpuFd {
    /// Returns the vCPU general purpose registers.
    ///
    /// The registers are returned in a `kvm_regs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_REGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// let regs = vcpu.get_regs().unwrap();
    /// ```
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<kvm_regs> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(regs)
    }

    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `regs` - general purpose registers. For details check the `kvm_regs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))] {
    ///     // Get the current vCPU registers.
    ///     let mut regs = vcpu.get_regs().unwrap();
    ///     // Set a new value for the Instruction Pointer.
    ///     regs.rip = 0x100;
    ///     vcpu.set_regs(&regs).unwrap();
    /// }
    /// ```
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_REGS(), regs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns the vCPU special registers.
    ///
    /// The registers are returned in a `kvm_sregs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_SREGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// let sregs = vcpu.get_sregs().unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = kvm_sregs::default();

        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(regs)
    }

    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `sregs` - Special registers. For details check the `kvm_sregs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))] {
    ///     let mut sregs = vcpu.get_sregs().unwrap();
    ///     // Update the code segment (cs).
    ///     sregs.cs.base = 0;
    ///     sregs.cs.selector = 0;
    ///     vcpu.set_sregs(&sregs).unwrap();
    /// }
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), sregs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns the floating point state (FPU) from the vCPU.
    ///
    /// The state is returned in a `kvm_fpu` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_FPU`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// let fpu = vcpu.get_fpu().unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        let mut fpu = kvm_fpu::default();

        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut fpu)
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fpu)
    }

    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioct.
    ///
    /// # Arguments
    ///
    /// * `fpu` - FPU configuration. For details check the `kvm_fpu` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// # use kvm_bindings::kvm_fpu;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    ///     let KVM_FPU_CWD: u16 = 0x37f;
    ///     let fpu = kvm_fpu {
    ///         fcw: KVM_FPU_CWD,
    ///         ..Default::default()
    ///     };
    ///     vcpu.set_fpu(&fpu).unwrap();
    /// }
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_ref(self, KVM_SET_FPU(), fpu)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// X86 specific call to setup the CPUID registers.
    ///
    /// See the documentation for `KVM_SET_CPUID2`.
    ///
    /// # Arguments
    ///
    /// * `cpuid` - CPUID registers.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd, MAX_KVM_CPUID_ENTRIES};
    /// # use kvm_bindings::kvm_fpu;
    /// let kvm = Kvm::new().unwrap();
    /// let mut kvm_cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Update the CPUID entries to disable the EPB feature.
    /// const ECX_EPB_SHIFT: u32 = 3;
    /// {
    ///     let entries = kvm_cpuid.mut_entries_slice();
    ///     for entry in entries.iter_mut() {
    ///         match entry.function {
    ///             6 => entry.ecx &= !(1 << ECX_EPB_SHIFT),
    ///             _ => (),
    ///         }
    ///     }
    /// }
    ///
    /// vcpu.set_cpuid2(&kvm_cpuid);
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_cpuid2 struct.
            ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_ptr())
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// The state is returned in a `kvm_lapic_state` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_LAPIC`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let lapic = vcpu.get_lapic().unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic = kvm_lapic_state::default();

        let ret = unsafe {
            // The ioctl is unsafe unless you trust the kernel not to write past the end of the
            // local_apic struct.
            ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(klapic)
    }

    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// See the documentation for `KVM_SET_LAPIC`.
    ///
    /// # Arguments
    ///
    /// * `klapic` - LAPIC state. For details check the `kvm_lapic_state` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// use std::io::Write;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mut lapic = vcpu.get_lapic().unwrap();
    ///
    /// // Write to APIC_ICR offset the value 2.
    /// let apic_icr_offset = 0x300;
    /// let write_value: &[u8] = &[2, 0, 0, 0];
    /// let mut apic_icr_slice =
    ///     unsafe { &mut *(&mut lapic.regs[apic_icr_offset..] as *mut [i8] as *mut [u8]) };
    /// apic_icr_slice.write(write_value).unwrap();
    ///
    /// // Update the value of LAPIC.
    ///vcpu.set_lapic(&lapic).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the klapic struct.
            ioctl_with_ref(self, KVM_SET_LAPIC(), klapic)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    /// It emulates `KVM_GET_MSRS` ioctl's behavior by returning the number of MSRs
    /// successfully read upon success or the last error number in case of failure.
    /// The MSRs are returned in the `msr` method argument.
    ///
    /// # Arguments
    ///
    /// * `msrs`  - MSRs (input/output). For details check the `kvm_msrs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// # use kvm_bindings::kvm_msrs;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mut msrs = kvm_msrs::default();
    /// vcpu.get_msrs(&mut msrs).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msrs: &mut kvm_msrs) -> Result<(i32)> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_mut_ref(self, KVM_GET_MSRS(), msrs)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret)
    }

    /// Setup the model-specific registers (MSR) for this vCPU.
    ///
    /// See the documentation for `KVM_SET_MSRS`.
    ///
    /// # Arguments
    ///
    /// * `msrs` - MSRs. For details check the `kvm_msrs` structure in the
    ///            [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// # use kvm_bindings::{kvm_msrs, kvm_msr_entry};
    /// # use std::mem;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mut msrs = kvm_msrs::default();
    /// vcpu.get_msrs(&mut msrs).unwrap();
    ///
    /// let msrs_entries = {
    ///     kvm_msr_entry {
    ///         index: 0x0000_0174,
    ///         ..Default::default()
    ///     }
    /// };
    ///
    /// // Create a vector large enough to hold the MSR entry defined above in
    /// // a `kvm_msrs`structure.
    /// let msrs_vec: Vec<u8> =
    ///     Vec::with_capacity(mem::size_of::<kvm_msrs>() + mem::size_of::<kvm_msr_entry>());
    /// let mut msrs: &mut kvm_msrs = unsafe {
    ///     &mut *(msrs_vec.as_ptr() as *mut kvm_msrs)
    /// };
    /// msrs.nmsrs = 1;
    /// vcpu.set_msrs(msrs).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_msrs(&self, msrs: &kvm_msrs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_SET_MSRS(), msrs)
        };
        if ret < 0 {
            // KVM_SET_MSRS actually returns the number of msr entries written.
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sets the type of CPU to be exposed to the guest and optional features.
    ///
    /// This initializes an ARM vCPU to the specified type with the specified features
    /// and resets the values of all of its registers to defaults. See the documentation for
    /// `KVM_ARM_VCPU_INIT`.
    ///
    /// # Arguments
    ///
    /// * `kvi` - information about preferred CPU target type and recommended features for it.
    ///           For details check the `kvm_vcpu_init` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// use kvm_bindings::kvm_vcpu_init;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let mut kvi = kvm_vcpu_init::default();
    /// vm.get_preferred_target(&mut kvi).unwrap();
    /// vcpu.vcpu_init(&kvi).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        // This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT(), kvi) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sets the value of one register for this vCPU.
    ///
    /// The id of the register is encoded as specified in the kernel documentation
    /// for `KVM_SET_ONE_REG`.
    ///
    /// # Arguments
    ///
    /// * `reg_id` - ID of the register for which we are setting the value.
    /// * `data` - value for the specified register.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()> {
        let data_ref = &data as *const u64;
        let onereg = kvm_one_reg {
            id: reg_id,
            addr: data_ref as u64,
        };
        // This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG(), &onereg) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    /// See documentation for `KVM_RUN`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use std::io::Write;
    /// # use std::ptr::null_mut;
    /// # use std::slice;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd, VcpuExit};
    /// # use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
    /// # let kvm = Kvm::new().unwrap();
    /// # let vm = kvm.create_vm().unwrap();
    /// // This is a dummy example for running on x86 based on https://lwn.net/Articles/658511/.
    /// #[cfg(target_arch = "x86_64")] {
    ///     let mem_size = 0x4000;
    ///     let guest_addr: u64 = 0x1000;
    ///     let load_addr: *mut u8 = unsafe {
    ///         libc::mmap(
    ///             null_mut(),
    ///             mem_size,
    ///             libc::PROT_READ | libc::PROT_WRITE,
    ///             libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
    ///             -1,
    ///             0,
    ///         ) as *mut u8
    ///     };
    ///
    ///     let mem_region = kvm_userspace_memory_region {
    ///         slot: 0,
    ///         guest_phys_addr: guest_addr,
    ///         memory_size: mem_size as u64,
    ///         userspace_addr: load_addr as u64,
    ///         flags: 0,
    ///     };
    ///     vm.set_user_memory_region(mem_region).unwrap();
    ///
    ///     // Dummy x86 code that just calls halt.
    ///     let x86_code = [
    ///             0xf4,             /* hlt */
    ///     ];
    ///
    ///     // Write the code in the guest memory. This will generate a dirty page.
    ///     unsafe {
    ///         let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
    ///         slice.write(&x86_code).unwrap();
    ///     }
    ///
    ///     let vcpu_fd = vm.create_vcpu(0).unwrap();
    ///
    ///     let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    ///     vcpu_sregs.cs.base = 0;
    ///     vcpu_sregs.cs.selector = 0;
    ///     vcpu_fd.set_sregs(&vcpu_sregs).unwrap();
    ///
    ///     let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    ///     // Set the Instruction Pointer to the guest address where we loaded the code.
    ///     vcpu_regs.rip = guest_addr;
    ///     vcpu_regs.rax = 2;
    ///     vcpu_regs.rbx = 3;
    ///     vcpu_regs.rflags = 2;
    ///     vcpu_fd.set_regs(&vcpu_regs).unwrap();
    ///
    ///     loop {
    ///         match vcpu_fd.run().expect("run failed") {
    ///             VcpuExit::Hlt => {
    ///                 break;
    ///             }
    ///             exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
    ///         }
    ///     }
    /// }
    /// ```
    ///
    pub fn run(&self) -> Result<VcpuExit> {
        // Safe because we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN()) };
        if ret == 0 {
            let run = self.kvm_run_ptr.as_mut_ref();
            match run.exit_reason {
                // make sure you treat all possible exit reasons from include/uapi/linux/kvm.h corresponding
                // when upgrading to a different kernel version
                KVM_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
                KVM_EXIT_IO => {
                    let run_start = run as *mut kvm_run as *mut u8;
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let io = unsafe { run.__bindgen_anon_1.io };
                    let port = io.port;
                    let data_size = io.count as usize * io.size as usize;
                    // The data_offset is defined by the kernel to be some number of bytes into the
                    // kvm_run stucture, which we have fully mmap'd.
                    let data_ptr = unsafe { run_start.offset(io.data_offset as isize) };
                    // The slice's lifetime is limited to the lifetime of this vCPU, which is equal
                    // to the mmap of the `kvm_run` struct that this is slicing from.
                    let data_slice = unsafe {
                        std::slice::from_raw_parts_mut::<u8>(data_ptr as *mut u8, data_size)
                    };
                    match u32::from(io.direction) {
                        KVM_EXIT_IO_IN => Ok(VcpuExit::IoIn(port, data_slice)),
                        KVM_EXIT_IO_OUT => Ok(VcpuExit::IoOut(port, data_slice)),
                        _ => Err(io::Error::from_raw_os_error(EINVAL)),
                    }
                }
                KVM_EXIT_HYPERCALL => Ok(VcpuExit::Hypercall),
                KVM_EXIT_DEBUG => Ok(VcpuExit::Debug),
                KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
                KVM_EXIT_MMIO => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
                    let addr = mmio.phys_addr;
                    let len = mmio.len as usize;
                    let data_slice = &mut mmio.data[..len];
                    if mmio.is_write != 0 {
                        Ok(VcpuExit::MmioWrite(addr, data_slice))
                    } else {
                        Ok(VcpuExit::MmioRead(addr, data_slice))
                    }
                }
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => Ok(VcpuExit::FailEntry),
                KVM_EXIT_INTR => Ok(VcpuExit::Intr),
                KVM_EXIT_SET_TPR => Ok(VcpuExit::SetTpr),
                KVM_EXIT_TPR_ACCESS => Ok(VcpuExit::TprAccess),
                KVM_EXIT_S390_SIEIC => Ok(VcpuExit::S390Sieic),
                KVM_EXIT_S390_RESET => Ok(VcpuExit::S390Reset),
                KVM_EXIT_DCR => Ok(VcpuExit::Dcr),
                KVM_EXIT_NMI => Ok(VcpuExit::Nmi),
                KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
                KVM_EXIT_OSI => Ok(VcpuExit::Osi),
                KVM_EXIT_PAPR_HCALL => Ok(VcpuExit::PaprHcall),
                KVM_EXIT_S390_UCONTROL => Ok(VcpuExit::S390Ucontrol),
                KVM_EXIT_WATCHDOG => Ok(VcpuExit::Watchdog),
                KVM_EXIT_S390_TSCH => Ok(VcpuExit::S390Tsch),
                KVM_EXIT_EPR => Ok(VcpuExit::Epr),
                KVM_EXIT_SYSTEM_EVENT => Ok(VcpuExit::SystemEvent),
                KVM_EXIT_S390_STSI => Ok(VcpuExit::S390Stsi),
                KVM_EXIT_IOAPIC_EOI => Ok(VcpuExit::IoapicEoi),
                KVM_EXIT_HYPERV => Ok(VcpuExit::Hyperv),
                r => panic!("unknown kvm exit reason: {}", r),
            }
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Helper function to create a new `VcpuFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vcpu` from `VmFd`. The function cannot be part of the `VcpuFd` implementation because
/// then it would be exported with the public `VcpuFd` interface.
pub fn new_vcpu(vcpu: File, kvm_run_ptr: KvmRunWrapper) -> VcpuFd {
    VcpuFd { vcpu, kvm_run_ptr }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    extern crate byteorder;

    use super::*;
    use ioctls::system::Kvm;
    use Cap;
    use MAX_KVM_CPUID_ENTRIES;

    use std::os::unix::io::FromRawFd;
    use std::ptr::null_mut;

    // Helper function for memory mapping `size` bytes of anonymous memory.
    // Panics if the mmap fails.
    fn mmap_anonymous(size: usize) -> *mut u8 {
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            panic!("mmap failed.");
        }

        return addr as *mut u8;
    }

    #[test]
    fn test_create_vcpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        assert!(vm.create_vcpu(0).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_cpuid2() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ExtCpuid) {
            let vm = kvm.create_vm().unwrap();
            let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
            assert!(cpuid.mut_entries_slice().len() <= MAX_KVM_CPUID_ENTRIES);
            let nr_vcpus = kvm.get_nr_vcpus();
            for cpu_id in 0..nr_vcpus {
                let vcpu = vm.create_vcpu(cpu_id as u8).unwrap();
                vcpu.set_cpuid2(&cpuid).unwrap();
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(non_snake_case)]
    #[test]
    fn test_fpu() {
        // as per https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/fpu/internal.h
        let KVM_FPU_CWD: usize = 0x37f;
        let KVM_FPU_MXCSR: usize = 0x1f80;
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut fpu: kvm_fpu = kvm_fpu {
            fcw: KVM_FPU_CWD as u16,
            mxcsr: KVM_FPU_MXCSR as u32,
            ..Default::default()
        };

        fpu.fcw = KVM_FPU_CWD as u16;
        fpu.mxcsr = KVM_FPU_MXCSR as u32;

        vcpu.set_fpu(&fpu).unwrap();
        assert_eq!(vcpu.get_fpu().unwrap().fcw, KVM_FPU_CWD as u16);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn lapic_test() {
        use std::io::Cursor;
        // We might get read of byteorder if we replace mem::transmute with something safer.
        use self::byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
        // As per https://github.com/torvalds/linux/arch/x86/kvm/lapic.c
        // Try to write and read the APIC_ICR (0x300) register which is non-read only and
        // one can simply write to it.
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::Irqchip));
        let vm = kvm.create_vm().unwrap();
        // The get_lapic ioctl will fail if there is no irqchip created beforehand.
        assert!(vm.create_irq_chip().is_ok());
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut klapic: kvm_lapic_state = vcpu.get_lapic().unwrap();

        let reg_offset = 0x300;
        let value = 2 as u32;
        //try to write and read the APIC_ICR	0x300
        let write_slice =
            unsafe { &mut *(&mut klapic.regs[reg_offset..] as *mut [i8] as *mut [u8]) };
        let mut writer = Cursor::new(write_slice);
        writer.write_u32::<LittleEndian>(value).unwrap();
        vcpu.set_lapic(&klapic).unwrap();
        klapic = vcpu.get_lapic().unwrap();
        let read_slice = unsafe { &*(&klapic.regs[reg_offset..] as *const [i8] as *const [u8]) };
        let mut reader = Cursor::new(read_slice);
        assert_eq!(reader.read_u32::<LittleEndian>().unwrap(), value);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn msrs_test() {
        use std::mem;
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut configured_entry_vec = Vec::<kvm_msr_entry>::new();

        configured_entry_vec.push(kvm_msr_entry {
            index: 0x0000_0174,
            data: 0x0,
            ..Default::default()
        });
        configured_entry_vec.push(kvm_msr_entry {
            index: 0x0000_0175,
            data: 0x1,
            ..Default::default()
        });

        let vec_size_bytes = mem::size_of::<kvm_msrs>()
            + (configured_entry_vec.len() * mem::size_of::<kvm_msr_entry>());
        let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        let msrs: &mut kvm_msrs = unsafe { &mut *(vec.as_ptr() as *mut kvm_msrs) };
        unsafe {
            let entries: &mut [kvm_msr_entry] =
                msrs.entries.as_mut_slice(configured_entry_vec.len());
            entries.copy_from_slice(&configured_entry_vec);
        }
        msrs.nmsrs = configured_entry_vec.len() as u32;
        vcpu.set_msrs(msrs).unwrap();

        //now test that GET_MSRS returns the same
        let wanted_kvm_msrs_entries = [
            kvm_msr_entry {
                index: 0x0000_0174,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x0000_0175,
                ..Default::default()
            },
        ];
        let vec2: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        let mut msrs2: &mut kvm_msrs = unsafe {
            // Converting the vector's memory to a struct is unsafe.  Carefully using the read-only
            // vector to size and set the members ensures no out-of-bounds errors below.
            &mut *(vec2.as_ptr() as *mut kvm_msrs)
        };

        unsafe {
            let entries: &mut [kvm_msr_entry] =
                msrs2.entries.as_mut_slice(configured_entry_vec.len());
            entries.copy_from_slice(&wanted_kvm_msrs_entries);
        }
        msrs2.nmsrs = configured_entry_vec.len() as u32;

        let read_msrs = vcpu.get_msrs(&mut msrs2).unwrap();
        assert_eq!(read_msrs, configured_entry_vec.len() as i32);

        let returned_kvm_msr_entries: &mut [kvm_msr_entry] =
            unsafe { msrs2.entries.as_mut_slice(msrs2.nmsrs as usize) };

        for (i, entry) in returned_kvm_msr_entries.iter_mut().enumerate() {
            assert_eq!(entry, &mut configured_entry_vec[i]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_code() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        // This example is based on https://lwn.net/Articles/658511/
        #[rustfmt::skip]
        let code = [
            0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
            0x00, 0xd8, /* add %bl, %al */
            0x04, b'0', /* add $'0', %al */
            0xee, /* out %al, %dx */
            0xec, /* in %dx, %al */
            0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
            0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
            0xc6, 0x06, 0x00, 0x20, 0x00, /* movl $0, (0x2000); Dirty one page in guest mem. */
            0xf4, /* hlt */
        ];

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size);
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        vm.set_user_memory_region(mem_region).unwrap();

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write(&code).unwrap();
        }

        let vcpu_fd = vm.create_vcpu(0).unwrap();

        let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
        // Set the Instruction Pointer to the guest address where we loaded the code.
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd.set_regs(&vcpu_regs).unwrap();

        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::IoOut(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], b'5');
                }
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], 0);
                }
                VcpuExit::Hlt => {
                    // The code snippet dirties 2 pages:
                    // * one when the code itself is loaded in memory;
                    // * and one more from the `movl` that writes to address 0x8000
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .fold(0, |dirty_page_count, i| dirty_page_count + i);
                    assert_eq!(dirty_pages, 2);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }

    fn get_raw_errno<T>(result: super::Result<T>) -> i32 {
        result.err().unwrap().raw_os_error().unwrap()
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_faulty_vcpu_fd() {
        let badf_errno = libc::EBADF;

        let faulty_vcpu_fd = VcpuFd {
            vcpu: unsafe { File::from_raw_fd(-1) },
            kvm_run_ptr: KvmRunWrapper {
                kvm_run_ptr: mmap_anonymous(10),
            },
        };

        assert_eq!(get_raw_errno(faulty_vcpu_fd.get_regs()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_regs(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vcpu_fd.get_sregs()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_sregs(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vcpu_fd.get_fpu()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_fpu(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(
                faulty_vcpu_fd.set_cpuid2(
                    &Kvm::new()
                        .unwrap()
                        .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
                        .unwrap()
                )
            ),
            badf_errno
        );
        // `kvm_lapic_state` does not implement debug by default so we cannot
        // use unwrap_err here.
        assert!(faulty_vcpu_fd.get_lapic().is_err());
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_lapic(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.get_msrs(&mut kvm_msrs::default())),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_msrs(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vcpu_fd.run()), badf_errno);
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn test_get_preferred_target() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        assert!(vcpu.vcpu_init(&kvi).is_err());

        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        assert!(vcpu.vcpu_init(&kvi).is_ok());
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn test_set_one_reg() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        vcpu.vcpu_init(&kvi).expect("Cannot initialize vcpu");
        let mut data: u64 = 0;
        let mut reg_id: u64 = 0;

        assert!(vcpu.set_one_reg(reg_id, data).is_err());
        // Exercising KVM_SET_ONE_REG by trying to alter the data inside the PSTATE register (which is a
        // specific aarch64 register).
        const PSTATE_REG_ID: u64 = 0x6030_0000_0010_0042;
        vcpu.set_one_reg(PSTATE_REG_ID, data)
            .expect("Failed to set pstate register");
    }
}
