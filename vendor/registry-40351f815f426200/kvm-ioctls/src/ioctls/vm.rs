// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use ioctls::Result;
use kvm_bindings::*;
use std::fs::File;
use std::io;
use std::os::raw::{c_ulong, c_void};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use ioctls::device::new_device;
use ioctls::device::DeviceFd;
use ioctls::vcpu::new_vcpu;
use ioctls::vcpu::VcpuFd;
use ioctls::KvmRunWrapper;
use kvm_ioctls::*;
use sys_ioctl::*;

/// An address either in programmable I/O space or in memory mapped I/O space.
///
/// The `IoEventAddress` is used for specifying the type when registering an event
/// in [register_ioevent](struct.VmFd.html#method.register_ioevent).
///
pub enum IoEventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}

/// Helper structure for disabling datamatch.
///
/// The structure can be used as a parameter to
/// [`register_ioevent`](struct.VmFd.html#method.register_ioevent)
/// to disable filtering of events based on the datamatch flag. For details check the
/// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
///
pub struct NoDatamatch;
impl Into<u64> for NoDatamatch {
    fn into(self) -> u64 {
        0
    }
}

/// Wrapper over KVM VM ioctls.
pub struct VmFd {
    vm: File,
    run_size: usize,
}

impl VmFd {
    /// Creates/modifies a guest physical memory slot.
    ///
    /// See the documentation for `KVM_SET_USER_MEMORY_REGION`.
    ///
    /// # Arguments
    ///
    /// * `user_memory_region` - Guest physical memory slot. For details check the
    ///             `kvm_userspace_memory_region` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// extern crate kvm_bindings;
    ///
    /// use kvm_ioctls::{Kvm, VmFd};
    /// use kvm_bindings::kvm_userspace_memory_region;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mem_region = kvm_userspace_memory_region {
    ///                     slot: 0,
    ///                     guest_phys_addr: 0x1000 as u64,
    ///                     memory_size: 0x4000 as u64,
    ///                     userspace_addr: 0x0 as u64,
    ///                     flags: 0,
    ///                 };
    /// vm.set_user_memory_region(mem_region).unwrap();
    /// ```
    ///
    pub fn set_user_memory_region(
        &self,
        user_memory_region: kvm_userspace_memory_region,
    ) -> Result<()> {
        let ret =
            unsafe { ioctl_with_ref(self, KVM_SET_USER_MEMORY_REGION(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation for `KVM_SET_TSS_ADDR`.
    ///
    /// # Arguments
    ///
    /// * `offset` - Physical address of a three-page region in the guest's physical address space.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// vm.set_tss_address(0xfffb_d000).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_tss_address(&self, offset: usize) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSS_ADDR(), offset as c_ulong) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates an in-kernel interrupt controller.
    ///
    /// See the documentation for `KVM_CREATE_IRQCHIP`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// vm.create_irq_chip().unwrap();
    /// ```
    ///
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn create_irq_chip(&self) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_CREATE_IRQCHIP()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates a PIT as per the `KVM_CREATE_PIT2` ioctl.
    ///
    /// # Arguments
    ///
    /// * pit_config - PIT configuration. For details check the `kvm_pit_config` structure in the
    ///                [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd};
    /// use kvm_bindings::kvm_pit_config;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let pit_config = kvm_pit_config::default();
    /// vm.create_pit2(pit_config).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn create_pit2(&self, pit_config: kvm_pit_config) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_PIT2(), &pit_config) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// See the documentation for `KVM_IOEVENTFD`.
    ///
    /// # Arguments
    ///
    /// * `fd` - FD which will be signaled. When signaling, the usual `vmexit` to userspace
    ///           is prevented.
    /// * `addr` - Address being written to.
    /// * `datamatch` - Limits signaling `fd` to only the cases where the value being written is
    ///                 equal to this parameter. The size of `datamatch` is important and it must
    ///                 match the expected size of the guest's write.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// extern crate libc;
    /// # use kvm_ioctls::{IoEventAddress, Kvm, NoDatamatch, VmFd};
    /// use libc::{eventfd, EFD_NONBLOCK};
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm_fd = kvm.create_vm().unwrap();
    /// let evtfd = unsafe { eventfd(0, EFD_NONBLOCK) };
    /// vm_fd
    ///    .register_ioevent(evtfd, &IoEventAddress::Pio(0xf4), NoDatamatch)
    ///    .unwrap();
    /// vm_fd
    ///    .register_ioevent(evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
    ///    .unwrap();
    /// ```
    ///
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        fd: RawFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        let mut flags = 0;
        if std::mem::size_of::<T>() > 0 {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        if let IoEventAddress::Pio(_) = *addr {
            flags |= 1 << kvm_ioeventfd_flag_nr_pio
        }

        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch.into(),
            len: std::mem::size_of::<T>() as u32,
            addr: match addr {
                IoEventAddress::Pio(ref p) => *p as u64,
                IoEventAddress::Mmio(ref m) => *m,
            },
            fd,
            flags,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Gets the bitmap of pages dirtied since the last call of this function.
    ///
    /// Leverages the dirty page logging feature in KVM. As a side-effect, this also resets the
    /// bitmap inside the kernel. For the dirty log to be available, you have to set the flag
    /// `KVM_MEM_LOG_DIRTY_PAGES` when creating guest memory regions.
    ///
    /// Check the documentation for `KVM_GET_DIRTY_LOG`.
    ///
    /// # Arguments
    ///
    /// * `slot` - Guest memory slot identifier.
    /// * `memory_size` - Size of the memory region.
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
    /// // This examples is based on https://lwn.net/Articles/658511/.
    /// let mem_size = 0x4000;
    /// let guest_addr: u64 = 0x1000;
    /// let load_addr: *mut u8 = unsafe {
    ///     libc::mmap(
    ///         null_mut(),
    ///         mem_size,
    ///         libc::PROT_READ | libc::PROT_WRITE,
    ///         libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
    ///         -1,
    ///         0,
    ///     ) as *mut u8
    /// };
    ///
    /// // Initialize a guest memory region using the flag `KVM_MEM_LOG_DIRTY_PAGES`.
    /// let mem_region = kvm_userspace_memory_region {
    ///     slot: 0,
    ///     guest_phys_addr: guest_addr,
    ///     memory_size: mem_size as u64,
    ///     userspace_addr: load_addr as u64,
    ///     flags: KVM_MEM_LOG_DIRTY_PAGES,
    /// };
    /// vm.set_user_memory_region(mem_region).unwrap();
    ///
    /// // Dummy x86 code that just calls halt.
    /// let x86_code = [
    ///         0xf4,             /* hlt */
    /// ];
    ///
    /// // Write the code in the guest memory. This will generate a dirty page.
    /// unsafe {
    ///     let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
    ///     slice.write(&x86_code).unwrap();
    /// }
    ///
    /// let vcpu_fd = vm.create_vcpu(0).unwrap();
    ///
    /// let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    /// vcpu_sregs.cs.base = 0;
    /// vcpu_sregs.cs.selector = 0;
    /// vcpu_fd.set_sregs(&vcpu_sregs).unwrap();
    ///
    /// let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    ///  // Set the Instruction Pointer to the guest address where we loaded the code.
    /// vcpu_regs.rip = guest_addr;
    /// vcpu_regs.rax = 2;
    /// vcpu_regs.rbx = 3;
    /// vcpu_regs.rflags = 2;
    /// vcpu_fd.set_regs(&vcpu_regs).unwrap();
    ///
    /// loop {
    ///     match vcpu_fd.run().expect("run failed") {
    ///         VcpuExit::Hlt => {
    ///             // The code snippet dirties 1 page when loading the code in memory.
    ///             let dirty_pages_bitmap = vm.get_dirty_log(0, mem_size).unwrap();
    ///             let dirty_pages = dirty_pages_bitmap
    ///                     .into_iter()
    ///                     .map(|page| page.count_ones())
    ///                     .fold(0, |dirty_page_count, i| dirty_page_count + i);
    ///             assert_eq!(dirty_pages, 1);
    ///             break;
    ///         }
    ///         exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
    ///     }
    /// }
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_dirty_log(&self, slot: u32, memory_size: usize) -> Result<Vec<u64>> {
        // Compute the length of the bitmap needed for all dirty pages in one memory slot.
        // One memory page is 4KiB (4096 bits) and `KVM_GET_DIRTY_LOG` returns one dirty bit for
        // each page.
        let page_size = 4 << 10;

        let div_round_up = |dividend, divisor| (dividend + divisor - 1) / divisor;
        // For ease of access we are saving the bitmap in a u64 vector. We are using ceil to
        // make sure we count all dirty pages even when `mem_size` is not a multiple of
        // page_size * 64.
        let bitmap_size = div_round_up(memory_size, page_size * 64);
        let mut bitmap = vec![0; bitmap_size];
        let b_data = bitmap.as_mut_ptr() as *mut c_void;
        let dirtylog = kvm_dirty_log {
            slot,
            padding1: 0,
            __bindgen_anon_1: kvm_dirty_log__bindgen_ty_1 {
                dirty_bitmap: b_data,
            },
        };
        // Safe because we know that our file is a VM fd, and we know that the amount of memory
        // we allocated for the bitmap is at least one bit per page.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_DIRTY_LOG(), &dirtylog) };
        if ret == 0 {
            Ok(bitmap)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - Event to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate libc;
    /// # use kvm_ioctls::{Kvm, VmFd};
    /// # use libc::{eventfd, EFD_NONBLOCK};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let evtfd = unsafe { eventfd(0, EFD_NONBLOCK) };
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// vm.register_irqfd(evtfd, 0).unwrap();
    /// ```
    ///
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd(&self, fd: RawFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: fd as u32,
            gsi,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates a new KVM vCPU file descriptor and maps the memory corresponding
    /// its `kvm_run` structure.
    ///
    /// See the documentation for `KVM_CREATE_VCPU`.
    ///
    /// # Arguments
    ///
    /// * `id` - The vCPU ID.
    ///
    /// # Errors
    ///
    /// Returns an io::Error when the VM fd is invalid or the vCPU memory cannot
    /// be mapped correctly.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // Create one vCPU with the ID=0.
    /// let vcpu = vm.create_vcpu(0);
    /// ```
    ///
    pub fn create_vcpu(&self, id: u8) -> Result<VcpuFd> {
        // Safe because we know that vm is a VM fd and we verify the return result.
        #[allow(clippy::cast_lossless)]
        let vcpu_fd = unsafe { ioctl_with_val(&self.vm, KVM_CREATE_VCPU(), id as c_ulong) };
        if vcpu_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Wrap the vCPU now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        let kvm_run_ptr = KvmRunWrapper::mmap_from_fd(&vcpu, self.run_size)?;

        Ok(new_vcpu(vcpu, kvm_run_ptr))
    }

    /// Creates an emulated device in the kernel.
    ///
    /// See the documentation for `KVM_CREATE_DEVICE`.
    ///
    /// # Arguments
    ///
    /// * `device`: device configuration. For details check the `kvm_create_device` structure in the
    ///                [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// use kvm_bindings::{
    ///     kvm_device_type_KVM_DEV_TYPE_VFIO,
    ///     kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    ///     KVM_CREATE_DEVICE_TEST,
    /// };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    ///
    /// // Creating a device with the KVM_CREATE_DEVICE_TEST flag to check
    /// // whether the device type is supported. This will not create the device.
    /// // To create the device the flag needs to be removed.
    /// let mut device = kvm_bindings::kvm_create_device {
    ///     #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ///     type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
    ///     #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    ///     type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    ///     fd: 0,
    ///     flags: KVM_CREATE_DEVICE_TEST,
    /// };
    /// let device_fd = vm
    ///     .create_device(&mut device).unwrap();
    /// ```
    ///
    pub fn create_device(&self, device: &mut kvm_create_device) -> Result<DeviceFd> {
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_DEVICE(), device) };
        if ret == 0 {
            Ok((new_device(unsafe { File::from_raw_fd(device.fd as i32) })))
        } else {
            return Err(io::Error::last_os_error());
        }
    }

    /// Returns the preferred CPU target type which can be emulated by KVM on underlying host.
    ///
    /// The preferred CPU target is returned in the `kvi` parameter.
    /// See documentation for `KVM_ARM_PREFERRED_TARGET`.
    ///
    /// # Arguments
    /// * `kvi` - CPU target configuration (out). For details check the `kvm_vcpu_init`
    ///           structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::{Kvm, VmFd, VcpuFd};
    /// use kvm_bindings::kvm_vcpu_init;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut kvi = kvm_vcpu_init::default();
    /// vm.get_preferred_target(&mut kvi).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn get_preferred_target(&self, kvi: &mut kvm_vcpu_init) -> Result<()> {
        // The ioctl is safe because we allocated the struct and we know the
        // kernel will write exactly the size of the struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_ARM_PREFERRED_TARGET(), kvi) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get the `kvm_run` size.
    pub fn run_size(&self) -> usize {
        self.run_size
    }
}

/// Helper function to create a new `VmFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vm` from `Kvm`. The function cannot be part of the `VmFd` implementation because
/// then it would be exported with the public `VmFd` interface.
pub fn new_vmfd(vm: File, run_size: usize) -> VmFd {
    VmFd { vm, run_size }
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {Cap, Kvm, MAX_KVM_CPUID_ENTRIES};

    use libc::{eventfd, EFD_NONBLOCK};

    #[test]
    fn test_set_invalid_memory() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let invalid_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        assert!(vm.set_user_memory_region(invalid_mem_region).is_err());
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_set_tss_address() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.set_tss_address(0xfffb_d000).is_ok());
    }

    #[test]
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    fn test_create_irq_chip() {
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::Irqchip));
        let vm = kvm.create_vm().unwrap();
        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            assert!(vm.create_irq_chip().is_ok());
        } else if cfg!(any(target_arch = "arm", target_arch = "aarch64")) {
            // On arm, we expect this to fail as the irq chip needs to be created after the vcpus.
            assert!(vm.create_irq_chip().is_err());
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_create_pit2() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.create_pit2(kvm_pit_config::default()).is_ok());
    }

    #[test]
    fn test_register_ioevent() {
        assert_eq!(std::mem::size_of::<NoDatamatch>(), 0);

        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let evtfd = unsafe { eventfd(0, EFD_NONBLOCK) };
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xf4), NoDatamatch)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc1), 0x7fu8)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc2), 0x1337u16)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc4), 0xdead_beefu32)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc8), 0xdead_beef_dead_beefu64)
            .is_ok());
    }

    #[test]
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    fn test_register_irqfd() {
        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let evtfd1 = unsafe { eventfd(0, EFD_NONBLOCK) };
        let evtfd2 = unsafe { eventfd(0, EFD_NONBLOCK) };
        let evtfd3 = unsafe { eventfd(0, EFD_NONBLOCK) };
        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            assert!(vm_fd.register_irqfd(evtfd1, 4).is_ok());
            assert!(vm_fd.register_irqfd(evtfd2, 8).is_ok());
            assert!(vm_fd.register_irqfd(evtfd3, 4).is_ok());
        }

        // On aarch64, this fails because setting up the interrupt controller is mandatory before
        // registering any IRQ.
        // On x86_64 this fails as the event fd was already matched with a GSI.
        assert!(vm_fd.register_irqfd(evtfd3, 4).is_err());
        assert!(vm_fd.register_irqfd(evtfd3, 5).is_err());
    }

    fn get_raw_errno<T>(result: super::Result<T>) -> i32 {
        result.err().unwrap().raw_os_error().unwrap()
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_faulty_vm_fd() {
        let badf_errno = libc::EBADF;

        let faulty_vm_fd = VmFd {
            vm: unsafe { File::from_raw_fd(-1) },
            run_size: 0,
        };

        let invalid_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };

        assert_eq!(
            get_raw_errno(faulty_vm_fd.set_user_memory_region(invalid_mem_region)),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vm_fd.set_tss_address(0)), badf_errno);
        assert_eq!(get_raw_errno(faulty_vm_fd.create_irq_chip()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vm_fd.create_pit2(kvm_pit_config::default())),
            badf_errno
        );
        let event_fd = unsafe { eventfd(0, EFD_NONBLOCK) };
        assert_eq!(
            get_raw_errno(faulty_vm_fd.register_ioevent(event_fd, &IoEventAddress::Pio(0), 0u64)),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vm_fd.register_irqfd(event_fd, 0)),
            badf_errno
        );

        assert_eq!(get_raw_errno(faulty_vm_fd.create_vcpu(0)), badf_errno);

        assert_eq!(get_raw_errno(faulty_vm_fd.get_dirty_log(0, 0)), badf_errno);
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn test_get_preferred_target() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        assert!(vm.get_preferred_target(&mut kvi).is_ok());
    }
}
