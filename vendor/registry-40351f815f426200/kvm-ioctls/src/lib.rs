// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![allow(unused)]
#![deny(missing_docs)]

//! A safe wrapper around the kernel's KVM interface.
//!
//! This crate offers safe wrappers for:
//! - [system ioctls](struct.Kvm.html) using the `Kvm` structure
//! - [VM ioctls](struct.VmFd.html) using the `VmFd` structure
//! - [vCPU ioctls](struct.VcpuFd.html) using the `VcpuFd` structure
//! - [device ioctls](struct.DeviceFd.html) using the `DeviceFd` structure
//!
//! # Platform support
//!
//! - x86_64
//! - arm64 (experimental)
//!
//! **NOTE:** The list of available ioctls is not extensive.
//!
//! # Example - Running a VM on x86_64
//!
//! In this example we are creating a Virtual Machine (VM) with one vCPU.
//! On the vCPU we are running x86_64 specific code. This example is based on
//! the [LWN article](https://lwn.net/Articles/658511/) on using the KVM API.
//!
//! To get code running on the vCPU we are going through the following steps:
//!
//! 1. Instantiate KVM. This is used for running
//!    [system specific ioctls](struct.Kvm.html).
//! 2. Use the KVM object to create a VM. The VM is used for running
//!    [VM specific ioctls](struct.VmFd.html).
//! 3. Initialize the guest memory for the created VM. In this dummy example we
//!    are adding only one memory region and write the code in one memory page.
//! 4. Create a vCPU using the VM object. The vCPU is used for running
//!    [vCPU specific ioctls](struct.VcpuFd.html).
//! 5. Setup x86 specific general purpose registers and special registers. For
//!    details about how and why these registers are set, please check the
//!    [LWN article](https://lwn.net/Articles/658511/) on which this example is
//!    built.
//! 6. Run the vCPU code in a loop and check the
//!    [exit reasons](enum.VcpuExit.html).
//!
//!
//! ```rust
//! extern crate kvm_ioctls;
//! extern crate kvm_bindings;
//!
//! use kvm_ioctls::{Kvm, VmFd, VcpuFd};
//! use kvm_ioctls::VcpuExit;
//!
//! #[cfg(target_arch = "x86_64")]
//! fn main(){
//!     use std::io::Write;
//!     use std::slice;
//!     use std::ptr::null_mut;
//!
//!     use kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES;
//!     use kvm_bindings::kvm_userspace_memory_region;
//!
//!     // 1. Instantiate KVM.
//!     let kvm = Kvm::new().unwrap();
//!
//!     // 2. Create a VM.
//!     let vm = kvm.create_vm().unwrap();
//!
//!     // 3. Initialize Guest Memory.
//!     let mem_size = 0x4000;
//!     let guest_addr: u64 = 0x1000;
//!     let load_addr: *mut u8 = unsafe {
//!         libc::mmap(
//!             null_mut(),
//!             mem_size,
//!             libc::PROT_READ | libc::PROT_WRITE,
//!             libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
//!             -1,
//!             0,
//!         ) as *mut u8
//!     };
//!
//!     let slot = 0;
//!     // When initializing the guest memory slot specify the
//!     // `KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
//!     let mem_region = kvm_userspace_memory_region {
//!         slot,
//!         guest_phys_addr: guest_addr,
//!         memory_size: mem_size as u64,
//!         userspace_addr: load_addr as u64,
//!         flags: KVM_MEM_LOG_DIRTY_PAGES,
//!     };
//!     vm.set_user_memory_region(mem_region).unwrap();
//!
//!
//!     let x86_code = [
//!         0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
//!         0x00, 0xd8, /* add %bl, %al */
//!         0x04, b'0', /* add $'0', %al */
//!         0xee, /* out %al, %dx */
//!         0xec, /* in %dx, %al */
//!         0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
//!         0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
//!         0xf4, /* hlt */
//!     ];
//!
//!     // Write the code in the guest memory. This will generate a dirty page.
//!     unsafe {
//!         let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
//!         slice.write(&x86_code).unwrap();
//!     }
//!
//!     // 4. Create one vCPU.
//!     let vcpu_fd = vm.create_vcpu(0).unwrap();
//!
//!     // 5. Initialize general purpose and special registers.
//!     let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
//!     vcpu_sregs.cs.base = 0;
//!     vcpu_sregs.cs.selector = 0;
//!     vcpu_fd.set_sregs(&vcpu_sregs).unwrap();
//!
//!     let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
//!     vcpu_regs.rip = guest_addr;
//!     vcpu_regs.rax = 2;
//!     vcpu_regs.rbx = 3;
//!     vcpu_regs.rflags = 2;
//!     vcpu_fd.set_regs(&vcpu_regs).unwrap();
//!
//!     // 6. Run code on the vCPU.
//!     loop {
//!         match vcpu_fd.run().expect("run failed") {
//!             VcpuExit::IoIn(addr, data) => {
//!                 println!(
//!                     "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
//!                     addr,
//!                     data[0],
//!                 );
//!             }
//!             VcpuExit::IoOut(addr, data) => {
//!                 println!(
//!                     "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
//!                     addr,
//!                     data[0],
//!                 );
//!             }
//!             VcpuExit::MmioRead(addr, data) => {
//!                 println!(
//!                     "Received an MMIO Read Request for the address {:#x}.",
//!                     addr,
//!                 );
//!             }
//!             VcpuExit::MmioWrite(addr, data) => {
//!                 println!(
//!                     "Received an MMIO Write Request to the address {:#x}.",
//!                     addr,
//!                 );
//!             }
//!             VcpuExit::Hlt => {
//!                 // The code snippet dirties 1 page when it is loaded in memory
//!                 let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
//!                 let dirty_pages = dirty_pages_bitmap
//!                     .into_iter()
//!                     .map(|page| page.count_ones())
//!                     .fold(0, |dirty_page_count, i| dirty_page_count + i);
//!                 assert_eq!(dirty_pages, 1);
//!                 break;
//!             }
//!             r => panic!("Unexpected exit reason: {:?}", r),
//!         }
//!     }
//! }
//!
//! #[cfg(not(target_arch = "x86_64"))]
//! fn main() {
//!     println!("This code example only works on x86_64.");
//! }
//! ```

extern crate kvm_bindings;
extern crate libc;

#[macro_use]
mod sys_ioctl;
#[macro_use]
mod kvm_ioctls;
mod cap;
mod ioctls;

pub use cap::Cap;
pub use ioctls::device::DeviceFd;
pub use ioctls::system::Kvm;
pub use ioctls::vcpu::{VcpuExit, VcpuFd};
pub use ioctls::vm::{IoEventAddress, NoDatamatch, VmFd};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use ioctls::CpuId;
// The following example is used to verify that our public
// structures are exported properly.
/// # Example
///
/// ```
/// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// use kvm_ioctls::{KvmRunWrapper, Result};
/// ```
pub use ioctls::{KvmRunWrapper, Result};

/// Maximum number of CPUID entries that can be returned by a call to KVM ioctls.
///
/// This value is taken from Linux Kernel v4.14.13 (arch/x86/include/asm/kvm_host.h).
/// It can be used for calls to [get_supported_cpuid](struct.Kvm.html#method.get_supported_cpuid) and
/// [get_emulated_cpuid](struct.Kvm.html#method.get_emulated_cpuid).
pub const MAX_KVM_CPUID_ENTRIES: usize = 80;
