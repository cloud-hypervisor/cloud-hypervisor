// Copyright © 2024 Institute of Software, CAS. All rights reserved.
// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//
// Memory layout of RISC-V 64-bit guest:
//
// Physical  +---------------------------------------------------------------+
// address   |                                                               |
// end       |                                                               |
//           ~                   ~                       ~                   ~
//           |                                                               |
//           |                    Highmem PCI MMIO space                     |
//           |                                                               |
// RAM end   +---------------------------------------------------------------+
// (dynamic, |                                                               |
// including |                                                               |
// hotplug   ~                   ~                       ~                   ~
// memory)   |                                                               |
//           |                             DRAM                              |
//           |                                                               |
//           |                                                               |
//           |                                                               |
//           |                                                               |
//    1 GB   +---------------------------------------------------------------+
//           |                                                               |
//           |                      PCI MMCONFIG space                       |
//           |                                                               |
//  768 MB   +---------------------------------------------------------------+
//           |                                                               |
//           |                                                               |
//           |                        PCI MMIO space                         |
//           |                                                               |
//  256 MB   +---------------------------------------------------------------|
//           |                                                               |
//           |                     Legacy devices space                      |
//           |                                                               |
//  128 MB   +---------------------------------------------------------------|
//           |                                                               |
//           |                            IMSICs                             |
//           |                                                               |
//   64 MB   +---------------------------------------------------------------+
//           |                                                               |
//           |                            APLICs                             |
//           |                                                               |
//    4 MB   +---------------------------------------------------------------+
//           |                          UEFI flash                           |
//    0 GB   +---------------------------------------------------------------+
//
//

use vm_memory::GuestAddress;

/// 0x0 ~ 0x40_0000 (4 MiB) is reserved to UEFI
/// UEFI binary size is required less than 3 MiB, reserving 4 MiB is enough.
pub const UEFI_START: GuestAddress = GuestAddress(0);
pub const UEFI_SIZE: u64 = 0x040_0000;

/// AIA related devices
/// See https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/uapi/asm/kvm.h
/// 0x40_0000 ~ 0x0400_0000 (64 MiB) resides APLICs
pub const APLIC_START: GuestAddress = GuestAddress(0x40_0000);
pub const APLIC_SIZE: u64 = 0x4000;

/// 0x0400_0000 ~ 0x0800_0000 (64 MiB) resides IMSICs
pub const IMSIC_START: GuestAddress = GuestAddress(0x0400_0000);
pub const IMSIC_SIZE: u64 = 0x1000;

/// Below this address will reside the AIA, above this address will reside the MMIO devices.
const MAPPED_IO_START: GuestAddress = GuestAddress(0x0800_0000);

/// Space 0x0800_0000 ~ 0x1000_0000 is reserved for legacy devices.
pub const LEGACY_SERIAL_MAPPED_IO_START: GuestAddress = MAPPED_IO_START;

/// Space 0x0905_0000 ~ 0x0906_0000 is reserved for pcie io address
pub const MEM_PCI_IO_START: GuestAddress = GuestAddress(0x0905_0000);
pub const MEM_PCI_IO_SIZE: u64 = 0x1_0000;

/// Starting from 0x1000_0000 (256MiB) to 0x3000_0000 (768MiB) is used for PCIE MMIO
pub const MEM_32BIT_DEVICES_START: GuestAddress = GuestAddress(0x1000_0000);
pub const MEM_32BIT_DEVICES_SIZE: u64 = 0x2000_0000;

/// PCI MMCONFIG space (start: after the device space at 768MiB, length: 256MiB)
pub const PCI_MMCONFIG_START: GuestAddress = GuestAddress(0x3000_0000);
pub const PCI_MMCONFIG_SIZE: u64 = 256 << 20;
// One bus with potentially 256 devices (32 slots x 8 functions).
pub const PCI_MMIO_CONFIG_SIZE_PER_SEGMENT: u64 = 4096 * 256;

/// Start of RAM.
pub const RAM_START: GuestAddress = GuestAddress(0x4000_0000);

/// Kernel command line maximum size on RISC-V.
/// See https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/uapi/asm/setup.h
pub const CMDLINE_MAX_SIZE: usize = 1024;

/// FDT is at the beginning of RAM.
pub const FDT_START: GuestAddress = RAM_START;
pub const FDT_MAX_SIZE: u64 = 0x1_0000;

/// Kernel start after FDT
pub const KERNEL_START: GuestAddress = GuestAddress(RAM_START.0 + FDT_MAX_SIZE);

/// Pci high memory base
pub const PCI_HIGH_BASE: GuestAddress = GuestAddress(0x2_0000_0000);

/// First usable interrupt on riscv64
pub const IRQ_BASE: u32 = 0;

// As per https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/asm/kvm_host.h#L31
/// Number of supported interrupts
pub const IRQ_NUM: u32 = 1023;
