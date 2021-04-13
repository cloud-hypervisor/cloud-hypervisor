// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//
// Memory layout of Aarch64 guest:
//
// Physical  +---------------------------------------------------------------+
// address   |                                                               |
// end       |                                                               |
//           ~                   ~                       ~                   ~
//           |                                                               |
//           |                      Highmem PCI MMIO space                   |
//           |                                                               |
// RAM end   +---------------------------------------------------------------+
// (dynamic, |                                                               |
// including |                                                               |
// hotplug   ~                   ~                       ~                   ~
// memory)   |                                                               |
//           |                            DRAM                               |
//           |                                                               |
//           |                                                               |
//           |                                                               |
// 1GB       +---------------------------------------------------------------+
//           |                                                               |
//           |                        PCI MMCONFIG space                     |
//           |                                                               |
// 768 M     +---------------------------------------------------------------+
//           |                                                               |
//           |                                                               |
//           |                           PCI MMIO space                      |
//           |                                                               |
// 256 M     +---------------------------------------------------------------|
//           |                                                               |
//           |                        Legacy devices space                   |
//           |                                                               |
// 144 M     +---------------------------------------------------------------|
//           |                    Reserved (now GIC is here)                 |
// 128 M     +---------------------------------------------------------------+
//           |                                                               |
//           |                          UEFI space                           |
//           |                                                               |
// 0GB       +---------------------------------------------------------------+
//
//

use vm_memory::GuestAddress;

/// 0x0 ~ 0x800_0000 is reserved to uefi
pub const UEFI_START: u64 = 0x0;
pub const MEM_UEFI_START: GuestAddress = GuestAddress(0);
pub const UEFI_SIZE: u64 = 0x0800_0000;

/// Below this address will reside the GIC, above this address will reside the MMIO devices.
pub const MAPPED_IO_START: u64 = 0x0900_0000;

/// Space 0x0900_0000 ~ 0x1000_0000 is reserved for legacy devices.
pub const LEGACY_SERIAL_MAPPED_IO_START: u64 = 0x0900_0000;
pub const LEGACY_RTC_MAPPED_IO_START: u64 = 0x0901_0000;
pub const LEGACY_GPIO_MAPPED_IO_START: u64 = 0x0902_0000;

/// Space 0x0902_0000 ~ 0x903_0000 is reserved for pcie io address
pub const MEM_PCI_IO_START: GuestAddress = GuestAddress(0x0902_0000);
pub const MEM_PCI_IO_SIZE: u64 = 0x10000;

/// Legacy space will be allocated at once whiling setting up legacy devices.
pub const LEGACY_DEVICES_MAPPED_IO_SIZE: u64 = 0x0700_0000;

/// Starting from 0x1000_0000 (256MiB) to 0x3000_0000 (768MiB) is used for PCIE MMIO
pub const MEM_32BIT_DEVICES_START: GuestAddress = GuestAddress(0x1000_0000);
pub const MEM_32BIT_DEVICES_SIZE: u64 = 0x2000_0000;

/// PCI MMCONFIG space (start: after the device space at 1 GiB, length: 256MiB)
pub const PCI_MMCONFIG_START: GuestAddress = GuestAddress(0x3000_0000);
pub const PCI_MMCONFIG_SIZE: u64 = 256 << 20;

/// Start of RAM on 64 bit ARM.
pub const RAM_64BIT_START: u64 = 0x4000_0000;

/// Kernel command line maximum size.
/// As per `arch/arm64/include/uapi/asm/setup.h`.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Maximum size of the device tree blob as specified in https://www.kernel.org/doc/Documentation/arm64/booting.txt.
pub const FDT_MAX_SIZE: usize = 0x20_0000;

/// Put ACPI table above dtb
pub const ACPI_START: u64 = RAM_64BIT_START + FDT_MAX_SIZE as u64;
pub const RSDP_POINTER: GuestAddress = GuestAddress(ACPI_START);

// As per virt/kvm/arm/vgic/vgic-kvm-device.c we need
// the number of interrupts our GIC will support to be:
// * bigger than 32
// * less than 1023 and
// * a multiple of 32.
// We are setting up our interrupt controller to support a maximum of 256 interrupts.
/// First usable interrupt on aarch64.
pub const IRQ_BASE: u32 = 0;

/// Last usable interrupt on aarch64.
pub const IRQ_MAX: u32 = 255;
