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
// 2GB       +---------------------------------------------------------------+
//           |                                                               |
//           |                           Reserved                            |
//           |                                                               |
// 1G+256M   +---------------------------------------------------------------+
//           |                                                               |
//           |                        PCI MMCONFIG space                     |
//           |                                                               |
// 1GB       +---------------------------------------------------------------+
//           |                                                               |
//           |                           PCI MMIO space                      |
//           |                                                               |
// 256 M     +---------------------------------------------------------------|
//           |                                                               |
//           |                        Legacy devices space                   |
//           |                                                               |
// 144 M     +---------------------------------------------------------------|
//           |                                                               |
//           |                    Reserverd (now GIC is here)                |
//           |                                                               |
// 0GB       +---------------------------------------------------------------+
//
//

use vm_memory::{GuestAddress, GuestUsize};

/// Below this address will reside the GIC, above this address will reside the MMIO devices.
pub const MAPPED_IO_START: u64 = 0x0900_0000;

/// Space 0x0900_0000 ~ 0x1000_0000 is reserved for legacy devices.
pub const LEGACY_SERIAL_MAPPED_IO_START: u64 = 0x0900_0000;
pub const LEGACY_RTC_MAPPED_IO_START: u64 = 0x0901_0000;

/// Legacy space will be allocated at once whiling setting up legacy devices.
pub const LEGACY_DEVICES_MAPPED_IO_SIZE: u64 = 0x0700_0000;

/// Starting from 0x1000_0000 (256MiB), the 768MiB (ends at 1 GiB) is used for PCIE MMIO
pub const PCI_DEVICES_MAPPED_IO_START: u64 = 0x1000_0000;
pub const PCI_DEVICES_MAPPED_IO_SIZE: u64 = 0x3000_0000;

/// PCI MMCONFIG space (start: after the device space at 1 GiB, length: 256MiB)
pub const PCI_MMCONFIG_START: GuestAddress = GuestAddress(0x4000_0000);
pub const PCI_MMCONFIG_SIZE: GuestUsize = 256 << 20;

/// Start of RAM on 64 bit ARM.
pub const RAM_64BIT_START: u64 = 0x8000_0000;

/// Kernel command line maximum size.
/// As per `arch/arm64/include/uapi/asm/setup.h`.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Maximum size of the device tree blob as specified in https://www.kernel.org/doc/Documentation/arm64/booting.txt.
pub const FDT_MAX_SIZE: usize = 0x20_0000;

// As per virt/kvm/arm/vgic/vgic-kvm-device.c we need
// the number of interrupts our GIC will support to be:
// * bigger than 32
// * less than 1023 and
// * a multiple of 32.
// We are setting up our interrupt controller to support a maximum of 128 interrupts.
/// First usable interrupt on aarch64.
pub const IRQ_BASE: u32 = 32;

/// Last usable interrupt on aarch64.
pub const IRQ_MAX: u32 = 159;
