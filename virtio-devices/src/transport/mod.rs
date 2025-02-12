// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::eventfd::EventFd;
mod pci_common_config;
mod pci_device;
pub use pci_common_config::{VirtioPciCommonConfig, VIRTIO_PCI_COMMON_CONFIG_ID};
pub use pci_device::{VirtioPciDevice, VirtioPciDeviceActivator, VirtioPciDeviceError};

pub trait VirtioTransport {
    fn ioeventfds(&self, base_addr: u64) -> impl Iterator<Item = (&EventFd, u64)>;
}
