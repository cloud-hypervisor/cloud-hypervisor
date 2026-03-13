// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;

use vmm_sys_util::eventfd::EventFd;
mod pci_common_config;
mod pci_device;
pub use pci_common_config::{VIRTIO_PCI_COMMON_CONFIG_ID, VirtioPciCommonConfig};
pub use pci_device::{
    PrivatelyConstructableError, VirtioPciDevice, VirtioPciDeviceActivator, VirtioPciDeviceError,
    doorbell_addr,
};

pub trait VirtioTransport {
    fn ioeventfds<T: Debug>(
        &self,
        old_base_addr: u64,
        new_base_addr: u64,
        cb: &mut dyn FnMut(&EventFd, u64, u64) -> core::result::Result<(), T>,
    ) -> core::result::Result<(), T>;
}
