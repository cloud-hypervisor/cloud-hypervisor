// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::eventfd::EventFd;
mod pci_common_config;
mod pci_device;
pub use pci_common_config::{VIRTIO_PCI_COMMON_CONFIG_ID, VirtioPciCommonConfig};
pub use pci_device::{
    MAX_DOORBELLS, VirtioPciDevice, VirtioPciDeviceActivator, VirtioPciDeviceError, doorbell_addr,
};

#[derive(Debug)]
pub enum IoeventfdError {
    RegisterIoevent(anyhow::Error),
    UnRegisterIoevent(anyhow::Error),
}

pub trait VirtioTransport {
    fn ioeventfds(
        &self,
        old_base_addr: u64,
        new_base_addr: u64,
        cb: &mut dyn FnMut(&EventFd, u64, u64) -> Result<(), IoeventfdError>,
    ) -> Result<(), IoeventfdError>;
}
