// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::eventfd::EventFd;
mod pci_common_config;
mod pci_device;
pub use pci_common_config::VirtioPciCommonConfig;
pub use pci_device::VirtioPciDevice;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_queue::Error as QueueError;

pub trait VirtioTransport {
    fn ioeventfds(&self, base_addr: u64) -> Vec<(&EventFd, u64)>;
}

#[derive(Versionize)]
struct QueueState {
    max_size: u16,
    size: u16,
    ready: bool,
    vector: u16,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
}

#[derive(Debug)]
enum Error {
    /// Failed to retrieve queue ring's index.
    QueueRingIndex(QueueError),
}
