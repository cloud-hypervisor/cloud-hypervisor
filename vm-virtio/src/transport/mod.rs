// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "pci_support")]
mod pci_common_config;
#[cfg(feature = "pci_support")]
mod pci_device;
#[cfg(feature = "pci_support")]
pub use pci_common_config::VirtioPciCommonConfig;
#[cfg(feature = "pci_support")]
pub use pci_device::VirtioPciDevice;
