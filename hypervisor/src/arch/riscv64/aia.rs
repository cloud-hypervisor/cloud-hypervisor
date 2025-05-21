// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::result;

use thiserror::Error;

use crate::{AiaState, HypervisorDeviceError, HypervisorVmError};

/// Errors thrown while setting up the VAIA.
#[derive(Debug, Error)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    #[error("Failed creating AIA device")]
    CreateAia(#[source] HypervisorVmError),
    /// Error while setting device attributes for the AIA.
    #[error("Failed setting device attributes for the AIA")]
    SetDeviceAttribute(#[source] HypervisorDeviceError),
    /// Error while getting device attributes for the AIA.
    #[error("Failed getting device attributes for the AIA")]
    GetDeviceAttribute(#[source] HypervisorDeviceError),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct VaiaConfig {
    pub vcpu_count: u32,
    pub aplic_addr: u64,
    pub imsic_addr: u64,
    pub nr_irqs: u32,
}

/// Hypervisor agnostic interface for a virtualized AIA
pub trait Vaia: Send + Sync {
    /// Returns the compatibility property of APLIC
    fn aplic_compatibility(&self) -> &str;

    /// Returns an array with APLIC device properties
    fn aplic_properties(&self) -> [u32; 4];

    /// Returns the compatibility property of IMSIC
    fn imsic_compatibility(&self) -> &str;

    /// Returns an array with IMSIC device properties
    fn imsic_properties(&self) -> [u32; 4];

    /// Returns the number of vCPUs this AIA handles
    fn vcpu_count(&self) -> u32;

    /// Returns whether the AIA device is MSI compatible or not
    fn msi_compatible(&self) -> bool;

    /// Downcast the trait object to its concrete type.
    fn as_any_concrete_mut(&mut self) -> &mut dyn Any;

    /// Save the state of AiaImsics.
    fn state(&self) -> Result<AiaState>;

    /// Restore the state of AiaImsics.
    fn set_state(&mut self, state: &AiaState) -> Result<()>;
}
