// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::result;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use serde_json;
use thiserror::Error;

use crate::{CpuState, HypervisorDeviceError, HypervisorVmError};

/// Errors thrown while setting up the VGIC.
#[derive(Debug, Error)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    #[error("Failed creating GIC device: {0}")]
    CreateGic(#[source] HypervisorVmError),
    /// Error while setting device attributes for the GIC.
    #[error("Failed setting device attributes for the GIC: {0}")]
    SetDeviceAttribute(#[source] HypervisorDeviceError),
    /// Error while getting device attributes for the GIC.
    #[error("Failed getting device attributes for the GIC: {0}")]
    GetDeviceAttribute(#[source] HypervisorDeviceError),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct VgicConfig {
    pub vcpu_count: u64,
    pub dist_addr: u64,
    pub dist_size: u64,
    pub redists_addr: u64,
    pub redists_size: u64,
    pub msi_addr: u64,
    pub msi_size: u64,
    pub nr_irqs: u32,
}

#[derive(Clone, Serialize)]
pub enum GicState {
    #[cfg(feature = "kvm")]
    Kvm(crate::kvm::aarch64::gic::Gicv3ItsState),
    #[cfg(feature = "mshv")]
    MshvGicV2M(crate::mshv::aarch64::gic::MshvGicV2MState),
}

impl<'de> Deserialize<'de> for GicState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // GicStateDefaultDeserialize is a helper enum that mirrors GicState but also derives the Deserialize trait.
        // This enables backward-compatible deserialization of GicState, facilitating live-upgrade scenarios.
        #[derive(Deserialize)]
        pub enum GicStateDefaultDeserialize {
            #[cfg(feature = "kvm")]
            Kvm(crate::kvm::aarch64::gic::Gicv3ItsState),
            #[cfg(feature = "mshv")]
            MshvGicV2M(crate::mshv::aarch64::gic::MshvGicV2MState),
        }

        const {
            assert!(
                std::mem::size_of::<GicStateDefaultDeserialize>()
                    == std::mem::size_of::<GicState>()
            )
        };

        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        #[cfg(feature = "kvm")]
        if let Ok(gicv3_its_state) =
            crate::kvm::aarch64::gic::Gicv3ItsState::deserialize(value.clone())
        {
            return Ok(GicState::Kvm(gicv3_its_state));
        }

        if let Ok(gic_state_de) = GicStateDefaultDeserialize::deserialize(value.clone()) {
            return match gic_state_de {
                #[cfg(feature = "kvm")]
                GicStateDefaultDeserialize::Kvm(state) => Ok(GicState::Kvm(state)),
                #[cfg(feature = "mshv")]
                GicStateDefaultDeserialize::MshvGicV2M(state) => Ok(GicState::MshvGicV2M(state)),
            };
        }
        Err(SerdeError::custom("Failed to deserialize GicState"))
    }
}
/// Hypervisor agnostic interface for a virtualized GIC
pub trait Vgic: Send + Sync {
    /// Returns the fdt compatibility property of the device
    fn fdt_compatibility(&self) -> &str;

    /// Returns the maint_irq fdt property of the device
    fn fdt_maint_irq(&self) -> u32;

    /// Returns an array with GIC device properties
    fn device_properties(&self) -> [u64; 4];

    /// Returns the number of vCPUs this GIC handles
    fn vcpu_count(&self) -> u64;

    /// Returns whether the GIC device is MSI compatible or not
    fn msi_compatible(&self) -> bool;

    /// Returns the MSI compatibility property of the device
    fn msi_compatibility(&self) -> &str;

    /// Returns the MSI reg property of the device
    fn msi_properties(&self) -> [u64; 2];

    /// Get the values of GICR_TYPER for each vCPU.
    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]);

    /// Downcast the trait object to its concrete type.
    fn as_any_concrete_mut(&mut self) -> &mut dyn Any;

    /// Save the state of GICv3ITS.
    fn state(&self) -> Result<GicState>;

    /// Restore the state of GICv3ITS.
    fn set_state(&mut self, state: &GicState) -> Result<()>;

    /// Saves GIC internal data tables into RAM.
    fn save_data_tables(&self) -> Result<()>;
}
