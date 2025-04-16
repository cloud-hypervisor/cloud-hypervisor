// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;

use kvm_ioctls::DeviceFd;
use serde::{Deserialize, Serialize};

use crate::arch::riscv64::aia::{Error, Result, Vaia, VaiaConfig};
use crate::device::HypervisorDeviceError;
use crate::kvm::KvmVm;
use crate::Vm;

pub struct KvmAiaImsics {
    /// The KVM device for the Aia
    device: DeviceFd,

    /// AIA APLIC address
    aplic_addr: u64,

    /// AIA IMSIC address
    imsic_addr: u64,

    /// Number of CPUs handled by the device
    vcpu_count: u32,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AiaImsicsState {}

impl KvmAiaImsics {
    /// Device trees specific constants
    fn version() -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_RISCV_AIA
    }

    /// Setup the device-specific attributes
    fn init_device_attributes(&mut self, nr_irqs: u32) -> Result<()> {
        // AIA part attributes
        // Getting the working mode of RISC-V AIA, defaults to EMUL, passible
        // variants are EMUL, HW_ACCL, AUTO
        let mut aia_mode = kvm_bindings::KVM_DEV_RISCV_AIA_MODE_EMUL;
        Self::get_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_MODE),
            &mut aia_mode as *mut u32 as u64,
            0,
        )?;

        // Report AIA MODE

        // Setting up the number of wired interrupt sources
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            &nr_irqs as *const u32 as u64,
            0,
        )?;

        // Getting the number of ids
        let mut aia_nr_ids: u32 = 0;
        Self::get_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_IDS),
            &mut aia_nr_ids as *mut u32 as u64,
            0,
        )?;

        // Report NR_IDS

        // Setting up hart_bits
        let max_hart_index = self.vcpu_count as u64 - 1;
        let hart_bits = std::cmp::max(64 - max_hart_index.leading_zeros(), 1);
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            &hart_bits as *const u32 as u64,
            0,
        )?;

        // Designate addresses of APLIC and IMSICS

        // Setting up RISC-V APLIC
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_ADDR_APLIC),
            &self.aplic_addr as *const u64 as u64,
            0,
        )?;

        // Helpers to calculate address and attribute of IMSIC of each vCPU
        let riscv_imsic_addr_of = |cpu_index: u32| -> u64 {
            self.imsic_addr + (cpu_index * kvm_bindings::KVM_DEV_RISCV_IMSIC_SIZE) as u64
        };
        let riscv_imsic_attr_of = |cpu_index: u32| -> u64 { cpu_index as u64 + 1 };

        // Setting up RISC-V IMSICs
        for cpu_index in 0..self.vcpu_count {
            let cpu_imsic_addr = riscv_imsic_addr_of(cpu_index);
            Self::set_device_attribute(
                &self.device,
                kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
                riscv_imsic_attr_of(cpu_index),
                &cpu_imsic_addr as *const u64 as u64,
                0,
            )?;
        }

        // Finalizing the AIA device
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CTRL_INIT),
            0,
            0,
        )
    }

    /// Create a KVM Vaia device
    fn create_device(vm: &KvmVm) -> Result<DeviceFd> {
        let mut aia_device = kvm_bindings::kvm_create_device {
            type_: Self::version(),
            fd: 0,
            flags: 0,
        };

        let device_fd = vm
            .create_device(&mut aia_device)
            .map_err(Error::CreateAia)?;

        // We know for sure this is a KVM fd
        Ok(device_fd.to_kvm().unwrap())
    }

    /// Get an AIA device attribute
    fn get_device_attribute(
        device: &DeviceFd,
        group: u32,
        attr: u64,
        addr: u64,
        flags: u32,
    ) -> Result<()> {
        let mut attr = kvm_bindings::kvm_device_attr {
            flags,
            group,
            attr,
            addr,
        };
        // SAFETY: attr.addr is safe to write to.
        unsafe {
            device.get_device_attr(&mut attr).map_err(|e| {
                Error::GetDeviceAttribute(HypervisorDeviceError::GetDeviceAttribute(e.into()))
            })
        }
    }

    /// Set an AIA device attribute
    fn set_device_attribute(
        device: &DeviceFd,
        group: u32,
        attr: u64,
        addr: u64,
        flags: u32,
    ) -> Result<()> {
        let attr = kvm_bindings::kvm_device_attr {
            flags,
            group,
            attr,
            addr,
        };
        device.set_device_attr(&attr).map_err(|e| {
            Error::SetDeviceAttribute(HypervisorDeviceError::SetDeviceAttribute(e.into()))
        })
    }

    /// Method to initialize the AIA device
    pub fn new(vm: &dyn Vm, config: VaiaConfig) -> Result<KvmAiaImsics> {
        // This is inside KVM module
        let vm = vm.as_any().downcast_ref::<KvmVm>().expect("Wrong VM type?");

        let vaia = Self::create_device(vm)?;

        let mut aia_device = KvmAiaImsics {
            device: vaia,
            vcpu_count: config.vcpu_count,
            aplic_addr: config.aplic_addr,
            imsic_addr: config.imsic_addr,
        };

        aia_device.init_device_attributes(config.nr_irqs)?;

        Ok(aia_device)
    }
}

impl Vaia for KvmAiaImsics {
    fn aplic_compatibility(&self) -> &str {
        "riscv,aplic"
    }

    fn aplic_properties(&self) -> [u32; 4] {
        [
            0,
            self.aplic_addr as u32,
            0,
            kvm_bindings::KVM_DEV_RISCV_APLIC_SIZE,
        ]
    }

    fn imsic_compatibility(&self) -> &str {
        "riscv,imsics"
    }

    fn imsic_properties(&self) -> [u32; 4] {
        [
            0,
            self.imsic_addr as u32,
            0,
            kvm_bindings::KVM_DEV_RISCV_IMSIC_SIZE * self.vcpu_count,
        ]
    }

    fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    fn msi_compatible(&self) -> bool {
        true
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }

    /// Save the state of AIA.
    fn state(&self) -> Result<AiaImsicsState> {
        unimplemented!()
    }

    /// Restore the state of AIA_IMSICs.
    fn set_state(&mut self, _state: &AiaImsicsState) -> Result<()> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use crate::arch::riscv64::aia::VaiaConfig;
    use crate::kvm::KvmAiaImsics;

    fn create_test_vaia_config() -> VaiaConfig {
        VaiaConfig {
            vcpu_count: 1,
            aplic_addr: 0xd000000,
            imsic_addr: 0x2800000,
            nr_irqs: 256,
        }
    }

    #[test]
    fn test_create_aia() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0, None).unwrap();

        assert!(KvmAiaImsics::new(&*vm, create_test_vaia_config()).is_ok());
    }
}
