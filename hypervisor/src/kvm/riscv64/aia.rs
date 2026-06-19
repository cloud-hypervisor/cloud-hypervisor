// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::cmp;

use kvm_ioctls::DeviceFd;
use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::Vm;
use crate::arch::riscv64::aia::{Error, Result, Vaia, VaiaConfig};
use crate::device::HypervisorDeviceError;
use crate::kvm::KvmVm;

pub struct KvmAiaImsics {
    /// The KVM device for the Aia
    device: DeviceFd,

    /// AIA APLIC address
    aplic_addr: u64,

    /// AIA IMSIC address
    imsic_addr: u64,

    /// Number of CPUs handled by the device
    vcpu_count: u32,

    /// Number of IMSIC interrupt identities configured by KVM
    imsic_num_ids: u32,
}

/// Snapshot state for the RISC-V AIA (APLIC + IMSIC) device.
///
/// Saves the full register state to support live migration.
/// Only non-zero registers are stored to keep the snapshot compact.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AiaImsicsState {
    imsic_num_ids: u32,
    /// APLIC register snapshot: sparse (offset, value) pairs.
    /// Offset is the 4-byte-aligned MMIO offset in range 0x0000..=0x3FFC.
    aplic_regs: Vec<(u32, u32)>,
    /// IMSIC register snapshot: sparse (vcpu_index, iselect, value) tuples.
    /// iselect is the register selector in range 0x70..=0xFF.
    imsic_regs: Vec<(u32, u32, u32)>,
}

impl KvmAiaImsics {
    /// Device trees specific constants
    fn version() -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_RISCV_AIA
    }

    /// Setup the device-specific attributes
    fn init_device_attributes(&mut self, nr_irqs: u32) -> Result<()> {
        // Read the working mode selected by KVM. Possible modes are EMUL,
        // HW_ACCL and AUTO.
        let mut aia_mode_readback: u32 = 0;
        Self::get_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_MODE),
            &raw mut aia_mode_readback as u64,
            0,
        )?;

        // Query KVM's max interrupt IDs to determine the safe SRCS limit.
        // Kernel requires: SRCS < kvm_riscv_aia_max_ids, where
        //   kvm_riscv_aia_max_ids = nr_ids + 1
        // so safe SRCS = nr_ids.
        let mut aia_nr_ids: u32 = 0;
        Self::get_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_IDS),
            &raw mut aia_nr_ids as u64,
            0,
        )?;
        self.imsic_num_ids = aia_nr_ids;

        // Setting up the number of wired interrupt sources, clamped to KVM capacity
        let safe_nr_irqs = cmp::min(nr_irqs, aia_nr_ids);
        info!(
            "Configuring AIA interrupt sources: {} (requested {}, max {})",
            safe_nr_irqs, nr_irqs, aia_nr_ids
        );
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            &raw const safe_nr_irqs as u64,
            0,
        )?;

        // Setting up hart_bits
        let max_hart_index = self.vcpu_count as u64 - 1;
        let hart_bits = std::cmp::max(64 - max_hart_index.leading_zeros(), 1);
        debug!("Configuring AIA hart bits: {}", hart_bits);
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            &raw const hart_bits as u64,
            0,
        )?;

        // Designate addresses of APLIC and IMSICS

        // Setting up RISC-V APLIC
        debug!("Configuring AIA APLIC address: {:#x}", self.aplic_addr);
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
            u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_ADDR_APLIC),
            &raw const self.aplic_addr as u64,
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
            debug!(
                "Configuring AIA IMSIC {} address: {:#x}",
                cpu_index, cpu_imsic_addr
            );
            Self::set_device_attribute(
                &self.device,
                kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
                riscv_imsic_attr_of(cpu_index),
                &raw const cpu_imsic_addr as u64,
                0,
            )?;
        }

        // Finalizing the AIA device
        debug!("Initializing AIA device");
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

    fn get_aplic_reg(&self, offset: u32) -> Result<u32> {
        let mut val: u32 = 0;
        Self::get_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_APLIC,
            offset as u64,
            &raw mut val as u64,
            0,
        )?;
        Ok(val)
    }

    fn set_aplic_reg(&self, offset: u32, value: u32) -> Result<()> {
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_APLIC,
            offset as u64,
            &raw const value as u64,
            0,
        )
    }

    fn get_imsic_reg(&self, vcpu_id: u32, iselect: u32) -> Result<u32> {
        let attr = ((vcpu_id as u64) << kvm_bindings::KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS)
            | (iselect as u64);
        let mut val: u32 = 0;
        Self::get_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_IMSIC,
            attr,
            &raw mut val as u64,
            0,
        )?;
        Ok(val)
    }

    fn set_imsic_reg(&self, vcpu_id: u32, iselect: u32, value: u32) -> Result<()> {
        let attr = ((vcpu_id as u64) << kvm_bindings::KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS)
            | (iselect as u64);
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_RISCV_AIA_GRP_IMSIC,
            attr,
            &raw const value as u64,
            0,
        )
    }

    /// Method to initialize the AIA device
    pub fn new(vm: &dyn Vm, config: &VaiaConfig) -> Result<KvmAiaImsics> {
        // This is inside KVM module
        let vm = vm.as_any().downcast_ref::<KvmVm>().expect("Wrong VM type?");

        let vaia = Self::create_device(vm)?;

        let mut aia_device = KvmAiaImsics {
            device: vaia,
            vcpu_count: config.vcpu_count,
            aplic_addr: config.aplic_addr,
            imsic_addr: config.imsic_addr,
            imsic_num_ids: 0,
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

    fn imsic_num_ids(&self) -> u32 {
        self.imsic_num_ids
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

    fn state(&self) -> Result<AiaImsicsState> {
        let mut aplic_regs = Vec::new();
        for offset in (0..=0x3FFCu32).step_by(4) {
            match self.get_aplic_reg(offset) {
                Ok(val) if val != 0 => aplic_regs.push((offset, val)),
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // Valid IMSIC iselects vary by word size:
        //   32-bit: 0x70, 0x72, 0x80..=0xFF (130 registers)
        //   64-bit: 0x70, 0x72, 0x80/0x82/.../0xBE, 0xC0/0xC2/.../0xFE (66 registers)
        // Iterate the full range and skip invalid iselects (kernel returns ENOENT/EINVAL).
        let mut imsic_regs = Vec::new();
        for vcpu_id in 0..self.vcpu_count {
            for iselect in 0x70u32..=0xFF {
                match self.get_imsic_reg(vcpu_id, iselect) {
                    Ok(val) if val != 0 => imsic_regs.push((vcpu_id, iselect, val)),
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
        }

        Ok(AiaImsicsState {
            imsic_num_ids: self.imsic_num_ids,
            aplic_regs,
            imsic_regs,
        })
    }

    fn set_state(&mut self, state: &AiaImsicsState) -> Result<()> {
        self.imsic_num_ids = state.imsic_num_ids;
        for &(offset, value) in &state.aplic_regs {
            self.set_aplic_reg(offset, value)?;
        }
        for &(vcpu_id, iselect, value) in &state.imsic_regs {
            self.set_imsic_reg(vcpu_id, iselect, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::HypervisorVmConfig;
    use crate::arch::riscv64::aia::{Vaia, VaiaConfig};
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
        let vm = hv.create_vm(HypervisorVmConfig::default()).unwrap();
        let _vcpu = vm.create_vcpu(0, None).unwrap();

        let vaia_config = create_test_vaia_config();
        assert!(KvmAiaImsics::new(&*vm, &vaia_config).is_ok());
    }

    #[test]
    fn test_state_roundtrip() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm(HypervisorVmConfig::default()).unwrap();
        let _vcpu = vm.create_vcpu(0, None).unwrap();

        let vaia_config = create_test_vaia_config();
        let mut vaia = KvmAiaImsics::new(&*vm, &vaia_config).unwrap();

        let saved = vaia.state().unwrap();
        vaia.set_state(&saved).unwrap();

        let restored = vaia.state().unwrap();
        assert_eq!(restored.imsic_num_ids, saved.imsic_num_ids);
        assert_eq!(restored.aplic_regs.len(), saved.aplic_regs.len());
        assert_eq!(restored.imsic_regs.len(), saved.imsic_regs.len());
    }
}
