// Copyright 2021 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements the GicV3 device with ITS (Virtual Interrupt Translation Service).

pub mod kvm {
    use std::any::Any;
    use std::sync::Arc;
    use std::{boxed::Box, result};
    type Result<T> = result::Result<T, Error>;
    use crate::aarch64::gic::gicv3::kvm::KvmGicV3;
    use crate::aarch64::gic::kvm::KvmGicDevice;
    use crate::aarch64::gic::{Error, GicDevice};
    use hypervisor::kvm::kvm_bindings;
    use hypervisor::CpuState;

    /// Access an ITS device attribute.
    ///
    /// This is a helper function to get/set the ITS device attribute depending
    /// the bool parameter `set` provided.
    pub fn gicv3_its_attr_access(
        its_device: &Arc<dyn hypervisor::Device>,
        group: u32,
        attr: u32,
        val: &u64,
        set: bool,
    ) -> crate::aarch64::gic::Result<()> {
        let mut gicv3_its_attr = kvm_bindings::kvm_device_attr {
            group,
            attr: attr as u64,
            addr: val as *const u64 as u64,
            flags: 0,
        };
        if set {
            its_device
                .set_device_attr(&gicv3_its_attr)
                .map_err(crate::aarch64::gic::Error::SetDeviceAttribute)?;
        } else {
            its_device
                .get_device_attr(&mut gicv3_its_attr)
                .map_err(crate::aarch64::gic::Error::GetDeviceAttribute)?;
        }
        Ok(())
    }

    /// Function that saves/restores ITS tables into guest RAM.
    ///
    /// The tables get flushed to guest RAM whenever the VM gets stopped.
    pub fn gicv3_its_tables_access(
        its_device: &Arc<dyn hypervisor::Device>,
        save: bool,
    ) -> crate::aarch64::gic::Result<()> {
        let attr: u64;
        if save {
            attr = u64::from(kvm_bindings::KVM_DEV_ARM_ITS_SAVE_TABLES);
        } else {
            attr = u64::from(kvm_bindings::KVM_DEV_ARM_ITS_RESTORE_TABLES);
        }

        let init_gic_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr,
            addr: 0,
            flags: 0,
        };
        its_device
            .set_device_attr(&init_gic_attr)
            .map_err(crate::aarch64::gic::Error::SetDeviceAttribute)
    }

    pub struct KvmGicV3Its {
        /// The hypervisor agnostic device for the GicV3
        device: Arc<dyn hypervisor::Device>,

        /// The hypervisor agnostic device for the Its device
        its_device: Option<Arc<dyn hypervisor::Device>>,

        /// GIC device properties, to be used for setting up the fdt entry
        gic_properties: [u64; 4],

        /// MSI device properties, to be used for setting up the fdt entry
        msi_properties: [u64; 2],

        /// Number of CPUs handled by the device
        vcpu_count: u64,
    }

    impl KvmGicV3Its {
        const KVM_VGIC_V3_ITS_SIZE: u64 = (2 * KvmGicV3::SZ_64K);

        fn get_msi_size() -> u64 {
            KvmGicV3Its::KVM_VGIC_V3_ITS_SIZE
        }

        fn get_msi_addr(vcpu_count: u64) -> u64 {
            KvmGicV3::get_redists_addr(vcpu_count) - KvmGicV3Its::get_msi_size()
        }
    }

    impl GicDevice for KvmGicV3Its {
        fn device(&self) -> &Arc<dyn hypervisor::Device> {
            &self.device
        }

        fn its_device(&self) -> Option<&Arc<dyn hypervisor::Device>> {
            self.its_device.as_ref()
        }

        fn fdt_compatibility(&self) -> &str {
            "arm,gic-v3"
        }

        fn msi_compatible(&self) -> bool {
            true
        }

        fn msi_compatibility(&self) -> &str {
            "arm,gic-v3-its"
        }

        fn fdt_maint_irq(&self) -> u32 {
            KvmGicV3::ARCH_GIC_V3_MAINT_IRQ
        }

        fn msi_properties(&self) -> &[u64] {
            &self.msi_properties
        }

        fn device_properties(&self) -> &[u64] {
            &self.gic_properties
        }

        fn vcpu_count(&self) -> u64 {
            self.vcpu_count
        }

        fn set_its_device(&mut self, its_device: Option<Arc<dyn hypervisor::Device>>) {
            self.its_device = its_device;
        }

        fn set_gicr_typers(&mut self, _vcpu_states: &[CpuState]) {}

        fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    impl KvmGicDevice for KvmGicV3Its {
        fn version() -> u32 {
            KvmGicV3::version()
        }

        fn create_device(
            device: Arc<dyn hypervisor::Device>,
            vcpu_count: u64,
        ) -> Box<dyn GicDevice> {
            Box::new(KvmGicV3Its {
                device,
                its_device: None,
                gic_properties: [
                    KvmGicV3::get_dist_addr(),
                    KvmGicV3::get_dist_size(),
                    KvmGicV3::get_redists_addr(vcpu_count),
                    KvmGicV3::get_redists_size(vcpu_count),
                ],
                msi_properties: [
                    KvmGicV3Its::get_msi_addr(vcpu_count),
                    KvmGicV3Its::get_msi_size(),
                ],
                vcpu_count,
            })
        }

        fn init_device_attributes(
            vm: &Arc<dyn hypervisor::Vm>,
            gic_device: &mut dyn GicDevice,
        ) -> Result<()> {
            KvmGicV3::init_device_attributes(vm, gic_device)?;

            let mut its_device = kvm_bindings::kvm_create_device {
                type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
                fd: 0,
                flags: 0,
            };

            let its_fd = vm
                .create_device(&mut its_device)
                .map_err(Error::CreateGic)?;

            Self::set_device_attribute(
                &its_fd,
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
                &KvmGicV3Its::get_msi_addr(gic_device.vcpu_count()) as *const u64 as u64,
                0,
            )?;

            Self::set_device_attribute(
                &its_fd,
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
                u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
                0,
                0,
            )?;

            gic_device.set_its_device(Some(its_fd));

            Ok(())
        }
    }
}
