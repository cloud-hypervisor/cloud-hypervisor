// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod kvm {
    use crate::aarch64::gic::kvm::KvmGICDevice;
    use crate::aarch64::gic::{Error, GICDevice};
    use crate::layout;
    use hypervisor::kvm::kvm_bindings;
    use std::sync::Arc;
    use std::{boxed::Box, result};
    type Result<T> = result::Result<T, Error>;

    pub struct KvmGICv3 {
        /// The hypervisor agnostic device
        device: Arc<dyn hypervisor::Device>,

        /// GIC device properties, to be used for setting up the fdt entry
        properties: [u64; 4],

        /// Number of CPUs handled by the device
        vcpu_count: u64,
    }

    impl KvmGICv3 {
        // Unfortunately bindgen omits defines that are based on other defines.
        // See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
        pub const SZ_64K: u64 = 0x0001_0000;
        const KVM_VGIC_V3_DIST_SIZE: u64 = KvmGICv3::SZ_64K;
        const KVM_VGIC_V3_REDIST_SIZE: u64 = (2 * KvmGICv3::SZ_64K);

        // Device trees specific constants
        pub const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

        /// Get the address of the GIC distributor.
        pub fn get_dist_addr() -> u64 {
            layout::MAPPED_IO_START - KvmGICv3::KVM_VGIC_V3_DIST_SIZE
        }

        /// Get the size of the GIC distributor.
        pub fn get_dist_size() -> u64 {
            KvmGICv3::KVM_VGIC_V3_DIST_SIZE
        }

        /// Get the address of the GIC redistributors.
        pub fn get_redists_addr(vcpu_count: u64) -> u64 {
            KvmGICv3::get_dist_addr() - KvmGICv3::get_redists_size(vcpu_count)
        }

        /// Get the size of the GIC redistributors.
        pub fn get_redists_size(vcpu_count: u64) -> u64 {
            vcpu_count * KvmGICv3::KVM_VGIC_V3_REDIST_SIZE
        }
    }

    impl GICDevice for KvmGICv3 {
        fn device(&self) -> &Arc<dyn hypervisor::Device> {
            &self.device
        }

        fn fdt_compatibility(&self) -> &str {
            "arm,gic-v3"
        }

        fn fdt_maint_irq(&self) -> u32 {
            KvmGICv3::ARCH_GIC_V3_MAINT_IRQ
        }

        fn device_properties(&self) -> &[u64] {
            &self.properties
        }

        fn vcpu_count(&self) -> u64 {
            self.vcpu_count
        }
    }

    impl KvmGICDevice for KvmGICv3 {
        fn version() -> u32 {
            kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
        }

        fn create_device(
            device: Arc<dyn hypervisor::Device>,
            vcpu_count: u64,
        ) -> Box<dyn GICDevice> {
            Box::new(KvmGICv3 {
                device,
                properties: [
                    KvmGICv3::get_dist_addr(),
                    KvmGICv3::get_dist_size(),
                    KvmGICv3::get_redists_addr(vcpu_count),
                    KvmGICv3::get_redists_size(vcpu_count),
                ],
                vcpu_count,
            })
        }

        fn init_device_attributes(
            _vm: &Arc<dyn hypervisor::Vm>,
            gic_device: &dyn GICDevice,
        ) -> Result<()> {
            /* Setting up the distributor attribute.
             We are placing the GIC below 1GB so we need to substract the size of the distributor.
            */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
                &KvmGICv3::get_dist_addr() as *const u64 as u64,
                0,
            )?;

            /* Setting up the redistributors' attribute.
            We are calculating here the start of the redistributors address. We have one per CPU.
            */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
                &KvmGICv3::get_redists_addr(gic_device.vcpu_count()) as *const u64 as u64,
                0,
            )?;

            Ok(())
        }
    }
}
