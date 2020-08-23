// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod kvm {
    use crate::aarch64::gic::kvm::KvmGICDevice;
    use crate::aarch64::gic::{Error, GICDevice};
    use std::{boxed::Box, result};
    type Result<T> = result::Result<T, Error>;
    use crate::layout;
    use hypervisor::kvm::kvm_bindings;
    use std::sync::Arc;

    /// Represent a GIC v2 device
    pub struct KvmGICv2 {
        /// The hypervisor agnostic device
        device: Arc<dyn hypervisor::Device>,

        /// GIC device properties, to be used for setting up the fdt entry
        properties: [u64; 4],

        /// Number of CPUs handled by the device
        vcpu_count: u64,
    }

    impl KvmGICv2 {
        // Unfortunately bindgen omits defines that are based on other defines.
        // See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
        const KVM_VGIC_V2_DIST_SIZE: u64 = 0x1000;
        const KVM_VGIC_V2_CPU_SIZE: u64 = 0x2000;

        // Device trees specific constants
        const ARCH_GIC_V2_MAINT_IRQ: u32 = 8;

        /// Get the address of the GICv2 distributor.
        const fn get_dist_addr() -> u64 {
            layout::MAPPED_IO_START - KvmGICv2::KVM_VGIC_V2_DIST_SIZE
        }

        /// Get the size of the GIC_v2 distributor.
        const fn get_dist_size() -> u64 {
            KvmGICv2::KVM_VGIC_V2_DIST_SIZE
        }

        /// Get the address of the GIC_v2 CPU.
        const fn get_cpu_addr() -> u64 {
            KvmGICv2::get_dist_addr() - KvmGICv2::KVM_VGIC_V2_CPU_SIZE
        }

        /// Get the size of the GIC_v2 CPU.
        const fn get_cpu_size() -> u64 {
            KvmGICv2::KVM_VGIC_V2_CPU_SIZE
        }
    }

    impl GICDevice for KvmGICv2 {
        fn device(&self) -> &Arc<dyn hypervisor::Device> {
            &self.device
        }

        fn device_properties(&self) -> &[u64] {
            &self.properties
        }

        fn fdt_compatibility(&self) -> &str {
            "arm,gic-400"
        }

        fn fdt_maint_irq(&self) -> u32 {
            KvmGICv2::ARCH_GIC_V2_MAINT_IRQ
        }

        fn vcpu_count(&self) -> u64 {
            self.vcpu_count
        }
    }

    impl KvmGICDevice for KvmGICv2 {
        fn version() -> u32 {
            kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2
        }

        fn create_device(
            device: Arc<dyn hypervisor::Device>,
            vcpu_count: u64,
        ) -> Box<dyn GICDevice> {
            Box::new(KvmGICv2 {
                device,
                properties: [
                    KvmGICv2::get_dist_addr(),
                    KvmGICv2::get_dist_size(),
                    KvmGICv2::get_cpu_addr(),
                    KvmGICv2::get_cpu_size(),
                ],
                vcpu_count,
            })
        }

        fn init_device_attributes(
            _vm: &Arc<dyn hypervisor::Vm>,
            gic_device: &dyn GICDevice,
        ) -> Result<()> {
            /* Setting up the distributor attribute.
            We are placing the GIC below 1GB so we need to substract the size of the distributor. */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
                &KvmGICv2::get_dist_addr() as *const u64 as u64,
                0,
            )?;

            /* Setting up the CPU attribute. */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
                &KvmGICv2::get_cpu_addr() as *const u64 as u64,
                0,
            )?;

            Ok(())
        }
    }
}
