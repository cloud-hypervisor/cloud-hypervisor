// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;
use std::sync::Arc;

/// Errors thrown while setting up the GIC.
#[derive(Debug)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    CreateGIC(hypervisor::HypervisorVmError),
    /// Error while setting device attributes for the GIC.
    SetDeviceAttribute(hypervisor::HypervisorDeviceError),
}
type Result<T> = result::Result<T, Error>;

pub trait GICDevice {
    /// Returns the hypervisor agnostic Device of the GIC device
    fn device(&self) -> &Arc<dyn hypervisor::Device>;

    /// Returns the fdt compatibility property of the device
    fn fdt_compatibility(&self) -> &str;

    /// Returns the maint_irq fdt property of the device
    fn fdt_maint_irq(&self) -> u32;

    /// Returns an array with GIC device properties
    fn device_properties(&self) -> &[u64];

    /// Returns the number of vCPUs this GIC handles
    fn vcpu_count(&self) -> u64;

    /// Returns whether the GIC device is MSI compatible or not
    fn msi_compatible(&self) -> bool {
        false
    }

    /// Returns the MSI compatibility property of the device
    fn msi_compatiblility(&self) -> &str {
        ""
    }

    /// Returns the MSI reg property of the device
    fn msi_properties(&self) -> &[u64] {
        &[]
    }
}

pub mod kvm {
    use super::GICDevice;
    use super::Result;
    use crate::aarch64::gicv2::kvm::KvmGICv2;
    use crate::aarch64::gicv3::kvm::KvmGICv3;
    use crate::aarch64::gicv3_its::kvm::KvmGICv3ITS;
    use crate::layout;
    use hypervisor::kvm::kvm_bindings;
    use std::boxed::Box;
    use std::sync::Arc;

    /// Trait for GIC devices.
    pub trait KvmGICDevice: Send + Sync + GICDevice {
        /// Returns the GIC version of the device
        fn version() -> u32;

        /// Create the GIC device object
        fn create_device(
            device: Arc<dyn hypervisor::Device>,
            vcpu_count: u64,
        ) -> Box<dyn GICDevice>;

        /// Setup the device-specific attributes
        fn init_device_attributes(
            vm: &Arc<dyn hypervisor::Vm>,
            gic_device: &dyn GICDevice,
        ) -> Result<()>;

        /// Initialize a GIC device
        fn init_device(vm: &Arc<dyn hypervisor::Vm>) -> Result<Arc<dyn hypervisor::Device>> {
            let mut gic_device = kvm_bindings::kvm_create_device {
                type_: Self::version(),
                fd: 0,
                flags: 0,
            };

            vm.create_device(&mut gic_device)
                .map_err(super::Error::CreateGIC)
        }

        /// Set a GIC device attribute
        fn set_device_attribute(
            device: &Arc<dyn hypervisor::Device>,
            group: u32,
            attr: u64,
            addr: u64,
            flags: u32,
        ) -> Result<()> {
            let attr = kvm_bindings::kvm_device_attr {
                group,
                attr,
                addr,
                flags,
            };
            device
                .set_device_attr(&attr)
                .map_err(super::Error::SetDeviceAttribute)?;

            Ok(())
        }

        /// Finalize the setup of a GIC device
        fn finalize_device(gic_device: &dyn GICDevice) -> Result<()> {
            /* We need to tell the kernel how many irqs to support with this vgic.
             * See the `layout` module for details.
             */
            let nr_irqs: u32 = layout::IRQ_MAX - layout::IRQ_BASE + 1;
            let nr_irqs_ptr = &nr_irqs as *const u32;
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
                0,
                nr_irqs_ptr as u64,
                0,
            )?;

            /* Finalize the GIC.
             * See https://code.woboq.org/linux/linux/virt/kvm/arm/vgic/vgic-kvm-device.c.html#211.
             */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
                u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
                0,
                0,
            )?;

            Ok(())
        }

        /// Method to initialize the GIC device
        fn new(vm: &Arc<dyn hypervisor::Vm>, vcpu_count: u64) -> Result<Box<dyn GICDevice>> {
            let vgic_fd = Self::init_device(vm)?;

            let device = Self::create_device(vgic_fd, vcpu_count);

            Self::init_device_attributes(vm, &*device)?;

            Self::finalize_device(&*device)?;

            Ok(device)
        }
    }

    /// Create a GIC device.
    ///
    /// It will try to create by default a GICv3 device. If that fails it will try
    /// to fall-back to a GICv2 device.
    pub fn create_gic(
        vm: &Arc<dyn hypervisor::Vm>,
        vcpu_count: u64,
        its_required: bool,
    ) -> Result<Box<dyn GICDevice>> {
        if its_required {
            KvmGICv3ITS::new(vm, vcpu_count)
        } else {
            KvmGICv3ITS::new(vm, vcpu_count).or_else(|_| {
                debug!("Failed to create GICv3-ITS, will try GICv3 instead.");
                KvmGICv3::new(vm, vcpu_count).or_else(|_| {
                    debug!("Failed to create GICv3, will try GICv2 instead.");
                    KvmGICv2::new(vm, vcpu_count)
                })
            })
        }
    }
}
