// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod dist_regs;
pub mod gicv3;
pub mod gicv3_its;
pub mod icc_regs;
pub mod redist_regs;

pub use self::dist_regs::{get_dist_regs, read_ctlr, set_dist_regs, write_ctlr};
pub use self::icc_regs::{get_icc_regs, set_icc_regs};
pub use self::redist_regs::{get_redist_regs, set_redist_regs};
use hypervisor::CpuState;
use std::any::Any;
use std::result;
use std::sync::Arc;

/// Errors thrown while setting up the GIC.
#[derive(Debug)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    CreateGic(hypervisor::HypervisorVmError),
    /// Error while setting device attributes for the GIC.
    SetDeviceAttribute(hypervisor::HypervisorDeviceError),
    /// Error while getting device attributes for the GIC.
    GetDeviceAttribute(hypervisor::HypervisorDeviceError),
}
type Result<T> = result::Result<T, Error>;

pub trait GicDevice: Send {
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
    fn msi_compatibility(&self) -> &str {
        ""
    }

    /// Returns the MSI reg property of the device
    fn msi_properties(&self) -> &[u64] {
        &[]
    }

    /// Get the values of GICR_TYPER for each vCPU.
    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]);

    /// Downcast the trait object to its concrete type.
    fn as_any_concrete_mut(&mut self) -> &mut dyn Any;
}

pub mod kvm {
    use super::GicDevice;
    use super::Result;
    use crate::aarch64::gic::gicv3_its::kvm::KvmGicV3Its;
    use crate::layout;
    use hypervisor::kvm::kvm_bindings;
    use std::boxed::Box;
    use std::sync::Arc;

    /// Trait for GIC devices.
    pub trait KvmGicDevice: Send + Sync + GicDevice {
        /// Returns the GIC version of the device
        fn version() -> u32;

        /// Create the GIC device object
        fn create_device(
            device: Arc<dyn hypervisor::Device>,
            vcpu_count: u64,
        ) -> Box<dyn GicDevice>;

        /// Setup the device-specific attributes
        fn init_device_attributes(
            vm: &Arc<dyn hypervisor::Vm>,
            gic_device: &dyn GicDevice,
        ) -> Result<()>;

        /// Initialize a GIC device
        fn init_device(vm: &Arc<dyn hypervisor::Vm>) -> Result<Arc<dyn hypervisor::Device>> {
            let mut gic_device = kvm_bindings::kvm_create_device {
                type_: Self::version(),
                fd: 0,
                flags: 0,
            };

            vm.create_device(&mut gic_device)
                .map_err(super::Error::CreateGic)
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
                flags,
                group,
                attr,
                addr,
            };
            device
                .set_device_attr(&attr)
                .map_err(super::Error::SetDeviceAttribute)?;

            Ok(())
        }

        /// Get a GIC device attribute
        fn get_device_attribute(
            device: &Arc<dyn hypervisor::Device>,
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
            device
                .get_device_attr(&mut attr)
                .map_err(super::Error::GetDeviceAttribute)?;

            Ok(())
        }

        /// Finalize the setup of a GIC device
        fn finalize_device(gic_device: &dyn GicDevice) -> Result<()> {
            /* We need to tell the kernel how many irqs to support with this vgic.
             * See the `layout` module for details.
             */
            let nr_irqs: u32 = layout::IRQ_NUM;
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
        #[allow(clippy::new_ret_no_self)]
        fn new(vm: &Arc<dyn hypervisor::Vm>, vcpu_count: u64) -> Result<Box<dyn GicDevice>> {
            let vgic_fd = Self::init_device(vm)?;

            let device = Self::create_device(vgic_fd, vcpu_count);

            Self::init_device_attributes(vm, &*device)?;

            Self::finalize_device(&*device)?;

            Ok(device)
        }
    }

    /// Create a GICv3-ITS device.
    ///
    pub fn create_gic(vm: &Arc<dyn hypervisor::Vm>, vcpu_count: u64) -> Result<Box<dyn GicDevice>> {
        debug!("creating a GICv3-ITS");
        KvmGicV3Its::new(vm, vcpu_count)
    }

    /// Function that saves RDIST pending tables into guest RAM.
    ///
    /// The tables get flushed to guest RAM whenever the VM gets stopped.
    pub fn save_pending_tables(gic: &Arc<dyn hypervisor::Device>) -> Result<()> {
        let init_gic_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
            addr: 0,
            flags: 0,
        };
        gic.set_device_attr(&init_gic_attr)
            .map_err(super::Error::SetDeviceAttribute)
    }
}
