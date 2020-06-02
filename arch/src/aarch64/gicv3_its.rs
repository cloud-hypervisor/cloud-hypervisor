// Copyright 2020 ARM Limited
// SPDX-License-Identifier: Apache-2.0

use super::gic::{Error, GICDevice};
use super::gicv3::GICv3;
use kvm_ioctls::DeviceFd;
use std::sync::Arc;
use std::{boxed::Box, result};

type Result<T> = result::Result<T, Error>;

pub struct GICv3ITS {
    /// The file descriptor for the KVM device
    fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    gic_properties: [u64; 4],

    /// MSI device properties, to be used for setting up the fdt entry
    msi_properties: [u64; 2],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl GICv3ITS {
    const KVM_VGIC_V3_ITS_SIZE: u64 = (2 * GICv3::SZ_64K);

    fn get_msi_size() -> u64 {
        GICv3ITS::KVM_VGIC_V3_ITS_SIZE
    }

    fn get_msi_addr(vcpu_count: u64) -> u64 {
        GICv3::get_redists_addr(vcpu_count) - GICv3ITS::get_msi_size()
    }
}

impl GICDevice for GICv3ITS {
    fn version() -> u32 {
        GICv3::version()
    }

    fn device_fd(&self) -> &DeviceFd {
        &self.fd
    }

    fn device_properties(&self) -> &[u64] {
        &self.gic_properties
    }

    fn msi_properties(&self) -> &[u64] {
        &self.msi_properties
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn msi_compatible(&self) -> bool {
        true
    }

    fn msi_compatiblility(&self) -> &str {
        "arm,gic-v3-its"
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICv3::ARCH_GIC_V3_MAINT_IRQ
    }

    fn create_device(fd: DeviceFd, vcpu_count: u64) -> Box<dyn GICDevice> {
        Box::new(GICv3ITS {
            fd: fd,
            gic_properties: [
                GICv3::get_dist_addr(),
                GICv3::get_dist_size(),
                GICv3::get_redists_addr(vcpu_count),
                GICv3::get_redists_size(vcpu_count),
            ],
            msi_properties: [GICv3ITS::get_msi_addr(vcpu_count), GICv3ITS::get_msi_size()],
            vcpu_count: vcpu_count,
        })
    }

    fn init_device_attributes(
        vm: &Arc<dyn hypervisor::Vm>,
        gic_device: &Box<dyn GICDevice>,
    ) -> Result<()> {
        GICv3::init_device_attributes(vm, gic_device)?;

        let mut its_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
            fd: 0,
            flags: 0,
        };

        let its_fd = vm
            .create_device(&mut its_device)
            .map_err(Error::CreateGIC)?;

        Self::set_device_attribute(
            &its_fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
            &GICv3ITS::get_msi_addr(u64::from(gic_device.vcpu_count())) as *const u64 as u64,
            0,
        )?;

        Self::set_device_attribute(
            &its_fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            0,
        )?;

        Ok(())
    }
}
