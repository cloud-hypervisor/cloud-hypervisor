// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

mod dist_regs;
mod icc_regs;
mod redist_regs;

use std::any::Any;

use dist_regs::{get_dist_regs, read_ctlr, set_dist_regs, write_ctlr};
use icc_regs::{get_icc_regs, set_icc_regs};
use kvm_ioctls::DeviceFd;
use redist_regs::{construct_gicr_typers, get_redist_regs, set_redist_regs};
use serde::{Deserialize, Serialize};

use crate::arch::aarch64::gic::{Error, GicState, Result, Vgic, VgicConfig};
use crate::device::HypervisorDeviceError;
use crate::kvm::KvmVm;
use crate::{CpuState, Vm};

const GITS_CTLR: u32 = 0x0000;
const GITS_IIDR: u32 = 0x0004;
const GITS_CBASER: u32 = 0x0080;
const GITS_CWRITER: u32 = 0x0088;
const GITS_CREADR: u32 = 0x0090;
const GITS_BASER: u32 = 0x0100;

fn gicv3_its_attr_set(its_device: &DeviceFd, group: u32, attr: u32, val: u64) -> Result<()> {
    let gicv3_its_attr = kvm_bindings::kvm_device_attr {
        group,
        attr: attr as u64,
        addr: &val as *const u64 as u64,
        flags: 0,
    };

    its_device
        .set_device_attr(&gicv3_its_attr)
        .map_err(|e| Error::SetDeviceAttribute(HypervisorDeviceError::SetDeviceAttribute(e.into())))
}

fn gicv3_its_attr_get(its_device: &DeviceFd, group: u32, attr: u32) -> Result<u64> {
    let mut val = 0;

    let mut gicv3_its_attr = kvm_bindings::kvm_device_attr {
        group,
        attr: attr as u64,
        addr: &mut val as *mut u64 as u64,
        flags: 0,
    };

    // SAFETY: gicv3_its_attr.addr is safe to write to.
    unsafe { its_device.get_device_attr(&mut gicv3_its_attr) }.map_err(|e| {
        Error::GetDeviceAttribute(HypervisorDeviceError::GetDeviceAttribute(e.into()))
    })?;

    Ok(val)
}

/// Function that saves/restores ITS tables into guest RAM.
///
/// The tables get flushed to guest RAM whenever the VM gets stopped.
pub fn gicv3_its_tables_access(its_device: &DeviceFd, save: bool) -> Result<()> {
    let attr = if save {
        u64::from(kvm_bindings::KVM_DEV_ARM_ITS_SAVE_TABLES)
    } else {
        u64::from(kvm_bindings::KVM_DEV_ARM_ITS_RESTORE_TABLES)
    };

    let init_gic_attr = kvm_bindings::kvm_device_attr {
        group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr,
        addr: 0,
        flags: 0,
    };
    its_device
        .set_device_attr(&init_gic_attr)
        .map_err(|e| Error::SetDeviceAttribute(HypervisorDeviceError::SetDeviceAttribute(e.into())))
}

pub struct KvmGicV3Its {
    /// The KVM device for the GicV3
    device: DeviceFd,

    /// The KVM device for the Its device
    its_device: Option<DeviceFd>,

    /// Vector holding values of GICR_TYPER for each vCPU
    gicr_typers: Vec<u64>,

    /// GIC distributor address
    dist_addr: u64,

    /// GIC distributor size
    dist_size: u64,

    /// GIC distributors address
    redists_addr: u64,

    /// GIC distributors size
    redists_size: u64,

    /// GIC MSI address
    msi_addr: u64,

    /// GIC MSI size
    msi_size: u64,

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Gicv3ItsState {
    dist: Vec<u32>,
    rdist: Vec<u32>,
    icc: Vec<u32>,
    // special register that enables interrupts and affinity routing
    gicd_ctlr: u32,
    its_ctlr: u64,
    its_iidr: u64,
    its_cbaser: u64,
    its_cwriter: u64,
    its_creadr: u64,
    its_baser: [u64; 8],
}

impl From<GicState> for Gicv3ItsState {
    fn from(state: GicState) -> Self {
        match state {
            GicState::Kvm(state) => state,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("GicState is not valid"),
        }
    }
}

impl From<Gicv3ItsState> for GicState {
    fn from(state: Gicv3ItsState) -> Self {
        GicState::Kvm(state)
    }
}

impl KvmGicV3Its {
    /// Device trees specific constants
    pub const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

    /// Returns the GIC version of the device
    fn version() -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
    }

    /// Setup the device-specific attributes
    fn init_device_attributes(&mut self, vm: &KvmVm, nr_irqs: u32) -> Result<()> {
        // GicV3 part attributes
        /* Setting up the distributor attribute. */
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &self.dist_addr as *const u64 as u64,
            0,
        )?;

        /* Setting up the redistributors' attribute. */
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &self.redists_addr as *const u64 as u64,
            0,
        )?;

        // ITS part attributes
        let mut its_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
            fd: 0,
            flags: 0,
        };

        let its_fd = vm
            .create_device(&mut its_device)
            .map_err(Error::CreateGic)?;

        // We know vm is KvmVm
        let its_fd = its_fd.to_kvm().unwrap();

        Self::set_device_attribute(
            &its_fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
            &self.msi_addr as *const u64 as u64,
            0,
        )?;

        Self::set_device_attribute(
            &its_fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            0,
        )?;

        self.its_device = Some(its_fd);

        /* We need to tell the kernel how many irqs to support with this vgic.
         * See the `layout` module for details.
         */
        let nr_irqs_ptr = &nr_irqs as *const u32;
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            nr_irqs_ptr as u64,
            0,
        )?;

        /* Finalize the GIC.
         * See https://code.woboq.org/linux/linux/virt/kvm/arm/vgic/vgic-kvm-device.c.html#211.
         */
        Self::set_device_attribute(
            &self.device,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            0,
        )
    }

    /// Create a KVM Vgic device
    fn create_device(vm: &KvmVm) -> Result<DeviceFd> {
        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: Self::version(),
            fd: 0,
            flags: 0,
        };

        let device_fd = vm
            .create_device(&mut gic_device)
            .map_err(Error::CreateGic)?;

        // We know for sure this is a KVM fd
        Ok(device_fd.to_kvm().unwrap())
    }

    /// Set a GIC device attribute
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

    /// Method to initialize the GIC device
    pub fn new(vm: &dyn Vm, config: VgicConfig) -> Result<KvmGicV3Its> {
        // This is inside KVM module
        let vm = vm.as_any().downcast_ref::<KvmVm>().expect("Wrong VM type?");

        let vgic = Self::create_device(vm)?;

        let mut gic_device = KvmGicV3Its {
            device: vgic,
            its_device: None,
            gicr_typers: vec![0; config.vcpu_count.try_into().unwrap()],
            dist_addr: config.dist_addr,
            dist_size: config.dist_size,
            redists_addr: config.redists_addr,
            redists_size: config.redists_size,
            msi_addr: config.msi_addr,
            msi_size: config.msi_size,
            vcpu_count: config.vcpu_count,
        };

        gic_device.init_device_attributes(vm, config.nr_irqs)?;

        Ok(gic_device)
    }
}

impl Vgic for KvmGicV3Its {
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
        KvmGicV3Its::ARCH_GIC_V3_MAINT_IRQ
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn device_properties(&self) -> [u64; 4] {
        [
            self.dist_addr,
            self.dist_size,
            self.redists_addr,
            self.redists_size,
        ]
    }

    fn msi_properties(&self) -> [u64; 2] {
        [self.msi_addr, self.msi_size]
    }

    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]) {
        let gicr_typers = construct_gicr_typers(vcpu_states);
        self.gicr_typers = gicr_typers;
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }

    /// Save the state of GICv3ITS.
    fn state(&self) -> Result<GicState> {
        let gicr_typers = self.gicr_typers.clone();

        let gicd_ctlr = read_ctlr(&self.device)?;

        let dist_state = get_dist_regs(&self.device)?;

        let rdist_state = get_redist_regs(&self.device, &gicr_typers)?;

        let icc_state = get_icc_regs(&self.device, &gicr_typers)?;

        let mut its_baser_state: [u64; 8] = [0; 8];
        for i in 0..8 {
            its_baser_state[i as usize] = gicv3_its_attr_get(
                self.its_device.as_ref().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_BASER + i * 8,
            )?;
        }

        let its_ctlr_state = gicv3_its_attr_get(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CTLR,
        )?;

        let its_cbaser_state = gicv3_its_attr_get(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CBASER,
        )?;

        let its_creadr_state = gicv3_its_attr_get(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CREADR,
        )?;

        let its_cwriter_state = gicv3_its_attr_get(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CWRITER,
        )?;

        let its_iidr_state = gicv3_its_attr_get(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_IIDR,
        )?;

        let gic_state: GicState = Gicv3ItsState {
            dist: dist_state,
            rdist: rdist_state,
            icc: icc_state,
            gicd_ctlr,
            its_ctlr: its_ctlr_state,
            its_iidr: its_iidr_state,
            its_cbaser: its_cbaser_state,
            its_cwriter: its_cwriter_state,
            its_creadr: its_creadr_state,
            its_baser: its_baser_state,
        }
        .into();

        Ok(gic_state)
    }

    /// Restore the state of GICv3ITS.
    fn set_state(&mut self, state: &GicState) -> Result<()> {
        let kvm_state: Gicv3ItsState = state.clone().into();

        let gicr_typers = self.gicr_typers.clone();

        write_ctlr(&self.device, kvm_state.gicd_ctlr)?;

        set_dist_regs(&self.device, &kvm_state.dist)?;

        set_redist_regs(&self.device, &gicr_typers, &kvm_state.rdist)?;

        set_icc_regs(&self.device, &gicr_typers, &kvm_state.icc)?;

        //Restore GICv3ITS registers
        gicv3_its_attr_set(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_IIDR,
            kvm_state.its_iidr,
        )?;

        gicv3_its_attr_set(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CBASER,
            kvm_state.its_cbaser,
        )?;

        gicv3_its_attr_set(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CREADR,
            kvm_state.its_creadr,
        )?;

        gicv3_its_attr_set(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CWRITER,
            kvm_state.its_cwriter,
        )?;

        for i in 0..8 {
            gicv3_its_attr_set(
                self.its_device.as_ref().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_BASER + i * 8,
                kvm_state.its_baser[i as usize],
            )?;
        }

        // Restore ITS tables
        gicv3_its_tables_access(self.its_device.as_ref().unwrap(), false)?;

        gicv3_its_attr_set(
            self.its_device.as_ref().unwrap(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            GITS_CTLR,
            kvm_state.its_ctlr,
        )
    }

    /// Saves GIC internal data tables into RAM, including:
    /// - RDIST pending tables
    /// - ITS tables into guest RAM.
    fn save_data_tables(&self) -> Result<()> {
        // Flash RDIST pending tables
        let init_gic_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
            addr: 0,
            flags: 0,
        };
        self.device.set_device_attr(&init_gic_attr).map_err(|e| {
            Error::SetDeviceAttribute(HypervisorDeviceError::SetDeviceAttribute(e.into()))
        })?;
        // Flush ITS tables to guest RAM.
        gicv3_its_tables_access(self.its_device.as_ref().unwrap(), true)
    }
}

#[cfg(test)]
mod tests {
    use crate::aarch64::gic::{
        get_dist_regs, get_icc_regs, get_redist_regs, set_dist_regs, set_icc_regs, set_redist_regs,
    };
    use crate::arch::aarch64::gic::VgicConfig;
    use crate::kvm::KvmGicV3Its;

    fn create_test_vgic_config() -> VgicConfig {
        VgicConfig {
            vcpu_count: 1,
            dist_addr: 0x0900_0000 - 0x01_0000,
            dist_size: 0x01_0000,
            // dist_addr - redists_size
            redists_addr: 0x0900_0000 - 0x01_0000 - 0x02_0000,
            redists_size: 0x02_0000,
            // redists_addr - msi_size
            msi_addr: 0x0900_0000 - 0x01_0000 - 0x02_0000 - 0x02_0000,
            msi_size: 0x02_0000,
            nr_irqs: 256,
        }
    }

    #[test]
    fn test_create_gic() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm().unwrap();

        KvmGicV3Its::new(&*vm, create_test_vgic_config()).unwrap();
    }

    #[test]
    fn test_get_set_dist_regs() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = KvmGicV3Its::new(&*vm, create_test_vgic_config()).expect("Cannot create gic");

        let state = get_dist_regs(&gic.device).unwrap();
        assert_eq!(state.len(), 568);

        set_dist_regs(&gic.device, &state).unwrap();
    }

    #[test]
    fn test_get_set_redist_regs() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = KvmGicV3Its::new(&*vm, create_test_vgic_config()).expect("Cannot create gic");

        let gicr_typer = vec![123];
        let state = get_redist_regs(&gic.device, &gicr_typer).unwrap();
        println!("{}", state.len());
        assert!(state.len() == 24);

        set_redist_regs(&gic.device, &gicr_typer, &state).unwrap();
    }

    #[test]
    fn test_get_set_icc_regs() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = KvmGicV3Its::new(&*vm, create_test_vgic_config()).expect("Cannot create gic");

        let gicr_typer = vec![123];
        let state = get_icc_regs(&gic.device, &gicr_typer).unwrap();
        println!("{}", state.len());
        assert!(state.len() == 9);

        set_icc_regs(&gic.device, &gicr_typer, &state).unwrap();
    }

    #[test]
    fn test_save_data_tables() {
        let hv = crate::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _ = vm.create_vcpu(0, None).unwrap();
        let gic = vm
            .create_vgic(create_test_vgic_config())
            .expect("Cannot create gic");

        gic.lock().unwrap().save_data_tables().unwrap();
    }
}
