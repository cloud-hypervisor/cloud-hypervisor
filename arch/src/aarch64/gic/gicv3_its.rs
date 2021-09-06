// Copyright 2021 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements the GicV3 device with ITS (Virtual Interrupt Translation Service).

pub mod kvm {
    use crate::aarch64::gic::dist_regs::{get_dist_regs, read_ctlr, set_dist_regs, write_ctlr};
    use crate::aarch64::gic::icc_regs::{get_icc_regs, set_icc_regs};
    use crate::aarch64::gic::redist_regs::{
        construct_gicr_typers, get_redist_regs, set_redist_regs,
    };

    use crate::aarch64::gic::gicv3::kvm::KvmGicV3;
    use crate::aarch64::gic::kvm::{save_pending_tables, KvmGicDevice};
    use crate::aarch64::gic::GicDevice;
    use crate::layout;
    use anyhow::anyhow;
    use hypervisor::kvm::kvm_bindings;
    use hypervisor::CpuState;
    use std::any::Any;
    use std::convert::TryInto;
    use std::sync::Arc;
    use std::{boxed::Box, result};
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;
    use vm_migration::{
        Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable,
        VersionMapped,
    };

    const GITS_CTLR: u32 = 0x0000;
    const GITS_IIDR: u32 = 0x0004;
    const GITS_CBASER: u32 = 0x0080;
    const GITS_CWRITER: u32 = 0x0088;
    const GITS_CREADR: u32 = 0x0090;
    const GITS_BASER: u32 = 0x0100;

    /// Errors thrown while saving/restoring the GICv3ITS.
    #[derive(Debug)]
    pub enum Error {
        /// Error in saving RDIST pending tables into guest RAM.
        SavePendingTables(crate::aarch64::gic::Error),
        /// Error in saving GIC distributor registers.
        SaveDistributorRegisters(crate::aarch64::gic::Error),
        /// Error in restoring GIC distributor registers.
        RestoreDistributorRegisters(crate::aarch64::gic::Error),
        /// Error in saving GIC distributor control registers.
        SaveDistributorCtrlRegisters(crate::aarch64::gic::Error),
        /// Error in restoring GIC distributor control registers.
        RestoreDistributorCtrlRegisters(crate::aarch64::gic::Error),
        /// Error in saving GIC redistributor registers.
        SaveRedistributorRegisters(crate::aarch64::gic::Error),
        /// Error in restoring GIC redistributor registers.
        RestoreRedistributorRegisters(crate::aarch64::gic::Error),
        /// Error in saving GIC CPU interface registers.
        SaveIccRegisters(crate::aarch64::gic::Error),
        /// Error in restoring GIC CPU interface registers.
        RestoreIccRegisters(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS IIDR register.
        SaveITSIIDR(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS IIDR register.
        RestoreITSIIDR(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS CBASER register.
        SaveITSCBASER(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS CBASER register.
        RestoreITSCBASER(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS CREADR register.
        SaveITSCREADR(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS CREADR register.
        RestoreITSCREADR(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS CWRITER register.
        SaveITSCWRITER(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS CWRITER register.
        RestoreITSCWRITER(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS BASER register.
        SaveITSBASER(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS BASER register.
        RestoreITSBASER(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS CTLR register.
        SaveITSCTLR(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS CTLR register.
        RestoreITSCTLR(crate::aarch64::gic::Error),
        /// Error in saving GICv3ITS restore tables.
        SaveITSTables(crate::aarch64::gic::Error),
        /// Error in restoring GICv3ITS restore tables.
        RestoreITSTables(crate::aarch64::gic::Error),
    }

    type Result<T> = result::Result<T, Error>;

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

        /// Vector holding values of GICR_TYPER for each vCPU
        gicr_typers: Vec<u64>,

        /// GIC device properties, to be used for setting up the fdt entry
        gic_properties: [u64; 4],

        /// MSI device properties, to be used for setting up the fdt entry
        msi_properties: [u64; 2],

        /// Number of CPUs handled by the device
        vcpu_count: u64,
    }

    #[derive(Versionize)]
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

    impl VersionMapped for Gicv3ItsState {}

    impl KvmGicV3Its {
        fn get_msi_size() -> u64 {
            layout::GIC_V3_ITS_SIZE
        }

        fn get_msi_addr(vcpu_count: u64) -> u64 {
            KvmGicV3::get_redists_addr(vcpu_count) - KvmGicV3Its::get_msi_size()
        }

        /// Save the state of GICv3ITS.
        fn state(&self, gicr_typers: &[u64]) -> Result<Gicv3ItsState> {
            let gicd_ctlr =
                read_ctlr(self.device()).map_err(Error::SaveDistributorCtrlRegisters)?;

            let dist_state =
                get_dist_regs(self.device()).map_err(Error::SaveDistributorRegisters)?;

            let rdist_state = get_redist_regs(self.device(), gicr_typers)
                .map_err(Error::SaveRedistributorRegisters)?;

            let icc_state =
                get_icc_regs(self.device(), gicr_typers).map_err(Error::SaveIccRegisters)?;

            let its_baser_state: [u64; 8] = [0; 8];
            for i in 0..8 {
                gicv3_its_attr_access(
                    self.its_device().unwrap(),
                    kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                    GITS_BASER + i * 8,
                    &its_baser_state[i as usize],
                    false,
                )
                .map_err(Error::SaveITSBASER)?;
            }

            let its_ctlr_state: u64 = 0;
            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CTLR,
                &its_ctlr_state,
                false,
            )
            .map_err(Error::SaveITSCTLR)?;

            let its_cbaser_state: u64 = 0;
            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CBASER,
                &its_cbaser_state,
                false,
            )
            .map_err(Error::SaveITSCBASER)?;

            let its_creadr_state: u64 = 0;
            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CREADR,
                &its_creadr_state,
                false,
            )
            .map_err(Error::SaveITSCREADR)?;

            let its_cwriter_state: u64 = 0;
            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CWRITER,
                &its_cwriter_state,
                false,
            )
            .map_err(Error::SaveITSCWRITER)?;

            let its_iidr_state: u64 = 0;
            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_IIDR,
                &its_iidr_state,
                false,
            )
            .map_err(Error::SaveITSIIDR)?;

            Ok(Gicv3ItsState {
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
            })
        }

        /// Restore the state of GICv3ITS.
        fn set_state(&mut self, gicr_typers: &[u64], state: &Gicv3ItsState) -> Result<()> {
            write_ctlr(self.device(), state.gicd_ctlr)
                .map_err(Error::RestoreDistributorCtrlRegisters)?;

            set_dist_regs(self.device(), &state.dist)
                .map_err(Error::RestoreDistributorRegisters)?;

            set_redist_regs(self.device(), gicr_typers, &state.rdist)
                .map_err(Error::RestoreRedistributorRegisters)?;

            set_icc_regs(self.device(), gicr_typers, &state.icc)
                .map_err(Error::RestoreIccRegisters)?;

            //Restore GICv3ITS registers
            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_IIDR,
                &state.its_iidr,
                true,
            )
            .map_err(Error::RestoreITSIIDR)?;

            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CBASER,
                &state.its_cbaser,
                true,
            )
            .map_err(Error::RestoreITSCBASER)?;

            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CREADR,
                &state.its_creadr,
                true,
            )
            .map_err(Error::RestoreITSCREADR)?;

            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CWRITER,
                &state.its_cwriter,
                true,
            )
            .map_err(Error::RestoreITSCWRITER)?;

            for i in 0..8 {
                gicv3_its_attr_access(
                    self.its_device().unwrap(),
                    kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                    GITS_BASER + i * 8,
                    &state.its_baser[i as usize],
                    true,
                )
                .map_err(Error::RestoreITSBASER)?;
            }

            // Restore ITS tables
            gicv3_its_tables_access(self.its_device().unwrap(), false)
                .map_err(Error::RestoreITSTables)?;

            gicv3_its_attr_access(
                self.its_device().unwrap(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                GITS_CTLR,
                &state.its_ctlr,
                true,
            )
            .map_err(Error::RestoreITSCTLR)?;

            Ok(())
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

        fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]) {
            let gicr_typers = construct_gicr_typers(vcpu_states);
            self.gicr_typers = gicr_typers;
        }

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
                gicr_typers: vec![0; vcpu_count.try_into().unwrap()],
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
        ) -> crate::aarch64::gic::Result<()> {
            KvmGicV3::init_device_attributes(vm, gic_device)?;

            let mut its_device = kvm_bindings::kvm_create_device {
                type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
                fd: 0,
                flags: 0,
            };

            let its_fd = vm
                .create_device(&mut its_device)
                .map_err(crate::aarch64::gic::Error::CreateGic)?;

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

    pub const GIC_V3_ITS_SNAPSHOT_ID: &str = "gic-v3-its";
    impl Snapshottable for KvmGicV3Its {
        fn id(&self) -> String {
            GIC_V3_ITS_SNAPSHOT_ID.to_string()
        }

        fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
            let gicr_typers = self.gicr_typers.clone();
            Snapshot::new_from_versioned_state(&self.id(), &self.state(&gicr_typers).unwrap())
        }

        fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
            let gicr_typers = self.gicr_typers.clone();
            self.set_state(&gicr_typers, &snapshot.to_versioned_state(&self.id())?)
                .map_err(|e| {
                    MigratableError::Restore(anyhow!("Could not restore GICv3ITS state {:?}", e))
                })
        }
    }

    impl Pausable for KvmGicV3Its {
        fn pause(&mut self) -> std::result::Result<(), MigratableError> {
            // Flush redistributors pending tables to guest RAM.
            save_pending_tables(self.device()).map_err(|e| {
                MigratableError::Pause(anyhow!(
                    "Could not save GICv3ITS GIC pending tables {:?}",
                    e
                ))
            })?;
            // Flush ITS tables to guest RAM.
            gicv3_its_tables_access(self.its_device().unwrap(), true).map_err(|e| {
                MigratableError::Pause(anyhow!("Could not save GICv3ITS ITS tables {:?}", e))
            })?;

            Ok(())
        }
    }
    impl Transportable for KvmGicV3Its {}
    impl Migratable for KvmGicV3Its {}
}
