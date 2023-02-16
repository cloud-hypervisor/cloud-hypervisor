// Copyright © 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use log::info;
use pci::PciBarConfiguration;
use std::{fs::File, mem::size_of, path::PathBuf};
use vfio_bindings::bindings::vfio::{
    vfio_region_info, VFIO_IRQ_INFO_EVENTFD, VFIO_PCI_BAR2_REGION_INDEX,
    VFIO_PCI_CONFIG_REGION_INDEX, VFIO_PCI_INTX_IRQ_INDEX, VFIO_PCI_NUM_IRQS, VFIO_PCI_NUM_REGIONS,
    VFIO_REGION_INFO_FLAG_READ, VFIO_REGION_INFO_FLAG_WRITE,
};
use vfio_user::{IrqInfo, Server, ServerBackend};

#[derive(Copy, Clone)]
enum PciVfioUserSubclass {
    VfioUserSubclass = 0xff,
}

impl pci::PciSubclass for PciVfioUserSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

struct TestBackend {
    configuration: pci::PciConfiguration,
}
impl TestBackend {
    fn new() -> TestBackend {
        let subclass = PciVfioUserSubclass::VfioUserSubclass;

        let mut configuration = pci::PciConfiguration::new(
            0x494f,
            0xdc8,
            0x0,
            pci::PciClassCode::Other,
            &subclass as &dyn pci::PciSubclass,
            None,
            pci::PciHeaderType::Device,
            0,
            0,
            None,
            None,
        );

        configuration
            .add_pci_bar(&PciBarConfiguration::new(
                VFIO_PCI_BAR2_REGION_INDEX as usize,
                0x100,
                pci::PciBarRegionType::IoRegion,
                pci::PciBarPrefetchable::NotPrefetchable,
            ))
            .unwrap();

        configuration.set_irq(1, pci::PciInterruptPin::IntA);
        TestBackend { configuration }
    }
}

impl ServerBackend for TestBackend {
    fn region_read(
        &mut self,
        region: u32,
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), std::io::Error> {
        info!("read region = {region} offset = {offset}");

        if region == VFIO_PCI_CONFIG_REGION_INDEX {
            let reg_idx = offset as usize / 4;
            let v = self.configuration.read_config_register(reg_idx);
            let reg_offset = offset as usize % 4;
            data.copy_from_slice(&v.to_le_bytes()[reg_offset..reg_offset + data.len()]);
        }

        Ok(())
    }

    fn region_write(
        &mut self,
        region: u32,
        offset: u64,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        info!("write region = {region} offset = {offset}");
        if region == VFIO_PCI_CONFIG_REGION_INDEX {
            self.configuration
                .write_config_register(offset as usize / 4, offset % 4, data);
        }

        Ok(())
    }

    fn dma_map(
        &mut self,
        flags: vfio_user::DmaMapFlags,
        offset: u64,
        address: u64,
        size: u64,
        fd: Option<&File>,
    ) -> Result<(), std::io::Error> {
        info!("dma_map flags = {flags:?} offset = {offset} address = {address} size = {size} fd = {fd:?}");
        Ok(())
    }

    fn dma_unmap(
        &mut self,
        flags: vfio_user::DmaUnmapFlags,
        address: u64,
        size: u64,
    ) -> Result<(), std::io::Error> {
        info!("dma_unmap flags = {flags:?}  address = {address} size = {size}");
        Ok(())
    }

    fn reset(&mut self) -> Result<(), std::io::Error> {
        info!("reset");
        Ok(())
    }

    fn set_irqs(
        &mut self,
        index: u32,
        flags: u32,
        start: u32,
        count: u32,
        fds: Vec<File>,
    ) -> Result<(), std::io::Error> {
        info!("set_irqs index = {index} flags = {flags} start = {start} count = {count} fds = {fds:?}");
        Ok(())
    }
}

fn create_regions() -> Vec<vfio_region_info> {
    let mut regions = Vec::with_capacity(VFIO_PCI_NUM_REGIONS as usize);
    for index in 0..VFIO_PCI_NUM_REGIONS {
        let mut region = vfio_region_info {
            argsz: size_of::<vfio_region_info>() as u32,
            index,
            ..Default::default()
        };

        if index == VFIO_PCI_CONFIG_REGION_INDEX || index == VFIO_PCI_BAR2_REGION_INDEX {
            region.size = 256;
            region.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
        }

        regions.push(region);
    }

    regions
}

fn create_irqs() -> Vec<IrqInfo> {
    let mut irqs = Vec::with_capacity(VFIO_PCI_NUM_IRQS as usize);
    for index in 0..VFIO_PCI_NUM_IRQS {
        let mut irq = IrqInfo {
            index,
            count: 0,
            flags: 0,
        };

        if index == VFIO_PCI_INTX_IRQ_INDEX {
            irq.count = 1;
            irq.flags = VFIO_IRQ_INFO_EVENTFD
        }

        irqs.push(irq);
    }

    irqs
}

fn main() {
    env_logger::init();

    let regions = create_regions();
    let irqs = create_irqs();

    let path = PathBuf::from("/tmp/vfio-user-test.socket");
    let s = Server::new(&path, true, irqs, regions).unwrap();
    let mut test_backend = TestBackend::new();
    s.run(&mut test_backend).unwrap();
}
