// Copyright © 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Handles routing to devices in an address space.
use std::sync::{Arc, Mutex};
use vm_memory::{GuestAddress, GuestUsize};

/// Trait for devices with basic functions.
#[allow(unused_variables)]
pub trait Device: Send {
    /// Get the device name.
    fn name(&self) -> String;
    /// Read from the guest physical address `addr` to `data`.
    fn read(&mut self, addr: GuestAddress, data: &mut [u8], io_type: IoType);
    /// Write `data` to the guest physical address `addr`.
    fn write(&mut self, addr: GuestAddress, data: &[u8], io_type: IoType);
    /// Set the allocated resource to device.
    ///
    /// This will be called by DeviceManager::register_device() to set
    /// the allocated resource from the vm_allocator back to device.
    fn set_resources(&mut self, res: &[IoResource], irq: Option<IrqResource>);
}

/// IO Resource type.
#[derive(Debug, Copy, Clone)]
pub enum IoType {
    /// Port I/O resource.
    Pio,
    /// Memory I/O resource.
    Mmio,
    /// Non-exit physically backed mmap IO
    PhysicalMmio,
}

/// Device resource information.
#[derive(Debug, Copy, Clone)]
pub struct IoResource {
    /// Resource address.
    pub addr: Option<GuestAddress>,
    /// Resource size.
    pub size: GuestUsize,
    /// Resource type.
    pub res_type: IoType,
}

impl IoResource {
    /// Build a Resource struct.
    pub fn new(addr: Option<GuestAddress>, size: GuestUsize, res_type: IoType) -> IoResource {
        IoResource {
            addr,
            size,
            res_type,
        }
    }
}

/// Legacy interrupt resource.
#[derive(Debug, Copy, Clone)]
pub struct IrqResource(pub Option<u32>);

/// Storing Device information and for topology managing.
pub struct DeviceDescriptor {
    /// Device instance id information.
    pub instance_id: u32,
    /// Device type name.
    pub name: String,
    /// The device to descript.
    pub device: Arc<Mutex<dyn Device>>,
    /// The parent bus of this device.
    pub parent_bus: Option<Arc<Mutex<dyn Device>>>,
    /// Device resource set.
    pub resources: Vec<IoResource>,
    /// Device IRQ resource.
    pub irq: Option<IrqResource>,
}

impl DeviceDescriptor {
    /// Create a descriptor for one device.
    pub fn new(
        instance_id: u32,
        name: String,
        dev: Arc<Mutex<dyn Device>>,
        parent_bus: Option<Arc<Mutex<dyn Device>>>,
        resources: Vec<IoResource>,
        irq: Option<IrqResource>,
    ) -> Self {
        DeviceDescriptor {
            instance_id,
            name,
            device: dev,
            parent_bus,
            resources,
            irq,
        }
    }
}
