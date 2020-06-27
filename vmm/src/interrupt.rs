// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use devices::interrupt_controller::InterruptController;
use hypervisor::kvm::{kvm_irq_routing, kvm_irq_routing_entry, KVM_IRQ_ROUTING_MSI};

use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vm_allocator::SystemAllocator;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceConfig, InterruptSourceGroup,
    LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vmm_sys_util::eventfd::EventFd;

/// Reuse std::io::Result to simplify interoperability among crates.
pub type Result<T> = std::io::Result<T>;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

struct InterruptRoute {
    pub gsi: u32,
    pub irq_fd: EventFd,
    registered: AtomicBool,
}

impl InterruptRoute {
    pub fn new(allocator: &mut SystemAllocator) -> Result<Self> {
        let irq_fd = EventFd::new(libc::EFD_NONBLOCK)?;
        let gsi = allocator
            .allocate_gsi()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed allocating new GSI"))?;

        Ok(InterruptRoute {
            gsi,
            irq_fd,
            registered: AtomicBool::new(false),
        })
    }

    pub fn enable(&self, vm: &Arc<dyn hypervisor::Vm>) -> Result<()> {
        if !self.registered.load(Ordering::SeqCst) {
            vm.register_irqfd(&self.irq_fd, self.gsi).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed registering irq_fd: {}", e),
                )
            })?;

            // Update internals to track the irq_fd as "registered".
            self.registered.store(true, Ordering::SeqCst);
        }

        Ok(())
    }

    pub fn disable(&self, vm: &Arc<dyn hypervisor::Vm>) -> Result<()> {
        if self.registered.load(Ordering::SeqCst) {
            vm.unregister_irqfd(&self.irq_fd, self.gsi).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed unregistering irq_fd: {}", e),
                )
            })?;

            // Update internals to track the irq_fd as "unregistered".
            self.registered.store(false, Ordering::SeqCst);
        }

        Ok(())
    }
}

pub struct RoutingEntry<E> {
    route: E,
    masked: bool,
}

type KvmRoutingEntry = RoutingEntry<kvm_irq_routing_entry>;

pub struct MsiInterruptGroup<E> {
    vm_fd: Arc<dyn hypervisor::Vm>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry<E>>>>,
    irq_routes: HashMap<InterruptIndex, InterruptRoute>,
}

pub trait MsiInterruptGroupOps {
    fn set_gsi_routes(&self) -> Result<()>;
}

pub trait RoutingEntryExt {
    fn make_entry(gsi: u32, config: &InterruptSourceConfig) -> Result<Box<Self>>;
}

impl RoutingEntryExt for KvmRoutingEntry {
    fn make_entry(gsi: u32, config: &InterruptSourceConfig) -> Result<Box<Self>> {
        if let InterruptSourceConfig::MsiIrq(cfg) = &config {
            let mut kvm_route = kvm_irq_routing_entry {
                gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                ..Default::default()
            };

            kvm_route.u.msi.address_lo = cfg.low_addr;
            kvm_route.u.msi.address_hi = cfg.high_addr;
            kvm_route.u.msi.data = cfg.data;

            let kvm_entry = KvmRoutingEntry {
                route: kvm_route,
                masked: false,
            };

            return Ok(Box::new(kvm_entry));
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Interrupt config type not supported",
        ))
    }
}

impl<E> MsiInterruptGroup<E> {
    fn new(
        vm_fd: Arc<dyn hypervisor::Vm>,
        gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry<E>>>>,
        irq_routes: HashMap<InterruptIndex, InterruptRoute>,
    ) -> Self {
        MsiInterruptGroup {
            vm_fd,
            gsi_msi_routes,
            irq_routes,
        }
    }
}

type KvmMsiInterruptGroup = MsiInterruptGroup<kvm_irq_routing_entry>;

impl MsiInterruptGroupOps for KvmMsiInterruptGroup {
    fn set_gsi_routes(&self) -> Result<()> {
        let gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();
        let mut entry_vec: Vec<kvm_irq_routing_entry> = Vec::new();
        for (_, entry) in gsi_msi_routes.iter() {
            if entry.masked {
                continue;
            }

            entry_vec.push(entry.route);
        }

        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(entry_vec.len());
        irq_routing[0].nr = entry_vec.len() as u32;
        irq_routing[0].flags = 0;

        unsafe {
            let entries: &mut [kvm_irq_routing_entry] =
                irq_routing[0].entries.as_mut_slice(entry_vec.len());
            entries.copy_from_slice(&entry_vec);
        }

        self.vm_fd.set_gsi_routing(&irq_routing[0]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed setting GSI routing: {}", e),
            )
        })
    }
}

impl<E> InterruptSourceGroup for MsiInterruptGroup<E>
where
    E: Send + Sync,
    RoutingEntry<E>: RoutingEntryExt,
    MsiInterruptGroup<E>: MsiInterruptGroupOps,
{
    fn enable(&self) -> Result<()> {
        for (_, route) in self.irq_routes.iter() {
            route.enable(&self.vm_fd)?;
        }

        Ok(())
    }

    fn disable(&self) -> Result<()> {
        for (_, route) in self.irq_routes.iter() {
            route.disable(&self.vm_fd)?;
        }

        Ok(())
    }

    fn trigger(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.irq_fd.write(1);
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("trigger: Invalid interrupt index {}", index),
        ))
    }

    fn notifier(&self, index: InterruptIndex) -> Option<&EventFd> {
        if let Some(route) = self.irq_routes.get(&index) {
            return Some(&route.irq_fd);
        }

        None
    }

    fn update(&self, index: InterruptIndex, config: InterruptSourceConfig) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let entry = RoutingEntry::<_>::make_entry(route.gsi, &config)?;
            self.gsi_msi_routes
                .lock()
                .unwrap()
                .insert(route.gsi, *entry);

            return self.set_gsi_routes();
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("update: Invalid interrupt index {}", index),
        ))
    }

    fn mask(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let mut gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();
            if let Some(entry) = gsi_msi_routes.get_mut(&route.gsi) {
                entry.masked = true;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("mask: No existing route for interrupt index {}", index),
                ));
            }
            // Drop the guard because set_gsi_routes will try to take the lock again.
            drop(gsi_msi_routes);
            self.set_gsi_routes()?;
            return route.disable(&self.vm_fd);
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("mask: Invalid interrupt index {}", index),
        ))
    }

    fn unmask(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let mut gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();
            if let Some(entry) = gsi_msi_routes.get_mut(&route.gsi) {
                entry.masked = false;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("mask: No existing route for interrupt index {}", index),
                ));
            }
            // Drop the guard because set_gsi_routes will try to take the lock again.
            drop(gsi_msi_routes);
            self.set_gsi_routes()?;
            return route.enable(&self.vm_fd);
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unmask: Invalid interrupt index {}", index),
        ))
    }
}

pub struct LegacyUserspaceInterruptGroup {
    ioapic: Arc<Mutex<dyn InterruptController>>,
    irq: u32,
}

impl LegacyUserspaceInterruptGroup {
    fn new(ioapic: Arc<Mutex<dyn InterruptController>>, irq: u32) -> Self {
        LegacyUserspaceInterruptGroup { ioapic, irq }
    }
}

impl InterruptSourceGroup for LegacyUserspaceInterruptGroup {
    fn trigger(&self, _index: InterruptIndex) -> Result<()> {
        self.ioapic
            .lock()
            .unwrap()
            .service_irq(self.irq as usize)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to inject IRQ #{}: {:?}", self.irq, e),
                )
            })
    }

    fn update(&self, _index: InterruptIndex, _config: InterruptSourceConfig) -> Result<()> {
        Ok(())
    }
}

pub struct LegacyUserspaceInterruptManager {
    ioapic: Arc<Mutex<dyn InterruptController>>,
}

pub struct MsiInterruptManager<E> {
    allocator: Arc<Mutex<SystemAllocator>>,
    vm_fd: Arc<dyn hypervisor::Vm>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry<E>>>>,
}

pub type KvmMsiInterruptManager = MsiInterruptManager<kvm_irq_routing_entry>;

impl LegacyUserspaceInterruptManager {
    pub fn new(ioapic: Arc<Mutex<dyn InterruptController>>) -> Self {
        LegacyUserspaceInterruptManager { ioapic }
    }
}

impl<E> MsiInterruptManager<E> {
    pub fn new(allocator: Arc<Mutex<SystemAllocator>>, vm_fd: Arc<dyn hypervisor::Vm>) -> Self {
        // Create a shared list of GSI that can be shared through all PCI
        // devices. This way, we can maintain the full list of used GSI,
        // preventing one device from overriding interrupts setting from
        // another one.
        let gsi_msi_routes = Arc::new(Mutex::new(HashMap::new()));

        MsiInterruptManager {
            allocator,
            vm_fd,
            gsi_msi_routes,
        }
    }
}

impl InterruptManager for LegacyUserspaceInterruptManager {
    type GroupConfig = LegacyIrqGroupConfig;

    fn create_group(
        &self,
        config: Self::GroupConfig,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        Ok(Arc::new(Box::new(LegacyUserspaceInterruptGroup::new(
            self.ioapic.clone(),
            config.irq as u32,
        ))))
    }

    fn destroy_group(&self, _group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        Ok(())
    }
}

impl<E> InterruptManager for MsiInterruptManager<E>
where
    E: Send + Sync + 'static,
    RoutingEntry<E>: RoutingEntryExt,
    MsiInterruptGroup<E>: MsiInterruptGroupOps,
{
    type GroupConfig = MsiIrqGroupConfig;

    fn create_group(
        &self,
        config: Self::GroupConfig,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        let mut allocator = self.allocator.lock().unwrap();
        let mut irq_routes: HashMap<InterruptIndex, InterruptRoute> =
            HashMap::with_capacity(config.count as usize);
        for i in config.base..config.base + config.count {
            irq_routes.insert(i, InterruptRoute::new(&mut allocator)?);
        }

        Ok(Arc::new(Box::new(MsiInterruptGroup::new(
            self.vm_fd.clone(),
            self.gsi_msi_routes.clone(),
            irq_routes,
        ))))
    }

    fn destroy_group(&self, _group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        Ok(())
    }
}
