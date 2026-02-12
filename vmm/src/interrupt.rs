// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use devices::interrupt_controller::InterruptController;
use hypervisor::IrqRoutingEntry;
use vm_allocator::SystemAllocator;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptManagerMsi, InterruptSourceConfig,
    InterruptSourceGroup, InterruptSourceGroupMsi, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vmm_sys_util::eventfd::EventFd;

/// Reuse std::io::Result to simplify interoperability among crates.
pub type Result<T> = std::io::Result<T>;

struct InterruptRoute {
    gsi: u32,
    irq_fd: Option<EventFd>,
    registered: AtomicBool,
}

impl InterruptRoute {
    // TODO(DemiMarie,vvu): do not create an EventFd directly.
    // Leave the irqfd at `None` for registration later.
    pub fn new(allocator: &mut SystemAllocator) -> Result<Self> {
        Self::new_with_fd(allocator, Some(EventFd::new(libc::EFD_NONBLOCK)?))
    }

    pub fn new_with_fd(allocator: &mut SystemAllocator, irq_fd: Option<EventFd>) -> Result<Self> {
        let gsi = allocator
            .allocate_gsi()
            .ok_or_else(|| io::Error::other("Failed allocating new GSI"))?;

        Ok(InterruptRoute {
            gsi,
            irq_fd,
            registered: AtomicBool::new(false),
        })
    }

    pub fn enable(&self, vm: &dyn hypervisor::Vm) -> Result<()> {
        if !self.registered.load(Ordering::Acquire) {
            if let Some(ref irq_fd) = self.irq_fd {
                vm.register_irqfd(irq_fd, self.gsi)
                    .map_err(|e| io::Error::other(format!("Failed registering irq_fd: {e}")))?;
            }

            // Update internals to track the irq_fd as "registered".
            self.registered.store(true, Ordering::Release);
        }

        Ok(())
    }

    pub fn disable(&self, vm: &dyn hypervisor::Vm) -> Result<()> {
        if self.registered.load(Ordering::Acquire) {
            vm.unregister_irqfd(
                self.irq_fd
                    .as_ref()
                    .expect("cannot have registered if there is no irqfd"),
                self.gsi,
            )
            .map_err(|e| io::Error::other(format!("Failed unregistering irq_fd: {e}")))?;

            // Update internals to track the irq_fd as "unregistered".
            self.registered.store(false, Ordering::Release);
        }

        Ok(())
    }

    pub fn trigger(&self) -> Result<()> {
        match self.irq_fd {
            Some(ref fd) => fd.write(1),
            None => Ok(()),
        }
    }

    pub fn notifier(&self) -> Option<EventFd> {
        Some(
            self.irq_fd
                .as_ref()?
                .try_clone()
                .expect("Failed cloning interrupt's EventFd"),
        )
    }
}

pub struct RoutingEntry {
    route: IrqRoutingEntry,
    masked: bool,
}

pub struct MsiInterruptGroup {
    vm: Arc<dyn hypervisor::Vm>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry>>>,
    irq_routes: HashMap<InterruptIndex, InterruptRoute>,
}

impl MsiInterruptGroup {
    fn set_gsi_routes(&self, routes: &HashMap<u32, RoutingEntry>) -> Result<()> {
        let mut entry_vec: Vec<IrqRoutingEntry> = Vec::new();
        for (_, entry) in routes.iter() {
            if entry.masked {
                continue;
            }

            entry_vec.push(entry.route);
        }

        self.vm
            .set_gsi_routing(&entry_vec)
            .map_err(|e| io::Error::other(format!("Failed setting GSI routing: {e}")))
    }
}

impl MsiInterruptGroup {
    fn new(
        vm: Arc<dyn hypervisor::Vm>,
        gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry>>>,
        irq_routes: HashMap<InterruptIndex, InterruptRoute>,
    ) -> Self {
        MsiInterruptGroup {
            vm,
            gsi_msi_routes,
            irq_routes,
        }
    }
}

impl InterruptSourceGroupMsi for MsiInterruptGroup {
    fn set_notifier(
        &mut self,
        index: InterruptIndex,
        eventfd: Option<EventFd>,
        vm: &dyn hypervisor::Vm,
    ) -> core::result::Result<(), hypervisor::HypervisorVmError> {
        let route = self
            .irq_routes
            .get_mut(&index)
            .expect("attempt to set a notifier for an invalid interrupt index");
        if *route.registered.get_mut() {
            match (&eventfd, &route.irq_fd) {
                (Some(eventfd), _) => vm.register_irqfd(eventfd, route.gsi)?,
                (None, Some(irqfd)) => vm.unregister_irqfd(irqfd, route.gsi)?,
                (None, None) => {}
            }
        }
        route.irq_fd = eventfd;
        Ok(())
    }
}

impl InterruptSourceGroup for MsiInterruptGroup {
    fn enable(&self) -> Result<()> {
        for (_, route) in self.irq_routes.iter() {
            route.enable(self.vm.as_ref())?;
        }

        Ok(())
    }

    fn disable(&self) -> Result<()> {
        for (_, route) in self.irq_routes.iter() {
            route.disable(self.vm.as_ref())?;
        }

        Ok(())
    }

    fn trigger(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.trigger();
        }

        Err(io::Error::other(format!(
            "trigger: Invalid interrupt index {index}"
        )))
    }

    fn notifier(&self, index: InterruptIndex) -> Option<EventFd> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.notifier();
        }

        None
    }

    fn update(
        &self,
        index: InterruptIndex,
        config: InterruptSourceConfig,
        masked: bool,
        set_gsi: bool,
    ) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            let entry = RoutingEntry {
                route: self.vm.make_routing_entry(route.gsi, &config),
                masked,
            };

            // When mask a msi irq, entry.masked is set to be true,
            // and the gsi will not be passed to KVM through KVM_SET_GSI_ROUTING.
            // So it's required to call disable() (which deassign KVM_IRQFD) before
            // set_gsi_routes() to avoid kernel panic (see #3827)
            if masked {
                route.disable(self.vm.as_ref())?;
            }

            let mut routes = self.gsi_msi_routes.lock().unwrap();
            routes.insert(route.gsi, entry);
            if set_gsi {
                self.set_gsi_routes(&routes)?;
            }

            // Assign KVM_IRQFD after KVM_SET_GSI_ROUTING to avoid
            // panic on kernel which not have commit a80ced6ea514
            // (KVM: SVM: fix panic on out-of-bounds guest IRQ).
            if !masked {
                route.enable(self.vm.as_ref())?;
            }

            return Ok(());
        }

        Err(io::Error::other(format!(
            "update: Invalid interrupt index {index}"
        )))
    }

    fn set_gsi(&self) -> Result<()> {
        let routes = self.gsi_msi_routes.lock().unwrap();
        self.set_gsi_routes(&routes)
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
            .map_err(|e| io::Error::other(format!("failed to inject IRQ #{}: {e:?}", self.irq)))
    }

    fn update(
        &self,
        _index: InterruptIndex,
        _config: InterruptSourceConfig,
        _masked: bool,
        _set_gsi: bool,
    ) -> Result<()> {
        Ok(())
    }

    fn set_gsi(&self) -> Result<()> {
        Ok(())
    }

    fn notifier(&self, _index: InterruptIndex) -> Option<EventFd> {
        self.ioapic.lock().unwrap().notifier(self.irq as usize)
    }
}

pub struct LegacyUserspaceInterruptManager {
    ioapic: Arc<Mutex<dyn InterruptController>>,
}

pub struct MsiInterruptManager {
    allocator: Arc<Mutex<SystemAllocator>>,
    vm: Arc<dyn hypervisor::Vm>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry>>>,
}

impl LegacyUserspaceInterruptManager {
    pub fn new(ioapic: Arc<Mutex<dyn InterruptController>>) -> Self {
        LegacyUserspaceInterruptManager { ioapic }
    }
}

impl MsiInterruptManager {
    pub fn new(allocator: Arc<Mutex<SystemAllocator>>, vm: Arc<dyn hypervisor::Vm>) -> Self {
        // Create a shared list of GSI that can be shared through all PCI
        // devices. This way, we can maintain the full list of used GSI,
        // preventing one device from overriding interrupts setting from
        // another one.
        let gsi_msi_routes = Arc::new(Mutex::new(HashMap::new()));

        MsiInterruptManager {
            allocator,
            vm,
            gsi_msi_routes,
        }
    }
}

impl InterruptManager for LegacyUserspaceInterruptManager {
    type GroupConfig = LegacyIrqGroupConfig;

    fn create_group(&self, config: Self::GroupConfig) -> Result<Arc<dyn InterruptSourceGroup>> {
        Ok(Arc::new(LegacyUserspaceInterruptGroup::new(
            self.ioapic.clone(),
            config.irq,
        )))
    }

    fn destroy_group(&self, _group: Arc<dyn InterruptSourceGroup>) -> Result<()> {
        Ok(())
    }
}

impl MsiInterruptManager {
    fn create_group_raw(
        &self,
        config: <Self as InterruptManager>::GroupConfig,
    ) -> Result<MsiInterruptGroup> {
        let mut allocator = self.allocator.lock().unwrap();
        let mut irq_routes: HashMap<InterruptIndex, InterruptRoute> =
            HashMap::with_capacity(config.count as usize);
        for i in config.base..config.base + config.count {
            irq_routes.insert(i, InterruptRoute::new(&mut allocator)?);
        }

        Ok(MsiInterruptGroup::new(
            self.vm.clone(),
            self.gsi_msi_routes.clone(),
            irq_routes,
        ))
    }
}

impl InterruptManagerMsi for MsiInterruptManager {
    fn create_group_msi_mutex(
        &self,
        config: Self::GroupConfig,
    ) -> vm_device::interrupt::Result<Arc<Mutex<dyn InterruptSourceGroupMsi>>> {
        let r = self.create_group_raw(config)?;
        Ok(Arc::new(Mutex::new(r)))
    }
}

impl InterruptManager for MsiInterruptManager {
    type GroupConfig = MsiIrqGroupConfig;

    fn create_group(&self, config: Self::GroupConfig) -> Result<Arc<dyn InterruptSourceGroup>> {
        let mut allocator = self.allocator.lock().unwrap();
        let mut irq_routes: HashMap<InterruptIndex, InterruptRoute> =
            HashMap::with_capacity(config.count as usize);
        for i in config.base..config.base + config.count {
            irq_routes.insert(i, InterruptRoute::new(&mut allocator)?);
        }

        Ok(Arc::new(MsiInterruptGroup::new(
            self.vm.clone(),
            self.gsi_msi_routes.clone(),
            irq_routes,
        )))
    }

    fn destroy_group(&self, _group: Arc<dyn InterruptSourceGroup>) -> Result<()> {
        Ok(())
    }
}
