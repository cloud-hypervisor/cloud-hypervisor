// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use devices::interrupt_controller::InterruptController;
use hypervisor::IrqRoutingEntry;
use vm_allocator::SystemAllocator;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceConfig, InterruptSourceGroup,
    LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vmm_sys_util::eventfd::EventFd;

/// Reuse std::io::Result to simplify interoperability among crates.
type Result<T> = std::io::Result<T>;

/// Per-interrupt routing state for an MSI/MSI-X vector.
///
/// A route lazily allocates one GSI when the interrupt is first unmasked, then
/// reuses that same GSI for later routing updates until the route is dropped.
struct InterruptRoute {
    gsi: Option<u32>,
    irq_fd: Option<EventFd>,
    registered: bool,
    allocator: Arc<Mutex<SystemAllocator>>,
}

impl InterruptRoute {
    fn new(allocator: Arc<Mutex<SystemAllocator>>) -> Result<Self> {
        // The irq_fd must be created eagerly because external components
        // (say, VFIO) need the fd at device initialization time via notifier().
        Self::new_with_fd(Some(EventFd::new(libc::EFD_NONBLOCK)?), allocator)
    }

    fn new_with_fd(
        irq_fd: Option<EventFd>,
        allocator: Arc<Mutex<SystemAllocator>>,
    ) -> Result<Self> {
        Ok(InterruptRoute {
            gsi: None,
            irq_fd,
            registered: false,
            allocator,
        })
    }

    /// Allocates a GSI, if non was allocated yet.
    ///
    /// Repeated calls return a previously allocated GSI.
    fn allocate_gsi(&mut self) -> Result<u32> {
        match self.gsi {
            Some(existing) => Ok(existing),
            None => {
                let new_gsi = self
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_gsi()
                    .map_err(|e| io::Error::other(format!("Failed allocating new GSI: {e}")))?;
                self.gsi = Some(new_gsi);
                Ok(new_gsi)
            }
        }
    }

    fn enable(&mut self, vm: &dyn hypervisor::Vm) -> Result<()> {
        let gsi = match self.gsi {
            Some(gsi) => gsi,
            // Do nothing if no GSI was ever allocated for this route, which means the interrupt is still masked.
            None => return Ok(()),
        };

        if !self.registered {
            if let Some(ref irq_fd) = self.irq_fd {
                vm.register_irqfd(irq_fd, gsi)
                    .map_err(|e| io::Error::other(format!("Failed registering irq_fd: {e}")))?;
            }

            // Update internals to track the irq_fd as "registered".
            self.registered = true;
        }

        Ok(())
    }

    fn disable(&mut self, vm: &dyn hypervisor::Vm) -> Result<()> {
        let gsi = match self.gsi {
            Some(gsi) => gsi,
            // Do nothing if no GSI was ever allocated for this route, which means the interrupt is still masked.
            None => return Ok(()),
        };

        if self.registered {
            if let Some(ref irq_fd) = self.irq_fd {
                vm.unregister_irqfd(irq_fd, gsi)
                    .map_err(|e| io::Error::other(format!("Failed unregistering irq_fd: {e}")))?;
            }

            // Update internals to track the irq_fd as "unregistered".
            self.registered = false;
        }

        Ok(())
    }

    fn trigger(&mut self) -> Result<()> {
        match self.irq_fd {
            Some(ref fd) => fd.write(1),
            None => Ok(()),
        }
    }

    fn notifier(&mut self) -> Option<EventFd> {
        Some(
            self.irq_fd
                .as_ref()?
                .try_clone()
                .expect("Failed cloning interrupt's EventFd"),
        )
    }

    // This is currently not used, but the upcoming vhost-guest feature
    // will use it. Use #[allow(dead_code)] to suppress a compiler
    // warning.
    #[allow(dead_code)]
    fn set_notifier(&mut self, eventfd: Option<EventFd>, vm: &dyn hypervisor::Vm) -> Result<()> {
        let old_irqfd = core::mem::replace(&mut self.irq_fd, eventfd);
        if self.registered {
            // A registered route must have a GSI allocated, since enable()
            // only sets registered=true after using a valid GSI.
            let gsi = self.gsi.expect("registered route has no GSI allocated");
            if let Some(ref irq_fd) = self.irq_fd {
                vm.register_irqfd(irq_fd, gsi)
                    .map_err(|e| io::Error::other(format!("Failed registering irq_fd: {e}")))?;
            }
            // If the irqfd cannot be unregistered, what to do?  Spin?
            // Returning an error isn't helpful as the new irqfd is already registered.
            if let Some(old_irq_fd) = old_irqfd {
                match vm.unregister_irqfd(&old_irq_fd, gsi) {
                    Ok(()) => {}
                    Err(e) => log::warn!("Failed unregistering old irqfd: {e}"),
                }
            }
        }
        Ok(())
    }
}

impl Drop for InterruptRoute {
    fn drop(&mut self) {
        if let Some(gsi) = self.gsi {
            let mut allocator = self.allocator.lock().unwrap();
            // This panics only if we have a programming error (two entities
            // used the same interrupt and one was freed already). In these
            // cases, VMM and the VM are likely to fail soon anyway.
            allocator
                .free_gsi(gsi)
                .expect("previously allocated GSI should be in bounds and still allocated");
        }
    }
}

struct RoutingEntry {
    route: IrqRoutingEntry,
    masked: bool,
}

struct MsiInterruptGroup {
    vm: Arc<dyn hypervisor::Vm>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry>>>,
    irq_routes: HashMap<InterruptIndex, Mutex<InterruptRoute>>,
}

impl MsiInterruptGroup {
    fn new(
        vm: Arc<dyn hypervisor::Vm>,
        gsi_msi_routes: Arc<Mutex<HashMap<u32, RoutingEntry>>>,
        irq_routes: HashMap<InterruptIndex, Mutex<InterruptRoute>>,
    ) -> Self {
        MsiInterruptGroup {
            vm,
            gsi_msi_routes,
            irq_routes,
        }
    }

    fn set_gsi_routes(&self, routes: &HashMap<u32, RoutingEntry>) -> Result<()> {
        let mut entry_vec: Vec<IrqRoutingEntry> = Vec::new();
        for entry in routes.values() {
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

impl InterruptSourceGroup for MsiInterruptGroup {
    fn enable(&self) -> Result<()> {
        for route in self.irq_routes.values() {
            route.lock().unwrap().enable(self.vm.as_ref())?;
        }

        Ok(())
    }

    fn disable(&self) -> Result<()> {
        for route in self.irq_routes.values() {
            route.lock().unwrap().disable(self.vm.as_ref())?;
        }

        Ok(())
    }

    fn trigger(&self, index: InterruptIndex) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.lock().unwrap().trigger();
        }

        Err(io::Error::other(format!(
            "trigger: Invalid interrupt index {index}"
        )))
    }

    fn notifier(&self, index: InterruptIndex) -> Option<EventFd> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.lock().unwrap().notifier();
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
            let mut route = route.lock().unwrap();
            let gsi = if masked {
                match route.gsi {
                    Some(gsi) => gsi,
                    // No update needed if masked and no GSI was ever allocated
                    None => return Ok(()),
                }
            } else {
                // Allocate a GSI when the interrupt vector is first unmasked
                route.allocate_gsi()?
            };

            let entry = RoutingEntry {
                route: self.vm.make_routing_entry(gsi, &config),
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
            routes.insert(gsi, entry);
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

    fn set_notifier(
        &mut self,
        index: InterruptIndex,
        eventfd: Option<EventFd>,
        vm: &dyn hypervisor::Vm,
    ) -> Result<()> {
        if let Some(route) = self.irq_routes.get(&index) {
            return route.lock().unwrap().set_notifier(eventfd, vm);
        }

        Ok(())
    }
}

struct LegacyUserspaceInterruptGroup {
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
        let mut irq_routes: HashMap<InterruptIndex, Mutex<InterruptRoute>> =
            HashMap::with_capacity(config.count as usize);
        for i in config.base..config.base + config.count {
            irq_routes.insert(i, Mutex::new(InterruptRoute::new(self.allocator.clone())?));
        }

        Ok(MsiInterruptGroup::new(
            self.vm.clone(),
            self.gsi_msi_routes.clone(),
            irq_routes,
        ))
    }
}

impl InterruptManager for MsiInterruptManager {
    type GroupConfig = MsiIrqGroupConfig;

    fn create_group(&self, config: Self::GroupConfig) -> Result<Arc<dyn InterruptSourceGroup>> {
        let mut irq_routes: HashMap<InterruptIndex, Mutex<InterruptRoute>> =
            HashMap::with_capacity(config.count as usize);
        for i in config.base..config.base + config.count {
            irq_routes.insert(i, Mutex::new(InterruptRoute::new(self.allocator.clone())?));
        }

        Ok(Arc::new(MsiInterruptGroup::new(
            self.vm.clone(),
            self.gsi_msi_routes.clone(),
            irq_routes,
        )))
    }

    fn create_group_mut(
        &self,
        config: Self::GroupConfig,
    ) -> vm_device::interrupt::Result<Arc<Mutex<dyn InterruptSourceGroup>>> {
        let r = self.create_group_raw(config)?;
        Ok(Arc::new(Mutex::new(r)))
    }

    fn destroy_group(&self, _group: Arc<dyn InterruptSourceGroup>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod interrupt_route {
        #[cfg(target_arch = "x86_64")]
        use vm_allocator::GsiApic;
        use vm_memory::GuestAddress;

        use super::*;

        fn make_allocator() -> Arc<Mutex<SystemAllocator>> {
            Arc::new(Mutex::new(
                SystemAllocator::new(
                    GuestAddress(0x1000_0000),
                    0x1000_0000,
                    GuestAddress(0x2000_0000),
                    0x1000_0000,
                    #[cfg(target_arch = "x86_64")]
                    &[GsiApic::new(5, 19)],
                )
                .unwrap(),
            ))
        }

        #[test]
        fn test_allocate_gsi_on_same_route_is_idempotent() {
            let allocator = make_allocator();
            let mut route = InterruptRoute::new(allocator.clone()).unwrap();
            let gsi1 = route.allocate_gsi().unwrap();
            let gsi2 = route.allocate_gsi().unwrap();
            assert_eq!(
                gsi1, gsi2,
                "repeated allocate_gsi on the same route must return the same GSI (as it uses the buffered value)"
            );
        }

        #[test]
        fn test_allocated_gsis_are_distinct_for_different_routes() {
            let allocator = make_allocator();
            let mut route1 = InterruptRoute::new(allocator.clone()).unwrap();
            let mut route2 = InterruptRoute::new(allocator.clone()).unwrap();
            let gsi1 = route1.allocate_gsi().unwrap();
            let gsi2 = route2.allocate_gsi().unwrap();
            assert_ne!(gsi1, gsi2, "two routes must receive distinct GSIs");
        }

        #[test]
        // Test that a route can allocate a GSI, releases it on drop, and
        // that a second route can then allocate the very same GSI.
        fn test_drop_frees_gsi() {
            let allocator = make_allocator();
            let gsi = {
                let mut route = InterruptRoute::new(allocator.clone()).unwrap();
                route.allocate_gsi().unwrap()
            }; // Drop reclaims the GSI.
            let mut route2 = InterruptRoute::new(allocator.clone()).unwrap();
            let gsi2 = route2.allocate_gsi().unwrap();
            assert_eq!(gsi, gsi2, "dropped GSI should be reclaimed");
        }

        #[test]
        fn test_drop_without_gsi_does_not_panic() {
            // A route that never had a GSI allocated must drop cleanly.
            drop(InterruptRoute::new(make_allocator()).unwrap());
        }

        #[test]
        fn test_doesnt_run_out_of_gsis() {
            // Would be exhausted at 4072 if GSIs are not freed
            for _ in 0..5_000 {
                let mut route = InterruptRoute::new(make_allocator()).unwrap();
                route.allocate_gsi().expect("should allocate");
            }
        }
    }
}
