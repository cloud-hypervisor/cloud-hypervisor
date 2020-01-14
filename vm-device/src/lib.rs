extern crate serde;
extern crate thiserror;
extern crate vm_memory;

pub mod interrupt;

use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
    MemoryRegionAddress,
};

use thiserror::Error;

/// Trait meant for triggering the DMA mapping update related to an external
/// device not managed fully through virtio. It is dedicated to virtio-iommu
/// in order to trigger the map update anytime the mapping is updated from the
/// guest.
pub trait ExternalDmaMapping: Send + Sync {
    /// Map a memory range
    fn map(&self, iova: u64, gpa: u64, size: u64) -> std::result::Result<(), std::io::Error>;

    /// Unmap a memory range
    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), std::io::Error>;
}

#[derive(Error, Debug)]
pub enum MigratableError {
    #[error("Failed to pause migratable component: {0}")]
    Pause(#[source] anyhow::Error),

    #[error("Failed to resume migratable component: {0}")]
    Resume(#[source] anyhow::Error),
}

/// A Pausable component can be paused and resumed.
pub trait Pausable {
    /// Pause the component.
    fn pause(&mut self) -> std::result::Result<(), MigratableError>;

    /// Resume the component.
    fn resume(&mut self) -> std::result::Result<(), MigratableError>;
}

/// A snapshotable component can be snapshoted.
pub trait Snapshotable {}

/// Trait to be implemented by any component (device, CPU, RAM, etc) that
/// can be migrated.
/// All migratable components are paused before being snapshotted, and then
/// eventually resumed. Thus any Migratable component must be both Pausable
/// and Snapshotable.
pub trait Migratable: Pausable + Snapshotable {}

fn get_region_host_address_range(
    region: &GuestRegionMmap,
    addr: MemoryRegionAddress,
    size: usize,
) -> Option<*mut u8> {
    region.check_address(addr).and_then(|addr| {
        region
            .checked_offset(addr, size)
            .map(|_| region.as_ptr().wrapping_offset(addr.raw_value() as isize))
    })
}

/// Convert an absolute address into an address space (GuestMemory)
/// to a host pointer and verify that the provided size define a valid
/// range within a single memory region.
/// Return None if it is out of bounds or if addr+size overlaps a single region.
///
/// This is a temporary vm-memory wrapper.
pub fn get_host_address_range(
    mem: &GuestMemoryMmap,
    addr: GuestAddress,
    size: usize,
) -> Option<*mut u8> {
    mem.to_region_addr(addr)
        .and_then(|(r, addr)| get_region_host_address_range(r, addr, size))
}

#[cfg(test)]
mod tests {

    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn test_get_host_address_range() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::new(&[(start_addr1, 0x400), (start_addr2, 0x400)]).unwrap();

        assert!(get_host_address_range(&guest_mem, GuestAddress(0x600), 0x100).is_none());

        // Overlapping range
        assert!(get_host_address_range(&guest_mem, GuestAddress(0x1000), 0x500).is_none());

        // Overlapping range
        assert!(get_host_address_range(&guest_mem, GuestAddress(0x1200), 0x500).is_none());

        let ptr = get_host_address_range(&guest_mem, GuestAddress(0x1000), 0x100).unwrap();

        let ptr0 = get_host_address_range(&guest_mem, GuestAddress(0x1100), 0x100).unwrap();

        let ptr1 = guest_mem.get_host_address(GuestAddress(0x1200)).unwrap();
        assert_eq!(
            ptr,
            guest_mem
                .find_region(GuestAddress(0x1100))
                .unwrap()
                .as_ptr()
        );
        assert_eq!(unsafe { ptr0.offset(0x100) }, ptr1);
    }
}
