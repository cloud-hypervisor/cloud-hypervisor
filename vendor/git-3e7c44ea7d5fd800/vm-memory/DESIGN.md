## Objectives
For a typical hypervisor, there are seveval components, such as boot loader, virtual device drivers, virtio backend drivers and vhost drivers etc, that need to access VM's physical memory. The `vm-memory` crate aims to provide a set of stable traits to decouple VM memory consumers from VM memory providers. Based on these traits, VM memory consumers could access VM's physical memory without knowing the implementation details of the VM memory provider. Thus hypervisor components, such as boot loader, virtual device drivers, virtio backend drivers and vhost drivers etc, could be shared and reused by multiple hypervisors.

## API Principles
- Define consumer side interfaces to access VM's physical memory.
- Do not define provider side interfaces to supply VM physical memory.

The `vm-memory` crate focuses on defining consumer side interfaces to access VM's physical memory, and it dosen't define the way how the underline VM memory provider is implemented. For light-wieght hypervisors like crosvm and firecracker, they may make some assumptions about the structure of VM's physical memory and implement a light-weight backend to access VM's physical memory. For hypervisors like qemu, a high performance and full functionality backend may be implemented with less assumptions.

## Architecture
Th `vm-memory` is derived from two upstream projects:
- [crosvm project](https://chromium.googlesource.com/chromiumos/platform/crosvm/) commit 186eb8b0db644892e8ffba8344efe3492bb2b823
- [firecracker project](https://firecracker-microvm.github.io/) commit 80128ea61b305a27df1f751d70415b04b503eae7

To be hypervisor neutral, the high level abstraction has been heavily refactored. The new `vm-memory` crate could be divided into four logic parts as:

### Abstraction of Generic Address Space
Build generic abstractions to describe and access an address space as below:
- AddressValue: Stores the raw value of an address. Typically u32, u64 or usize is used to store the raw value. But pointers, such as \*u8, can't be used because it doesn't implement the Add and Sub traits.
- Address: Encapsulates an AddressValue object and defines methods to access it.
- Bytes: Common trait for volatile access to memory. The `Bytes` trait can be parameterized with newtypes that represent addresses, in order to enforce that addresses are used with the right "kind" of volatile memory.
- VolatileMemory: Basic implementation of volatile access to memory, implements `Bytes<usize>`.

To make the abstraction as generic as possible, all of above core traits only define methods to access the address space, and they never define methods to manage (create, delete, insert, remove etc) address spaces. By this way, the address space consumers (virtio device drivers, vhost-user drivers and boot loaders etc) may be decoupled from the address space provider (typically a hypervisor).

### Specialization for Virtual Machine Physical Address Space
The generic address space crates are specialized to access VM's physical memory with following traits:
- GuestAddress: represents a guest physical address (GPA). On ARM64, a 32-bit hypervisor may be used to support a 64-bit VM. For simplicity, u64 is used to store the the raw value no matter if it is a 32-bit or 64-bit virtual machine.
- GuestMemoryRegion: used to represent a continuous region of VM's physical memory.
- GuestMemory: used to represent a collection of GuestMemoryRegion objects. The main responsibilities of the GuestMemory trait are:
	- hide the detail of accessing VM's physical address (for example complex hierarchical structures).
	- map a request address to a GuestMemoryRegion object and relay the request to it.
	- handle cases where an access request spanning two or more GuestMemoryRegion objects.

The VM memory consumers, such as virtio device drivers, vhost drivers and boot loaders etc, should only rely on traits and structs defined here to access VM's physical memory.

### A Sample and Default Backend Implementation Based on mmap()
Provide a default and sample implementation of the GuestMemory trait by mmapping VM's physical memory into current process. Three data structures are defined here:
- MmapRegion: mmap a continous range of VM's physical memory into current and provide methods to access the mmapped memory.
- GuestRegionMmap: a wrapper structure to map VM's physical address into (mmap\_region, offset) tuple.
- GuestMemoryMmap: manage a collection of GuestRegionMmap objects for a VM.

One of the main responsibilities of the GuestMemoryMmap object is to handle the use cases where an access request crosses the memory region boundary. This scenario may be triggered when memory hotplug is supported. So there's a tradeoff between functionality and code complexity:
- use following pattern for simplicity which fails when the request crosses region boundary. It's current default behavior in the crosvm and firecracker project.
```rust
	let guest_memory_mmap: GuestMemoryMmap = ...
	let addr: GuestAddress = ...
        let buf = &mut [0u8; 5];
	let result = guest_memory_mmap.find_region(addr).unwrap().write(buf, addr);
```
- use following pattern for functionality to support request crossing region boundary:
```rust
	let guest_memory_mmap: GuestMemoryMmap = ...
	let addr: GuestAddress = ...
        let buf = &mut [0u8; 5];
	let result = guest_memory_mmap.write(buf, addr);
```

### Utilities and Helpers
Following utility and helper traits/macros are imported from the [crosvm project](https://chromium.googlesource.com/chromiumos/platform/crosvm/) with minor changes:
- ByteValued (originally `DataInit`): Types for which it is safe to initialize from raw data. A type `T` is `ByteValued` if and only if it can be initialized by reading its contents from a byte array. This is generally true for all plain-old-data structs.  It is notably not true for any type that includes a reference.
- {Le,Be}\_{16,32,64}: Explicit endian types useful for embedding in structs or reinterpreting data.

## Relationships between Traits, Structs and new Types
Traits:
- Address inherits AddressValue
- GuestMemoryRegion inherits Bytes<MemoryRegionAddress, E = Error> (must be implemented)
- GuestMemory implements Bytes<GuestAddress> (generic implementation)

New Types:
- GuestAddress: Address\<u64\>
- MemoryRegionAddress: Address\<u64\>

Structs:
- MmapRegion implements VolatileMemory
- GuestRegionMmap implements Bytes<MemoryRegionAddress> + GuestMemoryRegion
- GuestMemoryMmap implements GuestMemory
- VolatileSlice: Bytes<usize, E = volatile_memory::Error> + VolatileMemory

