# Memory

Cloud-Hypervisor has many ways to expose memory to the guest VM. This document
aims to explain what Cloud-Hypervisor is capable of and how it can be used to
meet the needs of very different use cases.

## Basic Parameters

`MemoryConfig` or what is known as `--memory` from the CLI perspective is the
easiest way to get started with Cloud-Hypervisor.

```rust
struct MemoryConfig {
    size: u64,
    mergeable: bool,
    shared: bool,
    hugepages: bool,
    hotplug_method: HotplugMethod,
    hotplug_size: Option<u64>,
    balloon: bool,
    balloon_size: u64,
    zones: Option<Vec<MemoryZoneConfig>>,
}
```

```
--memory <memory>	Memory parameters "size=<guest_memory_size>,mergeable=on|off,shared=on|off,hugepages=on|off,hotplug_method=acpi|virtio-mem,hotplug_size=<hotpluggable_memory_size>,balloon=on|off"
```

### `size`

Size of the RAM in the guest VM.

This option is mandatory when using the `--memory` parameter.

Value is an unsigned integer of 64 bits.

_Example_

```
--memory size=1G
```

### `mergeable`

Specifies if the pages from the guest RAM must be marked as _mergeable_. In
case this option is `true` or `on`, the pages will be marked with `madvise(2)`
to let the host kernel know which pages are eligible for being merged by the
KSM daemon.

This option can be used when trying to reach a higher density of VMs running
on a single host, as it will reduce the amount of memory consumed by each VM.

By default this option is turned off.

_Example_

```
--memory size=1G,mergeable=on
```

### `shared`

Specifies if the memory must be `mmap(2)` with `MAP_SHARED` flag.

By sharing a memory mapping, one can share the guest RAM with other processes
running on the host. One can use this option when running vhost-user devices
as part of the VM device model, as they will be driven by standalone daemons
needing access to the guest RAM content.

By default this option is turned off, which results in performing `mmap(2)`
with `MAP_PRIVATE` flag.

_Example_

```
--memory size=1G,shared=on
```

### `hugepages`

Specifies if the memory must be `mmap(2)` with `MAP_HUGETLB` and `MAP_HUGE_2MB`
flags. This performs a memory mapping relying on 2MiB pages instead of the
default 4kiB pages.

By using hugepages, one can improve the overall performance of the VM, assuming
the guest will allocate hugepages as well. Another interesting use case is VFIO
as it speeds up the VM's boot time since the amount of IOMMU mappings are
reduced.

By default this option is turned off.

_Example_

```
--memory size=1G,hugepages=on
```

### `hotplug_method`

Selects the way of adding and/or removing memory to/from a booted VM.

Possible values are `acpi` and `virtio-mem`. Default value is `acpi`.

_Example_

```
--memory size=1G,hotplug_method=acpi
```

### `hotplug_size`

Amount of memory that can be dynamically added to the VM.

Value is an unsigned integer of 64 bits. A value of 0 simply means that no
memory can be added to the VM.

_Example_

```
--memory size=1G,hotplug_size=1G
```

### `balloon`

Specifies if the `virtio-balloon` device must be activated. This creates a
dedicated virtio device for managing the balloon in the guest, which allows
guest to access more or less memory depending on the balloon size.

By default this option is turned off.

_Example_

```
--memory size=1G,balloon=on
```

## Advanced Parameters

`MemoryZoneConfig` or what is known as `--memory-zone` from the CLI perspective
is a power user parameter. It allows for a full description of the guest RAM,
describing how every memory region is backed and exposed to the guest.

```rust
struct MemoryZoneConfig {
    id: String,
    size: u64,
    file: Option<PathBuf>,
    shared: bool,
    hugepages: bool,
    host_numa_node: Option<u32>,
}
```

```
--memory-zone <memory-zone>	User defined memory zone parameters "size=<guest_memory_region_size>,file=<backing_file>,shared=on|off,hugepages=on|off,host_numa_node=<node_id>,id=<zone_identifier>"
```

This parameter expects one or more occurences, allowing for a list of memory
zones to be defined. It must be used with `--memory size=0`, clearly indicating
that the memory will be described through advanced parameters.

Each zone is given a list of options which we detail through the following
sections.

### `id`

Memory zone identifier. This identifier must be unique, otherwise an error will
be returned.

This option is useful when referring to a memory zone previously created. In
particular, the `--numa` parameter can associate a memory zone to a specific
NUMA node based on the memory zone identifier.

This option is mandatory when using the `--memory-zone` parameter.

Value is a string.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G
```

### `size`

Size of the memory zone.

This option is mandatory when using the `--memory-zone` parameter.

Value is an unsigned integer of 64 bits.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G
```

### `file`

Path to the file backing the memory zone. This can be either a file or a
directory. In case of a file, it will be opened and used as the backing file
for the `mmap(2)` operation. In case of a directory, a temporary file with no
hard link on the filesystem will be created. This file will be used as the
backing file for the `mmap(2)` operation.

This option can be particularly useful when trying to back a part of the guest
RAM with a well known file. In the context of the snapshot/restore feature, and
if the provided path is a file, the snapshot operation will not perform any
copy of the guest RAM content for this specific memory zone since the user has
access to it and it would duplicate data already stored on the current
filesystem.

Value is a string.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G,file=/foo/bar
```

### `shared`

Specifies if the memory zone must be `mmap(2)` with `MAP_SHARED` flag.

By sharing a memory zone mapping, one can share part of the guest RAM with
other processes running on the host. One can use this option when running
vhost-user devices as part of the VM device model, as they will be driven
by standalone daemons needing access to the guest RAM content.

By default this option is turned off, which result in performing `mmap(2)`
with `MAP_PRIVATE` flag.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G,shared=on
```

### `hugepages`

Specifies if the memory zone must be `mmap(2)` with `MAP_HUGETLB` and
`MAP_HUGE_2MB` flags. This performs a memory zone mapping relying on 2MiB
pages instead of the default 4kiB pages.

By using hugepages, one can improve the overall performance of the VM, assuming
the guest will allocate hugepages as well. Another interesting use case is VFIO
as it speeds up the VM's boot time since the amount of IOMMU mappings are
reduced.

By default this option is turned off.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G,hugepages=on
```

### `host_numa_node`

Node identifier of a node present on the host. This option will let the user
pick a specific NUMA node from which the memory must be allocated. After the
memory zone is `mmap(2)`, the NUMA policy for this memory mapping will be
applied through `mbind(2)`, relying on the provided node identifier. If the
node does not exist on the host, the call to `mbind(2)` will fail.

This option is useful when trying to back a VM memory with a specific type of
memory from the host. Assuming a host has two types of memory, with one slower
than the other, each related to a distinct NUMA node, one could create a VM
with slower memory accesses by backing the entire guest RAM from the furthest
NUMA node on the host.

This option also gives the opportunity to create a VM with non uniform memory
accesses as one could define a first memory zone backed by fast memory, and a
second memory zone backed by slow memory.

Value is an unsigned integer of 32 bits.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G,host_numa_node=0
```

## NUMA settings

`NumaConfig` or what is known as `--numa` from the CLI perspective has been
introduced to define a guest NUMA topology. It allows for a fine description
about the CPUs and memory ranges associated with each NUMA node. Additionally
it allows for specifying the distance between each NUMA node.

```rust
struct NumaConfig {
    id: u32,
    cpus: Option<Vec<u8>>,
    distances: Option<Vec<NumaDistance>>,
    memory_zones: Option<Vec<String>>,
}
```

```
--numa <numa>	Settings related to a given NUMA node "id=<node_id>,cpus=<cpus_id>,distances=<list_of_distances_to_destination_nodes>,memory_zones=<list_of_memory_zones>"
```

### `id`

Node identifier of a guest NUMA node. This identifier must be unique, otherwise
an error will be returned.

This option is mandatory when using the `--numa` parameter.

Value is an unsigned integer of 32 bits.

_Example_

```
--numa id=0
```

### `cpus`

List of virtual CPUs attached to the guest NUMA node identified by the `id`
option. This allows for describing a list of CPUs which must be seen by the
guest as belonging to the NUMA node `id`.

One can use this option for a fine grained description of the NUMA topology
regarding the CPUs associated with it, which might help the guest run more
efficiently.

Multiple values can be provided to define the list. Each value is an unsigned
integer of 8 bits.

For instance, if one needs to attach all CPUs from 0 to 4 to a specific node,
the syntax using `-` will help define a contiguous range with `cpus=0-4`. The
same example could also be described with `cpus=0:1:2:3:4`.

A combination of both `-` and `:` separators is useful when one might need to
describe a list containing all CPUs from 0 to 99 and the CPU 255, as it could
simply be described with `cpus=0-99:255`.

_Example_

```
--cpus boot=8
--numa id=0,cpus=1-3:7
--numa id=1,cpus=0:4-6
```

### `distances`

List of distances between the current NUMA node referred by `id` and the
destination NUMA nodes listed along with distances. This option let the user
choose the distances between guest NUMA nodes. This is important to provide an
accurate description of the way non uniform memory accesses will perform in the
guest.

One or more tuple of two values must be provided through this option. The first
value is an unsigned integer of 32 bits as it represents the destination NUMA
node. The second value is an unsigned integer of 8 bits as it represents the
distance between the current NUMA node and the destination NUMA node. The two
values are separated by `@` (`value1@value2`), meaning the destination NUMA
node `value1` is located at a distance of `value2`. Each tuple is separated
from the others with `:` separator.

For instance, if one wants to define 3 NUMA nodes, with each node located at
different distances, it can be described with the following example.

_Example_

```
--numa id=0,distances=1@15:2@25
--numa id=1,distances=0@15:2@20
--numa id=2,distances=0@25:1@20
```

### `memory_zones`

List of memory zones attached to the guest NUMA node identified by the `id`
option. This allows for describing a list of memory ranges which must be seen
by the guest as belonging to the NUMA node `id`.

This option can be very useful and powerful when combined with `host_numa_node`
option from `--memory-zone` parameter as it allows for creating a VM with non
uniform memory accesses, and let the guest know about it. It allows for
exposing memory zones through different NUMA nodes, which can help the guest
workload run more efficiently.

Multiple values can be provided to define the list. Each value is a string
referring to an existing memory zone identifier. Values are separated from
each other with the `:` separator.

_Example_

```
--memory size=0
--memory-zone id=mem0,size=1G
--memory-zone id=mem1,size=1G
--memory-zone id=mem2,size=1G
--numa id=0,memory_zones=mem0:mem2
--numa id=1,memory_zones=mem1
```
