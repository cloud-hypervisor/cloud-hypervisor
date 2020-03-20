- [v0.6.0](#v060)
    - [Directly Assigned Devices Hotplug](#directly-assigned-devices-hotplug)
    - [Shared Filesystem Improvements](#shared-filesystem-improvements)
    - [Block and Networking IO Self Offloading](#block-and-networking-io-self-offloading)
    - [Command Line Interface](#command-line-interface)
    - [PVH Boot](#pvh-boot)
    - [Contributors](#contributors)
- [v0.5.1](#v051)
- [v0.5.0](#v050)
    - [Virtual Machine Dynamic Resizing](#virtual-machine-dynamic-resizing)
    - [Multi-Queue, Multi-Threaded Paravirtualization](#multi-queue-multi-threaded-paravirtualization)
    - [New Interrupt Management Framework](#new-interrupt-management-framework)
    - [Development Tools](#development-tools)
    - [Kata Containers Integration](#kata-containers-integration)
    - [Contributors](#contributors)
- [v0.4.0](#v040)
    - [Dynamic virtual CPUs addition](#dynamic-virtual-cpus-addition)
    - [Programmatic firmware tables generation](#programmatic-firmware-tables-generation)
    - [Filesystem and block devices vhost-user backends](#filesystem-and-block-devices-vhost-user-backends)
    - [Guest pause and resume](#guest-pause-and-resume)
    - [Userspace IOAPIC by default](#userspace-ioapic-by-default)
    - [PCI BAR reprogramming](#pci-bar-reprogramming)
    - [New `cloud-hypervisor` organization](#new-cloud-hypervisor-organization)
    - [Contributors](#contributors-1)
- [v0.3.0](#v030)
    - [Block device offloading](#block-device-offloading)
    - [Network device backend](#network-device-backend)
    - [Virtual sockets](#virtual-sockets)
    - [HTTP based API](#http-based-api)
    - [Memory mapped virtio transport](#memory-mapped-virtio-transport)
    - [Paravirtualized IOMMU](#paravirtualized-iommu)
    - [Ubuntu 19.10](#ubuntu-1910)
    - [Large memory guests](#large-memory-guests)
- [v0.2.0](#v020)
    - [Network device offloading](#network-device-offloading)
    - [Minimal hardware-reduced ACPI](#minimal-hardware-reduced-acpi)
    - [Debug I/O port](#debug-io-port)
    - [Improved direct device assignment](#improved-direct-device-assignment)
    - [Improved shared filesystem](#improved-shared-filesystem)
    - [Ubuntu bionic based CI](#ubuntu-bionic-based-ci)
- [v0.1.0](#v010)
    - [Shared filesystem](#shared-filesystem)
    - [Initial direct device assignment support](#initial-direct-device-assignment-support)
    - [Userspace IOAPIC](#userspace-ioapic)
    - [Virtual persistent memory](#virtual-persistent-memory)
    - [Linux kernel bzImage](#linux-kernel-bzimage)
    - [Console over virtio](#console-over-virtio)
    - [Unit testing](#unit-testing)
    - [Integration tests parallelization](#integration-tests-parallelization)

# v0.6.0

This release has been tracked through the [0.6.0 project](https://github.com/cloud-hypervisor/cloud-hypervisor/projects/7).

Highlights for `cloud-hypervisor` version 0.6.0 include:

### Directly Assigned Devices Hotplug

We continued our efforts around supporting dynamically changing the guest
resources. After adding support for CPU and memory hotplug, Cloud Hypervisor
now supports hot plugging and hot unplugging directly assigned (a.k.a. `VFIO`)
devices into an already running guest. This closes the features gap for
providing a complete Kata Containers workloads support with Cloud Hypervisor.

### Shared Filesystem Improvements

We enhanced our shared filesystem support through many `virtio-fs` improvements.
By adding support for DAX, parallel processing of multiple requests, `FS_IO`,
`LSEEK` and the `MMIO` virtio transport layer to our `vhost_user_fs` daemon, we
improved our filesystem sharing performance, but also made it more stable and
compatible with other `virtio-fs` implementations.

### Block and Networking IO Self Offloading

When choosing to offload the paravirtualized block and networking I/O to an
external process (through the `vhost-user` protocol), Cloud Hypervisor now
automatically spawns its default `vhost-user-blk` and `vhost-user-net` backends
into their own, separate processes.
This provides a seamless parvirtualized I/O user experience for those who want
to run their guest I/O into separate executions contexts.

### Command Line Interface

More and more Cloud Hypervisor services are exposed through the
[Rest API](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/vmm/src/api/openapi/cloud-hypervisor.yaml)
and thus only accessible via relatively cumbersome HTTP calls. In order
to abstract those calls into a more user friendly tool, we created a Cloud
Hypervisor Command Line Interface (CLI) called `ch-remote`.
The `ch-remote` binary is created with each build and available e.g. at
`cloud-hypervisor/target/debug/ch-remote` when doing a debug build.

Please check `ch-remote --help` for a complete description of all available
commands.

### PVH Boot

In addition to the traditional Linux boot protocol, Cloud Hypervisor now
supports direct kernel booting through the [PVH ABI](https://xenbits.xen.org/docs/unstable/misc/pvh.html).

### Contributors

With the 0.6.0 release, we are welcoming a few new contributors. Many thanks
to them and to everyone that contributed to this release:

* Alejandro Jimenez <alejandro.j.jimenez@oracle.com>
* Arron Wang <arron.wang@intel.com>
* Bin Liu <liubin0329@gmail.com>
* Bo Chen <chen.bo@intel.com>
* Cathy Zhang <cathy.zhang@intel.com>
* Eryu Guan <eguan@linux.alibaba.com>
* Jose Carlos Venegas Munoz <jose.carlos.venegas.munoz@intel.com>
* Liu Bo <bo.liu@linux.alibaba.com>
* Qiu Wenbo <qiuwenbo@phytium.com.cn>
* Rob Bradford <robert.bradford@intel.com>
* Samuel Ortiz <sameo@linux.intel.com>
* Sebastien Boeuf <sebastien.boeuf@intel.com>
* Sergio Lopez <slp@redhat.com>

# v0.5.1

This is a bugfix release branched off v0.5.0. It contains the following fixes:

* Update DiskConfig to contain missing disk control features (#790) - Samuel Ortiz and Sergio Lopez
* Prevent memory overcommit via virtio-fs (#763) - Sebastien Boeuf
* Fixed error reporting for resize command - Samuel Ortiz
* Double reboot workaround (#783) - Rob Bradford
* Various CI and development tooling fixes - Sebastien Boeuf, Samuel Ortiz, Rob Bradford

# v0.5.0

This release has been tracked through the [0.5.0 project](https://github.com/cloud-hypervisor/cloud-hypervisor/projects/6).

Highlights for `cloud-hypervisor` version 0.5.0 include:

### Virtual Machine Dynamic Resizing

With 0.4.0 we added support for CPU hot plug, and 0.5.0 adds CPU hot unplug and
memory hot plug as well. This allows to dynamically resize Cloud Hypervisor
guests which is needed for e.g. Kubernetes related use cases.
The memory hot plug implementation is based on the same framework as the CPU hot
plug/unplug one, i.e. hardware-reduced ACPI notifications to the guest.

Next on our VM resizing roadmap is the PCI devices hotplug feature.

### Multi-Queue, Multi-Threaded Paravirtualization

We enhanced our virtio networking and block support by having both devices use
multiple I/O queues handled by multiple threads. This improves our default
paravirtualized networking and block devices throughput.

### New Interrupt Management Framework

We improved our interrupt management implementation by introducing an Interrupt
Manager framework, based on the currently on-going [rust-vmm vm-device](https://github.com/rust-vmm/vm-device)
crates discussions. This move made the code significantly cleaner, and allowed
us to remove several KVM related dependencies from crates like the PCI and
virtio ones.

### Development Tools

In order to provide a better developer experience, we worked on improving our
build, development and testing tools.
Somehow similar to the excellent
[Firecracker's devtool](https://github.com/firecracker-microvm/firecracker/blob/master/tools/devtool),
we now provide a [dev_cli script](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/scripts/dev_cli.sh).

With this new tool, our users and contributors will be able to build and test
Cloud Hypervisor through a containerized environment.

### Kata Containers Integration

We spent some significant time and efforts debugging and fixing our integration
with the [Kata Containers](https://github.com/kata-containers) project. Cloud
Hypervisor is now a fully supported Kata Containers hypervisor, and is
integrated into the project's CI.

### Contributors

Many thanks to everyone that contributed to the 0.5.0 release:

* Bo Chen <chen.bo@intel.com>
* Cathy Zhang <cathy.zhang@intel.com>
* Qiu Wenbo <qiuwenbo@phytium.com.cn>
* Rob Bradford <robert.bradford@intel.com>
* Samuel Ortiz <sameo@linux.intel.com>
* Sebastien Boeuf <sebastien.boeuf@intel.com>
* Sergio Lopez <slp@redhat.com>
* Yang Zhong <yang.zhong@intel.com>

# v0.4.0

This release has been tracked through the [0.4.0 project](https://github.com/cloud-hypervisor/cloud-hypervisor/projects/4).

Highlights for `cloud-hypervisor` version 0.4.0 include:

### Dynamic virtual CPUs addition

As a way to vertically scale Cloud-Hypervisor guests, we now support dynamically
adding virtual CPUs to the guests, a mechanism also known as CPU hot plug.
Through hardware-reduced ACPI notifications, Cloud Hypervisor can now add CPUs
to an already running guest and the high level operations for that process are
documented [here](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/docs/hotplug.md)

During the next release cycles we are planning to extend Cloud Hypervisor
hot plug framework to other resources, namely PCI devices and memory.

### Programmatic firmware tables generation

As part of the CPU hot plug feature enablement, and as a requirement for hot
plugging other resources like devices or RAM, we added support for
programmatically generating the needed ACPI tables. Through a dedicated
`acpi-tables` crate, we now have a flexible and clean way of generating those
tables based on the VMM device model and topology.

### Filesystem and block devices vhost-user backends

Our objective of running all Cloud Hypervisor paravirtualized I/O to a
vhost-user based framework is getting closer as we've added Rust based
implementations for vhost-user-blk and virtiofs backends. Together with the
vhost-user-net backend that came with the 0.3.0 release, this will form the
default Cloud Hypervisor I/O architecture.

### Guest pause and resume

As an initial requiremnt for enabling live migration, we added support for
pausing and resuming any VMM components. As an intermediate step towards live
migration, the upcoming guest snapshotting feature will be based on the pause
and resume capabilities.

### Userspace IOAPIC by default

As a way to simplify our device manager implementation, but also in order to
stay away from privileged rings as often as possible, any device that relies on
pin based interrupts will be using the userspace IOAPIC implementation by
default.

### PCI BAR reprogramming

In order to allow for a more flexible device model, and also support guests
that would want to move PCI devices, we added support for PCI devices BAR
reprogramming.

### New `cloud-hypervisor` organization

As we wanted to be more flexible on how we manage the Cloud Hypervisor project,
we decided to move it under a [dedicated GitHub organization](https://github.com/cloud-hypervisor).
Together with the [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
project, this new organization also now hosts our [kernel](https://github.com/cloud-hypervisor/linux)
and [firmware](https://github.com/cloud-hypervisor/rust-hypervisor-firmware)
repositories. We may also use it to host any rust-vmm that we'd need to
temporarily fork.
Thanks to GitHub's seamless repository redirections, the move is completely
transparent to all Cloud Hypervisor contributors, users and followers.

### Contributors

Many thanks to everyone that contributed to the 0.4.0 release:

* Cathy Zhang <cathy.zhang@intel.com>
* Emin Ghuliev <drmint80@gmail.com>
* Jose Carlos Venegas Munoz <jose.carlos.venegas.munoz@intel.com>
* Qiu Wenbo <qiuwenbo@phytium.com.cn>
* Rob Bradford <robert.bradford@intel.com>
* Samuel Ortiz <sameo@linux.intel.com>
* Sebastien Boeuf <sebastien.boeuf@intel.com>
* Sergio Lopez <slp@redhat.com>
* Wu Zongyong <wuzongyong@linux.alibaba.com>

# v0.3.0

This release has been tracked through the [0.3.0 project](https://github.com/cloud-hypervisor/cloud-hypervisor/projects/3).

Highlights for `cloud-hypervisor` version 0.3.0 include:

### Block device offloading

We continue to work on offloading paravirtualized I/O to external processes,
and we added support for
[vhost-user-blk](https://access.redhat.com/solutions/3394851) backends.
This enables `cloud-hypervisor` users to plug a `vhost-user` based block device
like [SPDK](https://spdk.io)) into the VMM as their paravirtualized storage
backend.

### Network device backend

The previous release provided support for
[vhost-user-net](https://access.redhat.com/solutions/3394851) backends. Now we
also provide a TAP based vhost-user-net backend, implemented in Rust. Together
with the vhost-user-net device implementation, this will eventually become the
Cloud Hypervisor default paravirtualized networking architecture.

### Virtual sockets

In order to more efficiently and securely communicate between host and guest,
we added an hybrid implementation of the
[VSOCK](http://man7.org/linux/man-pages/man7/vsock.7.html) socket address
family over virtio. Credits go to the
[Firecracker](https://github.com/firecracker-microvm/firecracker/blob/master/docs/vsock.md)
project as our implementation is a copy of theirs.

### HTTP based API

In anticipation of the need to support asynchronous operations to Cloud
Hypervisor guests (e.g. resources hotplug and guest migration), we added a HTTP
based API to the VMM. The API will be more extensively documented during the
next release cycle.

### Memory mapped virtio transport

In order to support potential PCI-free use cases, we added support for the
[virtio MMIO](https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-1440002)
transport layer. This will allow us to support simple, minimal guest
configurations that do not require a PCI bus emulation.

### Paravirtualized IOMMU

As we want to improve our nested guests support, we added support for exposing
a [paravirtualized IOMMU](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/docs/iommu.md)
device through virtio. This allows for a safer nested virtio and directly
assigned devices support.

To add the IOMMU support, we had to make some CLI changes for Cloud Hypervisor
users to be able to specify if devices had to be handled through this virtual
IOMMU or not. In particular, the `--disk` option now expects disk paths to be
prefixed with a `path=` string, and supports an optional `iommu=[on|off]`
setting.

### Ubuntu 19.10

With the latest [hypervisor firmware](https://github.com/cloud-hypervisor/rust-hypervisor-firmware),
we can now support the latest
[Ubuntu 19.10 (Eoan Ermine)](http://releases.ubuntu.com/19.10/) cloud images.

### Large memory guests

After simplifying and changing our guest address space handling, we can now
support guests with large amount of memory (more than 64GB).

# v0.2.0

This release has been tracked through the [0.2.0 project](https://github.com/cloud-hypervisor/cloud-hypervisor/projects/2).

Highlights for `cloud-hypervisor` version 0.2.0 include:

### Network device offloading

As part of our general effort to offload paravirtualized I/O to external
processes, we added support for
[vhost-user-net](https://access.redhat.com/solutions/3394851) backends. This
enables `cloud-hypervisor` users to plug a `vhost-user` based networking device
(e.g. [DPDK](https://dpdk.org)) into the VMM as their virtio network backend.

### Minimal hardware-reduced ACPI

In order to properly implement and guest reset and shutdown, we implemented
a minimal version of the hardware-reduced ACPI specification. Together with
a tiny I/O port based ACPI device, this allows `cloud-hypervisor` guests to
cleanly reboot and shutdown.

The ACPI implementation is a `cloud-hypervisor` build time option that is
enabled by default.

### Debug I/O port

Based on the Firecracker idea of using a dedicated I/O port to measure guest
boot times, we added support for logging guest events through the
[0x80](https://www.intel.com/content/www/us/en/support/articles/000005500/boards-and-kits.html)
PC debug port. This allows, among other things, for granular guest boot time
measurements. See our [debug port documentation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/docs/debug-port.md)
for more details.

### Improved direct device assignment

We fixed a major performance issue with our initial VFIO implementation: When
enabling VT-d through the KVM and VFIO APIs, our guest memory writes and reads
were (in many cases) not cached. After correctly tagging the guest memory from
`cloud-hypervisor` we're now able to reach the expected performance from
directly assigned devices.

### Improved shared filesystem

We added shared memory region with [DAX](https://www.kernel.org/doc/Documentation/filesystems/dax.txt)
support to our [virtio-fs](https://virtio-fs.gitlab.io/) shared file system.
This provides better shared filesystem IO performance with a smaller guest
memory footprint.

### Ubuntu bionic based CI

Thanks to our [simple KVM firmware](https://github.com/cloud-hypervisor/rust-hypervisor-firmware)
improvements, we are now able to boot Ubuntu bionic images. We added those to
our CI pipeline.

# v0.1.0

This release has been tracked through the [0.1.0 project](https://github.com/cloud-hypervisor/cloud-hypervisor/projects/1).

Highlights for `cloud-hypervisor` version 0.1.0 include:

### Shared filesystem

We added support for the [virtio-fs](https://virtio-fs.gitlab.io/) shared file
system, allowing for an efficient and reliable way of sharing a filesystem
between the host and the `cloud-hypervisor` guest.

See our [filesystem sharing](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/docs/fs.md)
documentation for more details on how to use virtio-fs with `cloud-hypervisor`.

### Initial direct device assignment support

VFIO (Virtual Function I/O) is a kernel framework that exposes direct device
access to userspace. `cloud-hypervisor` uses VFIO to directly assign host
physical devices into its guest.

See our [VFIO](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/docs/vfio.md)
documentation for more detail on how to directly assign host devices to
`cloud-hypervisor` guests.

### Userspace IOAPIC

`cloud-hypervisor` supports a so-called split IRQ chip implementation by
implementing support for the [IOAPIC](https://wiki.osdev.org/IOAPIC).
By moving part of the IRQ chip implementation from kernel space to user space,
the IRQ chip emulation does not always run in a fully privileged mode.

### Virtual persistent memory

The `virtio-pmem` implementation emulates a virtual persistent memory device
that `cloud-hypervisor` can e.g. boot from. Booting from a `virtio-pmem` device
allows to bypass the guest page cache and improve the guest memory footprint.

### Linux kernel bzImage

The `cloud-hypervisor` linux kernel loader now supports direct kernel boot from
`bzImage` kernel images, which is usually the format that Linux distributions
use to ship their kernels. For example, this allows for booting from the host
distribution kernel image.

### Console over virtio

`cloud-hypervisor` now exposes a `virtio-console` device to the guest. Although
using this device as a guest console can potentially cut some early boot
messages, it can reduce the guest boot time and provides a complete console
implementation.

The `virtio-console` device is enabled by default for the guest console.
Switching back to the legacy serial port is done by selecting
`--serial tty --console off` from the command line.

### Unit testing

We now run all unit tests from all our crates directly from our CI.

### Integration tests parallelization

The CI cycle run time has been significantly reduced by refactoring our
integration tests; allowing them to all be run in parallel.
