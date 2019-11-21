- [v0.3.0](#v030)
    + [Block device offloading](#block-device-offloading)
    + [Network device backend](#network-device-backend)
    + [Virtual sockets](#virtual-sockets)
    + [HTTP based API](#http-based-api)
    + [Memory mapped virtio transport](#memory-mapped-virtio-transport)
    + [Paravirtualized IOMMU](#paravirtualized-iommu)
    + [Ubuntu 19.10](#ubuntu-1910)
    + [Guest large memory](#guest-large-memory)
- [v0.2.0](#v020)
    + [Network device offloading](#network-device-offloading)
    + [Minimal hardware-reduced ACPI](#minimal-hardware-reduced-acpi)
    + [Debug I/O port](#debug-i-o-port)
    + [Improved direct device assignment](#improved-direct-device-assignment)
    + [Improved shared filesystem](#improved-shared-filesystem)
    + [Ubuntu bionic based CI](#ubuntu-bionic-based-ci)
- [v0.1.0](#v010)
    + [Shared filesystem](#shared-filesystem)
    + [Initial direct device assignment support](#initial-direct-device-assignment-support)
    + [Userspace IOAPIC](#userspace-ioapic)
    + [Virtual persistent memory](#virtual-persistent-memory)
    + [Linux kernel bzImage](#linux-kernel-bzimage)
    + [Console over virtio](#console-over-virtio)
    + [Unit testing](#unit-testing)
    + [Integration tests parallelization](#integration-tests-parallelization)

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
