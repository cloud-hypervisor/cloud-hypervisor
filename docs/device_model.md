# Device Model

This document describes the device model supported by `cloud-hypervisor`.

## Summary

| Device | Build configurable | Enabled by default | Runtime configurable |
| :----: | :----: | :----: | :----: |
| Serial port | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| RTC/CMOS | :heavy_check_mark: | :heavy_check_mark: | :negative_squared_cross_mark: |
| I/O APIC | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| i8042 shutdown/reboot | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :negative_squared_cross_mark: |
| ACPI shutdown/reboot | :negative_squared_cross_mark: | :heavy_check_mark: | :negative_squared_cross_mark: |
| virtio-blk | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| virtio-console | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| virtio-iommu | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| virtio-net | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| virtio-pmem | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| virtio-rng | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| virtio-vsock | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| vhost-user-blk | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| vhost-user-fs | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| vhost-user-net | :negative_squared_cross_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |
| VFIO | :heavy_check_mark: | :negative_squared_cross_mark: | :heavy_check_mark: |

## Legacy devices

### Serial port

Simple emulation of a serial port by reading and writing to specific port I/O
addresses. Used as the default console for Linux when booting with the option
`console=ttyS0`, the serial port can be very useful to gather early logs from
the operating system booted inside the VM.

This device is always built-in, and it is disabled by default. It can be
enabled with the `--serial` option, as long as its parameter is not `off`.

### RTC/CMOS

For environments such as Windows or EFI which cannot rely on KVM clock, the
emulation of this legacy device makes the platform usable.

This device is built-in by default, but it can be compiled out with Rust
features. When compiled in, it is always enabled, and cannot be disabled
from the command line.

### I/O APIC

`cloud-hypervisor` supports a so-called split IRQ chip implementation by
implementing support for the [IOAPIC](https://wiki.osdev.org/IOAPIC).
By moving part of the IRQ chip implementation from kernel space to user space,
the IRQ chip emulation does not always run in a fully privileged mode.

The device is always built-in, and it is enabled depending on the presence of
the serial port. If the serial port is disabled, and because no other device
would require pin based interrupts (INTx), the I/O APIC is disabled.

### i8042

Simplified PS/2 port since it supports only one key to trigger a reboot or
shutdown, depending on the ACPI support.

This device is always built-in, but it is disabled by default. Because ACPI is
enabled by default, the handling of reboot/shutdown goes through the dedicated
ACPI device. In case ACPI is disabled, this device is enabled to bring to the
VM some reboot/shutdown support.

### ACPI device

This is a dedicated device for handling ACPI shutdown and reboot when ACPI is
enabled.

This device is always built-in, and it is enabled by default since the ACPI
feature is enabled by default.

## Virtio devices

For all virtio devices listed below, both `virtio-mmio` and `virtio-pci`
transport layers are supported, `virtio-pci` being the default.

Both `virtio-mmio` and `virtio-pci` can be compiled out. `virtio-pci` is
built-in by default, and enabled by default. If both transport layers were
built at the same time, `virtio-pci` would be the default transport layer.

### virtio-block

The `virtio-blk` device exposes a block device to the guest. This device is
usually used to boot the operating system running in the VM.

This device is always built-in, and it is enabled based on the presence of the
flag `--disk`.

### virtio-console

`cloud-hypervisor` exposes a `virtio-console` device to the guest. Although
using this device as a guest console can potentially cut some early boot
messages, it can reduce the guest boot time and provides a complete console
implementation.

This device is always built-in, and it is enabled by default to provide a guest
console. It can be disabled, switching back to the legacy serial port by
selecting `--serial tty --console off` from the command line.

### virtio-iommu

As we want to improve our nested guests support, we added support for exposing
a [paravirtualized IOMMU](https://github.com/intel/cloud-hypervisor/blob/master/docs/iommu.md)
device through virtio. This allows for a safer nested virtio and directly
assigned devices support.

This device is always built-in, and it is enabled based on the presence of the
parameter `iommu=on` in any of the virtio or VFIO devices. If at least one of
these devices needs to be connected to the paravirtualized IOMMU, the
`virtio-iommu` device will be created.

### virtio-net

The `virtio-net` device provides network connectivity for the guest, as it
creates a network interface connected to a TAP interface automatically created
by the `cloud-hypervisor` on the host.

This device is always built-in, and it is enabled based on the presence of the
flag `--net`.

### virtio-pmem

The `virtio-pmem` implementation emulates a virtual persistent memory device
that `cloud-hypervisor` can e.g. boot from. Booting from a `virtio-pmem` device
allows to bypass the guest page cache and improve the guest memory footprint.

This device is always built-in, and it is enabled based on the presence of the
flag `--pmem`.

### virtio-rng

A VM does not generate entropy like a real machine would, which is an issue
when workloads running in the guest need random numbers to be generated. The
`virtio-rng` device provides entropy to the guest by relying on the generator
that can be found on the host. By default, the chosen source of entropy is
`/dev/urandom`.

This device is always built-in, and it is always enabled. The `--rng` flag can
be used to change the source of entropy.

### virtio-vsock

In order to more efficiently and securely communicate between host and guest,
we added a hybrid implementation of the [VSOCK](http://man7.org/linux/man-pages/man7/vsock.7.html)
socket address family over virtio.
Credits go to the [Firecracker](https://github.com/firecracker-microvm/firecracker/blob/master/docs/vsock.md)
project as our implementation is a copy of theirs.

This device is always built-in, and it is enabled based on the presence of the
flag `--vsock`.

## Vhost-user devices

Vhost-user devices are virtio backends running outside of the VMM, as its own
separate process. They are usually used to bring more flexibility and increased
isolation.

### vhost-user-blk

As part of the general effort to offload paravirtualized I/O to external
processes, we added support for vhost-user-blk backends. This enables
`cloud-hypervisor` users to plug a `vhost-user` based block device (e.g. SPDK)
into the VMM as their virtio block backend.

This device is always built-in, and it is enabled based on the presence of the
flag `--vhost-user-blk`.

### vhost-user-fs

`cloud-hypervisor` supports the [virtio-fs](https://virtio-fs.gitlab.io/)
shared file system, allowing for an efficient and reliable way of sharing
a filesystem between the host and the cloud-hypervisor guest.

See our [filesystem sharing](https://github.com/intel/cloud-hypervisor/blob/master/docs/fs.md)
documentation for more details on how to use virtio-fs with cloud-hypervisor.

This device is always built-in, and it is enabled based on the presence of the
flag `--fs`.

### vhost-user-net

As part of the general effort to offload paravirtualized I/O to external
processes, we added support for [vhost-user-net](https://access.redhat.com/solutions/3394851)
backends. This enables `cloud-hypervisor` users to plug a `vhost-user` based
networking device (e.g. DPDK) into the VMM as their virtio network backend.

This device is always built-in, and it is enabled based on the presence of the
flag `--vhost-user-net`.

## VFIO

VFIO (Virtual Function I/O) is a kernel framework that exposes direct device
access to userspace. `cloud-hypervisor` uses VFIO to directly assign host
physical devices into its guest.

See our [VFIO documentation](https://github.com/intel/cloud-hypervisor/blob/master/docs/vfio.md)
for more details on how to directly assign host devices to `cloud-hypervisor`
guests.

Because VFIO implies `vfio-pci` in the `cloud-hypervisor` context, the VFIO
support is built-in when the `pci` feature is selected. And because the `pci`
feature is built-in by default, VFIO support is also built-in by default.
When VFIO support is built-in, a physical device can be passed through, using
the flag `--device` in order to enable the VFIO code.
