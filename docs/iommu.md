# Virtual IOMMU

## Rationales

Having the possibility to expose a virtual IOMMU to the guest can be
interesting to support specific use cases. That being said, it is always
important to keep in mind a virtual IOMMU can impact the performance of the
attached devices, which is the reason why one should be careful when enabling
this feature.

### Protect nested virtual machines

The first reason why one might want to expose a virtual IOMMU to the guest is
to increase the security regarding the memory accesses performed by the virtual
devices (VIRTIO devices), on behalf of the guest drivers.

With a virtual IOMMU, the VMM stands between the guest driver and its device
counterpart, validating and translating every address before to try accessing
the guest memory. This is standard interposition that is performed here by the
VMM.

The increased security does not apply for a simple case where we have one VM
per VMM. Because the guest cannot be trusted, as we always consider it could
be malicious and gain unauthorized privileges inside the VM, preventing some
devices from accessing the entire guest memory is pointless.

But let's take the interesting case of nested virtualization, and let's assume
we have a VMM running a first layer VM. This L1 guest is fully trusted as the
user intends to run multiple VMs from this L1. We can end up with multiple L2
VMs running on a single L1 VM. In this particular case, and without exposing a
virtual IOMMU to the L1 guest, it would be possible for any L2 guest to use the
device implementation from the host VMM to access the entire guest L1 memory.
The virtual IOMMU prevents from this kind of trouble as it will validate the
addresses the device is authorized to access.

### Achieve VFIO nested

Another reason for having a virtual IOMMU is to allow passing physical devices
from the host through multiple layers of virtualization. Let's take as example
a system with a physical IOMMU running a VM with a virtual IOMMU. The
implementation of the virtual IOMMU is responsible for updating the physical
DMA Remapping table (DMAR) everytime the DMA mapping changes. This must happen
through the VFIO framework on the host as this is the only userspace interface
to interact with a physical IOMMU.

Relying on this update mechanism, it is possible to attach physical devices to
the virtual IOMMU, which allows these devices to be passed from L1 to another
layer of virtualization.

## Why virtio-iommu?

The Cloud Hypervisor project decided to implement the brand new virtio-iommu
device in order to provide a virtual IOMMU to its users. The reason being the
simplicity brought by the paravirtualization solution. By having one side
handled from the guest itself, it removes the complexity of trapping memory
page accesses and shadowing them. This is why the project will not try to
implement a full emulation of a physical IOMMU.

## Pre-requisites

### Kernel

Since virtio-iommu has landed partially into the version 5.3 of the Linux
kernel, a special branch is needed to get things working with Cloud Hypervisor.
By partially, we are talking about x86 specifically, as it is already fully
functional for ARM architectures.

## Usage

In order to expose a virtual IOMMU to the guest, it is required to create a
virtio-iommu device and expose it through the ACPI IORT table. This can be
simply achieved by attaching at least one device to the virtual IOMMU.

The way to expose to the guest a specific device as sitting behind this IOMMU
is to explicitly tag it from the command line with the option `iommu=on`.

Not all devices support this extra option, and the default value will always
be `off` since we want to avoid the performance impact for most users who don't
need this.

Refer to the command line `--help` to find out which device support to be
attached to the virtual IOMMU.

Below is a simple example exposing the `virtio-blk` device as attached to the
virtual IOMMU:

```bash
./cloud-hypervisor \
    --cpus 1 \
    --memory size=512M \
    --disk path=clear-kvm.img,iommu=on \
    --kernel custom-bzImage \
    --cmdline "console=ttyS0 root=/dev/vda3" \
```

From a guest perspective, it is easy to verify if the device is protected by
the virtual IOMMU. Check the directories listed under
`/sys/kernel/iommu_groups`:

```bash
ls /sys/kernel/iommu_groups
0
```

In this case, only one IOMMU group should be created. Under this group, it is
possible to find out the b/d/f of the device(s) part of this group.

```bash
ls /sys/kernel/iommu_groups/0/devices/
0000:00:03.0
```

And you can validate the device is the one we expect running `lspci`:

```bash
lspci
00:00.0 Host bridge: Intel Corporation Device 0d57
00:01.0 Unassigned class [ffff]: Red Hat, Inc. Device 1057
00:02.0 Unassigned class [ffff]: Red Hat, Inc. Virtio console
00:03.0 Mass storage controller: Red Hat, Inc. Virtio block device
00:04.0 Unassigned class [ffff]: Red Hat, Inc. Virtio RNG
```
