# Cloud Hypervisor VFIO HOWTO

VFIO (Virtual Function I/O) is a kernel framework that exposes direct device
access to userspace. `cloud-hypervisor`, as many VMMs do, uses the VFIO
framework to directly assign host physical devices to the guest workloads.

## Direct Device Assignment with Cloud Hypervisor

To assign a device to a `cloud-hypervisor` guest, the device needs to be managed
by the VFIO kernel drivers. However, by default, a host device will be bound to
its native driver, which is not the VFIO one.

As a consequence, a device must be unbound from its native driver before passing
it to `cloud-hypervisor` for assigning it to a guest.

### Example

In this example we're going to assign a PCI memory card (SD, MMC, etc) reader
from the host in a cloud hypervisor guest.

`cloud-hypervisor` only supports assigning PCI devices to its guests. `lspci`
helps with identifying PCI devices on the host:

```
$ lspci
[...]
01:00.0 Unassigned class [ff00]: Realtek Semiconductor Co., Ltd. RTS525A PCI Express Card Reader (rev 01)
[...]
```

Here we see that our device is on bus 1, slot 0 and function 0 (`01:00.0`).

Now that we have identified the device, we must unbind it from its native driver
(`rtsx_pci`) and bind it to the VFIO driver instead (`vfio_pci`).

First we add VFIO support to the host:

```
# modprobe -r vfio_pci
# modprobe -r vfio_iommu_type1
# modprobe vfio_iommu_type1 allow_unsafe_interrupts
# modprobe vfio_pci
```

In case the VFIO drivers are built-in, enable unsafe interrupts with:

```
# echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
```

Then we unbind it from its native driver:

```
# echo 0000:01:00.0 > /sys/bus/pci/devices/0000\:01\:00.0/driver/unbind
```

And finally we bind it to the VFIO driver. To do that we first need to get the
device's VID (Vendor ID) and PID (Product ID):

```
$ lspci -n -s 01:00.0
01:00.0 ff00: 10ec:525a (rev 01)

# echo 10ec 525a > /sys/bus/pci/drivers/vfio-pci/new_id
```

If you have more than one device with the same `vendorID`/`deviceID`, starting
with the second device, the binding is performed as follows:

```
# echo 0000:02:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
```

Now the device is managed by the VFIO framework.

The final step is to give that device to `cloud-hypervisor` to assign it to the
guest. This is done by using the `--device` command line option. This option
takes the device's sysfs path as an argument. In our example it is
`/sys/bus/pci/devices/0000:01:00.0/`:

```
./target/debug/cloud-hypervisor \
    --kernel ~/vmlinux \
    --disk path=~/focal-server-cloudimg-amd64.raw \
    --console off \
    --serial tty \
    --cmdline "console=ttyS0 root=/dev/vda1 rw" \
    --cpus 4 \
    --memory size=512M \
    --device path=/sys/bus/pci/devices/0000:01:00.0/
```

The guest kernel will then detect the card reader on its PCI bus and provided
that support for this device is enabled, it will probe and enable it for the
guest to use.

In case you want to pass multiple devices, here is the correct syntax:

```
--device path=/sys/bus/pci/devices/0000:01:00.0/ path=/sys/bus/pci/devices/0000:02:00.0/
```

### Multiple devices in the same IOMMU group

There are cases where multiple devices can be found under the same IOMMU group.
This happens often with graphics card embedding an audio controller.

```
$ lspci
[...]
01:00.0 VGA compatible controller: NVIDIA Corporation GK208B [GeForce GT 710] (rev a1)
01:00.1 Audio device: NVIDIA Corporation GK208 HDMI/DP Audio Controller (rev a1)
[...]
```

This is usually exposed as follows through `sysfs`:

```
$ ls /sys/kernel/iommu_groups/22/devices/
0000:01:00.0  0000:01:00.1
```

This means these two devices are under the same IOMMU group 22. In such case,
it is important to bind both devices to VFIO and pass them both through the
VM, otherwise this could cause some functional and security issues.

### Advanced Configuration Options

When using NVIDIA GPUs in a VFIO passthrough configuration, advanced
configuration options are supported to enable GPUDirect P2P DMA over
PCIe. When enabled, loads and stores between GPUs use native PCIe
peer-to-peer transactions instead of a shared memory buffer. This drastically
decreases P2P latency between GPUs. This functionality is supported by
cloud-hypervisor on NVIDIA Turing, Ampere, Hopper, and Lovelace GPUs.

The NVIDIA driver does not enable GPUDirect P2P over PCIe within guests
by default because hardware support for routing P2P TLP between PCIe root
ports is optional. PCIe P2P should always be supported between devices
on the same PCIe switch. The `x_nv_gpudirect_clique` config argument may
be used to signal support for PCIe P2P traffic between NVIDIA VFIO endpoints.
The guest driver assumes that P2P traffic is supported between all endpoints
that are part of the same clique.
```
--device path=/sys/bus/pci/devices/0000:01:00.0/,x_nv_gpudirect_clique=0
```

The following command can be run on the guest to verify that GPUDirect P2P is
correctly enabled.
```
nvidia-smi topo -p2p r
 	GPU0	GPU1	GPU2	GPU3	GPU4	GPU5	GPU6	GPU7	
 GPU0	X	OK	OK	OK	OK	OK	OK	OK	
 GPU1	OK	X	OK	OK	OK	OK	OK	OK	
 GPU2	OK	OK	X	OK	OK	OK	OK	OK	
 GPU3	OK	OK	OK	X	OK	OK	OK	OK	
 GPU4	OK	OK	OK	OK	X	OK	OK	OK	
 GPU5	OK	OK	OK	OK	OK	X	OK	OK	
 GPU6	OK	OK	OK	OK	OK	OK	X	OK	
 GPU7	OK	OK	OK	OK	OK	OK	OK	X	
```

Some VFIO devices have a 32-bit mmio BAR. When using many such devices, it is
possible to exhaust the 32-bit mmio space available on a PCI segment. The
following example demonstrates an example device with a 16 MiB 32-bit mmio BAR.
```
lspci -s 0000:01:00.0  -v
0000:01:00.0 3D controller: NVIDIA Corporation Device 26b9 (rev a1)
    [...]
    Memory at f9000000 (32-bit, non-prefetchable) [size=16M]
    Memory at 46000000000 (64-bit, prefetchable) [size=64G]
    Memory at 48040000000 (64-bit, prefetchable) [size=32M]
    [...]
```

When using multiple PCI segments, the 32-bit mmio address space available to
be allocated to VFIO devices is equally split between all PCI segments by
default. This can be tuned with the `--pci-segment` flag. The following example
demonstrates a guest with two PCI segments. 2/3 of the 32-bit mmio address
space is available for use by devices on PCI segment 0 and 1/3 of the 32-bit
mmio address space is available for use by devices on PCI segment 1.
```
--platform num_pci_segments=2
--pci-segment pci_segment=0,mmio32_aperture_weight=2
--pci-segment pci_segment=1,mmio32_aperture_weight=1
```
