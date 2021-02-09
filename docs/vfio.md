# Cloud Hypervisor VFIO HOWTO

VFIO (Virtual Function I/O) is a kernel framework that exposes direct device
access to userspace. `cloud-hypervisor`, as many VMMs do, uses the VFIO
framework to directly assign host physical devices to the guest workloads.

## Direct Device Assignment with Cloud Hypervisor

To assign a device to a `cloud-hypervisor` guest, the device needs to be managed
by the VFIO kernel drivers. However, by default, a host device will be bound to
its native driver, which is not the VFIO one.

As a consequence, a device must be unbound from its native driver before passing
it to `cloud-hypervisor` for assigning it to a guess.

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
$ sudo modprobe vfio_pci
$ sudo modprobe vfio_iommu_type1 allow_unsafe_interrupts
```

Then we unbind it from its native driver:

```
$ echo 0000:01:00.0 > /sys/bus/pci/devices/0000\:01\:00.0/driver/unbind
```

And finally we bind it to the VFIO driver. To do that we first need to get the
device's VID (Vendor ID) and PID (Product ID):

```
$ lspci -n -s 01:00.0
01:00.0 ff00: 10ec:525a (rev 01)

$ echo 10ec 525a > /sys/bus/pci/drivers/vfio-pci/new_id
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
