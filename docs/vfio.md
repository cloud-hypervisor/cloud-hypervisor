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

## Limitations

Cloud-Hypervisor does not implement legacy IRQ for VFIO devices. The choice is
intentional, based on the fact that recent PCI cards should either support MSI
or MSI-X. This prevents from adding extra complexity to the project.

A PCI card works in combination with a driver, meaning the combination of
hardware and software must support either MSI or MSI-X to be compatible with
Cloud-Hypervisor.

### NVIDIA cards

Some NVIDIA graphic cards may support only MSI, therefore one could think they
would work with Cloud-Hypervisor. Unfortunately, because of the implementation
of the NVIDIA proprietary driver (observed on version `460.39`), the driver
will fail to be probed. As shown below, if there is no legacy IRQ support, the
driver will search for MSI-X capability, ignoring a potential MSI support.

```
static int
nv_pci_probe
(
    struct pci_dev *pci_dev,
    const struct pci_device_id *id_table
)
{

...

    if ((pci_dev->irq == 0 && !pci_find_capability(pci_dev, PCI_CAP_ID_MSIX))
        && nv_treat_missing_irq_as_error())
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: Can't find an IRQ for your NVIDIA card!\n");
        nv_printf(NV_DBG_ERRORS, "NVRM: Please check your BIOS settings.\n");
        nv_printf(NV_DBG_ERRORS, "NVRM: [Plug & Play OS] should be set to NO\n");
        nv_printf(NV_DBG_ERRORS, "NVRM: [Assign IRQ to VGA] should be set to YES \n");
        goto failed;
    }

```

This means if one tries to use NVIDIA proprietary driver with Cloud-Hypervisor,
the card __MUST__ support MSI-X.

The alternatives to be able to use NVIDIA cards with MSI only support along with
Cloud-Hypervisor are:
- Use the Open Source driver `nouveau` provided by the Linux kernel
- Modify the NVIDIA proprietary driver to allow for MSI support

### Identify PCI capabilities

A quick way to identify if a PCI card supports MSI and/or MSI-X capabilities is
by running `lspci` and by parsing its output. Assuming the card is located at
`01:00.0` in the PCI tree, here is the command one could run:

```
sudo lspci -vvv -s 01:00.0 | grep MSI
```

Generating the following possible output:

```
Capabilities: [68] MSI: Enable- Count=1/1 Maskable- 64bit+
Capabilities: [78] Express (v2) Legacy Endpoint, MSI 00
```
