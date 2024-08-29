# Inter-VM shared memory device

The Inter-VM shared memory device (ivshmem) is designed to share a memory region between a guest and the host.
In order for all guests to be able to pick up the shared memory area, it is modeled as a PCI device exposing said memory
to the guest as a PCI BAR.

Device Specification is at https://www.qemu.org/docs/master/specs/ivshmem-spec.html.

Now we support setting a backend file to share data between host and guest.

## Usage

`--ivshmem`, an optional argument, can be passed to enable ivshmem device.
This argument takes a file as a `path` value and a file size as a `size` value.
```
--ivshmem <ivshmem>  device backend file "path=</path/to/a/file>,size=<file_size/must=2^n>";
```

## Example

Create a file with a size bigger than passed to `cloud-hypervisor`:

```
truncate -s 1M /tmp/ivshmem.data
```

Start application to mmap the file data to a memory region:
```
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --kernel vmlinux \
    --disk path=focal-server-cloudimg-amd64.raw \
    --cpus boot=4 \
    --memory size=1024M \
    --ivshmem path=/tmp/ivshmem.data,size=1M
```

Insmod a ivshmem device driver to enable the device. The file data will be mmapped to the PCI `bar2` of ivshmem device, 
guest can r/w data by accessing this memory.

A simple example of ivshmem driver:
```c
typedef struct ivshmem_device {
	void __iomem * regs;

	void * base_addr;

	unsigned int ioaddr;
	unsigned int ioaddr_size;

	struct pci_dev *dev;
    // ...

} ivshmem_device;

static ivshmem_device ivshmem_dev;

tatic struct pci_device_id cube_ivshmem_id_table[] = {
{ 0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
{ 0 },
};
MODULE_DEVICE_TABLE (pci, cube_ivshmem_id_table);

static int ivshmem_probe_device (struct pci_dev *pdev, const struct pci_device_id * ent)
{

	int result;
    char buff[64] = {0};
    int i;

	printk("ivshmem: Probing for ivshmem Device\n");

	result = pci_enable_device(pdev);
	if (result) {
		printk(KERN_ERR "Cannot probe ivshmem device %s: error %d\n",
		pci_name(pdev), result);
		return result;
	}

	result = pci_request_regions(pdev, "ivshmem");
	if (result < 0) {
		printk(KERN_ERR "ivshmem: cannot request regions\n");
		goto pci_disable;
	} else {
        printk(KERN_ERR "ivshmem: result is %d\n", result);
    }

	ivshmem_dev.ioaddr = pci_resource_start(pdev, 2);
	ivshmem_dev.ioaddr_size = pci_resource_len(pdev, 2);

	ivshmem_dev.base_addr = pci_iomap(pdev, 2, 0);
	printk(KERN_INFO "ivshmem: iomap base = 0x%lu \n",
							(unsigned long) ivshmem_dev.base_addr);

	if (!ivshmem_dev.base_addr) {
		printk(KERN_ERR "ivshmem: cannot iomap region of size %d\n",
							ivshmem_dev.ioaddr_size);
		goto pci_release;
	}

    printk(KERN_INFO "A samply use case to write to ivshmem \n");
    for (i = 0; i < 1024;) {
        sprintf(buff, "hello ivshmem i am guest%d", i);
        memcpy(ivshmem_dev.base_addr + i*25, buff, 25);
        i += 25;
    }
	return 0;

pci_release:
	pci_iounmap(pdev, ivshmem_dev.base_addr);
	pci_release_regions(pdev);
pci_disable:
	pci_disable_device(pdev);
	return -EBUSY;
}
```

The host process can r/w this data by remmaping the `/tmp/ivshmem.data`.
