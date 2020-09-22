# Cloud Hypervisor Hot Plug

Currently Cloud Hypervisor only support hot plugging of CPU devices.

## Kernel support

For hotplug on Cloud Hypervisor ACPI GED support is needed. This can either be achieved by turning on `CONFIG_ACPI_REDUCED_HARDWARE_ONLY` 
or by using this kernel patch (available in 5.5-rc1 and later): https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/drivers/acpi/Makefile?id=ac36d37e943635fc072e9d4f47e40a48fbcdb3f0

## CPU Hot Plug

Extra vCPUs can be added and removed from a running Cloud Hypervisor instance. This is controlled by two mechanisms:

1. Specifying a number of maximum potential vCPUs that is greater than the number of default (boot) vCPUs.
2. Making a HTTP API request to the VMM to ask for the additional vCPUs to be added.

To use CPU hotplug start the VM with the number of max vCPUs greater than the number of boot vCPUs, e.g.

```shell
$ pushd $CLOUDH
$ sudo setcap cap_net_admin+ep ./cloud-hypervisor/target/release/cloud-hypervisor
$ ./cloud-hypervisor/target/release/cloud-hypervisor \
	--kernel custom-vmlinux.bin \
	--cmdline "console=ttyS0 console=hvc0 root=/dev/vda1 rw" \
	--disk path=focal-server-cloudimg-amd64.raw \
	--cpus boot=4,max=8 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--rng \
    --api-socket=/tmp/ch-socket
$ popd
```

Notice the addition of `--api-socket=/tmp/ch-socket` and a `max` parameter on `--cpus boot=4.max=8`.

To ask the VMM to add additional vCPUs then use the resize API:

```shell
curl -H "Accept: application/json" -H "Content-Type: application/json" -i -XPUT --unix-socket /tmp/ch-socket -d "{ \"desired_vcpus\":8}" http://localhost/api/v1/vm.resize
```

The extra vCPU threads will be created and advertised to the running kernel. The kernel does not bring up the CPUs immediately and instead the user must "online" them from inside the VM:

```shell
root@ch-guest ~ # lscpu | grep list:
On-line CPU(s) list:             0-3
Off-line CPU(s) list:            4-7
root@ch-guest ~ # echo 1 | tee /sys/devices/system/cpu/cpu[4,5,6,7]/online
1
root@ch-guest ~ # lscpu | grep list:
On-line CPU(s) list:             0-7
```

After a reboot the added CPUs will remain.

Removing CPUs works similarly by reducing the number in the "desired_vcpus" field of the reisze API. The CPUs will be automatically offlined inside the guest so there is no need to run any commands inside the guest:

```shell
curl -H "Accept: application/json" -H "Content-Type: application/json" -i -XPUT --unix-socket /tmp/ch-socket -d "{ \"desired_vcpus\":2}" http://localhost/api/v1/vm.resize
```

As per adding CPUs to the guest, after a reboot the VM will be running with the reduced number of vCPUs.

## Memory Hot Plug

Extra memory can be added from a running Cloud Hypervisor instance. This is controlled by two mechanisms:

1. Allocating some of the guest physical address space for hotplug memory.
2. Making a HTTP API request to the VMM to ask for a new amount of RAM to be assigned to the VM. In the case of expanding the memory for the VM the new memory will be hotplugged into the running VM, if reducing the size of the memory then change will take effect after the next reboot.

To use memory hotplug start the VM specifying some size RAM in the "hotplug_size" parameter to the memory configuration. Not all the memory specified in this parameter will be available to hotplug as there are spacing and alignment requirements so it is recommended to make it larger than the hotplug RAM needed.

```shell
$ pushd $CLOUDH
$ sudo setcap cap_net_admin+ep ./cloud-hypervisor/target/release/cloud-hypervisor
$ ./cloud-hypervisor/target/release/cloud-hypervisor \
	--kernel custom-vmlinux.bin \
	--cmdline "console=ttyS0 console=hvc0 root=/dev/vda1 rw" \
	--disk path=focal-server-cloudimg-amd64.raw \
	--cpus boot=4,max=8 \
	--memory size=1024M,hotplug_size=8192M \
	--net "tap=,mac=,ip=,mask=" \
	--rng \
    --api-socket=/tmp/ch-socket
$ popd
```

Before issuing the API request it is necessary to run the following command inside the VM to make it automatically online the added memory:

```shell
root@ch-guest ~ # echo online | sudo tee /sys/devices/system/memory/auto_online_blocks
```

To ask the VMM to add expand the RAM for the VM  (request is in bytes):

```shell
curl -H "Accept: application/json" -H "Content-Type: application/json" -i -XPUT --unix-socket /tmp/ch-socket -d "{ \"desired_vcpus\": 4, \"desired_ram\" : 3221225472}" http://localhost/api/v1/vm.resize
```

The new memory is now available to use inside the VM:

```shell
free -h
              total        used        free      shared  buff/cache   available
Mem:          3.0Gi        71Mi       2.8Gi       0.0Ki        47Mi       2.8Gi
Swap:          32Mi          0B        32Mi
```

Due to guest OS limitations is is necessary to ensure that amount of memory added (between currently assigned RAM and that which is desired) is a multiple of 128MiB.

The same API can also be used to reduce the desired RAM for a VM but the change will not be applied until the VM is rebooted.

Memory and CPU resizing can be combined together into the same HTTP API request.
