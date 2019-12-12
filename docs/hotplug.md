# Cloud Hypervisor Hot Plug

Currently Cloud Hypervisor only support hot plugging of CPU devices.

## Kernel support

For hotplug on Cloud Hypervisor ACPI GED support is needed. This can either be achieved by turning on `CONFIG_ACPI_REDUCED_HARDWARE_ONLY` 
or by using this kernel patch (available in 5.5rc1 and later): https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/drivers/acpi/Makefile?id=ac36d37e943635fc072e9d4f47e40a48fbcdb3f0

This patch is integrated into the Clear Linux KVM and cloudguest images.

## CPU Hot Plug

Extra vCPUs can be added (but not removed [1]) from a running Cloud Hypervisor instance. This is controlled by two mechanisms:

1. Specifying a number of maximum potential vCPUs that is greater than the number of default (boot) vCPUs.
2. Making a HTTP API request to the VM to ask for the additional vCPUs to be added.

To use CPU hotplug start the VM with the number of max vCPUs greater than the number of boot vCPUs, e.g.

```shell
$ pushd $CLOUDH
$ sudo setcap cap_net_admin+ep ./cloud-hypervisor/target/release/cloud-hypervisor
$ ./cloud-hypervisor/target/release/cloud-hypervisor \
	--kernel ./hypervisor-fw \
	--disk path=clear-31890-kvm.img \
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

The extra vCPU threads will be created and advertised to the running kernel. The kernel does not bring up the CPUs immediately and instead the user must "on-line" them from inside the VM:

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

[1]: It is not currently possible to remove CPUs after they are added however CPU hot unplug is included in our roadmap for a future version.