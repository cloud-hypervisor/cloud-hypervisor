# Sandboxing using Landlock

Landlock is a lightweight mechanism to allow unprivileged applications to
sandbox themselves.

During initial stages of running, applications can define the set of resources
(mostly files) they need to access during their lifetime. All such rules are
used to create a ruleset. Once the ruleset is applied, the process cannot access
any resources outside of the ruleset during its lifetime, even if it were
compromised.

Under the scope of `read` and `write` access, Landlock currently allows some
additional accesses (eg: for now, access to extended file attributes is always
allowed). Eventually, Landlock will only allow accesses similar to Unix
permissions.

## Host Setup

Landlock should be enabled in Host kernel to use it with cloud-hypervisor.
Please following [Kernel-Support](https://docs.kernel.org/userspace-api/landlock.html#kernel-support) link to enable Landlock on Host kernel.


Landlock support can be checked with following command:
```
$ sudo dmesg | grep -w  landlock
[    0.000000] landlock: Up and running.
```
Linux kernel confirms Landlock support with above message in dmesg.

## Implementation Details

To enable Landlock, Cloud-Hypervisor process needs the full list of files it
needs to access over its lifetime. Landlock is enabled in the `vm_create` stage.

## Enable Landlock

Append `--landlock` to Cloud-Hypervisor's command line to enable Landlock
support.

If you expect guest to access additional paths after it boots
(ex: during hotplug), those paths can be passed using `--landlock-rules` command
line parameter.

## Usage Examples

To enable Landlock:

```
./cloud-hypervisor \
	--kernel ./linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin \
	--disk path=focal-server-cloudimg-amd64.raw path=/tmp/ubuntu-cloudinit.img \
	--cmdline "console=hvc0 root=/dev/vda1 rw" \
	--cpus boot=4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--landlock
```
Hotplugging any new file-backed resources to above guest will result in
**Permission Denied** error.

To enable Landlock with hotplug support:

```
./cloud-hypervisor \
	--api-socket /tmpXXXX/ch.socket \
	--kernel ./linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin \
	--disk path=focal-server-cloudimg-amd64.raw path=/tmp/ubuntu-cloudinit.img \
	--cmdline "console=hvc0 root=/dev/vda1 rw" \
	--cpus boot=4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--landlock \
	--landlock-rules path="/path/to/hotplug1",access="rw" path="/path/to/hotplug2",access="rw"

./ch-remote --api-socket /tmpXXXX/ch.socket \
	add-disk "path=/path/to/hotplug/blk.raw"
```

`--landlock-rules` accepts file or directory paths among its options.

# References

* https://landlock.io/
