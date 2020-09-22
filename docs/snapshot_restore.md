# Snapshot and Restore

The goal for the snapshot/restore feature is to provide the user with the
ability to take a snapshot of a previously paused virtual machine. This
snapshot can be used as the base for creating new identical virtual machines,
without the need to boot them from scratch. The restore codepath takes the
snapshot and creates the exact same virtual machine, restoring the previously
saved states. The new virtual machine is restored in a paused state, as it was
before the snapshot was performed.

This feature is important for the project as it establishes the first step
towards the support for live migration.

## Snapshot a Cloud-Hypervisor VM

First thing, we must run a Cloud-Hypervisor VM:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --cpus boot=4 \
    --memory size=4G \
    --kernel bzImage \
    --cmdline "root=/dev/vda1 console=hvc0 rw" \
    --disk path=focal-server-cloudimg-amd64.raw
```

At any point in time when the VM is running, one might choose to pause it:

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock pause
```

Once paused, the VM can be safely snapshot into the specified directory and
using the following command:

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock snapshot file:///home/foo/snapshot
```

Given the directory was present on the system, the snapshot will succeed and
it should contain the following files:

```bash
ll /home/foo/snapshot/
total 4194536
drwxrwxr-x  2 foo bar       4096 Jul 22 11:50 ./
drwxr-xr-x 47 foo bar       4096 Jul 22 11:47 ../
-rw-------  1 foo bar 3221225472 Jul 22 11:19 memory-region-0
-rw-------  1 foo bar 1073741824 Jul 22 11:19 memory-region-1
-rw-------  1 foo bar     217853 Jul 22 11:19 vm.json
```

In this particular example, we can observe that 2 memory region files were
created. That is explained by the size of the guest RAM, which is 4GiB in this
case. Because it exceeds 3GiB (which is where we can find a ~1GiB memory hole),
Cloud-Hypervisor needs 2 distinct memory regions to be created. Each memory
region's content is stored through a dedicated file, which explains why we end
up with 2 different files, the first one containing the guest RAM range 0-3GiB
and the second one containing the guest RAM range 3-4GiB.

`vm.json` gathers all information related to the virtual machine configuration
and state. The configuration bits are used to create a similar virtual machine
with the correct amount of CPUs, RAM, and other expected devices. The state
bits are used to restore each component in the state it was left before the
snapshot occurred.

## Restore a Cloud-Hypervisor VM

Given that one has access to an existing snapshot in `/home/foo/snapshot`,
it is possible to create a new VM based on this snapshot with the following 
command:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot
```

Or using two different commands from two terminals:

```bash
# First terminal
./cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock

# Second terminal
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock restore source_url=file:///home/foo/snapshot
```

Remember the VM is restored in a `paused` state, which was the VM's state when
it was snapshot. For this reason, one must explicitly `resume` the VM before to
start using it.

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock resume
```

At this point, the VM is fully restored and is identical to the VM which was
snapshot earlier.

## Limitations

The support of snapshot/restore feature is still experimental, meaning one
might still find some bugs associated with it.

Additionally, some devices and features don't support to be snapshot and
restored yet:
- `vhost-user` devices
- `virtio-mem`
- Intel SGX

VFIO devices are out of scope.
