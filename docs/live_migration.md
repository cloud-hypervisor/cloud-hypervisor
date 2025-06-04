# Live Migration

This document gives examples of how to use the live migration support
in Cloud Hypervisor:

1. local migration - migrating a VM from one Cloud Hypervisor instance to another on the same machine;
1. remote migration - migrating a VM between two machines;

> :warning: These examples place sockets /tmp. This is done for
> simplicity and should not be done in production.

## Local Migration (Suitable for Live Upgrade of VMM)

Launch the source VM (on the host machine):

```console
$ target/release/cloud-hypervisor
    --kernel ~/workloads/vmlinux \
    --disk path=~/workloads/focal.raw \
    --cpus boot=1 --memory size=1G,shared=on \
    --cmdline "root=/dev/vda1 console=ttyS0"  \
    --serial tty --console off --api-socket=/tmp/api1
```

Launch the destination VM from the same directory (on the host machine):

```console
$ target/release/cloud-hypervisor --api-socket=/tmp/api2
```

Get ready for receiving migration for the destination VM (on the host machine):

```console
$ target/release/ch-remote --api-socket=/tmp/api2 receive-migration unix:/tmp/sock
```

Start to send migration for the source VM (on the host machine):

```console
$ target/release/ch-remote --api-socket=/tmp/api1 send-migration --local unix:/tmp/sock
```

When the above commands completed, the source VM should be successfully
migrated to the destination VM. Now the destination VM is running while
the source VM is terminated gracefully.

## Remote Migration

In this example, we will migrate a VM from one machine (`src`) to
another (`dst`) across the network. To keep it simple, we will use a
minimal VM setup without storage.

### Preparation

Make sure that `src` and `dst` can reach each other via the
network. You should be able to ping each machine. Also each machine
should have an open TCP port.

You will need a kernel and initramfs for a minimal Linux system. For
this example, we will use the Debian netboot image.

Place the kernel and initramfs into the _same directory_ on both
machines. This is important for the migration to succeed. We will use
`/var/images`:

```console
src $ export DEBIAN=https://ftp.debian.org/debian/dists/stable/main/installer-amd64/current/images/netboot/debian-installer/amd64
src $ mkdir -p /var/images
src $ curl $DEBIAN/linux > /var/images/linux
src $ curl $DEBIAN/initrd.gz > /var/images/initrd
```

Repeat the above steps on the destination host.

### Unix Socket Migration

If Unix socket is selected for migration, we can tunnel traffic through "socat".

#### Starting the Receiver VM

On the receiver side, we prepare an empty VM:

```console
dst $ cloud-hypervisor --api-socket /tmp/api
```

In a different terminal, configure the VM as a migration target:

```console
dst $ ch-remote --api-socket=/tmp/api receive-migration unix:/tmp/sock
```

In yet another terminal, forward TCP connections to the Unix domain socket:

```console
dst $ socat TCP-LISTEN:{port},reuseaddr UNIX-CLIENT:/tmp/sock
```

#### Starting the Sender VM

Let's start the VM on the source machine:

```console
src $ cloud-hypervisor \
        --serial tty --console off \
        --cpus boot=2 --memory size=4G \
        --kernel /var/images/linux \
        --initramfs /var/images/initrd \
        --cmdline "console=ttyS0" \
        --api-socket /tmp/api
```

After a few seconds the VM should be up and you can interact with it.

#### Performing the Migration

First, we start `socat`:

```console
src $ socat UNIX-LISTEN:/tmp/sock,reuseaddr TCP:{dst}:{port}
```

> Replace {dst}:{port} with the actual IP address and port of your destination host.

Then we kick-off the migration itself:

```console
src $ ch-remote --api-socket=/tmp/api send-migration unix:/tmp/sock
```

When the above commands completed, the VM should be successfully
migrated to the destination machine without interrupting the workload.

### TCP Socket Migration

If TCP socket is selected for migration, we need to consider migrating
in a trusted network.

#### Starting the Receiver VM

On the receiver side, we prepare an empty VM:

```console
dst $ cloud-hypervisor --api-socket /tmp/api
```

In a different terminal, prepare to receive the migration:

```console
dst $ ch-remote --api-socket=/tmp/api receive-migration tcp:0.0.0.0:{port}
```

#### Starting the Sender VM

Let's start the VM on the source machine:

```console
src $ cloud-hypervisor \
        --serial tty --console off \
        --cpus boot=2 --memory size=4G \
        --kernel /var/images/linux \
        --initramfs /var/images/initrd \
        --cmdline "console=ttyS0" \
        --api-socket /tmp/api
```

After a few seconds the VM should be up and you can interact with it.

#### Performing the Migration

Initiate the Migration over TCP:

```console
src $ ch-remote --api-socket=/tmp/api send-migration tcp:{dst}:{port}
```

With migration parameters:

```console
src $ ch-remote --api-socket=/tmp/api send-migration tcp:{dst}:{port} --migration-timeout 60 --downtime 5000
```

> Replace {dst}:{port} with the actual IP address and port of your destination host.

After completing the above commands, the source VM will be migrated to
the destination host and continue running there. The source VM instance
will terminate normally. All ongoing processes and connections within
the VM should remain intact after the migration.

#### Migration Parameters

Cloud Hypervisor supports additional parameters to control the
migration process:

- `migration-timeout <seconds>`
Sets the maximum time (in seconds) allowed for the migration process.
If the migration takes longer than this timeout, it will be aborted. A
value of 0 means no timeout limit.
- `downtime <milliseconds>`
Sets the maximum acceptable downtime (in milliseconds) during the
migration. This parameter helps control the trade-off between migration
time and VM downtime.

> The downtime limit is related to the cost of serialization
(deserialization) of vCPU and device state. Therefore, the expected
downtime is always shorter than the actual downtime.

These parameters can be used with the `send-migration` command to
fine-tune the migration behavior according to your requirements.