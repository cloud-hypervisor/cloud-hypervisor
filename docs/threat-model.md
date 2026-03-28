# Cloud Hypervisor Threat Model

This document describes the threat model of Cloud Hypervisor.

## Fully Trusted Components

Cloud Hypervisor unconditionally trusts:

- The Linux kernel it is running on.
- The process that spawned it.
- Any client of its API.
- Any libraries linked into it.
- Any process with the ability to debug it (perhaps via ptrace()).
- Any entity that can execute code in the context of any of the above.

An attacker with control of any of these must be assumed to be able to
execute arbitrary code in the context of the Cloud Hypervisor process.

## Guest Virtual Machine

Cloud Hypervisor considers the guest VM to be untrusted. This means that a guest
VM is only allowed to perform I/O using the interfaces Cloud Hypervisor has been
told to provide to it.

Cloud Hypervisor cannot protect itself or the host from speculative execution
attacks. Such self-protection This is entirely the responsibility of the hardware and the Linux
kernel.

Cloud Hypervisor assumes that guest VMs may have internal security boundaries.
For instance, a guest OS may run untrusted userspace programs or nested VMs.
Cloud Hypervisor cannot be used as a confused deputy to violate these
boundaries.

## Vhost-User Devices

Cloud Hypervisor gives vhost-user devices complete control over the guest.
Cloud Hypervisor does not allow vhost-user devices to take control over the
Cloud Hypervisor process itself.

## Block, Network, and Console Devices

Block, network, and console devices allow guests to send and receive arbitrary
data. Cloud Hypervisor does not trust this data. Guests may choose to trust or
not trust this data.

Cloud Hypervisor does not allow a guest to write to read-only storage devices.
Cloud Hypervisor also does not allow MAC address spoofing, if a MAC address is
provided.

With the above exceptions, Cloud Hypervisor does not filter data sent and
received by the guest in any way. If such filtering is necessary, it must be
done outside of Cloud Hypervisor. For instance, network traffic can be filtered
by a firewall.

## Files Provided to Cloud Hypervisor

### File names

Cloud Hypervisor does not protect against symlink attacks when
opening files.  Files that Cloud Hypervisor is told to open
must be in paths that are protected from symlink attacks.
This can be accomplished by mounting filesystems with `nosymfollow`.

Cloud Hypervisor does not protect against being told to open a file in `/proc`.
Accesses to such a files could corrupt Cloud Hypervisor's own memory.

In short, if an untrusted entity is allowed to choose a filename, a trusted
component must ensure that path traversal attacks are blocked.

The safest way to provide a file to Cloud Hypervisor is via a file descriptor.

### Disk Images

With one exception, Cloud Hypervisor assumes that disk images provided to it are
untrusted. The exception is that qcow2 images are assumed trusted if the
`backing_files` option is enabled. It is disabled by default.

If a non-raw disk image is not corrupt, Cloud Hypervisor does not allow a guest
to corrupt it. If it is corrupt and writable, it may be further corrupted in an
arbitrary way.

### Firmware

Cloud Hypervisor does not itself trust the firmware image, but assumes that the
guest does trust it.

### Guest Kernel and Initramfs

Cloud Hypervisor does not itself trust the guest kernel and initramfs.  Unless
the guest uses secure boot, the guest must itself trust them.

## PCI and vDPA devices

By default, Cloud Hypervisor provides PCI and vDPA devices assigned to a guest
with access to all guest memory. Therefore, these devices can take over the
guest. Even if a virtual IOMMU is enabled, there is no interrupt remapping on
x86\_64, so a device can probably use malicious MSIs to take over a guest. On
Arm, the GIC performs interrupt remapping, so a guest could theoretically defend
itself from a malicious device. However, it is extremely unlikely that a
real-world guest actually does.

However, it is possible for a guest to influence the behavior of PCI and vDPA
devices attached to it. Therefore, Cloud Hypervisor treats these devices as
untrusted. This is done by only allowing them to access memory that is mapped
into the guest. They are not allowed to access Cloud Hypervisor's own memory.

Cloud Hypervisor *cannot* protect against hardware infection. Attackers may
attempt to install malicious firmware on a device, tamper with an option ROM, or
otherwise attempt to retain control of the device after the host reboots.  If
the attacker succeeds, they can compromise the host through any of a number of
methods. These include, but are not limited to, DMA attacks and impersonating
trusted devices like a keyboard or OS boot disk.

Systems where assigned devices have no mutable state that persists across host
CPU resets are not vulnerable to such attacks. If the device has a secure boot
process and is power cycled whenever the host resets, the system may also not be
vulnerable. This depends heavily on both the host and device firmware and
hardware design and no generic statement can be given.  SR-IOV virtual functions
(including vDPA) are the safest options, as they are intended to be assigned to
guests. A detailed explanation is beyond the scope of this policy.

## Sandboxing

Cloud Hypervisor can sandbox itself via Landlock and seccomp. Once sandboxed,
Cloud Hypervisor is not able to access any resources blocked by the sandbox.
This is true even if an attacker can execute arbitrary code in the context of
the Cloud Hypervisor process.

The sandbox only prevents access to resources subject to Landlock access
controls. For instance, it does not prevent access to AF\_UNIX sockets. This can
be blocked via namespaces or by other kernel-enforced access controls.
