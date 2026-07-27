# Cloud Hypervisor Threat Model

The interfaces Cloud Hypervisor interacts with can be divided into four groups:

1. Hardware and software responsible for the execution of Cloud Hypervisor.
2. Management interfaces used to configure and control Cloud Hypervisor.
3. Guest-facing interfaces used by guest virtual machines.
4. Data-plane interfaces used for guest I/O.

## Cloud Hypervisor's Execution Environment

Like any other program, Cloud Hypervisor must trust the hardware,
firmware, and software responsible for executing it. This includes, but
is not limited to:

- The CPU, including (if present) its microcode and privileged firmware.
- The Linux kernel.
- Any hypervisor or emulation environment the kernel is running on.
- Any hypervisor or emulator Linux is running on. This includes both
  using KVM under nested virtualization and using MSHV.

Cloud Hypervisor assumes that these components have been configured to
provide isolation. This includes, but is not limited to:

- Using an up-to-date kernel, microcode, and firmware.
- If MSHV is in use, using an up-to-date version of MSHV.
- Enabling mitigations for all known hardware vulnerabilities.
- Disabling SMT (simultaneous multithreading) if necessary.
- Enabling Data Operand Independent Timing Mode (DOITM) on Intel systems
  that have it to avoid timing side-channel vulnerabilities in
  cryptographic code.

Cloud Hypervisor does protect the host kernel from vulnerabilities in
kernel code it does not use. For instance, Cloud Hypervisor does not
use user namespaces, AF_ALG, or splice(), so vulnerabilities that
require any of these cannot be exploited by a Cloud Hypervisor guest.

## Management Interfaces

Cloud Hypervisor can be configured and controlled via three ways:

- The command-line passed to the Cloud Hypervisor process.
- An HTTP API.
- A D-Bus API.

These interfaces are considered trusted. For instance, Cloud Hypervisor
does not prevent an API client from telling Cloud Hypervisor to access
/proc/self/mem and thus overwrite its own memory. Nevertheless, it is
safe and useful for management stacks to perform some management actions
on behalf of untrusted parties. For instance, a cloud service may allow
users to upload arbitrary files and attach them to their VMs as block
devices.

## Guest Virtual Machine

Cloud Hypervisor considers the guest VM to be untrusted. This means that
a guest VM is only allowed to perform I/O using the interfaces Cloud
Hypervisor has been told to provide to it.

Cloud Hypervisor is not hardened against denial of service attacks from
the guest kernel it is running. The guest may cause Cloud Hypervisor to
crash in a non-exploitable way, such as a Rust panic. Cloud Hypervisor
assumes that a guest doing this only hurts itself.

Cloud Hypervisor only provides the guest VM with a limited number of
vCPUs and a limited amount of memory. However, a guest might be able to
cause Cloud Hypervisor itself to consume excessive CPU or memory.
Applications that need to impose limits on guest CPU or memory usage
should rely on control groups, which provide kernel-enforced resource
limits.

Cloud Hypervisor assumes that guest VMs may have internal security
boundaries. For instance, a guest OS may run untrusted userspace
programs or nested VMs. Cloud Hypervisor cannot be used as a confused
deputy to violate these boundaries, unless the guest allows userspace to
drive a Cloud Hypervisor-provided device. This includes both in-guest
privilege escalation and in-guest denial of service.

It is not safe to use a userspace driver for a device provided by Cloud
Hypervisor *except* on Arm64 with a virtio IOMMU. While a virtio IOMMU
is provided on x86_64, it does not provide interrupt remapping and so
does not provide strong isolation. Even then, the userspace driver can
still cause Cloud Hypervisor (and thus the guest) to crash due to bugs
in the PCI emulation code. These bugs should still be fixed, but they
are not considered vulnerabilities at this time.

## Confidential Computing

Even when running a confidential guest VM, Cloud Hypervisor still
assumes the guest VM trusts Cloud Hypervisor. Cloud Hypervisor may
attempt to access guest memory that is private to the confidential VM.
It is the responsibility of the hardware, firmware, and guest to ensure
that such accesses fail. If accessing host-inaccessible guest memory
can cause a host-wide denial of service, it is the responsibility of
the host kernel to prevent such accesses.

## Vhost-User Devices

Cloud Hypervisor gives vhost-user devices complete control over the
guest. Cloud Hypervisor does not allow vhost-user devices to take
control over the Cloud Hypervisor process itself.

If a virtio IOMMU is in use, it is the responsibility of the vhost-user
device to use it for address translation.

## I/O Devices

The I/O devices exposed by Cloud Hypervisor allow guests to send and
receive arbitrary data. Cloud Hypervisor threats this data as opaque.

Cloud Hypervisor does not allow a guest to write to read-only storage
devices. Cloud Hypervisor also does not allow MAC address spoofing, if
a MAC address is provided.

With the above exceptions, Cloud Hypervisor does not filter data sent
and received by the guest in any way. If such filtering is necessary, it
must be done outside of Cloud Hypervisor. For instance, network traffic
can be filtered by a firewall.

## Files Provided to Cloud Hypervisor

### File names

Cloud Hypervisor does not protect against symlink attacks when opening
files. Files that Cloud Hypervisor is told to open must be in paths
that are protected from symlink attacks. This can be accomplished by
mounting filesystems with `nosymfollow`.

Cloud Hypervisor does not protect against being told to open a file in
`/proc`. Accesses to such a files could corrupt Cloud Hypervisor's own
memory.

In short, if an untrusted entity is allowed to choose a filename, a
trusted component must ensure that path traversal attacks are blocked.

The safest way to provide a file to Cloud Hypervisor is via a file
descriptor.

### Disk Images

With one exception, Cloud Hypervisor assumes that disk images provided
to it are untrusted. The exception is that qcow2 images are assumed
trusted if the `backing_files` option is enabled. It is disabled by
default. If a backing file must be used with an untrusted image, the
management stack must validate that the backing file is the expected
value and resides in sector 0.

Cloud Hypervisor does not protect against decompression bombs.
This means that malicious compressed data in a qcow2 image can cause
Cloud Hypervisor to use very large amounts of CPU and/or memory.

If a non-raw disk image is not corrupt, Cloud Hypervisor does not allow
a guest to corrupt it. If it is corrupt and writable, it may be further
corrupted in an arbitrary way, except that the header of a qcow2 image
will not be altered.

Provided that symlink attacks are avoided and backing files are not
used, it is safe to provide a file backed by an untrusted FUSE
filesystem, or by a trusted FUSE file backed by untrusted network
storage. This means that Cloud Hypervisor must be secure even if an
attacker can cause I/O to complete at times of their choosing. Cloud
Hypervisor must also be secure against time-of-check to time-of-use
attacks.

### Virtual Firmware

Cloud Hypervisor does not itself trust the firmware image, but assumes
that the guest does trust it.

### Guest Kernel and Initramfs

Cloud Hypervisor does not itself trust the guest kernel and initramfs.
Unless the guest uses secure boot, the guest must itself trust them.

## PCI and vDPA devices

By default, Cloud Hypervisor provides PCI and vDPA devices assigned to a
guest with access to all guest memory. Therefore, these devices can take
over the guest. Even if a virtual IOMMU is enabled, there is no
interrupt remapping on x86\_64, so a device can probably use malicious
MSIs to take over a guest. On Arm, the GIC performs interrupt remapping,
so a guest could theoretically defend itself from a malicious device.
However, it is extremely unlikely that a real-world guest actually does.

However, it is possible for a guest to influence the behavior of PCI and
vDPA devices attached to it. Therefore, Cloud Hypervisor treats these
devices as untrusted. This is done by only allowing them to access
memory that is mapped into the guest. They are not allowed to access
Cloud Hypervisor's own memory.

Cloud Hypervisor *cannot* protect against hardware infection. Attackers
may attempt to install malicious firmware on a device, tamper with an
option ROM, or otherwise attempt to retain control of the device after
the host reboots. If the attacker succeeds, they can compromise the host
through any of a number of methods. These include, but are not limited
to, DMA attacks and impersonating trusted devices like a keyboard or OS
boot disk.

Systems where assigned devices have no mutable state that persists
across host CPU resets are not vulnerable to such attacks. If the device
has a secure boot process and is power cycled whenever the host resets,
the system may also not be vulnerable. This depends heavily on both the
host and device firmware and hardware design and no generic statement
can be given. SR-IOV virtual functions (including vDPA) are the safest
options, as they are intended to be assigned to guests. A detailed
explanation is beyond the scope of this policy.

## Sandboxing

Cloud Hypervisor can sandbox itself via Landlock and seccomp. Once
sandboxed, Cloud Hypervisor is not able to access any resources blocked
by the sandbox. This is true even if an attacker can execute arbitrary
code in the context of the Cloud Hypervisor process.

The sandbox only prevents access to resources subject to Landlock access
controls. For instance, it does not prevent access to AF\_UNIX sockets.
This can be blocked via namespaces or by other kernel-enforced access
controls. Additionally, the restricted resources are limited by the
version of the Landlock API Cloud Hypervisor uses.

Until support for blocking AF\_UNIX sockets is implemented in Landlock
and used by Cloud Hypervisor, sandbox escapes will not be considered
security vulnerabilities. Once Cloud Hypervisor enables and uses
AF\_UNIX socket restrictions, sandbox escapes will be considered
security vulnerabilities. This only applies to sandbox escapes that do
not exploit vulnerabilities in the host kernel.
