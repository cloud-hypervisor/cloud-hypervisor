# Cloud Hypervisor Security Policy

This document describes:

- The threat model of Cloud Hypervisor.
- What is and isn’t considered a vulnerability.
- The process for handling security vulnerabilities

## Threat model

### Privilege escalation (VM escape)

Guest VMs running in Cloud Hypervisor are assumed untrusted.
Flaws that allow a guest to escalate its privileges (to that of the Cloud Hypervisor process) are
considered to be critical security vulnerabilities and will be treated as such.
Flaws that allow guests to corrupt Cloud Hypervisor's memory are assumed
to allow privilege escalation, even if no exploit has actually been demonstrated.

### Denial of service

Cloud Hypervisor is a standalone executable, not a library,
and only runs one guest throughout the entire lifetime
of the process.  Therefore, a guest that merely *crashes*
Cloud Hypervisor does not gain anything.  Such a crash
is not considered a vulnerability unless either:

1. The crash can be triggered by an unprivileged process.
2. There is evidence of memory unsafety.

Cloud Hypervisor only assigns a certain number of vCPUs and a certain
amount of memory to a guest.  However, Cloud Hypervisor also uses
some memory and CPU time itself.  Multi-tenant scenarios that require enforcing resource limits should
use control groups.

### Disk images

Untrusted disk images are supported, regardless of format, as long
as the `backing_files` option is **not** enabled.  The `backing_files`
option allows the guest to read a file with a name included in the image.

### Information Leaks

Flaws that allow obtaining information from other processes on the
host system, or from the host filesystem or kernel, are considered
to be security vulnerabilities.  These are likely to allow an attacker
to obtain sensitive information they should not be able to obtain.

The situation is more complicated if the attacker can only obtain
information from Cloud Hypervisor's own address space.  Cloud Hypervisor
does not possess any authentication keys or other high-value secrets.
While Cloud Hypervisor does support a virtual TPM device, the
actual TPM implementation runs in a separate process.

Therefore, being able to leak information from Cloud Hypervisor's
own memory is considered to be of low severity.  It is not of *zero*
severity, as it reveals information about host configuration that
a guest should not be able to obtain.

### Guest I/O

#### Network and Storage

Network traffic and storage devices are considered untrusted
by *both* the guest and the host.  In most configurations, the guest
assumes that its storage is trusted.  However, Cloud Hypervisor
itself does not make this assumption.

Cloud Hypervisor does not protect against symlink attacks when
opening files.  Files that Cloud Hypervisor is told to open
must be in paths that are protected from symlink attacks.
This can be accomplished by mounting filesystems with `nosymfollow`.

#### Vhost-user devices

Currently, vhost-user devices can access all guest memory,
even if a virtual IOMMU is in use.  Therefore, the guest
must trust them.

Cloud Hypervisor does assume that these devices might be more
tightly sandboxed than Cloud Hypervisor itself.  Therefore, a
vhost-user device being able to execute code in Cloud Hypervisor
is considered a vulnerability, as it could be one part of an
exploit chain.

#### PCI devices

Cloud Hypervisor does not protect its guests from assigned
PCI devices.  This includes vDPA.  An assigned PCI device
can fully compromise the guest.

Arm platforms with a virtualized IOMMU are an exception,
but only to the extent that the guest OS distrusts devices.
In practice, essentially no guest OS actually does.

Cloud Hypervisor does aim to protect itself and the host from
malicious PCI devices, though.  This is because there are situations
where a guest can cause a PCI device assigned to it to behave
in a way it controls.

Cloud Hypervisor *cannot* protect against hardware infection
attacks.  This involves a guest implanting malware into the
device's firmware that persists after the host reboots.  The
malware then compromises the host through any of a number of
methods, of which a DMA attack is just one possibility.

Systems where assigned devices have no mutable state that
persists across host CPU resets are not vulnerable to such attacks.
If the device has a secure boot process and is power cycled whenever
the host resets, the system may also not be vulnerable.  This
depends heavily on both the host and device firmware and hardware
design and no generic statement can be given.  SR-IOV virtual functions
(including vDPA) are the safest options, as they are intended
to be assigned to guests.  A detailed explanation is beyond the
scope of this policy.

### Guest Userspace

Cloud Hypervisor should not allow unprivileged guest userspace
processes to subvert the security of the guest OS.  For instance,
it should not allow unprivileged guest software to gain guest
kernel privileges.  Bugs in Cloud Hypervisor that allow for guest
userspace to violate the security guarantees provided by the guest OS are
considered security vulnerabilities.

### Management API

Cloud Hypervisor assumes that only trusted programs will be
allowed to access its API socket.  Cloud Hypervisor will access
arbitrary files provided through this socket without any
validation.

However, a trusted management stack may expose a carefully
filtered subset of the API's functionality to untrusted parties.
A management stack is allowed to expose the following operations
to untrusted parties:

- Hotplug and hot-unplug virtualized devices of any type.
- Hotplug and hot-unplug hardware devices, provided that the
  use of the device by the guest is permitted by the host's
  security policy.
- Trigger live migration of the guest.
- Influence the amount of memory or vCPUs available to the guest.

### Landlock Sandbox

Defects that allow escaping the Landlock sandbox are considered
vulnerabilities, unless they involve known weaknesses in the Linux
kernel.

### Attacks involving multiple hostile components

Cloud Hypervisor assumes that untrusted components may
be controlled by the same entity and may conspire with
each other.  For instance, a guest could try to create
a situation in which incoming network traffic will be
written to memory that the guest should not be able
to access.

## What configurations are supported?

### Build options

Currently, all combinations of Cargo features are considered
secure and safe for production use.

### Platforms

Running Cloud Hypervisor on a 32-bit host platform is not
not security supported.  Using Cloud Hypervisor to run
32-bit guests is security supported.

## Security Process

### Reporting vulnerabilities

Vulnerabilities should be reported via the GitHub Security Advisory
process.  A Proof of Concept (PoC) is highly desired, though not always
strictly required.  There are cases where reproducing a bug is
very difficult, perhaps because it requires changing guest
kernel code that the reporter poorly understands.

A PoC does not need to be a weaponized exploit.
For instance, demonstrating memory unsafety (such as a SIGSEGV
or even an ASAN report) is sufficient.  In some cases,
the PoC may require making slight changes to Cloud Hypervisor
itself.  In particular, adding artificial delays can be extremely
helpful when reproducing race conditions.  It is assumed that
a sophisticated attacker can trigger the race condition reliably
even without such delays, but the effort needed is often too much
to ask of a reporter.

The use of generative AI to create proofs of concept is permitted.
Proofs of concept are generally meant to be thrown away and
are not going to be incorporated into the Cloud Hypervisor
project.  It is not necessary for the reporter to understand the
proof of concept, and indeed in some cases (such as fuzzer outputs)


### What will happen when a vulnerability is reported

Cloud Hypervisor generally adopts [Xen Project’s Security Process][1]
Differences are noted below:

1. Reports use GitHub Security Advisories instead of a mailing list.
2. The project name, email addresses, and predisclosure list are, of course, different.
3. Instead of backporting patches to existing releases, a completely
   new release is made.  If a patch release is made, it will only be
   for the immediately preceding release.

A summarized version:

1. If the vulnerability is already publicly known, or is being exploited in the wild,
   it will be handled in public and as quickly as possible.
2. Otherwise:
   1. The process will be coordinated with other software systems that are likely
      to be affected, if such systems exist.
   2. Patches will be written for the current `main` branch and,
      sometimes, for the most recent release.
   3. A pre-release will be made and disclosed to those on the predisclosure list.
   4. A public release will be made after the embargo is finished.
3. Any decisions made by the security team during the embargo will be disclosed
   after the embargo is complete.

### Predisclosure list

Major users of Cloud Hypervisor may be eligible for advance
notice of security vulnerabilities.  The criteria for this are
the same as those used by the [Xen Project][2].

[1]: https://xenproject.org/about/security-policy/#specific-process
[2]: https://xenproject.org/about/security-policy/#predisclosure-list-membership-application-process
