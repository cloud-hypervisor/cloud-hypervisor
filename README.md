[![Build Status](https://travis-ci.com/intel/cloud-hypervisor.svg?branch=master)](https://travis-ci.com/intel/cloud-hypervisor)

1. [What is Cloud Hypervisor?](#1-what-is-cloud-hypervisor)
   * [Requirements](#requirements)
	 + [High Level](#high-level)
     + [Architectures](#architectures)
	 + [Guest OS](#guest-os)
2. [Getting Started](#2-getting-started)
   * [Clone and build](#clone-and-build)
   * [Run](#run)
	 + [Cloud image](#cloud-image)
	 + [Custom kernel and disk image](#custom-kernel-and-disk-image)
		 - [Building your kernel](#building-your-kernel)
		 - [Disk image](#disk-image)
		 - [Booting the guest VM](#booting-the-guest-vm)
3. [Status](#2-status)
	* [TODO](#todo)
4. [rust-vmm dependency](#4-rust-vmm-dependency)
	* [Firecracker and crosvm](#firecracker-and-crosvm)
5. [Community](#5-community)
	* [Join us](#join-us)
6. [Security](#6-security)

# 1. What is Cloud Hypervisor?

**This project is an experiment and should not be used with production workloads.**

Cloud Hypervisor is an open source Virtual Machine Monitor (VMM) that runs on top of [KVM](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
The project focuses on exclusively running modern, cloud workloads, on top of a limited set of hardware architectures and platforms.
Cloud workloads refers to those that are usually run by customers inside a cloud provider. For our purposes this means modern
Linux* distributions with most I/O handled by paravirtualised devices (i.e. virtio), no requirement for legacy devices and recent CPUs and KVM.

Cloud Hypervisor is implemented in [Rust](https://www.rust-lang.org/) and is based on the [rust-vmm](https://github.com/rust-vmm) crates.

## Objectives

### High Level

* KVM and KVM only based
* Minimal emulation
* Low latency
* Low memory footprint
* Low complexity
* High performance
* Small attack surface
* 64-bit support only
* Build time configurable CPU, memory, PCI and NVDIMM hotplug
* Machine to machine migration

### Architectures

`cloud-hypervisor` only supports the `x86-64` CPU architecture for now.

We're planning to add support for the `AArch64` architecture in the future.

### Guest OS
* `64-bit Linux`

Support for *modern* 64-bit Windows guest is being evaluated.

# 2. Getting Started

We create a folder to build and run `cloud-hypervisor` at `$HOME/cloud-hypervisor`

```shell
$ export CLOUDH=$HOME/cloud-hypervisor
$ mkdir $CLOUDH
```

## Clone and build

First you need to clone and build the cloud-hypervisor repo:

```shell
$ pushd $CLOUDH
$ git clone https://github.com/intel/cloud-hypervisor.git
$ cd cloud-hypervisor
$ cargo build --release

# We need to give the cloud-hypervisor binary the NET_ADMIN capabilities for it to set TAP interfaces up on the host.
$ sudo setcap cap_net_admin+ep ./target/release/cloud-hypervisor

$ popd
```

This will build a `cloud-hypervisor` binary under `$CLOUDH/cloud-hypervisor/target/release/cloud-hypervisor`.

## Run

You can run a guest VM by either using an existing cloud image or booting into your own kernel and disk image.

### Cloud image

`cloud-hypervisor` supports booting disk images containing all needed
components to run cloud workloads, a.k.a. cloud images.  To do that we rely on
the [Rust Hypervisor
Firmware](https://github.com/intel/rust-hypervisor-firmware) project to provide
an ELF
formatted KVM firmware for `cloud-hypervisor` to directly boot into.

We need to get the latest `rust-hypervisor-firmware` release and also a working cloud image. Here we will use a Clear Linux image:

```shell
$ pushd $CLOUDH
$ wget https://download.clearlinux.org/releases/29160/clear/clear-29160-kvm.img.xz
$ unxz clear-29160-kvm.img.xz
$ wget https://github.com/intel/rust-hypervisor-firmware/releases/download/0.2.0/hypervisor-fw
$ popd
```

```shell
$ pushd $CLOUDH
$ sudo setcap cap_net_admin+ep ./cloud-hypervisor/target/release/cloud-hypervisor
$ ./cloud-hypervisor/target/release/cloud-hypervisor \
	--kernel ./hypervisor-fw \
	--disk ./clear-29160-kvm.img \
	--cpus 4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--rng
$ popd
```

Multiple arguments can be given to the `--disk` parameter, currently the firmware requires that the bootable image is on the first disk.

### Custom kernel and disk image

#### Building your kernel

`cloud-hypervisor` also supports direct kernel boot into a `vmlinux` ELF kernel
image. You want to build such an image first:

```shell

# Clone a 5.0 Linux kernel
$ pushd $CLOUDH
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-cloud-hypervisor
$ cd linux-cloud-hypervisor
$ git reset --hard v5.0

# Use the cloud-hypervisor kernel config to build your kernel
$ cp $CLOUDH/cloud-hypervisor/resources/linux-5.0-config .config
$ make bzImage -j `nproc`
$ popd
```

The `vmlinux` kernel image will then be located at `linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin`.

#### Disk image

For the disk image, we will use a Clear Linux cloud image that contains a root partition:

```shell
$ pushd $CLOUDH
$ wget https://download.clearlinux.org/releases/29160/clear/clear-29160-kvm.img.xz
$ unxz clear-29160-kvm.img.xz
$ popd
```

#### Booting the guest VM

Now we can directly boot into our custom kernel and make it use the Clear Linux root partition.
If we want to have 4 vCPUs and 512 MBytes of memory:

```shell
$ pushd $CLOUDH
$ sudo setcap cap_net_admin+ep ./cloud-hypervisor/target/release/cloud-hypervisor
$ ./cloud-hypervisor/target/release/cloud-hypervisor \
	--kernel ./linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin \
	--disk ./clear-29160-kvm.img \
	--cmdline "console=hvc0 reboot=k panic=1 nomodules i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd root=/dev/vda3" \
	--cpus 4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--rng
```

The above example use the `virtio-console` device as the guest console, and this
device may not be enabled soon enough by the guest kernel to get early kernel
debug messages.

When in need for earlier debug messages, using the legacy serial device based
console is preferred:

```
$ ./cloud-hypervisor/target/release/cloud-hypervisor \
	--kernel ./linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin \
	--console off \
	--serial tty \
	--disk ./clear-29160-kvm.img \
	--cmdline "console=ttyS0 reboot=k panic=1 nomodules i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd root=/dev/vda3" \
	--cpus 4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--rng
```


# 3. Status

`cloud-hypervisor` is in a very early, pre-alpha stage. Use at your own risk!

As of 2019/05/12, booting cloud images has only been tested with [Clear Linux images](https://download.clearlinux.org/current/).
Direct kernel boot to userspace should work with most rootfs and it's been tested with
Clear Linux root partitions, and also basic initrd/initramfs images.

## TODO

We are not tracking the `cloud-hypervisor` TODO list from a specific git tracked file but through
[github issues](https://github.com/intel/cloud-hypervisor/issues/new) instead.

# 4. `rust-vmm` project dependency

In order to satisfy the design goal of having a high-performance, security-focused hypervisor the decision
was made to use the [Rust](https://www.rust-lang.org/) programming language.
The language's strong focus on memory and thread safety makes it an ideal candidate for implementing VMMs

Instead of implementing the VMM components from scratch, `cloud-hypervisor` is importing the [rust-vmm](https://github.com/rust-vmm)
crates, and sharing code and architecture together with other VMMs like e.g. Amazon's [Firecracker](https://firecracker-microvm.github.io/)
and Google's [crosvm](https://chromium.googlesource.com/chromiumos/platform/crosvm/).

`cloud-hypervisor` embraces the rust-vmm project goals, which is to be able to share and re-use
as many virtualization crates as possible. As such, the `cloud-hypervisor` relationship with the rust-vmm
project is twofold:

1. It will use as much of the rust-vmm code as possible. Any new rust-vmm crate that's relevant to the project
   goals will be integrated as soon as possible.
2. As it is likely that the rust-vmm project will lack some of the features that `cloud-hypervisor` needs (e.g. ACPI,
   VFIO, vhost-user, etc), we will be using the `cloud-hypervisor` VMM to implement and test them, and contribute them
   back to the rust-vmm project.

## Firecracker and crosvm

A large part of the `cloud-hypervisor` code is based on either the Firecracker or the crosvm projects implementations.
Both of these are VMMs written in Rust with a focus on safety and security, like Cloud Hypervisor.

However we want to emphasize that the Cloud Hypervisor project is neither a fork nor a reimplementation of any of those
projects. The goals and use cases we're trying to meet are different.
We're aiming at supporting cloud workloads, i.e. those modern, full Linux distribution images currently being run by
Cloud Service Provider (CSP) tenants.

Our primary target is not to support client or serverless use cases, and as such our code base already diverges
from the crosvm and Firecracker ones. As we add more features to support our use cases, we believe that the divergence
will increase while at the same time sharing as much of the fundamental virtualization code through the rust-vmm project
crates as possible.

# 5. Community

We are working on building a global, diverse and collaborative community around the Cloud Hypervisor project.
Anyone who is interested in [contributing](CONTRIBUTING.md) to the project is welcome to participate.

We believe that contributing to a open source project like Cloud Hypervisor covers a lot more than just sending
code. Testing, documentation, pull request reviews, bug reports, feature requests, project improvement suggestions,
etc, are all equal and welcome means of contribution. See the [CONTRIBUTING](CONTRIBUTING.md) document for more details.

## Join us

Get an [invite to our Slack channel](https://join.slack.com/t/cloud-hypervisor/shared_invite/enQtNjY3MTE3MDkwNDQ4LWQ1MTA1ZDVmODkwMWQ1MTRhYzk4ZGNlN2UwNTI3ZmFlODU0OTcwOWZjMTkwZDExYWE3YjFmNzgzY2FmNDAyMjI)
and [join us on Slack](https://cloud-hypervisor.slack.com/).

# 6. Security

**Reporting a Potential Security Vulnerability**: If you have discovered
potential security vulnerability in this project, please send an e-mail to
secure@intel.com. For issues related to Intel Products, please visit
https://security-center.intel.com.

It is important to include the following details:
  - The projects and versions affected
  - Detailed description of the vulnerability
  - Information on known exploits

Vulnerability information is extremely sensitive. Please encrypt all security
vulnerability reports using our *PGP key*

A member of the Intel Product Security Team will review your e-mail and
contact you to to collaborate on resolving the issue. For more information on
how Intel works to resolve security issues, see: *Vulnerability Handling
Guidelines*

PGP Key: https://www.intel.com/content/www/us/en/security-center/pgp-public-key.html

Vulnerability Handling Guidelines: https://www.intel.com/content/www/us/en/security-center/vulnerability-handling-guidelines.html
