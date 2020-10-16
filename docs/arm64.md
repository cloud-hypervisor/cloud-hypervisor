# How to build and run Cloud-hypervisor on AArch64

Cloud-hypervisor is partially enabled on AArch64 architecture.
Although all features are not ready yet, you can begin to test Cloud-hypervisor on a AArch64 host by following this guide.

## Prerequisites

On AArch64 machines, Cloud-hypervisor depends on an external library `libfdt-dev` for generating Flattened Device Tree (FDT).

The long-term plan is to replace `libfdt-dev` with some pure-Rust component to get rid of such dependency.

```bash
sudo apt-get update
sudo apt-get install libfdt-dev
```

## Build

Using PCI devices requires GICv3-ITS for MSI messaging. GICv3-ITS is very common in modern servers.

```bash
cargo build --no-default-features --features kvm
```

## Image

Download kernel binary and rootfs image from AWS.

```bash
wget https://s3.amazonaws.com/spec.ccfc.min/img/aarch64/ubuntu_with_ssh/fsfiles/xenial.rootfs.ext4 -O rootfs.ext4
wget https://s3.amazonaws.com/spec.ccfc.min/img/aarch64/ubuntu_with_ssh/kernel/vmlinux.bin -O kernel.bin
```

## Containerized build

If you want to build and test Cloud Hypervisor without having to install all the required dependencies, you can also turn to the development script: dev_cli.sh.

To build the development container:

```bash
./scripts/dev_cli.sh build-container
```

To build Cloud-hypervisor in the container:

```bash
./scripts/dev_cli.sh build
```

## Run

Assuming you have built Cloud-hypervisor with the development container, a VM can be started with command:

```bash
sudo build/cargo_target/aarch64-unknown-linux-gnu/debug/cloud-hypervisor --kernel kernel.bin --disk path=rootfs.ext4 --cmdline "keep_bootcon console=hvc0 reboot=k panic=1 root=/dev/vda rw" --cpus boot=4 --memory size=512M --serial file=serial.log --log-file log.log -vvv
```

If the build was done out of the container, replace the binary path with `target/debug/cloud-hypervisor`.
