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

Before building, a hack trick need to be performed to get rid of some build error in vmm component. See [this](https://github.com/cloud-hypervisor/kvm-bindings/pull/1) for more info about this temporary workaround.

```bash
sed -i 's/"with-serde",\ //g' hypervisor/Cargo.toml
```

For Virtio devices, you can choose MMIO or PCI as transport option.

### MMIO

```bash
cargo build --no-default-features --features "mmio"
```

### PCI

Using PCI devices requires GICv3-ITS for MSI messaging. GICv3-ITS is very common in modern servers, but your machine happen to be old ones with GICv2(M) (like Raspberry Pi 4) or GICv3 without ITS, MMIO can still work.

```bash
cargo build --no-default-features --features "pci"
```

## Image

Download kernel binary and rootfs image from AWS.

```bash
wget https://s3.amazonaws.com/spec.ccfc.min/img/aarch64/ubuntu_with_ssh/fsfiles/xenial.rootfs.ext4 -O rootfs.img
wget https://s3.amazonaws.com/spec.ccfc.min/img/aarch64/ubuntu_with_ssh/kernel/vmlinux.bin -O kernel.bin
```

## Containerized build

If you want to build and test Cloud Hypervisor without having to install all the required dependencies, you can also turn to the development script: dev_cli.sh.

To build the development container:

```bash
./scripts/dev_cli.sh build-container
```

To build Cloud-hypervisor in the container: (The default option for Virtio transport is MMIO.)

```bash
./scripts/dev_cli.sh build
```

## Run

Assuming you have built Cloud-hypervisor with the development container, a VM can be started with command:

```bash
sudo build/cargo_target/aarch64-unknown-linux-gnu/debug/cloud-hypervisor --kernel kernel.bin --disk path=rootfs.ext4 --cmdline "keep_bootcon console=hvc0 reboot=k panic=1 pci=off root=/dev/vda rw" --cpus boot=4 --memory size=512M --serial file=serial.log --log-file log.log -vvv
```

If the build was done out of the container, replace the binary path with `target/debug/cloud-hypervisor`.
