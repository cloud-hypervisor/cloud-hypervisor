# How to build and run Cloud-hypervisor on Arm64

Cloud-hypervisor is partially enabled on AArch64 architecture.
Although all features are not ready yet, you can begin to test Cloud-hypervisor on a Arm64 host by following this guide.

## Prerequisites

On Arm64 machines, Cloud-hypervisor depends on an external library `libfdt-dev` for generating Flatted Device Tree (FDT).

The long-term plan is to replace `libfdt-dev` with some pure-Rust component to get rid of such dependency.

```bash
sudo apt-get update
sudo apt-get install libfdt-dev
```

## Build

Before building, a hack trick need to be performed to get rid of some build error in vmm component. See [this](https://github.com/cloud-hypervisor/kvm-bindings/pull/1) for more info about this temporary workaround.

```bash
sed -i 's/"with-serde",\ //g' vmm/Cargo.toml
```

The support of AArch64 is in very early stage, only Virtio devices with MMIO tranport is available.

```bash
cargo build --no-default-features --features "mmio"
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

To build Cloud-hypervisor in the container:

```bash
./scripts/dev_cli.sh build
```

## Run

Assuming you have built Cloud-hypervisor with the development container, a VM can be started with command:

```bash
sudo target/debug/cloud-hypervisor --kernel kernel.bin --disk path=rootfs.ext4 --cmdline "keep_bootcon console=hvc0 reboot=k panic=1 pci=off root=/dev/vda rw" --cpus boot=4 --memory size=512M --seccomp false --serial file=serial.log --log-file log.log -vvv
```

If the build was done out of the container, replace the binary path with `build/cargo_target/aarch64-unknown-linux-gnu/debug/cloud-hypervisor`.
