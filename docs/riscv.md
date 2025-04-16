# How to build and test Cloud Hypervisor on riscv64

This document introduces how to build and test Cloud Hypervisor on `riscv64`.
All instructions here are tested with Ubuntu 24.04.2 as the host OS.

## Hardware requirements

- riscv64 servers (recommended) or development boards equipped with the AIA
(Advance Interrupt Architecture) interrupt controller.

## Getting started

We create a folder to build and run Cloud Hypervisor at `$HOME/cloud-hypervisor`

```console
export CLOUDH=$HOME/cloud-hypervisor
mkdir $CLOUDH
```

## Prerequisites

You need to install some prerequisite packages to build and test Cloud Hypervisor.

### Tools

```console
# Install rust tool chain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Install the tools used for building guest kernel, EDK2 and converting guest disk
sudo apt-get update
sudo apt-get install git build-essential m4 bison flex uuid-dev qemu-utils
```

### Building Cloud Hypervisor

```console
pushd $CLOUDH
git clone https://github.com/cloud-hypervisor/cloud-hypervisor.git
cd cloud-hypervisor
cargo build
popd
```

### Disk image

Download the Ubuntu cloud image and convert the image type.

```console
pushd $CLOUDH
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-riscv64.img
qemu-img convert -p -f qcow2 -O raw jammy-server-cloudimg-riscv64.img jammy-server-cloudimg-riscv64.raw
popd
```

## Direct-kernel booting

### Building kernel

```console
pushd $CLOUDH
git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b ch-6.12.8
cd linux
make ch_defconfig
make -j `nproc`
popd
```

### Booting the guest VM

```console
pushd $CLOUDH
sudo $CLOUDH/cloud-hypervisor/target/debug/cloud-hypervisor \
           --kernel $CLOUDH/linux/arch/riscv64/boot/Image \
           --disk path=jammy-server-cloudimg-riscv64.raw \
           --cmdline "console=hvc0 root=/dev/vda rw" \
           --cpus boot=1 \
           --memory size=1024M \
           --seccomp false \
           --log-file boot.log -vv
popd
```

## Known limitations

- Direct kernel boot only
- `64-bit Linux` guest OS only
- For more details, see
  [here](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/6978).
