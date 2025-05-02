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

## Virtualized Development Setup

Since there are few RISC-V development boards on the market and not 
many details about the AIA interrupt controller featured in product listings,
QEMU is a popular and viable choice for creating a RISC-V development environment. 
Below are the steps used to create a QEMU virtual machine that can be used for 
cloud-hypervisor RISC-V development:

### Install Dependencies

```console
sudo apt update
sudo apt install opensbi qemu-system-misc u-boot-qemu
```

### Download and Build QEMU (>=v9.2.0)

Older versions of QEMU may not have support for the AIA 
interrupt controller.

```console
wget https://download.qemu.org/qemu-10.0.0.tar.xz
tar xvJf qemu-10.0.0.tar.xz
cd qemu-10.0.0
./configure --target-list=riscv64-softmmu
make -j $(nproc)
sudo make install
```

### Download Ubuntu Server Image

At the time of writing, the best results have been seen with 
the Ubuntu 24.10 (Oracular) server image. Ex:

```console
wget https://cdimage.ubuntu.com/releases/oracular/release/ubuntu-24.10-preinstalled-server-riscv64.img.xz
xz -dk ubuntu-24.10-preinstalled-server-riscv64.img.xz
```

### (Optional) Resize Disk

If you would like a larger disk, you can resize it now.

```console
qemu-img resize -f raw <ubuntu-image> +5G
```

### Boot VM

Note the inclusion of the AIA interrupt controller in the 
invocation.

```console
qemu-system-riscv64 \
  -machine virt,aia=aplic-imsic \
  -nographic -m 1G -smp 8 \
  -kernel /usr/lib/u-boot/qemu-riscv64_smode/uboot.elf \
  -device virtio-rng-pci \
  -device virtio-net-device,netdev=eth0 -netdev user,id=eth0 \
  -drive file=<ubuntu-image>,format=raw,if=virtio
```

### Install KVM Kernel Module Within VM
KVM is not enabled within the VM by default, so we must enable 
it manually.

```console
sudo modprobe kvm
```

From this point, you can continue with the above steps from the beginning.

### Sources

https://risc-v-getting-started-guide.readthedocs.io/en/latest/linux-qemu.html

https://canonical-ubuntu-boards.readthedocs-hosted.com/en/latest/how-to/qemu-riscv/#using-the-live-server-image

https://www.qemu.org/docs/master/specs/riscv-aia.html

## Known limitations

- Direct kernel boot only
- `64-bit Linux` guest OS only
- For more details, see
  [here](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/6978).
