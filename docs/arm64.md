# How to build and test Cloud Hypervisor on AArch64

This document introduces how to build and test Cloud Hypervisor on AArch64.
Currently, Cloud Hypervisor supports 2 methods of booting on AArch64: UEFI
booting and direct-kernel booting. The document covers both methods.

All the steps are based on Ubuntu. We use the Ubuntu cloud image for guest VM
disk.

### Disk image

Download the Ubuntu cloud image and convert the image type.

```bash
$ pushd $CLOUDH
$ wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-arm64.img
$ qemu-img convert -p -f qcow2 -O raw focal-server-cloudimg-arm64.img focal-server-cloudimg-arm64.raw
$ popd
```

## Direct-kernel booting

Alternativelly, you can build your own kernel for guest VM. This way, UEFI is
not involved and ACPI cannot be enabled.

### Building kernel

```bash
$ pushd $CLOUDH
$ git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b ch-5.12
$ cd linux
$ cp $CLOUDH/cloud-hypervisor/resources/linux-config-aarch64 .config
$ make -j `nproc`
$ popd
```

### Booting the guest VM

```bash
$ pushd $CLOUDH
$ sudo $CLOUDH/cloud-hypervisor/target/debug/cloud-hypervisor \
           --api-socket /tmp/cloud-hypervisor.sock \
           --kernel $CLOUDH/linux/arch/arm64/boot/Image \
           --disk path=focal-server-cloudimg-arm64.raw \
           --cmdline "keep_bootcon console=ttyAMA0 reboot=k panic=1 root=/dev/vda1 rw" \
           --cpus boot=4 \
           --memory size=4096M \
           --net tap=,mac=12:34:56:78:90:01,ip=192.168.1.1,mask=255.255.255.0 \
           --serial tty \
           --console off
$ popd
```
