# UEFI Boot

Cloud Hypervisor supports UEFI boot through the utilization of the EDK II based UEFI firmware. 

## Building UEFI Firmware

To avoid any unnecessary issues, it is recommended to use Ubuntu 18.04 and its default toolset. Any other compatible Linux distribution is otherwise suitable, however it is suggested to use a temporary Docker container with Ubuntu 18.04 for a quick build on an existing Linux machine.

The commands below will compile an OVMF firmware suitable for Cloud Hypervisor.

```shell
sudo apt-get update
sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git

git clone https://github.com/cloud-hypervisor/edk2 -b ch
cd edk2
. edksetup.sh
git submodule update --init

echo "ACTIVE_PLATFORM=OvmfPkg/OvmfCh.dsc" >> Conf/target.txt
echo "TARGET_ARCH=X64" >> Conf/target.txt
echo "TOOL_CHAIN_TAG=GCC5" >> Conf/target.txt

make -C ./BaseTools
build
```

After the successful build, the resulting firmware binaries are available under `Build/OvmfCh/DEBUG_GCC5/FV` underneath the edk2 checkout.

## Using OVMF Binaries

Any UEFI capable image can be booted using the Cloud Hypervisor specific firmware. Windows guests under Cloud Hypervisor only support UEFI boot, therefore OVMF is mandatory there.

To make Cloud Hypervisor use UEFI boot, pass the `OVMF.fd` file path as an argument to the `--kernel` option. The firmware file will be opened in read only mode.

The same firmware can be used with Cloud Hypervisor or with QEMU. This is particularly useful if using QEMU for the preparation phase.

# Links

- [OVMF wiki](https://github.com/tianocore/tianocore.github.io/wiki/OVMF) 
- [Cloud Hypervisor specific tree](https://github.com/cloud-hypervisor/edk2/tree/ch)

