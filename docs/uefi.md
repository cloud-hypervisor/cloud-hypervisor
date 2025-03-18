# UEFI Boot

Cloud Hypervisor supports UEFI boot through the utilization of the EDK II based UEFI firmware. 

## Building UEFI Firmware for x86-64

To avoid any unnecessary issues, it is recommended to use Ubuntu 18.04 and its default toolset. Any other compatible Linux distribution is otherwise suitable, however it is suggested to use a temporary Docker container with Ubuntu 18.04 for a quick build on an existing Linux machine.

Please note that nasm-2.15 is required for the build to succeed.

The commands below will compile an OVMF firmware suitable for Cloud Hypervisor.

```shell
sudo apt-get update
sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git

git clone https://github.com/tianocore/edk2
cd edk2
. edksetup.sh
git submodule update --init

echo "ACTIVE_PLATFORM=OvmfPkg/CloudHv/CloudHvX64.dsc" >> Conf/target.txt
echo "TARGET_ARCH=X64" >> Conf/target.txt
echo "TOOL_CHAIN_TAG=GCC5" >> Conf/target.txt

make -C ./BaseTools
build
```

After the successful build, the resulting firmware binaries are available under `Build/CloudHvX64/DEBUG_GCC5/FV` underneath the edk2 checkout.

## Building UEFI Firmware for AArch64

```shell
# On an AArch64 machine:
$ sudo apt-get update
$ sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git
$ git clone --depth 1 https://github.com/tianocore/edk2.git -b master
$ cd edk2
$ git submodule update --init
$ cd ..
$ git clone --depth 1 https://github.com/tianocore/edk2-platforms.git -b master
$ git clone --depth 1 https://github.com/acpica/acpica.git -b master

# Build tools
$ export PACKAGES_PATH="$PWD/edk2:$PWD/edk2-platforms"
$ export IASL_PREFIX="$PWD/acpica/generate/unix/bin/"
$ make -C acpica
$ cd edk2/
$ . edksetup.sh
$ cd ..
$ make -C edk2/BaseTools

# Build EDK2
$ build -a AARCH64 -t GCC5 -p ArmVirtPkg/ArmVirtCloudHv.dsc -b RELEASE
```

If the build goes well, the EDK2 binary is available at
`edk2/Build/ArmVirtCloudHv-AARCH64/RELEASE_GCC5/FV/CLOUDHV_EFI.fd`.

## Using OVMF Binaries

Any UEFI capable image can be booted using the Cloud Hypervisor specific firmware. Windows guests under Cloud Hypervisor only support UEFI boot, therefore OVMF is mandatory there.

To make Cloud Hypervisor use UEFI boot, pass the `CLOUDHV.fd` (for x86-64) / `CLOUDHV_EFI.fd` (for AArch64) file path as an argument to the `--kernel` option. The firmware file will be opened in read only mode.

# Links

- [OVMF wiki](https://github.com/tianocore/tianocore.github.io/wiki/OVMF) 
- [Cloud Hypervisor specific tree](https://github.com/cloud-hypervisor/edk2/tree/ch)
