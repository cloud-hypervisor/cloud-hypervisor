# UEFI Boot

Cloud Hypervisor supports UEFI boot through the utilization of the EDK II based UEFI firmware.

## Using Prebuilt UEFI Firmware

Cloud Hypervisor's [edk2 fork](https://github.com/cloud-hypervisor/edk2)
publishes prebuilt UEFI firmware binaries as release assets. The x86-64
binary is named `CLOUDHV.fd` and the AArch64 binary is named
`CLOUDHV_EFI.fd`.

The latest release is always available at
<https://github.com/cloud-hypervisor/edk2/releases/latest>.

```shell
# x86-64
$ wget https://github.com/cloud-hypervisor/edk2/releases/latest/download/CLOUDHV.fd

# AArch64
$ wget https://github.com/cloud-hypervisor/edk2/releases/latest/download/CLOUDHV_EFI.fd
```

Pass the firmware file to `--firmware`.

```shell
# x86-64
$ ./cloud-hypervisor --firmware ./CLOUDHV.fd --disk path=guest.raw ...

# AArch64
$ ./cloud-hypervisor --firmware ./CLOUDHV_EFI.fd --disk path=guest.raw ...
```

Cloud Hypervisor opens the firmware file in read-only mode.

The sections below describe how to build the firmware from source, which is
only necessary if you need to test edk2 changes or build for a configuration
that the release assets don't cover.

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

Build from Cloud Hypervisor's
[edk2 fork](https://github.com/cloud-hypervisor/edk2), which carries
the submodule revisions and patches needed to boot AArch64 guests on
Cloud Hypervisor. This is the same build that produces the prebuilt
firmware in the fork's release workflow.

```shell
# On an AArch64 machine.
$ sudo apt-get update
$ sudo apt-get install uuid-dev iasl build-essential git libbrotli-dev

$ git clone --branch ch https://github.com/cloud-hypervisor/edk2.git
$ cd edk2
$ git submodule update --init --recursive

$ source edksetup.sh
$ make -C BaseTools

$ build -p ArmVirtPkg/ArmVirtCloudHv.dsc -a AARCH64 -t GCC -b RELEASE \
    --pcd gEfiMdeModulePkgTokenSpaceGuid.PcdDxeNxMemoryProtectionPolicy=0xC000000000007FD1
```

The `--pcd` argument keeps `EfiLoaderData` executable so older GRUB
versions can boot, as described in the EfiLoaderData Executability
section below.

The built firmware is produced at
`Build/ArmVirtCloudHv-AARCH64/RELEASE_GCC/FV/CLOUDHV_EFI.fd`.

## AArch64 Firmware Notes

### Multiple PCI Segments

The AArch64 UEFI firmware (`CLOUDHV_EFI.fd`) uses `FdtPciHostBridgeLib`
to discover PCI host bridges from the device tree. This library only
enumerates the first PCI host bridge (segment 0), regardless of how
many `pci-host-ecam-generic` FDT nodes Cloud Hypervisor provides.
When booting with `--platform num_pci_segments=N` (N > 1), segments
1 through N-1 are not visible to the firmware itself.

This is not a functional limitation because Cloud Hypervisor provides
ACPI tables (MCFG, DSDT) describing all segments directly to the guest
via `CloudHvAcpiPlatformDxe`. The Linux kernel re-enumerates PCI from
the MCFG table and assigns BARs independently of UEFI. Boot devices
(virtio-blk, virtio-net) must reside on segment 0, which UEFI does
enumerate.

The DEBUG build configuration additionally asserts and terminates
when more than one `pci-host-ecam-generic` node is present.
The prebuilt `CLOUDHV_EFI.fd` is built with RELEASE configuration to
avoid this assert. If you build the firmware from source and intend
to use multiple PCI segments, build with `-b RELEASE`.

### EfiLoaderData Executability

The AArch64 firmware in cloud-hypervisor/edk2 allows code execution
from `EfiLoaderData` memory regions. The upstream tianocore/edk2
default does the opposite and marks `EfiLoaderData` as non-executable
through the `PcdDxeNxMemoryProtectionPolicy` PCD set in
`ArmVirt.dsc.inc`. The non-executable default was introduced in
upstream commit
[2997ae3873](https://github.com/tianocore/edk2/commit/2997ae3873)
in 2022 and sets the PCD to `0xC000000000007FD5`.

Keeping `EfiLoaderData` executable is required for older GRUB versions
that allocate their modules into `EfiLoaderData` memory and then
execute code from those allocations. GRUB upstream switched to
`EfiLoaderCode` for this in 2017, but some distributions still ship
the older behavior (e.g. Ubuntu 22.04 / Jammy AArch64 cloud images).
Without the override, those guests fail to boot with an instruction
abort (permission fault, second level).

The prebuilt `CLOUDHV_EFI.fd` overrides the PCD back to
`0xC000000000007FD1` at build time (clears the `EfiLoaderData` NX
bit). If you build the firmware from source and need to boot guests
with the older GRUB behavior, apply the same override. x86-64
(`CLOUDHV.fd`) is unaffected as it does not enforce this NX policy.

## Using OVMF Binaries

Any UEFI capable image can be booted using the Cloud Hypervisor specific firmware. Windows guests under Cloud Hypervisor only support UEFI boot, therefore OVMF is mandatory there.

To make Cloud Hypervisor use UEFI boot, pass the `CLOUDHV.fd` (for x86-64) or `CLOUDHV_EFI.fd` (for AArch64) file path as an argument to the `--firmware` option, which opens the firmware file in read-only mode.

# Links

- [OVMF wiki](https://github.com/tianocore/tianocore.github.io/wiki/OVMF)
- [Cloud Hypervisor edk2 fork](https://github.com/cloud-hypervisor/edk2)
- [Cloud Hypervisor edk2 releases](https://github.com/cloud-hypervisor/edk2/releases)
