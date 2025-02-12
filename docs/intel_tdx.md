# Intel TDX

Intel® Trust Domain Extensions (Intel® TDX) is an Intel technology designed to
isolate virtual machines from the VMM, hypervisor and any other software on the
host platform. Here are some useful links:

- [TDX Homepage](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html):
  more information about TDX technical aspects, design and specification

- [KVM TDX tree](https://github.com/intel/tdx/tree/kvm): the required
  Linux kernel changes for the host side

- [Guest TDX tree](https://github.com/intel/tdx/tree/guest): the Linux
  kernel changes for the guest side

- [EDK2 project](https://github.com/tianocore/edk2): the TDVF firmware

- [Confidential Containers project](https://github.com/confidential-containers/td-shim):
  the TDShim firmware

- [TDX Linux](https://github.com/intel/tdx-linux): a collection of tools
  and scripts to setup TDX environment for testing purpose (such as
  installing required packages on the host, creating guest images, and
  building the custom Linux kernel for TDX host and guest)

## Cloud Hypervisor support

It is required to use a machine with TDX enabled in hardware and
with the host OS compiled from the [KVM TDX tree](https://github.com/intel/tdx/tree/kvm).
The host environment can also be setup with the [TDX Linux](https://github.com/intel/tdx-linux).

Cloud Hypervisor can run TDX VM (Trust Domain) by loading a TD firmware ([TDVF](https://github.com/tianocore/edk2)),
which will then load the guest kernel from the image. The image must be custom
as it must include a kernel built from the [Guest TDX tree](https://github.com/intel/tdx/tree/guest).
Cloud Hypervisor can also boot a TDX VM with direct kernel boot using [TDshim](https://github.com/confidential-containers/td-shim).
The custom Linux kernel for the guest can be built with the [TDX Linux](https://github.com/intel/tdx-linux).

### TDVF

> **Note**
> The latest version of TDVF being tested is [_13b9773_](https://github.com/tianocore/edk2/commit/13b97736c876919b9786055829caaa4fa46984b7).

The firmware can be built as follows:

```bash
sudo apt-get update
sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git

git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout 13b97736c876919b9786055829caaa4fa46984b7
source ./edksetup.sh
git submodule update --init --recursive
make -C BaseTools -j `nproc`
build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC5 -b RELEASE
```

If debug logs are needed, here is the alternative command:

```bash
build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC5 -D DEBUG_ON_SERIAL_PORT=TRUE
```

On the Cloud Hypervisor side, all you need is to build the project with the
`tdx` feature enabled:

```bash
cargo build --features tdx
```

And run a TDX VM by providing the firmware previously built, along with the
guest image containing the TDX enlightened kernel. The latest image
`td-guest-rhel8.5.raw` contains `console=hvc0` on the kernel boot parameters,
meaning it will be printing guest kernel logs to the `virtio-console` device.

```bash
./cloud-hypervisor \
    --platform tdx=on
    --firmware edk2/Build/IntelTdx/RELEASE_GCC5/FV/OVMF.fd \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs from the
firmware:

```bash
./cloud-hypervisor \
    --platform tdx=on
    --firmware edk2/Build/IntelTdx/DEBUG_GCC5/FV/OVMF.fd \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img \
    --serial file=/tmp/ch_serial \
    --console tty
```

### TDShim

> **Note**
> The latest version of TDShim being tested is [_v0.8.0_](https://github.com/confidential-containers/td-shim/releases/tag/v0.8.0).

This is a lightweight version of the TDVF, written in Rust and designed for
direct kernel boot, which is useful for containers use cases.

To build TDShim from source, it is required to install `Rust`, `NASM`,
and `LLVM` first. The TDshim can be build as follows:

```bash
git clone https://github.com/confidential-containers/td-shim
cd td-shim
git checkout v0.8.0
cargo install cargo-xbuild
export CC=clang
export AR=llvm-ar
export CC_x86_64_unknown_none=clang
export AR_x86_64_unknown_none=llvm-ar
git submodule update --init --recursive
./sh_script/preparation.sh
cargo image --release
```

If debug logs from the TDShim is needed, here are the alternative
commands:

```bash
cargo image
```

And run a TDX VM by providing the firmware previously built, along with a guest
kernel built from the [Guest TDX tree](https://github.com/intel/tdx/tree/guest)
or the [TDX Linux](https://github.com/intel/tdx-linux).
The appropriate kernel boot options must be provided through the `--cmdline`
option as well.

```bash
./cloud-hypervisor \
    --platform tdx=on
    --firmware td-shim/target/release/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda3 console=hvc0 rw"
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs from the
TDShim:

```bash
./cloud-hypervisor \
    --platform tdx=on
    --firmware td-shim/target/debug/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda3 console=hvc0 rw"
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

### Guest kernel limitations

#### Serial ports disabled

The latest guest kernel that can be found in the latest image
`td-guest-rhel8.5.raw` disabled the support for serial ports. This means adding
`console=ttyS0` will have no effect and will not print any log from the guest.

#### PCI hotplug through ACPI

Unless you run the guest kernel with the parameter `tdx_disable_filter`, ACPI
devices responsible for handling PCI hotplug (PCI hotplug controller, PCI
Express Bus and Generic Event Device) will not be allowed, therefore the
corresponding drivers will not be loaded and the PCI hotplug feature will not
be supported.
