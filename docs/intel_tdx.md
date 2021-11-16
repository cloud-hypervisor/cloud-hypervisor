# Intel TDX

Intel® Trust Domain Extensions (Intel® TDX) is an Intel technology designed to
isolate virtual machines from the VMM, hypervisor and any other software on the
host platform.

For more information about TDX technical aspects, design and specification
please refer to the
[TDX Homepage](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html).

The required Linux changes for the host side can be found in the
[KVM TDX tree](https://github.com/intel/tdx/tree/kvm) while the changes for
the guest side can be found in the [Guest TDX tree](https://github.com/intel/tdx/tree/guest).

The TDVF firmware can be found in the
[EDK2 staging project](https://github.com/tianocore/edk2-staging/tree/TDVF).

## Cloud Hypervisor support

First, you must be running on a machine with TDX enabled in hardware, and
with the host OS compiled from the [KVM TDX tree](https://github.com/intel/tdx/tree/kvm).

Cloud Hypervisor can run TDX VM (Trust Domain) by loading the TDVF firmware,
which will then load the guest kernel from the image. The image must be custom
as it must include a kernel built from the [Guest TDX tree](https://github.com/intel/tdx/tree/guest).
The firmware can be built as follows:

```bash
git clone https://github.com/tianocore/edk2-staging.git
cd edk2-staging
git checkout origin/TDVF
git submodule update --init --recursive
make -C BaseTools
source ./edksetup.sh
build -p OvmfPkg/OvmfCh.dsc -a X64 -t GCC5 -b RELEASE
```

If debug logs are needed, here is the alternative command:

```bash
build -p OvmfPkg/OvmfCh.dsc -a X64 -t GCC5 -D DEBUG_ON_SERIAL_PORT=TRUE
```

On the Cloud Hypervisor side, all you need is to build the project with the
`tdx` feature enabled:

```bash
cargo build --features tdx
```

And run a TDX VM by providing the firmware previously built, along with the
guest image containing the TDX enlightened kernel. Assuming the guest kernel
command line contains `console=hvc0` (printing to the `virtio-console` device),
run Cloud Hypervisor as follows:

```bash
./cloud-hypervisor \
    --tdx firmware=edk2-staging/Build/OvmfCh/RELEASE_GCC5/FV/OVMF.fd \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs (assuming the
guest kernel command line contains `console=ttyS0`):

```bash
./cloud-hypervisor \
    --tdx firmware=edk2-staging/Build/OvmfCh/DEBUG_GCC5/FV/OVMF.fd \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img \
    --serial tty \
    --console off
```
