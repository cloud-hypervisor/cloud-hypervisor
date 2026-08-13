# Intel TDX

Intel® Trust Domain Extensions (Intel® TDX) is an Intel technology designed to
isolate virtual machines from the VMM, hypervisor and any other software on the
host platform. Here are some useful links:

- [TDX Homepage](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html):
  more information about TDX technical aspects, design and specification

- [KVM TDX documentation](https://docs.kernel.org/virt/kvm/x86/intel-tdx.html):
  the host-side KVM ABI for TDX, which is part of the upstream Linux kernel
  (v6.16 and later)

- [TDX kernel documentation](https://docs.kernel.org/arch/x86/tdx.html): the
  host and guest kernel support for TDX, which is part of the upstream Linux
  kernel

- [EDK2 project](https://github.com/tianocore/edk2): the TDVF firmware

- [Confidential Containers project](https://github.com/confidential-containers/td-shim):
  the TDShim firmware

- [Intel TDX Enabling Guide](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/01/introduction/):
  Intel's official guide for enabling TDX, covering host and guest setup,
  building images, and running TDX guests

## Cloud Hypervisor support

It is required to use a machine with TDX enabled in hardware, running a host
kernel with TDX support. Host-side TDX support is part of the upstream Linux
kernel (v6.16 and later), so a recent distribution kernel or an upstream kernel
built with `CONFIG_INTEL_TDX_HOST=y` can be used. The host environment can also
be setup by following the [Intel TDX Enabling Guide](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/01/introduction/).

Cloud Hypervisor can run a TDX VM (Trust Domain) by loading a TD firmware ([TDVF](https://github.com/tianocore/edk2)),
which then loads the guest kernel from the image. The guest kernel must have
TDX guest support, which is also part of the upstream Linux kernel; recent
distributions ship such kernels, so a custom guest kernel is no longer required.
Cloud Hypervisor can also boot a TDX VM with direct kernel boot using [TDShim](https://github.com/confidential-containers/td-shim).

### TDVF

> **Note**
> TDVF (`OvmfPkg/IntelTdx`) is maintained in upstream edk2, so any recent edk2
> [stable release](https://github.com/tianocore/edk2/releases) can be used. The
> commands below use `edk2-stable202605` as an example.

The firmware can be built as follows:

```bash
sudo apt-get update
sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git

git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout edk2-stable202605
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

And run a TDX VM by providing the firmware previously built, along with a guest
image whose kernel has TDX guest support. Recent distribution cloud images
(such as RHEL 9/10, Ubuntu, or Fedora) already ship such kernels. If the guest
kernel is booted with `console=hvc0` in its boot parameters, it will print
guest kernel logs to the `virtio-console` device.

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware edk2/Build/IntelTdx/RELEASE_GCC5/FV/OVMF.fd \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs from the
firmware:

```bash
./cloud-hypervisor \
    --platform tdx=on \
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
direct kernel boot, which is useful for container use cases.

To build TDShim from source, it is required to install `Rust`, `NASM`,
and `LLVM` first. The TDShim can be built as follows:

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

If debug logs from the TDShim are needed, here is the alternative
command:

```bash
cargo image
```

And run a TDX VM by providing the firmware previously built, along with a guest
kernel that has upstream TDX guest support (shipped by recent distributions, or
built by following the [Intel TDX Enabling Guide](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/01/introduction/)).
The appropriate kernel boot options must be provided through the `--cmdline`
option as well.

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware td-shim/target/release/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda3 console=hvc0 rw" \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

And here is the alternative command when looking for debug logs from the
TDShim:

```bash
./cloud-hypervisor \
    --platform tdx=on \
    --firmware td-shim/target/debug/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda3 console=hvc0 rw" \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

### Remote attestation (GetQuote)

When a TD guest asks for a quote it issues the
`TDG.VP.VMCALL<GetQuote>` GHCI call, which traps out to Cloud Hypervisor. The
VMM forwards the embedded TD report to a Quote Generation Service (QGS) and
writes the returned quote back into the guest's shared buffer.

The QGS endpoint is configured through the `quote_generation_socket` platform
option. Mirroring QEMU's `SocketAddress`-typed `quote-generation-socket`, it
accepts a host Unix, `AF_VSOCK` or TCP socket using the following string forms:

- `<path>` or `unix:<path>` — host Unix socket (default when no scheme is given)
- `vsock:<cid>:<port>` — host `AF_VSOCK` socket
- `tcp:<host>:<port>` (or `inet:<host>:<port>`) — host TCP socket

```bash
./cloud-hypervisor \
    --platform tdx=on,quote_generation_socket=/var/run/tdx-qgs/qgs.socket \
    --firmware td-shim/target/release/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda3 console=hvc0 rw" \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

For example, a QGS reachable over vsock on the host would be configured with
`quote_generation_socket=vsock:2:4050`.

If `quote_generation_socket` is not set, GetQuote requests complete with the
GHCI `QGS_UNAVAILABLE` status. The transaction is handled synchronously on the
vCPU thread; TDs that rely on the asynchronous `SetupEventNotifyInterrupt`
completion interrupt are not yet supported.

## Measurement configuration registers

A TD carries three owner/configuration measurement registers that are baked
into its attestation report: `MRCONFIGID`, `MROWNER` and `MROWNERCONFIG`. Each
is a 384-bit (48-byte) SHA384 digest chosen by the tenant or platform owner.

They can be supplied through the matching `--platform` options as hex strings
of exactly 96 characters (48 bytes):

```bash
./cloud-hypervisor \
    --platform tdx=on,mrconfigid=<96-hex-chars>,mrowner=<96-hex-chars>,mrownerconfig=<96-hex-chars> \
    --firmware td-shim/target/release/final.bin \
    --kernel bzImage \
    --cmdline "root=/dev/vda3 console=hvc0 rw" \
    --cpus boot=1 \
    --memory size=1G \
    --disk path=tdx_guest_img
```

Any register left unset defaults to all zeros, preserving the previous
behavior.

