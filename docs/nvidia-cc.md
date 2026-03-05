# NVIDIA Confidential Computing GPU Passthrough

Pass an NVIDIA GPU in Confidential Computing (CC) mode through to a
Cloud Hypervisor SEV-SNP virtual machine. GPU memory (HBM) is encrypted,
PCIe bus traffic is encrypted, and attestation happens entirely inside the
guest. The VMM is explicitly untrusted.

Requires: AMD SEV-SNP on the host (see [amd_sev_snp.md](amd_sev_snp.md)),
NVIDIA H100/H200/Blackwell GPU, and the `sev_snp` + `fw_cfg` features enabled
at build time.

## Quick Start

```bash
GPU_BDF="0000:41:00.0"  # lspci -d 10de: to find yours

cloud-hypervisor \
    --platform sev_snp=on,num_pci_segments=2,iommu_segments=[1] \
    --cpus boot=16 \
    --memory size=64G \
    --firmware /path/to/OVMF.fd \
    --disk path=/path/to/guest.raw \
    --serial tty \
    --console off \
    --device path=/sys/bus/pci/devices/$GPU_BDF,iommu=on,pci_segment=1 \
    --fw-cfg-config items=[name=opt/ovmf/X-PciMmio64Mb,string=262144]
```

If the GPU BAR fails to map, the `fw-cfg-config` line is almost certainly why.
Read on.

## Why fw_cfg Matters

H100 exposes an 80 GiB HBM BAR. OVMF defaults to a tiny MMIO64 window
(varies by build, often 32 GiB or less). The BAR does not fit. OVMF silently
fails to assign it and the guest sees no GPU.

The fix: tell OVMF to allocate 256 GiB of MMIO64 space via the `fw_cfg`
device. QEMU has supported this for years with `-fw_cfg name=...,string=...`.
This PR adds the same `string` item support to Cloud Hypervisor:

```
--fw-cfg-config items=[name=opt/ovmf/X-PciMmio64Mb,string=262144]
```

`262144` = 256 GiB in MiB. This is the value NVIDIA uses in their reference
scripts (see [nvtrust](https://github.com/NVIDIA/nvtrust)).

You can mix file and string items:

```
--fw-cfg-config items=[name=opt/ovmf/X-PciMmio64Mb,string=262144:name=opt/org.test/data,file=/tmp/data.bin]
```

## Host Setup

### 1. Find the GPU

```bash
lspci -d 10de: -nn
# Example output:
# 41:00.0 3D controller [0302]: NVIDIA Corporation H100 [2330] (rev a1)
```

Note the BDF (`41:00.0`) and check the IOMMU group:

```bash
ls /sys/bus/pci/devices/0000:41:00.0/iommu_group/devices/
```

If multiple devices are in the same IOMMU group, you must bind all of them
to `vfio-pci` and pass them all to the VM. See [vfio.md](vfio.md) for details.

### 2. Enable CC Mode

CC mode is a persistent GPU setting — it survives reboots but requires a GPU
reset to take effect. Use NVIDIA's
[gpu-admin-tools](https://github.com/NVIDIA/gpu-admin-tools):

```bash
git clone https://github.com/NVIDIA/gpu-admin-tools.git
cd gpu-admin-tools

# Enable CC mode (requires root, triggers GPU reset)
sudo python3 nvidia_gpu_tools.py --devices gpus --set-cc-mode=on \
    --reset-after-cc-mode-switch

# Verify
sudo python3 nvidia_gpu_tools.py --devices gpus --query-cc-mode
# Expected: "CC mode: on"
```

For development and profiling, use `devtools` mode instead of `on`:

| Mode       | HBM Encryption | PCIe Encryption | Profiling |
|------------|---------------|-----------------|-----------|
| `off`      | No            | No              | Yes       |
| `on`       | AES-XTS       | Yes             | No        |
| `devtools` | AES-XTS       | Yes             | Yes       |

### 3. Bind to vfio-pci

```bash
GPU_BDF="0000:41:00.0"

# Load VFIO modules
sudo modprobe vfio-pci

# Unbind from nvidia driver (skip if not currently bound)
echo "$GPU_BDF" | sudo tee /sys/bus/pci/devices/$GPU_BDF/driver/unbind 2>/dev/null

# Bind to vfio-pci
echo "vfio-pci" | sudo tee /sys/bus/pci/devices/$GPU_BDF/driver_override
echo "$GPU_BDF" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind

# Verify
ls -la /dev/vfio/
```

## Guest Requirements

- Linux kernel 6.x+ with `CONFIG_AMD_MEM_ENCRYPT=y` and
  `CONFIG_SEV_GUEST=y`
- NVIDIA datacenter driver **550 TRD or later** (the driver must be
  CC-capable; consumer drivers will not work)
- OVMF firmware built with SEV-SNP support

## Guest-Side Verification

### Check the GPU is Visible

```bash
lspci -d 10de:
nvidia-smi
```

If `nvidia-smi` shows the GPU but reports "ERR!" for temperature/power, the
driver loaded but CC attestation has not completed — this is normal before
attestation.

### Run Attestation

Attestation proves the GPU hardware identity and CC mode state to the guest.
It runs over PCIe DOE/SPDM between the NVIDIA driver and the GPU's hardware
root of trust. The hypervisor is not involved.

```bash
pip install nv-attestation-sdk

python3 -c "
from nv_attestation_sdk import attestation
client = attestation.Attestation()
client.set_name('gpu-cc-verify')
client.add_verifier(
    attestation.Devices.GPU,
    attestation.Environment.LOCAL,
    '', ''
)
result = client.attest()
print('Attestation passed' if result else 'Attestation FAILED')
"
```

The SDK verifies the GPU's certificate chain back to NVIDIA's root CA and
checks firmware measurements against published Reference Integrity Manifests
(RIMs). If attestation fails, check that:

1. GPU firmware (VBIOS) is up to date
2. The driver version is in the
   [NVIDIA CC Compatibility Matrix](https://docs.nvidia.com/confidential-computing/)
3. CC mode is actually `on` (not `off` or `devtools` if you need production
   attestation)

## How It Works (For the Curious)

```
 Guest VM (SEV-SNP encrypted memory)
 ┌─────────────────────────────────────────┐
 │  CUDA App ─── NVIDIA Driver             │
 │                    │                     │
 │              Attestation SDK             │
 │                    │ SPDM over PCIe DOE  │
 ��────────────────────┼─────────────────────┘
                      │
      VFIO passthrough (VMM is untrusted)
                      │
 ┌────────────────────┴─────────────────────┐
 │         NVIDIA GPU (CC mode)             │
 │  HBM: AES-XTS encrypted                 │
 │  PCIe: bus-level encryption              │
 │  SPDM responder in hardware root of trust│
 └──────────────────────────────────────────┘
```

No SPDM code runs in the VMM. The DOE PCIe extended capability (0x002e)
passes through unfiltered in Cloud Hypervisor's VFIO implementation, so
the guest driver talks directly to the GPU hardware.

DMA between the guest and GPU works transparently via the kernel's
SWIOTLB bounce buffers and IOMMU. No VMM changes are needed for the
SEV-SNP + VFIO DMA path when using KVM.

## Troubleshooting

**GPU BAR not mapped / guest sees no GPU**
: The MMIO64 window is too small. Add:
  `--fw-cfg-config items=[name=opt/ovmf/X-PciMmio64Mb,string=262144]`
  and verify OVMF firmware supports `fw_cfg` (most SEV-SNP OVMF builds do).

**`nvidia-smi` not detecting GPU**
: Check `lspci -d 10de:` first. If the device is listed but the driver
  did not load, check `dmesg | grep -i nvidia` for errors. Ensure you are
  using a CC-capable driver (550+ TRD). Consumer/gaming drivers do not
  support CC mode.

**Attestation fails**
: Update GPU VBIOS and driver to versions listed in the
  [NVIDIA CC Compatibility Matrix](https://docs.nvidia.com/confidential-computing/).
  Check that CC mode is `on`, not `off`.

**DMA errors / device timeouts**
: Ensure the GPU is on an IOMMU-enabled PCI segment. Both `iommu=on` on
  the `--device` and the segment listed in `iommu_segments` on
  `--platform` are required.

**"fw_cfg: FwCfgItem requires either 'file' or 'string'"**
: Each `fw_cfg` item needs exactly one of `file=<path>` or
  `string=<value>`. You cannot specify both or neither.

## QEMU Equivalent

For reference, the equivalent QEMU command (from
[nvtrust](https://github.com/NVIDIA/nvtrust)):

```bash
qemu-system-x86_64 \
    -machine confidential-guest-support=sev0 \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
    -device pcie-root-port,id=pci.1,bus=pcie.0 \
    -device vfio-pci,host=0000:41:00.0,bus=pci.1 \
    -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=262144
```

## References

- [NVIDIA Confidential Computing Docs](https://docs.nvidia.com/confidential-computing/)
- [nvtrust (attestation + reference scripts)](https://github.com/NVIDIA/nvtrust)
- [gpu-admin-tools (CC mode)](https://github.com/NVIDIA/gpu-admin-tools)
- [Cloud Hypervisor VFIO](vfio.md)
- [Cloud Hypervisor AMD SEV-SNP](amd_sev_snp.md)
- [Cloud Hypervisor fw_cfg](fw_cfg.md)
