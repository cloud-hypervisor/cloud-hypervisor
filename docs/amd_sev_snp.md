# AMD SEV-SNP

AMD Secure Encrypted Virtualization & Secure Nested Paging (SEV-SNP) is an AMD
technology designed to add strong memory integrity protection to help prevent
malicious hypervisor-based attacks like data replay, memory-remapping and more
in order to create an isolated execution environment. Here are some useful
links:

- [SNP Homepage](https://docs.amd.com/v/u/en-US/amd-secure-encrypted-virtualization-solution-brief):
  more information about SEV-SNP technical aspects, design and specification.

## Cloud Hypervisor support

A machine with AMD SEV-SNP support which is enabled in the BIOS is required.

On the Cloud Hypervisor side, build the project with the `sev_snp` and `igvm`
and the hypervisor backend you want to use. For the MSHV SEV-SNP build:

```bash
cargo build --no-default-features --features "mshv,sev_snp,igvm"
```

Change `mshv` to `kvm` for the KVM backend. You can enable both at the same
time.

**Note**
Please note that `sev_snp` cannot be enabled in conjunction with the `tdx` feature flag.

SEV-SNP is also supported on KVM with an IGVM stage0 image and a guest kernel
provided through `fw_cfg`. Build that configuration with:

```bash
cargo build --no-default-features --features "kvm,igvm,sev_snp,fw_cfg"
```

You can run a SEV-SNP VM using the following command:

```bash
./cloud-hypervisor \
     --platform sev_snp=on \
     --cpus boot=1 \
     --memory size=1G \
     --disk path=ubuntu.img,image_type=raw
```

For more information related to Microsoft Hypervisor, please see [mshv.md](mshv.md).

**Limitations**
Note that Cloud Hypervisor does not support the following features with SEV-SNP:
- Memory & CPU hotplug
- Huge Pages (HugeTLB), and on KVM a memory zone file on hugetlbfs
- Virtual IOMMU
- pvmemcontrol (on KVM)

**Device DMA**
On KVM, VFIO, vfio-user and vDPA devices only get the pages the guest
shares with the host mapped for DMA. When the guest converts a page back
to private, it is unmapped from every device before the VMM discards
its shared backing. Each shared page is its own 4 KiB mapping, which counts
against the backend's mapping limit:
- Legacy VFIO container (`iommufd=off`): the `vfio_iommu_type1` module's
  `dma_entry_limit` parameter, 65535 by default (256 MiB of shared memory).
- vDPA: since Linux 7.2, the `max_iotlb_entries` parameter of the
  `vhost_vdpa` module and of the parent driver (e.g. `mlx5_vdpa`), 2048
  by default (8 MiB of shared memory), which most guests exceed. `0` is
  not accepted as unlimited by `vhost_vdpa`, so raise it to a large value
  instead, for example `vhost_vdpa.max_iotlb_entries=1048576`.
- vfio-user: the number of DMA mappings the server accepts.

A guest sharing more memory than the VFIO or vDPA limit allows is
stopped. The vfio-user client does not check the server's reply to a
DMA mapping request yet, so a mapping refused by the server goes
unnoticed.

vhost-user backends must not pin guest memory, for instance by mapping it
into an IOMMU of their own: the VMM is not told about their mappings.
