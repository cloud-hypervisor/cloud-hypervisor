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
     --disk path=ubuntu.img
```

For more information related to Microsoft Hypervisor, please see [mshv.md](mshv.md).
