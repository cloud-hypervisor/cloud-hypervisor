# AMD SEV-SNP

### WARNING

This feature is currently only supported on MSHV.

AMD Secure Encrypted Virtualization & Secure Nested Paging (SEV-SNP) is an AMD
technology designed to add strong memory integrity protection to help prevent
malicious hypervisor-based attacks like data replay, memory-remapping and more
in order to create an isolated execution environment. Here are some useful
links:

- [SNP Homepage](https://docs.amd.com/v/u/en-US/amd-secure-encrypted-virtualization-solution-brief):
  more information about SEV-SNP technical aspects, design and specification.

## Cloud Hypervisor support

A machine with AMD SEV-SNP support which is enabled in the BIOS is required.

On the Cloud Hypervisor side, all you need is to build the project with the
`sev_snp` feature enabled:

```bash
cargo build --no-default-features --features "sev_snp"
```

**Note**
Please note that `sev_snp` cannot be enabled in conjunction with the `tdx` feature flag.

You can run a SEV-SNP VM using the following command:

```bash
./cloud-hypervisor \
     --platform sev_snp=on \
     --cpus boot=1 \
     --memory size=1G \
     --disk path=ubuntu.img
```

For more information related to Microsoft Hypervisor, please see [mshv.md](mshv.md)
