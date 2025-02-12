# AMD SEV-SNP

### WARNING

This feature is only currently supported on MSHV.

AMD Secure Encrypted Virtualization & Secure Nested Paging (SEV-SNP) is an AMD
technology designed to add strong memory integrity protection to help prevent
malicious hypervisor-based attacks like data replay, memory-remapping and more
in order to create an isolated execution environment. Here are some useful
links:

- [SNP Homepage](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/solution-briefs/amd-secure-encrypted-virtualization-solution-brief.pdf):
  more information about SEV-SNP technical aspects, design and specification.

## Cloud Hypervisor support

It is required to use a machine which has enabled support for AMD SEV-SNP in
the BIOS.

On the Cloud Hypervisor side, all you need is to build the project with the
`sev_snp` feature enabled:

```bash
cargo build --no-default-features --features "sev_snp"
```

**Note**
Please note that `sev_snp` cannot be enabled in conjunction with `tdx` feature flag.

You can run a SEV-SNP VM using the following command:

```bash
./cloud-hypervisor \
     --platform sev_snp=on \
     --cpus boot=1 \
     --memory size=1G \
     --disk path=ubuntu.img
```

For more information related to Microsoft Hypervisor please see [mshv.md](mshv.md)
