# Microsoft Hypervisor

The Microsoft Hypervisor is a Type 1 hypervisor which runs on x64 and ARM64 architectures. As the foundation of the Hyper-V virtualization stack, it runs millions of Linux and Windows guests in Azure and on-premises deployments. It supports nested virtualization, and security features like AMD's SEV-SNP. It also supports various features in Windows such as [Device guard and confidential guard](https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419), and [WSL2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-faq)

Since 2020, Microsoft has been releasing open-source components to support Linux running as root partition on the Microsoft Hypervisor.

    1. Kernel patches to support Linux booting as root partition
    2. A Linux kernel driver exposing an IOCTL interface for managing guest partitions, via a device node - /dev/mshv
    3. Rust bindings and IOCTL wrappers
    4. IGVM related crates

## Components

The following components are related to MSHV support with Cloud-Hypervisor:

* [igvm-crates](https://github.com/microsoft/igvm) : Parsing IGVM file

* [mshv-crates](https://github.com/rust-vmm/mshv) : Rust crates to interact with kernel module (/dev/mshv)

* [igvm-tooling](https://github.com/microsoft/igvm-tooling) : Tool to generate IGVM file

## IGVM

Independent Guest Virtual Machine (IGVM) file format.The format specification can be found in the igvm_defs crate, with a Rust implementation of the binary format in the igvm crate.

The IGVM file format is designed to encapsulate all information required to launch a virtual machine on any given virtualization stack, with support for different isolation technologies such as AMD SEV-SNP and Intel TDX.

At a conceptual level, this file format is a set of commands created by the tool that generated the file, used by the loader to construct the initial guest state. The file format also contains measurement information that the underlying platform will use to confirm that the file was loaded correctly and signed by the appropriate authorities.

Cloud Hypervisor can be built using igvm feature flag along with mshv and/or sev-snp. IGVM only works with MSHV.

## SEV-SNP

AMD's [Secure Encrypted Virtualization (SEV)](https://www.amd.com/en/developer/sev.html) and extensions such as Secure Nested Paging (SEV-SNP) encrypt memory and restrict access to a guest VM's memory and registers, securing it against a compromised hypervisor or VMM. They utilize the Platform Security Processor (PSP) to store keys and encrypt/decrypt the data. Microsoft has been continuously adding/improving support for SEV-SNP on Microsoft Hyper-V. Cloud-Hypervisor can be built with the sev_snp feature including mshv and igvm feature.

## Use Cases

Cloud Hypervisor can be built to run on an MSHV root partition by enabling the mshv feature, e.g.:

```cargo build --locked --all --all-targets --no-default-features --tests --examples --features mshv```

Cloud Hypervisor on MSHV can boot Linux guests using an IGVM file. IGVM feature depends on mshv for running legacy VMs.e.g.:

```cargo build --locked --all --all-targets --no-default-features --tests --examples --features igvm```

For running confidential VMs on mshv, you will only need to enable sev_snp, it requires and enables mshv and igvm automatically, eg.:

```cargo build --locked --all --all-targets --no-default-features --tests --examples --features sev_snp```
