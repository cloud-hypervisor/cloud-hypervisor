# Maintainers

<!-- KEEP THIS IN SYNC WITH CODEOWNERS -->

People with merge permission are listed in the
[maintainers team](https://github.com/orgs/cloud-hypervisor/teams/cloud-hypervisor-maintainers).

In this document, "maintainer" has a broader meaning: it also includes
significant, trusted contributors who may not have merge permission. Maintainers
may focus on particular components or subsystems; the sections below identify
those domain experts.

## Leadership

The people listed in the
[maintainers team](https://github.com/orgs/cloud-hypervisor/teams/cloud-hypervisor-maintainers)
form the leadership of the project, with @rbradford taking the lead. They are,
however, in close contact with other major contributors and adopters of Cloud
Hypervisor.

## Domain Experts

The list below covers the project's most important components and identifies the
people who focus on them. It is not exhaustive or intended to assign exclusive
ownership for every component.

### General / Everything

- @likebreath
- @rbradford
- @sboeuf
- @phip1611

### Hypervisor Backends

- **KVM**
  - @likebreath
  - @phip1611
  - @rbradford

- **MSHV**
  - @jinankjain
  - @liuw
  - @russell-islam
  - @up2wing

### Architectures

- **ARM**: Shared responsibility across all maintainers
- **x86_64**: Shared responsibility across all maintainers
- **RISC-V**
  - @RuoqingHe

### Features & Subsystems

- **Confidential Computing**:
  - **SEV-SNP**
    - @jinankjain
    - @rhakobyan
    - @russell-islam
  - **TDX**
    <!-- - TODO Cyberus Technology will take over soon: Oliver, Leander -->
- **CPU Profiles**
  - @olivereanderson
- **Live Migration**
  - @phip1611
  - @likebreath
- **VFIO & vhost-user**
  - @alyssais
  - @sboeuf
- **Block and QCOW2**
  - @weltling
