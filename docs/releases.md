# Release Documentation

## Abstract

This document provides guidance to users, downstream maintainers and
any other consumers of the Cloud Hypervisor project, this document
describes the release process, release cadence, stability expectations and
related topics.

## Basic Terms

### Stability

For Cloud Hypervisor the following areas are subject to stability guarantees:

- [REST API](api.md#rest-api)
- [Command line options](api.md#command-line-interface)
- [Device Model](device_model.md)
- Device tree, device list, ACPI, Hyper-V enlightenments and any other
  features exposed to guest
- KVM compatibility
- Rust edition compatibility

This list is incomplete but this document serves as a best effort guide to stability
across releases.

### Experimental features

Experimental features are under active development and no guarantees are made about their stability.

List of experimental features:

- TDX
- vfio-user
- vDPA

### Security

Security fixes should be included in a new point release.

For security issues an advisory will be published via the GitHub security advisory process along with the release. Watching the project on GitHub will notify you of those issues.

## Releases

### Versioning

The versioning scheme uses `MAJOR.POINT` pattern:

- `MAJOR` can introduce incompatible changes along with support for new features. Changes to the [API](api.md#rest-api),
  [CLI options](api.md#command-line-interface) and [device model](device_model.md)
  require a notice at least 2 releases in advance for the actual change to take
  place.
- `POINT` contains bug fixes and/or security fixes.

### Major Release Cadence

Cloud Hypervisor is under active development. A new major release is issued approximately
every 6 weeks. Point releases are issued on demand, when important bug fixes are in
the queue. A major release would receive bug fixes for the next two cycles (~12 weeks)
and then be considered EOL.

```
+ - Active release support
E - EOL

        2021                2022                2023
         |    |    |    |    |    |    |    |    |
18.0     |    |    |  ++++++++E
19.0     |    |    |    |++++++++E
20.0     |    |    |    |   ++++++++E
21.0     |    |    |    |    | ++++++++E
22.0     |    |    |    |    |    +++++++++E
23.0     |    |    |    |    |    |  +++++++++E

```

### Major Release Stability Considerations

Snapshot/restore support is not compatible across `MAJOR` versions.
Live migration support is not compatible across `MAJOR` versions.

