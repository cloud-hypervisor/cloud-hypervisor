# Testing

- [Testing](#testing)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [The dev\_cli.sh entry point](#the-dev_clish-entry-point)
    - [Global flags](#global-flags)
    - [Building](#building)
    - [Running tests](#running-tests)
    - [Argument passthrough](#argument-passthrough)
    - [Custom kernel and firmware](#custom-kernel-and-firmware)
  - [Unit tests](#unit-tests)
  - [Integration tests](#integration-tests)
    - [x86\_64](#x86_64)
    - [ARM64](#arm64)
    - [VFIO](#vfio)
    - [Windows guests](#windows-guests)
    - [Live migration](#live-migration)
    - [Rate limiter](#rate-limiter)
    - [Confidential VMs](#confidential-vms)
  - [Performance metrics](#performance-metrics)
  - [Code coverage](#code-coverage)
  - [CI workflows](#ci-workflows)

## Overview

All Cloud Hypervisor builds and tests run inside a Docker container to
provide a reproducible environment. The main entry point is
`scripts/dev_cli.sh`, which manages the container lifecycle and
forwards arguments to the appropriate test scripts.

The container image is published at
`ghcr.io/cloud-hypervisor/cloud-hypervisor` and is automatically
pulled on first use. A local build of the container can be triggered
with `scripts/dev_cli.sh build-container` or by passing the `--local`
flag.

Test workloads (guest images, kernels, firmware) are stored on the host
under `$HOME/workloads` and bind-mounted into the container at
`/root/workloads`. Most test scripts download missing workloads
automatically on first run.

## Prerequisites

A working Docker (or Podman) installation and access to `/dev/kvm`
(or `/dev/mshv` for Microsoft Hypervisor tests) are required. The
host must be running Linux on x86_64 or aarch64.

```shell
# Verify KVM is available
ls -l /dev/kvm
```

The container image bundles all build dependencies. No Rust toolchain
is needed on the host.

## The dev_cli.sh entry point

```
scripts/dev_cli.sh [flags] <command> [<command args>]
```

### Global flags

| Flag      | Description                                      |
|-----------|--------------------------------------------------|
| `--local` | Build and use a local container image instead of pulling from the registry. |

### Building

```shell
scripts/dev_cli.sh build [--debug|--release] [--libc musl|gnu] \
    [--hypervisor kvm|mshv] [--features <features>] \
    [--volumes /host:/ctr#...] [-- <cargo args>]
```

| Flag           | Default | Description                              |
|----------------|---------|------------------------------------------|
| `--debug`      | yes     | Build debug binaries.                    |
| `--release`    |         | Build release binaries.                  |
| `--libc`       | `gnu`   | C library to link against (`musl`/`gnu`).|
| `--hypervisor` | `kvm`   | Hypervisor backend (`kvm`/`mshv`).       |
| `--features`   |         | Additional cargo features.               |
| `--volumes`    |         | Extra host volumes (`/a:/a#/b:/b`).      |
| `--runtime`    | `docker`| Container runtime (`docker`/`podman`).   |

Arguments after `--` are forwarded directly to `cargo build`.

### Running tests

```shell
scripts/dev_cli.sh tests [<test type>] [--libc musl|gnu] \
    [--hypervisor kvm|mshv] [--volumes /host:/ctr#...] \
    [-- <script args> [-- <binary args>]]
```

**Test type flags:**

| Flag                           | Description                        |
|--------------------------------|------------------------------------|
| `--unit`                       | Run unit tests.                    |
| `--integration`                | Run integration tests.             |
| `--integration-vfio`           | Run VFIO integration tests.        |
| `--integration-windows`        | Run Windows guest integration tests.|
| `--integration-live-migration` | Run live migration integration tests.|
| `--integration-rate-limiter`   | Run rate limiter integration tests. |
| `--integration-cvm`            | Run confidential VM integration tests.|
| `--metrics`                    | Generate performance metrics.      |
| `--coverage`                   | Generate code coverage.            |
| `--all`                        | Run both unit and integration tests.|

**Configuration flags:**

| Flag           | Default | Description                              |
|----------------|---------|------------------------------------------|
| `--libc`       | `gnu`   | C library to link against (`musl`/`gnu`).|
| `--hypervisor` | `kvm`   | Hypervisor backend (`kvm`/`mshv`).       |
| `--volumes`    |         | Extra host volumes (`/a:/a#/b:/b`).      |

### Argument passthrough

The `--` separator creates layers of argument forwarding:

```
dev_cli.sh tests <flags> -- <script args> -- <binary args>
```

1. Everything before the first `--` is consumed by `dev_cli.sh`.
2. Everything between the first and second `--` is forwarded to the
   test script (e.g., `run_integration_tests_x86_64.sh`).
3. Everything after the second `--` is forwarded to the test binary
   itself (e.g., `performance-metrics`).

The test scripts accept the following common arguments via
`process_common_args()` in `scripts/test-util.sh`:

| Argument              | Description                                  |
|-----------------------|----------------------------------------------|
| `--hypervisor kvm\|mshv` | Select hypervisor (also passed by dev_cli.sh). |
| `--test-filter <name>`| Run only tests matching the filter.           |
| `--test-exclude <name>`| Exclude tests matching the pattern.          |
| `--build-guest-kernel`| Build the guest kernel from source instead of downloading a prebuilt binary. |

**Example — run a single integration test:**

```shell
scripts/dev_cli.sh tests --integration -- --test-filter test_boot_from_virtio_pmem
```

**Example — run metrics excluding micro-benchmarks:**

```shell
scripts/dev_cli.sh tests --metrics -- --test-exclude micro_ -- --report-file /root/workloads/metrics.json
```

### Custom kernel and firmware

The following environment variables allow overriding the default guest
kernel or firmware binaries. Each variable is independent; set any
combination without affecting the others.

| Variable      | Description                                |
|---------------|--------------------------------------------|
| `CH_CUSTOM_KERNEL`   | Path to a custom `vmlinux` (x86_64) or `Image` (aarch64) kernel binary. |
| `CH_CUSTOM_FIRMWARE` | Path to a custom `hypervisor-fw` firmware binary. |
| `CH_CUSTOM_OVMF`     | Path to a custom OVMF binary (`CLOUDHV.fd` on x86_64, `CLOUDHV_EFI.fd` on aarch64). |

The paths refer to locations on the **host**. Before launching the
Docker container, `dev_cli.sh` copies the referenced files into
`$HOME/workloads` at the default names the test scripts expect
(e.g., `vmlinux-x86_64`, `hypervisor-fw`, `CLOUDHV.fd`). Because
the workloads directory is bind-mounted into the container, the
existing download-if-missing guards inside the test scripts
automatically skip the network fetch.

```shell
# Use a custom kernel for integration tests
CH_CUSTOM_KERNEL=/path/to/vmlinux scripts/dev_cli.sh tests --integration

# Override all three
CH_CUSTOM_KERNEL=/path/to/vmlinux \
CH_CUSTOM_FIRMWARE=/path/to/hypervisor-fw \
CH_CUSTOM_OVMF=/path/to/CLOUDHV.fd \
    scripts/dev_cli.sh tests --integration
```

## Unit tests

```shell
scripts/dev_cli.sh tests --unit [--libc musl|gnu] [--hypervisor kvm|mshv]
```

Unit tests run `cargo test` on the entire workspace in release mode:

```
cargo test --lib --bins --target <target> --release --workspace
cargo test --doc --target <target> --release --workspace
```

The container is _not_ fully privileged. It receives `--device
/dev/kvm` (or `/dev/mshv`), `--device /dev/net/tun`, and `--cap-add
net_admin` so that tests requiring a hypervisor device or TAP
interfaces can run.

When the hypervisor is `mshv`, the feature flag `--features mshv` is
passed to cargo. On x86_64, the `tdx` feature is also enabled.

## Integration tests

All integration test containers run with `--privileged` and full
access to `/dev`. Workloads are bind-mounted from the host.

Test scripts use `cargo nextest run` with the `--release` profile.
Tests are grouped by module name filter (e.g., `common_parallel`,
`common_sequential`). Most groups support automatic retries (default
3).

### x86_64

```shell
scripts/dev_cli.sh tests --integration [--libc musl|gnu]
```

Runs `scripts/run_integration_tests_x86_64.sh`. The script
automatically downloads and prepares all required workloads:

- **Kernel:** `vmlinux-x86_64` (prebuilt from the
  `ch-release-v6.16.9-20251112` tag, or built from source with
  `--build-guest-kernel`).
- **Firmware:** `hypervisor-fw` (rust-hypervisor-firmware v0.5.0).
- **OVMF:** `CLOUDHV.fd`.
- **Guest images:** Ubuntu Focal and Jammy cloud images in multiple
  formats (raw, qcow2, compressed, backing-file variants).
- **Alpine:** Minirootfs and initramfs for lightweight boot tests.
- **virtiofsd:** Built from source for virtio-fs tests.

**System tuning applied inside the container:**

- KSM (Kernel Same-page Merging) is enabled.
- 2 MiB hugepages are allocated for DPDK/VDPA tests.
- The open file descriptor limit is raised to 4096.

**Test groups executed:**

| Group               | Parallelism            | Retries |
|----------------------|------------------------|---------|
| `common_parallel`    | `nproc / 4` threads   | 3       |
| `common_sequential`  | 1 thread              | 3       |
| `dbus_api`           | `nproc / 4` threads   | 3       |
| `fw_cfg`             | `nproc / 4` threads   | 3       |
| `ivshmem`            | `nproc / 4` threads   | 3       |

The `dbus_api`, `fw_cfg`, and `ivshmem` groups are each built with
their respective cargo feature enabled before running.

### ARM64

```shell
scripts/dev_cli.sh tests --integration --libc musl
```

Runs `scripts/run_integration_tests_aarch64.sh`. The workload setup
mirrors x86_64 with aarch64-specific images:

- **Kernel:** `Image-arm64`.
- **OVMF:** `CLOUDHV_EFI.fd`.
- **Guest images:** Focal and Jammy aarch64 cloud images.

**Test groups executed:**

| Group                        | Parallelism          | Retries |
|------------------------------|----------------------|---------|
| `common_parallel`            | `nproc / 4` threads | 3       |
| `common_sequential`          | 1 thread            | 3       |
| `aarch64_acpi`               | `nproc / 4` threads | 3       |
| `live_migration_parallel`    | `nproc / 4` threads | 3       |
| `live_migration_sequential`  | 1 thread            | 3       |
| `dbus_api`                   | `nproc / 4` threads | 3       |
| `fw_cfg`                     | `nproc / 4` threads | 3       |
| `ivshmem`                    | `nproc / 4` threads | 3       |

### VFIO

```shell
scripts/dev_cli.sh tests --integration-vfio
```

Runs `scripts/run_integration_tests_vfio.sh`. Requires dedicated
hardware with an Nvidia GPU (Tesla T4) for VFIO passthrough testing.

**Test groups executed (single-threaded):**

| Group               | Description                               |
|----------------------|-------------------------------------------|
| `vfio::test_nvidia`  | Legacy VFIO with container/group interface.|
| `vfio::test_iommufd` | VFIO with cdev interface via iommufd.      |

### Windows guests

```shell
scripts/dev_cli.sh tests --integration-windows [--libc musl|gnu]
```

Runs the architecture-appropriate script:
- x86_64: `scripts/run_integration_tests_windows_x86_64.sh`
- aarch64: `scripts/run_integration_tests_windows_aarch64.sh`

Both scripts require a pre-downloaded Windows guest image in the
workloads directory. Device mapper snapshots are created to allow
concurrent test runs without corrupting the base image.

**Workloads:**

| Architecture | Image                                        | Firmware         |
|--------------|----------------------------------------------|------------------|
| x86_64       | `windows-server-2025-amd64-1.raw`            | `CLOUDHV.fd`     |
| aarch64      | `windows-11-iot-enterprise-aarch64.raw`       | `CLOUDHV_EFI.fd` |

**Test group:** `windows` (single-threaded, retries 3).

### Live migration

```shell
scripts/dev_cli.sh tests --integration-live-migration [--libc musl|gnu]
```

Runs `scripts/run_integration_tests_live_migration.sh`. Downloads a
static Cloud Hypervisor binary from a previous release (default
v39.0) to test migration compatibility across versions. The release
version can be overridden with the `MIGRATABLE_VERSION` environment
variable.

**Test groups executed:**

| Group                        | Parallelism          | Retries |
|------------------------------|----------------------|---------|
| `live_migration_parallel`    | `nproc / 4` threads | 3       |
| `live_migration_sequential`  | 1 thread            | 3       |

### Rate limiter

```shell
scripts/dev_cli.sh tests --integration-rate-limiter
```

Runs `scripts/run_integration_tests_rate_limiter.sh`. Downloads Jammy
guest images and a prebuilt kernel.

**Test group:** `rate_limiter` (single-threaded, no retries).

### Confidential VMs

```shell
scripts/dev_cli.sh tests --integration-cvm [--hypervisor mshv]
```

Runs `scripts/run_integration_tests_cvm.sh`. Builds with `--features
mshv,igvm,sev_snp` and requires IGVM files to be present at
`/usr/share/cloud-hypervisor/cvm` on the host.

**Test group:** `common_cvm` (`nproc / 4` threads, retries 3).

## Performance metrics

```shell
scripts/dev_cli.sh tests --metrics [-- <script args> [-- <binary args>]]
```

Runs `scripts/run_metrics.sh`, which builds and executes the
`performance-metrics` binary. The binary produces a JSON report with
boot time, throughput, and latency measurements.

Useful arguments:

```shell
# Exclude micro-benchmarks and write results to a file
scripts/dev_cli.sh tests --metrics -- --test-exclude micro_ -- --report-file /root/workloads/metrics.json
```

## Code coverage

```shell
scripts/dev_cli.sh tests --coverage
```

Runs `scripts/run_coverage.sh`, which instruments the build with
LLVM source-based code coverage, executes the test suite via
`dbus-run-session`, and produces either an LCOV or HTML report. See
[coverage.md](coverage.md) for details on collecting and viewing
coverage data.

## CI workflows

The following GitHub Actions workflows exercise the test
infrastructure on every pull request or merge-group event:

| Workflow                     | Tests run                                    | Runner            |
|------------------------------|----------------------------------------------|-------------------|
| `build.yaml`                 | Cargo build with multiple feature/toolchain combinations. | `ubuntu-latest`  |
| `quality.yaml`               | Clippy (stable + beta), bisectability check, typo scan. | `ubuntu-latest`  |
| `integration-x86-64.yaml`    | `--unit` + `--integration` + `--integration-live-migration` (gnu, musl). | `garm-jammy-16`  |
| `integration-arm64.yaml`     | `--unit` + `--integration` + `--integration-windows` (musl). | `bookworm-arm64` |
| `integration-vfio.yaml`      | `--integration-vfio`.                        | `vfio-nvidia`    |
| `integration-windows.yaml`   | `--integration-windows` (gnu, musl).         | `garm-jammy-16`  |
| `integration-rate-limiter.yaml` | `--integration-rate-limiter`.              | `bare-metal-9950x` |
| `mshv-integration.yaml`      | `--hypervisor mshv --integration` on an Azure VM. | Azure `Standard_D16s_v5` |
| `integration-metrics.yaml`   | `--metrics` (runs on push to `main` only).   | `bare-metal-9950x` |
