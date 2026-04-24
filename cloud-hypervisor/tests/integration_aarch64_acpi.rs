// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
#![cfg(target_arch = "aarch64")]
use test_infra::*;

mod common;
use common::utils::*;

#[test]
fn test_simple_launch_acpi() {
    let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

    vec![Box::new(focal)].drain(..).for_each(|disk_config| {
        let guest = Guest::new(disk_config);

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", edk2_path().to_str().unwrap()])
            .default_disks()
            .default_net()
            .args(["--serial", "tty", "--console", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
            assert!(guest.get_total_memory().unwrap_or_default() > 400_000);
            assert_eq!(guest.get_pci_bridge_class().unwrap_or_default(), "0x060000");
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    });
}

#[test]
fn test_guest_numa_nodes_acpi() {
    _test_guest_numa_nodes(true);
}

#[test]
fn test_cpu_topology_421_acpi() {
    test_cpu_topology(4, 2, 1, true);
}

#[test]
fn test_cpu_topology_142_acpi() {
    test_cpu_topology(1, 4, 2, true);
}

#[test]
fn test_cpu_topology_262_acpi() {
    test_cpu_topology(2, 6, 2, true);
}

#[test]
fn test_power_button_acpi() {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = GuestFactory::new_regular_guest_factory()
        .create_guest(Box::new(disk_config))
        .with_kernel_path(edk2_path().to_str().unwrap());
    _test_power_button(&guest);
}

#[test]
fn test_virtio_iommu() {
    _test_virtio_iommu(true);
}
