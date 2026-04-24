// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
#![cfg(target_arch = "x86_64")]
use std::time::Duration;

use test_infra::*;

mod common;
use common::utils::*;
const NVIDIA_VFIO_DEVICE: &str = "/sys/bus/pci/devices/0002:00:01.0";

fn platform_cfg(iommufd: bool) -> String {
    if iommufd {
        "iommufd=on,vfio_p2p_dma=off".to_string()
    } else {
        "iommufd=off".to_string()
    }
}

fn test_nvidia_card_memory_hotplug(hotplug_method: &str, iommufd: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_VFIO_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", "boot=4"])
        .args([
            "--memory",
            format!("size=4G,hotplug_size=4G,hotplug_method={hotplug_method}").as_str(),
        ])
        .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
        .args(["--platform", &platform_cfg(iommufd)])
        .args(["--device", format!("path={NVIDIA_VFIO_DEVICE}").as_str()])
        .args(["--api-socket", &api_socket])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);

        // Verify the VFIO device works before memory hotplug
        guest.check_nvidia_gpu();

        guest.enable_memory_hotplug();

        // Add RAM to the VM
        let desired_ram = 6 << 30;
        resize_command(&api_socket, None, Some(desired_ram), None, None);
        assert!(wait_until(Duration::from_secs(5), || {
            guest.get_total_memory().unwrap_or_default() > 5_760_000
        }));
        assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);

        // Check the VFIO device works when RAM is increased to 6GiB.
        // After guest memory hotplug, the VMM must refresh VFIO/iommufd DMA
        // mappings for the passthrough GPU.
        assert!(wait_until(Duration::from_secs(10), || guest.check_nvidia_gpu()));
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[test]
fn test_nvidia_card_memory_hotplug_acpi() {
    test_nvidia_card_memory_hotplug("acpi", false);
}

#[test]
fn test_nvidia_card_memory_hotplug_virtio_mem() {
    test_nvidia_card_memory_hotplug("virtio-mem", false);
}

#[test]
fn test_iommufd_nvidia_card_memory_hotplug_acpi() {
    test_nvidia_card_memory_hotplug("acpi", true);
}

#[test]
fn test_iommufd_nvidia_card_memory_hotplug_virtio_mem() {
    test_nvidia_card_memory_hotplug("virtio-mem", true);
}

fn test_nvidia_card_pci_hotplug_common(iommufd: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_VFIO_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", "boot=4"])
        .args(["--memory", "size=1G"])
        .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
        .args(["--platform", &platform_cfg(iommufd)])
        .args(["--api-socket", &api_socket])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Hotplug the card to the VM
        let (cmd_success, cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-device",
            Some(format!("id=vfio0,path={NVIDIA_VFIO_DEVICE}").as_str()),
        );
        assert!(cmd_success);
        assert!(
            String::from_utf8_lossy(&cmd_output)
                .contains("{\"id\":\"vfio0\",\"bdf\":\"0000:00:06.0\"}")
        );

        // Check the VFIO device works after hotplug
        assert!(wait_until(Duration::from_secs(10), || guest.check_nvidia_gpu()));
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[test]
fn test_nvidia_card_pci_hotplug() {
    test_nvidia_card_pci_hotplug_common(false);
}

#[test]
fn test_iommufd_nvidia_card_pci_hotplug() {
    test_nvidia_card_pci_hotplug_common(true);
}

fn test_nvidia_card_reboot_common(iommufd: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_VFIO_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", "boot=4"])
        .args(["--memory", "size=1G"])
        .args(["--platform", &platform_cfg(iommufd)])
        .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
        .args([
            "--device",
            format!("path={NVIDIA_VFIO_DEVICE},iommu=on").as_str(),
        ])
        .args(["--api-socket", &api_socket])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check the VFIO device works after boot
        assert!(guest.check_nvidia_gpu());

        guest.reboot_linux(0);

        // Check the VFIO device works after reboot
        assert!(guest.check_nvidia_gpu());
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[test]
fn test_nvidia_card_reboot() {
    test_nvidia_card_reboot_common(false);
}

#[test]
fn test_iommufd_nvidia_card_reboot() {
    test_nvidia_card_reboot_common(true);
}

fn test_nvidia_card_iommu_address_width_common(iommufd: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_VFIO_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let platform = format!(
        "num_pci_segments=2,iommu_segments=1,iommu_address_width=42,{}",
        platform_cfg(iommufd)
    );

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", "boot=4"])
        .args(["--memory", "size=1G"])
        .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
        .args(["--device", format!("path={NVIDIA_VFIO_DEVICE}").as_str()])
        .args(["--platform", &platform])
        .args(["--api-socket", &api_socket])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert!(
            guest
                .ssh_command("sudo dmesg")
                .unwrap()
                .contains("input address: 42 bits")
        );

        // Check the VFIO device works after boot
        guest.check_nvidia_gpu();
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[test]
fn test_nvidia_card_iommu_address_width() {
    test_nvidia_card_iommu_address_width_common(false);
}

#[test]
fn test_iommufd_nvidia_card_iommu_address_width() {
    test_nvidia_card_iommu_address_width_common(true);
}

fn test_nvidia_guest_numa_generic_initiator_common(iommufd: bool) {
    // Skip test if VFIO device is not available or not ready
    if !std::path::Path::new(NVIDIA_VFIO_DEVICE).exists() {
        println!("SKIPPED: VFIO device {NVIDIA_VFIO_DEVICE} not found");
        return;
    }

    // Check if device is bound to vfio-pci driver
    let driver_path = format!("{NVIDIA_VFIO_DEVICE}/driver");
    if let Ok(driver) = std::fs::read_link(&driver_path) {
        let driver_name = driver.file_name().unwrap_or_default().to_string_lossy();
        if driver_name != "vfio-pci" {
            println!(
                "SKIPPED: VFIO device {NVIDIA_VFIO_DEVICE} bound to {driver_name}, not vfio-pci"
            );
            return;
        }
    } else {
        println!("SKIPPED: VFIO device {NVIDIA_VFIO_DEVICE} not bound to any driver");
        return;
    }

    let disk_config = UbuntuDiskConfig::new(JAMMY_VFIO_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    // x86_64: Direct kernel boot
    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", "boot=4"])
        .args(["--memory", "size=0"])
        .args(["--memory-zone", "id=mem0,size=1G", "id=mem1,size=1G"])
        .args([
            "--numa",
            "guest_numa_id=0,cpus=[0-1],distances=[1@20,2@25],memory_zones=mem0",
            "guest_numa_id=1,cpus=[2-3],distances=[0@20,2@30],memory_zones=mem1",
            "guest_numa_id=2,device_id=vfio0,distances=[0@25,1@30]",
        ])
        .args(["--platform", &platform_cfg(iommufd)])
        .args([
            "--device",
            &format!("id=vfio0,path={NVIDIA_VFIO_DEVICE},iommu=on"),
        ])
        .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .args(["--api-socket", &api_socket])
        .capture_output()
        .default_disks()
        .default_net()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Verify NUMA topology is correct
        guest.check_numa_common(
            Some(&[960_000, 960_000]),
            Some(&[&[0, 1], &[2, 3]]),
            Some(&["10 20 25", "20 10 30", "25 30 10"]),
        );

        // Verify Generic Initiator support is present
        // Linux kernel sets has_generic_initiator when it parses Type 5 SRAT entries
        let has_gi = guest
            .ssh_command("cat /sys/devices/system/node/has_generic_initiator 2>/dev/null || echo 0")
            .unwrap()
            .trim()
            .to_string();

        assert_eq!(
            has_gi, "2",
            "Generic Initiator support should be detected by kernel"
        );

        // Verify SRAT table contains Generic Initiator entry (Type 5)
        // We'll check that /sys/firmware/acpi/tables/SRAT exists and contains our entry
        let srat_check = guest
            .ssh_command("[ -f /sys/firmware/acpi/tables/SRAT ] && echo 'exists' || echo 'missing'")
            .unwrap()
            .trim()
            .to_string();

        assert_eq!(
            srat_check, "exists",
            "SRAT table should exist in guest firmware"
        );

        // Use hexdump to verify Type 5 entry is present
        // Type 5 (0x05) should appear in the SRAT table
        let srat_has_type5 = guest
            .ssh_command("sudo hexdump -C /sys/firmware/acpi/tables/SRAT | grep -q '05 20' && echo 'found' || echo 'not_found'")
            .unwrap()
            .trim()
            .to_string();

        assert_eq!(
            srat_has_type5, "found",
            "SRAT table should contain Generic Initiator Affinity Structure (Type 5, Length 0x20/32)"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[test]
fn test_nvidia_guest_numa_generic_initiator() {
    test_nvidia_guest_numa_generic_initiator_common(false);
}

#[test]
fn test_iommufd_nvidia_guest_numa_generic_initiator() {
    test_nvidia_guest_numa_generic_initiator_common(true);
}
