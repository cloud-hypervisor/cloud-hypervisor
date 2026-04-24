// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
// When enabling the `mshv` feature, we skip quite some tests and
// hence have known dead-code. This annotation silences dead-code
// related warnings for our quality workflow to pass.
#![allow(dead_code)]
use std::fs::{File, OpenOptions, copy};
use std::io::{Read, Seek};
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::string::String;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

use block::ImageType;
use test_infra::*;
use vmm_sys_util::tempdir::TempDir;
use vmm_sys_util::tempfile::TempFile;
use wait_timeout::ChildExt;

mod common;
use common::tests_wrappers::*;
use common::utils::*;

macro_rules! basic_regular_guest {
    ($image_name:expr) => {{
        let disk_config = UbuntuDiskConfig::new($image_name.to_string());
        GuestFactory::new_regular_guest_factory().create_guest(Box::new(disk_config))
    }};
}

mod common_parallel {
    use std::io::{self, SeekFrom};
    use std::process::Command;

    use test_infra::GuestFactory;

    use crate::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_focal_hypervisor_fw() {
        let guest = basic_regular_guest!(FOCAL_IMAGE_NAME)
            .with_kernel(fw_path(FwType::RustHypervisorFirmware));
        _test_simple_launch(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_focal_ovmf() {
        let guest = basic_regular_guest!(FOCAL_IMAGE_NAME).with_kernel(fw_path(FwType::Ovmf));
        _test_simple_launch(&guest);
    }

    #[test]
    fn test_multi_cpu() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_multi_cpu(&guest);
    }

    #[test]
    #[cfg_attr(target_arch = "x86_64", should_panic)]
    fn test_cpu_topology_421() {
        test_cpu_topology(4, 2, 1, false);
    }

    #[test]
    fn test_cpu_topology_142() {
        test_cpu_topology(1, 4, 2, false);
    }

    #[test]
    fn test_cpu_topology_262() {
        test_cpu_topology(2, 6, 2, false);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    #[cfg(not(feature = "mshv"))]
    fn test_cpu_physical_bits() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let max_phys_bits: u8 = 36;
        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", &format!("max_phys_bits={max_phys_bits}")])
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(
                    guest
                        .ssh_command("lscpu | grep \"Address sizes:\" | cut -f 2 -d \":\" | sed \"s# *##\" | cut -f 1 -d \" \"")
                        .unwrap()
                        .trim()
                        .parse::<u8>()
                        .unwrap_or(max_phys_bits + 1) <= max_phys_bits,
                );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    fn _test_nested_virtualization(nested: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config)).with_nested(nested);
        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let expected = if nested { "yes" } else { "no" };
            assert_eq!(
                guest
                    .ssh_command("test -c /dev/kvm && echo yes || echo no")
                    .unwrap()
                    .trim(),
                expected
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_nested_virtualization_on() {
        _test_nested_virtualization(true);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_nested_virtualization_off() {
        _test_nested_virtualization(false);
    }

    #[test]
    fn test_cpu_affinity() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_cpu_affinity(&guest);
    }

    #[test]
    fn test_virtio_queue_affinity() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(4);
        _test_virtio_queue_affinity(&guest);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_large_vm() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut cmd = GuestCommand::new(&guest);
        cmd.args(["--cpus", "boot=48"])
            .args(["--memory", "size=5120M"])
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(["--serial", "tty"])
            .args(["--console", "off"])
            .capture_output()
            .default_disks()
            .default_net();

        let mut child = cmd.spawn().unwrap();

        guest.wait_vm_boot().unwrap();

        let r = std::panic::catch_unwind(|| {
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 48);
            assert_eq!(
                guest
                    .ssh_command("lscpu | grep \"On-line\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                    .unwrap()
                    .trim(),
                "0-47"
            );

            assert!(guest.get_total_memory().unwrap_or_default() > 5_000_000);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_huge_memory() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut cmd = GuestCommand::new(&guest);
        cmd.default_cpus()
            .args(["--memory", "size=128G"])
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .capture_output()
            .default_disks()
            .default_net();

        let mut child = cmd.spawn().unwrap();

        guest.wait_vm_boot().unwrap();

        let r = std::panic::catch_unwind(|| {
            assert!(guest.get_total_memory().unwrap_or_default() > 128_000_000);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_power_button() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_power_button(&guest);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See #7456
    fn test_user_defined_memory_regions() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .args(["--memory", "size=0,hotplug_method=virtio-mem"])
            .args([
                "--memory-zone",
                "id=mem0,size=1G,hotplug_size=2G",
                "id=mem1,size=1G,shared=on",
                "id=mem2,size=1G,host_numa_node=0,hotplug_size=2G",
            ])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(["--api-socket", &api_socket])
            .capture_output()
            .default_disks()
            .default_net()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(guest.get_total_memory().unwrap_or_default() > 2_880_000);

            guest.enable_memory_hotplug();

            resize_zone_command(&api_socket, "mem0", "3G");
            assert!(wait_until(Duration::from_secs(5), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 4_800_000));
            resize_zone_command(&api_socket, "mem2", "3G");
            assert!(wait_until(Duration::from_secs(5), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 6_720_000));
            resize_zone_command(&api_socket, "mem0", "2G");
            assert!(wait_until(Duration::from_secs(5), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 5_760_000));
            resize_zone_command(&api_socket, "mem2", "2G");
            assert!(wait_until(Duration::from_secs(5), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 4_800_000));

            guest.reboot_linux(0);

            // Check the amount of RAM after reboot
            assert!(guest.get_total_memory().unwrap_or_default() > 4_800_000);
            assert!(guest.get_total_memory().unwrap_or_default() < 5_760_000);

            // Check if we can still resize down to the initial 'boot'size
            resize_zone_command(&api_socket, "mem0", "1G");
            assert!(wait_until(Duration::from_secs(5), || guest
                .get_total_memory()
                .unwrap_or_default()
                < 4_800_000));
            resize_zone_command(&api_socket, "mem2", "1G");
            assert!(wait_until(Duration::from_secs(5), || guest
                .get_total_memory()
                .unwrap_or_default()
                < 3_840_000));
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See #7456
    fn test_guest_numa_nodes() {
        _test_guest_numa_nodes(false);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_iommu_segments() {
        let focal_image = FOCAL_IMAGE_NAME.to_string();
        let disk_config = UbuntuDiskConfig::new(focal_image);
        let guest = Guest::new(Box::new(disk_config));

        // Prepare another disk file for the virtio-disk device
        let test_disk_path = String::from(
            guest
                .tmp_dir
                .as_path()
                .join("test-disk.raw")
                .to_str()
                .unwrap(),
        );
        assert!(
            exec_host_command_status(format!("truncate {test_disk_path} -s 4M").as_str()).success()
        );
        assert!(exec_host_command_status(format!("mkfs.ext4 {test_disk_path}").as_str()).success());

        let api_socket = temp_api_path(&guest.tmp_dir);
        let mut cmd = GuestCommand::new(&guest);

        cmd.default_cpus()
            .args(["--api-socket", &api_socket])
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--platform",
                &format!("num_pci_segments={MAX_NUM_PCI_SEGMENTS},iommu_segments=[1]"),
            ])
            .default_disks()
            .capture_output()
            .default_net();

        let mut child = cmd.spawn().unwrap();

        guest.wait_vm_boot().unwrap();

        let r = std::panic::catch_unwind(|| {
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-disk",
                Some(
                    format!(
                        "path={},id=test0,pci_segment=1,iommu=on",
                        test_disk_path.as_str()
                    )
                    .as_str(),
                ),
            );
            assert!(cmd_success);
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0001:00:01.0\"}")
            );

            // Check IOMMU setup
            assert!(
                guest
                    .does_device_vendor_pair_match("0x1057", "0x1af4")
                    .unwrap_or_default()
            );
            assert!(
                guest
                    .ssh_command("ls /sys/kernel/iommu_groups/*/devices")
                    .unwrap()
                    .contains("0001:00:01.0")
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_pci_msi() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_pci_msi(&guest);
    }

    #[test]
    fn test_virtio_net_ctrl_queue() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_net_ctrl_queue(&guest);
    }

    #[test]
    fn test_pci_multiple_segments() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_pci_multiple_segments(&guest, MAX_NUM_PCI_SEGMENTS, 15u16);
    }

    #[test]
    fn test_pci_multiple_segments_numa_node() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);
        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        // Prepare another disk file for the virtio-disk device
        let test_disk_path = String::from(
            guest
                .tmp_dir
                .as_path()
                .join("test-disk.raw")
                .to_str()
                .unwrap(),
        );
        assert!(
            exec_host_command_status(format!("truncate {test_disk_path} -s 4M").as_str()).success()
        );
        assert!(exec_host_command_status(format!("mkfs.ext4 {test_disk_path}").as_str()).success());
        const TEST_DISK_NODE: u16 = 1;

        let mut child = GuestCommand::new(&guest)
            .args(["--platform", "num_pci_segments=2"])
            .args(["--cpus", "boot=2"])
            .args(["--memory", "size=0"])
            .args(["--memory-zone", "id=mem0,size=256M", "id=mem1,size=256M"])
            .args([
                "--numa",
                "guest_numa_id=0,cpus=[0],distances=[1@20],memory_zones=mem0,pci_segments=[0]",
                "guest_numa_id=1,cpus=[1],distances=[0@20],memory_zones=mem1,pci_segments=[1]",
            ])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(["--api-socket", &api_socket])
            .capture_output()
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={test_disk_path},pci_segment={TEST_DISK_NODE}").as_str(),
            ])
            .default_net()
            .spawn()
            .unwrap();

        let cmd = "cat /sys/block/vdc/device/../numa_node";

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command(cmd)
                    .unwrap()
                    .trim()
                    .parse::<u16>()
                    .unwrap_or_default(),
                TEST_DISK_NODE
            );

            // Each PNP0A08 host bridge in the DSDT must expose a unique
            // _UID matching its PCI segment id. Linux surfaces the
            // evaluated _UID via /sys/bus/acpi/devices/PNP0A08:*/uid.
            // This test uses firmware boot on aarch64, so ACPI is
            // available on both supported architectures.
            let mut uids: Vec<u16> = guest
                .ssh_command("cat /sys/bus/acpi/devices/PNP0A08:*/uid")
                .unwrap()
                .lines()
                .filter_map(|l| l.trim().parse::<u16>().ok())
                .collect();
            uids.sort();
            assert_eq!(uids, vec![0u16, 1u16]);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_direct_kernel_boot() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_direct_kernel_boot(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_direct_kernel_boot_bzimage() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let mut kernel_path = direct_kernel_boot_path();
        // Replace the default kernel with the bzImage.
        kernel_path.pop();
        kernel_path.push("bzImage-x86_64");

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
            assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

            let grep_cmd = "grep -c PCI-MSI /proc/interrupts";
            assert_eq!(
                guest
                    .ssh_command(grep_cmd)
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                12
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_virtio_block_io_uring() {
        let guest =
            make_virtio_block_guest(&GuestFactory::new_regular_guest_factory(), FOCAL_IMAGE_NAME);
        _test_virtio_block(&guest, false, true, false, false, ImageType::Raw);
    }

    #[test]
    fn test_virtio_block_aio() {
        let guest =
            make_virtio_block_guest(&GuestFactory::new_regular_guest_factory(), FOCAL_IMAGE_NAME)
                .with_cpu(4);
        _test_virtio_block(&guest, true, false, false, false, ImageType::Raw);
    }

    #[test]
    fn test_virtio_block_sync() {
        let guest =
            make_virtio_block_guest(&GuestFactory::new_regular_guest_factory(), FOCAL_IMAGE_NAME)
                .with_cpu(4);
        _test_virtio_block(&guest, true, true, false, false, ImageType::Raw);
    }

    #[test]
    fn test_compute_file_checksum_empty() {
        let mut reader = io::Cursor::new(vec![]);
        let checksum = compute_file_checksum(&mut reader, 0);
        assert_eq!(checksum, 5381);
    }

    #[test]
    fn test_compute_file_checksum_small() {
        let data = b"hello world";
        let mut reader = io::Cursor::new(data);
        let checksum = compute_file_checksum(&mut reader, data.len() as u64);
        assert_eq!(checksum, 894552257);
    }

    #[test]
    fn test_compute_file_checksum_same_data() {
        let data = b"test data 123";
        let mut reader1 = io::Cursor::new(data);
        let mut reader2 = io::Cursor::new(data);
        let checksum1 = compute_file_checksum(&mut reader1, data.len() as u64);
        let checksum2 = compute_file_checksum(&mut reader2, data.len() as u64);
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_compute_file_checksum_different_data() {
        let data1 = b"data1";
        let data2 = b"data2";
        let mut reader1 = io::Cursor::new(data1);
        let mut reader2 = io::Cursor::new(data2);
        let checksum1 = compute_file_checksum(&mut reader1, data1.len() as u64);
        let checksum2 = compute_file_checksum(&mut reader2, data2.len() as u64);
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_compute_file_checksum_large_data() {
        let size = 20 * 1024 * 1024;
        let data = vec![0xABu8; size];
        let mut reader = io::Cursor::new(data);
        let checksum = compute_file_checksum(&mut reader, size as u64);
        // Should only read first 16MB
        assert!(checksum != 5381);

        // Verify only 16MB was read
        let position = reader.position();
        assert_eq!(position, 16 * 1024 * 1024);
    }

    #[test]
    fn test_virtio_block_qcow2() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = GuestFactory::new_regular_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);
        _test_virtio_block(&guest, false, false, true, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_zlib() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2_ZLIB.to_string());
        let guest = GuestFactory::new_regular_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);
        _test_virtio_block(&guest, false, false, true, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_zstd() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_regular_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_ZSTD,
        );
        _test_virtio_block(&guest, false, false, true, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_backing_zstd_file() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_regular_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_BACKING_ZSTD_FILE,
        );
        _test_virtio_block(&guest, false, false, true, true, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_backing_uncompressed_file() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_regular_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_BACKING_UNCOMPRESSED_FILE,
        );
        _test_virtio_block(&guest, false, false, true, true, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_backing_raw_file() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_regular_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_BACKING_RAW_FILE,
        );
        _test_virtio_block(&guest, false, false, true, true, ImageType::Qcow2);
    }

    /// Configuration for QCOW2 multiqueue test image setup
    enum QcowTestImageConfig {
        /// Simple QCOW2 image with given size (e.g., "256M")
        Simple(&'static str),
        /// QCOW2 overlay with backing file
        WithBacking,
    }

    /// Helper to run QCOW2 multiqueue stress tests with shared setup/teardown.
    ///
    /// Creates a VM with multiple virtio queues on the test disk, then runs the
    /// provided test closure. Handles VM lifecycle and consistency checks.
    fn run_multiqueue_qcow2_test<F>(image_config: &QcowTestImageConfig, test_fn: F)
    where
        F: FnOnce(&Guest) + std::panic::UnwindSafe,
    {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_image_path = guest.tmp_dir.as_path().join("test.qcow2");

        // Create test image based on configuration and capture backing checksum if applicable
        let initial_backing_checksum = match *image_config {
            QcowTestImageConfig::Simple(size) => {
                Command::new("qemu-img")
                    .arg("create")
                    .args(["-f", "qcow2"])
                    .arg(test_image_path.to_str().unwrap())
                    .arg(size)
                    .output()
                    .expect("Failed to create QCOW2 test image");
                None
            }
            QcowTestImageConfig::WithBacking => {
                let backing_path = guest.tmp_dir.as_path().join("backing.qcow2");
                Command::new("qemu-img")
                    .arg("create")
                    .args(["-f", "qcow2"])
                    .arg(backing_path.to_str().unwrap())
                    .arg("256M")
                    .output()
                    .expect("Failed to create backing QCOW2");

                Command::new("qemu-img")
                    .arg("create")
                    .args(["-f", "qcow2"])
                    .args(["-b", backing_path.to_str().unwrap()])
                    .args(["-F", "qcow2"])
                    .arg(test_image_path.to_str().unwrap())
                    .output()
                    .expect("Failed to create overlay QCOW2");

                compute_backing_checksum(&test_image_path)
            }
        };

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=8"])
            .args(["--memory", "size=1024M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                &format!(
                    "path={},num_queues=8",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                ),
                &format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                ),
                &format!(
                    "path={},num_queues=8,backing_files={},image_type=qcow2",
                    test_image_path.to_str().unwrap(),
                    if initial_backing_checksum.is_some() {
                        "on"
                    } else {
                        "off"
                    },
                ),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            test_fn(&guest);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);

        disk_check_consistency(
            guest.disk_config.disk(DiskType::OperatingSystem).unwrap(),
            None,
        );
        disk_check_consistency(&test_image_path, initial_backing_checksum);
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_writes() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("256M"), |guest| {
            assert_eq!(
                guest
                    .ssh_command("ls -ll /sys/block/vdc/mq | grep ^d | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                8,
                "Expected 8 queues on vdc"
            );

            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount /dev/vdc /mnt/test")
                .expect("Failed to mount disk");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        sudo dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=32 conv=fsync & \
                    done; wait",
                )
                .expect("Failed to write files in parallel");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/file* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                8,
                "Expected 8 files to be created"
            );

            guest
                .ssh_command("sudo rm -f /mnt/test/file*")
                .expect("Failed to remove files");

            // Do another round of heavy parallel I/O
            guest
                .ssh_command(
                    "for i in $(seq 1 16); do \
                        sudo dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=16 conv=fsync & \
                    done; wait",
                )
                .expect("Failed to write files in second round");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/file* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                16,
                "Expected 16 files after second round"
            );

            guest
                .ssh_command("sudo umount /mnt/test")
                .expect("Failed to unmount");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_mixed_rw() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("512M"), |guest| {
            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount /dev/vdc /mnt/test")
                .expect("Failed to mount disk");

            guest
                .ssh_command(
                    "sudo dd if=/dev/urandom of=/mnt/test/readfile bs=1M count=64 conv=fsync",
                )
                .expect("Failed to create initial file");

            guest
                .ssh_command(
                    "for i in $(seq 1 4); do \
                        sudo dd if=/mnt/test/readfile of=/dev/null bs=64K & \
                        sudo dd if=/dev/urandom of=/mnt/test/writefile$i bs=1M count=32 conv=fsync & \
                    done; wait",
                )
                .expect("Failed mixed read/write workload");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/writefile* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4,
                "Expected 4 write files"
            );

            guest
                .ssh_command(
                    "for i in $(seq 1 4); do \
                        sudo dd if=/mnt/test/writefile$i of=/dev/null bs=64K & \
                        sudo dd if=/dev/urandom of=/mnt/test/newfile$i bs=1M count=16 conv=fsync & \
                    done; wait",
                )
                .expect("Failed second mixed workload");

            guest
                .ssh_command("sudo umount /mnt/test")
                .expect("Failed to unmount");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_backing() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::WithBacking, |guest| {
            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount /dev/vdc /mnt/test")
                .expect("Failed to mount disk");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        sudo dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=16 conv=fsync & \
                    done; wait",
                )
                .expect("Failed to write files");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        sudo dd if=/mnt/test/file$i of=/dev/null bs=64K & \
                        sudo dd if=/dev/urandom of=/mnt/test/new$i bs=1M count=8 conv=fsync & \
                    done; wait",
                )
                .expect("Failed mixed backing/overlay workload");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/new* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                8,
                "Expected 8 new files"
            );

            guest
                .ssh_command("sudo umount /mnt/test")
                .expect("Failed to unmount");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_random_4k() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("256M"), |guest| {
            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        sudo dd if=/dev/urandom of=/dev/vdc bs=4K count=1000 seek=$((RANDOM % 60000)) conv=notrunc & \
                    done; wait",
                )
                .expect("Failed random 4K writes round 1");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        sudo dd if=/dev/urandom of=/dev/vdc bs=4K count=1000 seek=$((RANDOM % 60000)) conv=notrunc & \
                    done; wait",
                )
                .expect("Failed random 4K writes round 2");

            guest
                .ssh_command(
                    "for i in $(seq 1 4); do \
                        sudo dd if=/dev/vdc of=/dev/null bs=4K count=500 skip=$((RANDOM % 60000)) & \
                        sudo dd if=/dev/urandom of=/dev/vdc bs=4K count=500 seek=$((RANDOM % 60000)) conv=notrunc & \
                    done; wait",
                )
                .expect("Failed mixed random I/O");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_fsync() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("256M"), |guest| {
            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount /dev/vdc /mnt/test")
                .expect("Failed to mount disk");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        (for j in $(seq 1 100); do \
                            echo \"data$j\" | sudo tee /mnt/test/file${i}_$j > /dev/null && sudo sync; \
                        done) & \
                    done; wait",
                )
                .expect("Failed fsync storm round 1");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/file* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                800,
                "Expected 800 files (8 processes x 100 files)"
            );

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        (for j in $(seq 1 50); do \
                            sudo dd if=/dev/urandom of=/mnt/test/dd${i}_$j bs=4K count=1 conv=fsync 2>/dev/null; \
                        done) & \
                    done; wait",
                )
                .expect("Failed fsync storm round 2");

            guest
                .ssh_command("sudo umount /mnt/test")
                .expect("Failed to unmount");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_metadata() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("256M"), |guest| {
            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount /dev/vdc /mnt/test")
                .expect("Failed to mount disk");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        (for j in $(seq 1 50); do \
                            sudo mkdir -p /mnt/test/dir$i/subdir$j; \
                        done) & \
                    done; wait",
                )
                .expect("Failed parallel mkdir");

            let dir_count: u32 = guest
                .ssh_command("find /mnt/test -type d | wc -l")
                .expect("Failed to count directories")
                .trim()
                .parse()
                .unwrap_or(0);
            assert!(
                dir_count >= 400,
                "Expected at least 400 directories, got {dir_count}"
            );

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \
                        (for j in $(seq 1 100); do \
                            sudo touch /mnt/test/dir$i/file$j; \
                        done) & \
                    done; wait",
                )
                .expect("Failed parallel touch");

            let file_count: u32 = guest
                .ssh_command("find /mnt/test -type f | wc -l")
                .expect("Failed to count files")
                .trim()
                .parse()
                .unwrap_or(0);
            assert!(
                file_count >= 400,
                "Expected at least 400 files, got {file_count}"
            );

            guest
                .ssh_command(
                    "for i in $(seq 1 4); do \
                        sudo rm -rf /mnt/test/dir$i & \
                        (for j in $(seq 1 50); do \
                            sudo touch /mnt/test/newfile${i}_$j; \
                        done) & \
                    done; wait",
                )
                .expect("Failed parallel rm + touch");

            guest
                .ssh_command(
                    "for i in $(seq 5 8); do \
                        (for j in $(seq 1 25); do \
                            sudo mv /mnt/test/dir$i/file$j /mnt/test/dir$i/renamed$j 2>/dev/null || true; \
                        done) & \
                    done; wait",
                )
                .expect("Failed parallel rename");

            guest
                .ssh_command("sync && sudo umount /mnt/test")
                .expect("Failed to unmount");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_discard_mount() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("256M"), |guest| {
            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");

            // Mount with discard option to enable automatic TRIM/DISCARD
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount -o discard /dev/vdc /mnt/test")
                .expect("Failed to mount disk with discard option");

            guest
                .ssh_command(
                    "for i in $(seq 1 4); do \n\
                        sudo dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=32 conv=fsync & \n\
                    done; wait",
                )
                .expect("Failed to write files in parallel");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/file* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4,
                "Expected 4 files to be created"
            );

            guest
                .ssh_command("sudo rm -f /mnt/test/file*")
                .expect("Failed to remove files");

            guest
                .ssh_command("sudo fstrim -v /mnt/test")
                .expect("fstrim failed - DISCARD not working");

            guest
                .ssh_command(
                    "for i in $(seq 1 8); do \n\
                        sudo dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=16 conv=fsync & \n\
                    done; wait",
                )
                .expect("Failed to write files in second round");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/file* | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                8,
                "Expected 8 files after second round"
            );

            guest
                .ssh_command("sudo umount /mnt/test")
                .expect("Failed to unmount");
        });
    }
    #[test]
    fn test_virtio_block_qcow2_multiqueue_wide_writes() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("1G"), |guest| {
            // Scattered write pattern - write to widely separated offsets in parallel.
            // This should initiate many L2 table allocations simultaneously across different queues.
            guest
            .ssh_command(
                "for i in $(seq 0 7); do \n\
                    offset=$((i * 128)) \n\
                    sudo dd if=/dev/urandom of=/dev/vdc bs=1M count=16 seek=$offset conv=notrunc,fsync & \n\
                done; wait",
            )
            .expect("Failed to write sparse pattern in parallel");

            // Write known patterns to the same sparse locations
            guest
            .ssh_command(
                "for i in $(seq 0 7); do \n\
                    offset=$((i * 128)) \n\
                    sudo dd if=/dev/zero of=/dev/vdc bs=1M count=8 seek=$offset conv=notrunc,fsync & \n\
                done; wait",
            )
            .expect("Failed second sparse write pattern");

            // Even more aggressive sparse writes with smaller chunks but more of them
            guest
            .ssh_command(
                "for i in $(seq 0 15); do \n\
                    offset=$((i * 64)) \n\
                    sudo dd if=/dev/urandom of=/dev/vdc bs=1M count=2 seek=$offset conv=notrunc,fsync & \n\
                done; wait",
            )
            .expect("Failed third sparse write pattern");

            guest
                .ssh_command("sudo dd if=/dev/vdc of=/dev/null bs=1M count=64")
                .expect("Failed to read back data after sparse writes");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_multiqueue_discard_stress() {
        run_multiqueue_qcow2_test(&QcowTestImageConfig::Simple("512M"), |guest| {
            guest
                .ssh_command("sudo mkfs.ext4 -F /dev/vdc")
                .expect("Failed to format disk");
            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount -o discard /dev/vdc /mnt/test")
                .expect("Failed to mount disk with discard option");

            // Round 1: Start background writes while simultaneously doing DISCARD operations
            // This stresses refcount table locking - writes increment refs, discard decrements
            guest
                .ssh_command(
                    "for i in $(seq 1 4); do \n\
                        sudo dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=32 & \n\
                    done",
                )
                .expect("Failed to start background writes");

            guest
                .ssh_command(
                    "for i in $(seq 5 8); do \n\
                        sudo dd if=/dev/urandom of=/mnt/test/temp$i bs=1M count=16 conv=fsync \n\
                        sudo rm -f /mnt/test/temp$i & \n\
                    done; \n\
                    wait; \n\
                    sudo fstrim -v /mnt/test",
                )
                .expect("Failed to do parallel write-delete-discard");

            guest
                .ssh_command("wait")
                .expect("Failed to wait for background writes");

            assert_eq!(
                guest
                    .ssh_command("ls /mnt/test/file* 2>/dev/null | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4,
                "Expected 4 files after round 1"
            );

            // Round 2: More aggressive - 8 parallel writes with simultaneous blkdiscard on raw device
            guest
                .ssh_command("sudo umount /mnt/test")
                .expect("Failed to unmount");

            guest
                .ssh_command(
                    "for i in $(seq 0 7); do \n\
                        offset=$((i * 64)) \n\
                        sudo dd if=/dev/urandom of=/dev/vdc bs=1M count=4 seek=$offset conv=notrunc,fsync & \n\
                    done; wait",
                )
                .expect("Failed sparse writes");

            // Now discard half the regions while writing to the other half
            guest
                .ssh_command(
                    "for i in $(seq 0 3); do \n\
                        offset=$((i * 64 * 1024 * 1024)) \n\
                        sudo blkdiscard -o $offset -l $((4 * 1024 * 1024)) /dev/vdc & \n\
                    done; \n\
                    for i in $(seq 4 7); do \n\
                        offset=$((i * 64)) \n\
                        sudo dd if=/dev/zero of=/dev/vdc bs=1M count=4 seek=$offset conv=notrunc,fsync & \n\
                    done; wait",
                )
                .expect("Failed parallel discard and write stress test");

            guest
                .ssh_command("sudo dd if=/dev/vdc of=/dev/null bs=1M count=128")
                .expect("Failed to read back data after discard stress");
        });
    }

    #[test]
    fn test_virtio_block_qcow2_uefi_direct_io() {
        // Regression test for #8007.
        // Place the QCOW2 OS image on a 4096 byte sector filesystem so
        // O_DIRECT forces 4096 byte alignment on all I/O buffers.
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = edk2_path();

        let mut workloads_path = dirs::home_dir().unwrap();
        workloads_path.push("workloads");
        let img_dir = TempDir::new_in(workloads_path.as_path()).unwrap();
        let fs_img_path = img_dir.as_path().join("fs_4ksec.img");

        assert!(
            exec_host_command_output(&format!("truncate -s 4G {}", fs_img_path.to_str().unwrap()))
                .status
                .success(),
            "truncate failed"
        );

        let loop_dev_path = create_loop_device(fs_img_path.to_str().unwrap(), 4096, 5);

        assert!(
            exec_host_command_output(&format!("mkfs.ext4 -q {loop_dev_path}"))
                .status
                .success(),
            "mkfs.ext4 failed"
        );

        let mnt_dir = img_dir.as_path().join("mnt");
        fs::create_dir_all(&mnt_dir).unwrap();
        assert!(
            exec_host_command_output(&format!(
                "mount {} {}",
                &loop_dev_path,
                mnt_dir.to_str().unwrap()
            ))
            .status
            .success(),
            "mount failed"
        );

        let src_qcow2 = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();
        let dest_qcow2 = mnt_dir.join("os.qcow2");
        assert!(
            exec_host_command_output(&format!(
                "cp {} {}",
                &src_qcow2,
                dest_qcow2.to_str().unwrap()
            ))
            .status
            .success(),
            "cp failed"
        );

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--disk",
                &format!(
                    "path={},direct=on,image_type=qcow2",
                    dest_qcow2.to_str().unwrap()
                ),
                &format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                ),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        let _ = exec_host_command_output(&format!("umount {}", mnt_dir.to_str().unwrap()));
        let _ = exec_host_command_output(&format!("losetup -d {loop_dev_path}"));

        handle_child_output(r, &output);
    }

    #[test]
    fn test_virtio_block_qcow2_dirty_bit_unclean_shutdown() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_image_path = guest.tmp_dir.as_path().join("test-dirty.qcow2");
        let original_image = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();

        copy(original_image, &test_image_path).expect("Failed to copy qcow2 image");

        assert_eq!(
            check_dirty_flag(&test_image_path).expect("Failed to check dirty flag"),
            Some(false),
            "Image should start with dirty bit cleared"
        );

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                &format!("path={}", test_image_path.to_str().unwrap()),
                &format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                ),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                check_dirty_flag(&test_image_path).expect("Failed to check dirty flag"),
                Some(true),
                "Dirty bit should be set while VM is running"
            );
        });

        if r.is_err() {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);
            return;
        }

        // Simulate unclean shutdown with SIGKILL
        let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let _ = child.wait();

        assert_eq!(
            check_dirty_flag(&test_image_path).expect("Failed to check dirty flag"),
            Some(true),
            "Dirty bit should remain set after unclean shutdown"
        );
    }

    #[test]
    fn test_virtio_block_qcow2_dirty_bit_clean_shutdown() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_image_path = guest.tmp_dir.as_path().join("test-dirty.qcow2");
        let original_image = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();

        copy(original_image, &test_image_path).expect("Failed to copy qcow2 image");

        assert_eq!(
            check_dirty_flag(&test_image_path).expect("Failed to check dirty flag"),
            Some(false),
            "Image should start with dirty bit cleared"
        );

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                &format!("path={}", test_image_path.to_str().unwrap()),
                &format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                ),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                check_dirty_flag(&test_image_path).expect("Failed to check dirty flag"),
                Some(true),
                "Dirty bit should be set while VM is running"
            );
        });

        // Clean shutdown using SIGTERM
        kill_child(&mut child);

        if r.is_err() {
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);
            return;
        }

        let _ = child.wait();

        disk_check_consistency(&test_image_path, None);
    }

    #[test]
    fn test_virtio_block_qcow2_corrupt_bit_rejected_for_write() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_image_path = guest.tmp_dir.as_path().join("test-corrupt.qcow2");
        let original_image = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();

        copy(original_image, &test_image_path).expect("Failed to copy qcow2 image");

        assert_eq!(
            check_corrupt_flag(&test_image_path).expect("Failed to check corrupt flag"),
            Some(false),
            "Image should start with corrupt bit cleared"
        );

        set_corrupt_flag(&test_image_path, true).expect("Failed to set corrupt flag");

        assert_eq!(
            check_corrupt_flag(&test_image_path).expect("Failed to check corrupt flag"),
            Some(true),
            "Corrupt bit should be set"
        );

        let child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                &format!("path={}", test_image_path.to_str().unwrap()),
                &format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                ),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let output = child.wait_with_output().unwrap();
        assert!(
            !output.status.success(),
            "VM should fail to start with corrupt disk image"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("corrupt") || stderr.contains("Corrupt"),
            "Error message should mention corruption: {stderr}"
        );
    }

    #[test]
    fn test_virtio_block_qcow2_corrupt_bit_allowed_readonly() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME_QCOW2.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_image_path = guest.tmp_dir.as_path().join("test-corrupt-ro.qcow2");
        let original_image = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();

        copy(original_image, &test_image_path).expect("Failed to copy qcow2 image");

        set_corrupt_flag(&test_image_path, true).expect("Failed to set corrupt flag");

        assert_eq!(
            check_corrupt_flag(&test_image_path).expect("Failed to check corrupt flag"),
            Some(true),
            "Corrupt bit should be set"
        );

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                &format!("path={},readonly=on", test_image_path.to_str().unwrap()),
                &format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                ),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        thread::sleep(Duration::from_secs(5));

        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                panic!(
                    "VM should not have exited when opening corrupt image as readonly. Exit status: {status}, stderr: {stderr}"
                );
            }
            Ok(None) => {
                // VM is still running as expected
            }
            Err(e) => {
                panic!("Error checking process status: {e}");
            }
        }

        let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let output = child.wait_with_output().unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("QCOW2 image is marked corrupt, opening read-only"),
            "Expected warning about corrupt image being opened read-only. stderr: {stderr}"
        );

        assert_eq!(
            check_corrupt_flag(&test_image_path).expect("Failed to check corrupt flag"),
            Some(true),
            "Corrupt bit should remain set for read-only access"
        );
    }

    #[test]
    fn test_virtio_block_vhd() {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut raw_file_path = workload_path.clone();
        let mut vhd_file_path = workload_path;
        raw_file_path.push(FOCAL_IMAGE_NAME);
        vhd_file_path.push(FOCAL_IMAGE_NAME_VHD);

        // Generate VHD file from RAW file
        std::process::Command::new("qemu-img")
            .arg("convert")
            .arg("-p")
            .args(["-f", "raw"])
            .args(["-O", "vpc"])
            .args(["-o", "subformat=fixed"])
            .arg(raw_file_path.to_str().unwrap())
            .arg(vhd_file_path.to_str().unwrap())
            .output()
            .expect("Expect generating VHD image from RAW image");
        let guest = make_virtio_block_guest(
            &GuestFactory::new_regular_guest_factory(),
            FOCAL_IMAGE_NAME_VHD,
        );
        _test_virtio_block(&guest, false, false, false, false, ImageType::FixedVhd);
    }

    #[test]
    fn test_virtio_block_vhdx() {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut raw_file_path = workload_path.clone();
        let mut vhdx_file_path = workload_path;
        raw_file_path.push(FOCAL_IMAGE_NAME);
        vhdx_file_path.push(FOCAL_IMAGE_NAME_VHDX);

        // Generate dynamic VHDX file from RAW file
        std::process::Command::new("qemu-img")
            .arg("convert")
            .arg("-p")
            .args(["-f", "raw"])
            .args(["-O", "vhdx"])
            .arg(raw_file_path.to_str().unwrap())
            .arg(vhdx_file_path.to_str().unwrap())
            .output()
            .expect("Expect generating dynamic VHDx image from RAW image");
        let guest = make_virtio_block_guest(
            &GuestFactory::new_regular_guest_factory(),
            FOCAL_IMAGE_NAME_VHDX,
        );
        _test_virtio_block(&guest, false, false, true, false, ImageType::Vhdx);
    }

    #[test]
    fn test_virtio_block_dynamic_vhdx_expand() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_block_dynamic_vhdx_expand(&guest);
    }

    #[test]
    fn test_virtio_block_direct_and_firmware() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        // The OS disk must be copied to a location that is not backed by
        // tmpfs, otherwise the syscall openat(2) with O_DIRECT simply fails
        // with EINVAL because tmpfs doesn't support this flag.
        let mut workloads_path = dirs::home_dir().unwrap();
        workloads_path.push("workloads");
        let os_dir = TempDir::new_in(workloads_path.as_path()).unwrap();
        let mut os_path = os_dir.as_path().to_path_buf();
        os_path.push("osdisk.img");
        rate_limited_copy(
            guest.disk_config.disk(DiskType::OperatingSystem).unwrap(),
            os_path.as_path(),
        )
        .expect("copying of OS disk failed");

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
            .args([
                "--disk",
                format!("path={},direct=on", os_path.as_path().to_str().unwrap()).as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_vhost_user_net_default() {
        test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon, false, false);
    }

    #[test]
    fn test_vhost_user_net_named_tap() {
        test_vhost_user_net(
            Some("mytap0"),
            2,
            &prepare_vhost_user_net_daemon,
            false,
            false,
        );
    }

    #[test]
    fn test_vhost_user_net_existing_tap() {
        test_vhost_user_net(
            Some("vunet-tap0"),
            2,
            &prepare_vhost_user_net_daemon,
            false,
            false,
        );
    }

    #[test]
    fn test_vhost_user_net_multiple_queues() {
        test_vhost_user_net(None, 4, &prepare_vhost_user_net_daemon, false, false);
    }

    #[test]
    fn test_vhost_user_net_tap_multiple_queues() {
        test_vhost_user_net(
            Some("vunet-tap1"),
            4,
            &prepare_vhost_user_net_daemon,
            false,
            false,
        );
    }

    #[test]
    fn test_vhost_user_net_host_mac() {
        test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon, true, false);
    }

    #[test]
    fn test_vhost_user_net_client_mode() {
        test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon, false, true);
    }

    #[test]
    #[cfg(not(target_arch = "aarch64"))]
    fn test_vhost_user_blk_default() {
        test_vhost_user_blk(2, false, false, Some(&prepare_vubd));
    }

    #[test]
    #[cfg(not(target_arch = "aarch64"))]
    fn test_vhost_user_blk_readonly() {
        test_vhost_user_blk(1, true, false, Some(&prepare_vubd));
    }

    #[test]
    #[cfg(not(target_arch = "aarch64"))]
    fn test_vhost_user_blk_direct() {
        test_vhost_user_blk(1, false, true, Some(&prepare_vubd));
    }

    #[test]
    fn test_boot_from_vhost_user_blk_default() {
        test_boot_from_vhost_user_blk(1, false, false, Some(&prepare_vubd));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_split_irqchip() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_split_irqchip(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_dmi_serial_number() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);

        _test_dmi_serial_number(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_dmi_uuid() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_dmi_uuid(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_dmi_oem_strings() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_dmi_oem_strings(&guest);
    }

    #[test]
    fn test_virtio_fs() {
        _test_virtio_fs(&prepare_virtiofsd, false, false, None);
    }

    #[test]
    fn test_virtio_fs_hotplug() {
        _test_virtio_fs(&prepare_virtiofsd, true, false, None);
    }

    #[test]
    fn test_virtio_fs_multi_segment_hotplug() {
        _test_virtio_fs(&prepare_virtiofsd, true, false, Some(15));
    }

    #[test]
    fn test_virtio_fs_multi_segment() {
        _test_virtio_fs(&prepare_virtiofsd, false, false, Some(15));
    }

    #[test]
    fn test_generic_vhost_user() {
        _test_virtio_fs(&prepare_virtiofsd, false, true, None);
    }

    #[test]
    fn test_generic_vhost_user_hotplug() {
        _test_virtio_fs(&prepare_virtiofsd, true, true, None);
    }

    #[test]
    fn test_generic_vhost_user_multi_segment_hotplug() {
        _test_virtio_fs(&prepare_virtiofsd, true, true, Some(15));
    }

    #[test]
    fn test_generic_vhost_user_multi_segment() {
        _test_virtio_fs(&prepare_virtiofsd, false, true, Some(15));
    }

    #[test]
    fn test_virtio_pmem_discard_writes() {
        test_virtio_pmem(true, false);
    }

    #[test]
    fn test_virtio_pmem_with_size() {
        test_virtio_pmem(true, true);
    }

    #[test]
    fn test_boot_from_virtio_pmem() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
            ])
            .default_net()
            .args([
                "--pmem",
                format!(
                    "file={},size={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap(),
                    fs::metadata(guest.disk_config.disk(DiskType::OperatingSystem).unwrap())
                        .unwrap()
                        .len()
                )
                .as_str(),
            ])
            .args([
                "--cmdline",
                DIRECT_KERNEL_BOOT_CMDLINE
                    .replace("vda1", "pmem0p1")
                    .as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Simple checks to validate the VM booted properly
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
            assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_multiple_network_interfaces() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_multiple_network_interfaces(&guest);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_pmu_on() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Test that PMU exists.
            assert_eq!(
                guest
                    .ssh_command(GREP_PMU_IRQ_CMD)
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_serial_off() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_serial_off(&guest);
    }

    #[test]
    fn test_serial_null() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut cmd = GuestCommand::new(&guest);
        #[cfg(target_arch = "x86_64")]
        let console_str: &str = "console=ttyS0";
        #[cfg(target_arch = "aarch64")]
        let console_str: &str = "console=ttyAMA0";

        cmd.default_cpus()
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args([
                "--cmdline",
                DIRECT_KERNEL_BOOT_CMDLINE
                    .replace("console=hvc0", console_str)
                    .as_str(),
            ])
            .default_disks()
            .default_net()
            .args(["--serial", "null"])
            .args(["--console", "off"])
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Test that there is a ttyS0
            assert_eq!(
                guest
                    .ssh_command(GREP_SERIAL_IRQ_CMD)
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(CONSOLE_TEST_STRING));
        });

        handle_child_output(r, &output);
    }

    #[test]
    fn test_serial_tty() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let kernel_path = direct_kernel_boot_path();

        #[cfg(target_arch = "x86_64")]
        let console_str: &str = "console=ttyS0";
        #[cfg(target_arch = "aarch64")]
        let console_str: &str = "console=ttyAMA0";

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--cmdline",
                DIRECT_KERNEL_BOOT_CMDLINE
                    .replace("console=hvc0", console_str)
                    .as_str(),
            ])
            .default_disks()
            .default_net()
            .args(["--serial", "tty"])
            .args(["--console", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Test that there is a ttyS0
            assert_eq!(
                guest
                    .ssh_command(GREP_SERIAL_IRQ_CMD)
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );
        });

        // This sleep is needed to wait for the login prompt
        thread::sleep(std::time::Duration::new(2, 0));

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(CONSOLE_TEST_STRING));
        });

        handle_child_output(r, &output);
    }

    #[test]
    fn test_serial_file() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let serial_path = guest.tmp_dir.as_path().join("serial-output");
        #[cfg(target_arch = "x86_64")]
        let console_str: &str = "console=ttyS0";
        #[cfg(target_arch = "aarch64")]
        let console_str: &str = "console=ttyAMA0";

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args([
                "--cmdline",
                DIRECT_KERNEL_BOOT_CMDLINE
                    .replace("console=hvc0", console_str)
                    .as_str(),
            ])
            .default_disks()
            .default_net()
            .args([
                "--serial",
                format!("file={}", serial_path.to_str().unwrap()).as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Test that there is a ttyS0
            assert_eq!(
                guest
                    .ssh_command(GREP_SERIAL_IRQ_CMD)
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            guest.ssh_command("sudo shutdown -h now").unwrap();
        });

        let _ = child.wait_timeout(std::time::Duration::from_secs(20));
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            // Check that the cloud-hypervisor binary actually terminated
            assert!(output.status.success());

            // Do this check after shutdown of the VM as an easy way to ensure
            // all writes are flushed to disk
            let mut f = std::fs::File::open(serial_path).unwrap();
            let mut buf = String::new();
            f.read_to_string(&mut buf).unwrap();
            assert!(buf.contains(CONSOLE_TEST_STRING));
        });

        handle_child_output(r, &output);
    }

    #[test]
    fn test_pty_interaction() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);
        let serial_option = if cfg!(target_arch = "x86_64") {
            " console=ttyS0"
        } else {
            " console=ttyAMA0"
        };
        let cmdline = DIRECT_KERNEL_BOOT_CMDLINE.to_owned() + serial_option;

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", &cmdline])
            .default_disks()
            .default_net()
            .args(["--serial", "null"])
            .args(["--console", "pty"])
            .args(["--api-socket", &api_socket])
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            // Get pty fd for console
            let console_path = get_pty_path(&api_socket, "console");
            _test_pty_interaction(console_path);

            guest.ssh_command("sudo shutdown -h now").unwrap();
        });

        let _ = child.wait_timeout(std::time::Duration::from_secs(20));
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            // Check that the cloud-hypervisor binary actually terminated
            assert!(output.status.success());
        });
        handle_child_output(r, &output);
    }

    #[test]
    fn test_serial_socket_interaction() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let serial_socket = guest.tmp_dir.as_path().join("serial.socket");
        let serial_socket_pty = guest.tmp_dir.as_path().join("serial.pty");
        let serial_option = if cfg!(target_arch = "x86_64") {
            " console=ttyS0"
        } else {
            " console=ttyAMA0"
        };
        let cmdline = DIRECT_KERNEL_BOOT_CMDLINE.to_owned() + serial_option;

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", &cmdline])
            .default_disks()
            .default_net()
            .args(["--console", "null"])
            .args([
                "--serial",
                format!("socket={}", serial_socket.to_str().unwrap()).as_str(),
            ])
            .spawn()
            .unwrap();

        let _ = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
        });

        let mut socat_command = Command::new("socat");
        let socat_args = [
            &format!("pty,link={},raw", serial_socket_pty.display()),
            &format!("UNIX-CONNECT:{}", serial_socket.display()),
        ];
        socat_command.args(socat_args);

        let mut socat_child = socat_command.spawn().unwrap();
        thread::sleep(std::time::Duration::new(1, 0));

        let _ = std::panic::catch_unwind(|| {
            _test_pty_interaction(serial_socket_pty);
        });

        let _ = socat_child.kill();
        let _ = socat_child.wait();

        let r = std::panic::catch_unwind(|| {
            guest.ssh_command("sudo shutdown -h now").unwrap();
        });

        let _ = child.wait_timeout(std::time::Duration::from_secs(20));
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            // Check that the cloud-hypervisor binary actually terminated
            if !output.status.success() {
                panic!(
                    "Cloud Hypervisor process failed to terminate gracefully: {:?}",
                    output.status
                );
            }
        });
        handle_child_output(r, &output);
    }

    #[test]
    fn test_virtio_console() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_console(&guest);
    }

    #[test]
    fn test_console_file() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_console_file(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    #[cfg(not(feature = "mshv"))]
    // The VFIO integration test starts cloud-hypervisor guest with 3 TAP
    // backed networking interfaces, bound through a simple bridge on the host.
    // So if the nested cloud-hypervisor succeeds in getting a directly
    // assigned interface from its cloud-hypervisor host, we should be able to
    // ssh into it, and verify that it's running with the right kernel command
    // line (We tag the command line from cloud-hypervisor for that purpose).
    // The third device is added to validate that hotplug works correctly since
    // it is being added to the L2 VM through hotplugging mechanism.
    // Also, we pass-through a virtio-blk device to the L2 VM to test the 32-bit
    // vfio device support
    fn test_vfio() {
        setup_vfio_network_interfaces();

        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new_from_ip_range(Box::new(disk_config), "172.18", 0);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let kernel_path = direct_kernel_boot_path();

        let mut vfio_path = workload_path.clone();
        vfio_path.push("vfio");

        let mut cloud_init_vfio_base_path = vfio_path.clone();
        cloud_init_vfio_base_path.push("cloudinit.img");

        // We copy our cloudinit into the vfio mount point, for the nested
        // cloud-hypervisor guest to use.
        rate_limited_copy(
            guest.disk_config.disk(DiskType::CloudInit).unwrap(),
            &cloud_init_vfio_base_path,
        )
        .expect("copying of cloud-init disk failed");

        let mut vfio_disk_path = workload_path.clone();
        vfio_disk_path.push("vfio.img");

        // Create the vfio disk image
        let output = Command::new("mkfs.ext4")
            .arg("-d")
            .arg(vfio_path.to_str().unwrap())
            .arg(vfio_disk_path.to_str().unwrap())
            .arg("2g")
            .output()
            .unwrap();
        if !output.status.success() {
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            panic!("mkfs.ext4 command generated an error");
        }

        let mut blk_file_path = workload_path;
        blk_file_path.push("blk.img");

        let vfio_tap0 = "vfio-tap0";
        let vfio_tap1 = "vfio-tap1";
        let vfio_tap2 = "vfio-tap2";
        let vfio_tap3 = "vfio-tap3";

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=4"])
            .args(["--memory", "size=2G,hugepages=on,shared=on"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={},image_type=raw", vfio_disk_path.to_str().unwrap()).as_str(),
                format!("path={},iommu=on,readonly=true", blk_file_path.to_str().unwrap()).as_str(),
            ])
            .args([
                "--cmdline",
                format!(
                    "{DIRECT_KERNEL_BOOT_CMDLINE} kvm-intel.nested=1 vfio_iommu_type1.allow_unsafe_interrupts"
                )
                .as_str(),
            ])
            .args([
                "--net",
                format!("tap={},mac={}", vfio_tap0, guest.network.guest_mac0).as_str(),
                format!(
                    "tap={},mac={},iommu=on",
                    vfio_tap1, guest.network.l2_guest_mac1
                )
                .as_str(),
                format!(
                    "tap={},mac={},iommu=on",
                    vfio_tap2, guest.network.l2_guest_mac2
                )
                .as_str(),
                format!(
                    "tap={},mac={},iommu=on",
                    vfio_tap3, guest.network.l2_guest_mac3
                )
                .as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        guest.wait_for_ssh(Duration::from_secs(30)).unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.ssh_command_l1("sudo systemctl start vfio").unwrap();
            let auth = PasswordAuth {
                username: String::from("cloud"),
                password: String::from("cloud123"),
            };
            wait_for_ssh(
                "true",
                &auth,
                &guest.network.l2_guest_ip1,
                Duration::from_secs(120),
            )
            .unwrap();
            wait_for_ssh(
                "true",
                &auth,
                &guest.network.l2_guest_ip2,
                Duration::from_secs(120),
            )
            .unwrap();

            // We booted our cloud hypervisor L2 guest with a "VFIOTAG" tag
            // added to its kernel command line.
            // Let's ssh into it and verify that it's there. If it is it means
            // we're in the right guest (The L2 one) because the QEMU L1 guest
            // does not have this command line tag.
            assert!(check_matched_lines_count(
                guest.ssh_command_l2_1("cat /proc/cmdline").unwrap().trim(),
                &["VFIOTAG"],
                1
            ));

            // Let's also verify from the second virtio-net device passed to
            // the L2 VM.
            assert!(check_matched_lines_count(
                guest.ssh_command_l2_2("cat /proc/cmdline").unwrap().trim(),
                &["VFIOTAG"],
                1
            ));

            // Check the amount of PCI devices appearing in L2 VM.
            assert!(check_lines_count(
                guest
                    .ssh_command_l2_1("ls /sys/bus/pci/devices")
                    .unwrap()
                    .trim(),
                8
            ));

            // Check both if /dev/vdc exists and if the block size is 16M in L2 VM
            assert!(check_matched_lines_count(
                guest.ssh_command_l2_1("lsblk").unwrap().trim(),
                &["vdc", "16M"],
                1
            ));

            // Hotplug an extra virtio-net device through L2 VM.
            guest
                .ssh_command_l1(
                    "echo 0000:00:09.0 | sudo tee /sys/bus/pci/devices/0000:00:09.0/driver/unbind",
                )
                .unwrap();
            guest
                .ssh_command_l1("echo 0000:00:09.0 | sudo tee /sys/bus/pci/drivers/vfio-pci/bind")
                .unwrap();
            let vfio_hotplug_output = guest
                .ssh_command_l1(
                    "sudo /mnt/ch-remote \
                 --api-socket=/tmp/ch_api.sock \
                 add-device path=/sys/bus/pci/devices/0000:00:09.0,id=vfio123",
                )
                .unwrap();
            assert!(check_matched_lines_count(
                vfio_hotplug_output.trim(),
                &["{\"id\":\"vfio123\",\"bdf\":\"0000:00:08.0\"}"],
                1
            ));

            wait_for_ssh(
                "true",
                &auth,
                &guest.network.l2_guest_ip3,
                Duration::from_secs(10),
            )
            .unwrap();
            assert!(wait_until(Duration::from_secs(10), || {
                guest
                    .ssh_command_l2_1("ls /sys/bus/pci/devices")
                    .is_ok_and(|output| check_lines_count(output.trim(), 9))
            }));

            // Let's also verify from the third virtio-net device passed to
            // the L2 VM. This third device has been hotplugged through the L2
            // VM, so this is our way to validate hotplug works for VFIO PCI.
            assert!(check_matched_lines_count(
                guest.ssh_command_l2_3("cat /proc/cmdline").unwrap().trim(),
                &["VFIOTAG"],
                1
            ));

            // Check the amount of PCI devices appearing in L2 VM.
            // There should be one more device than before, raising the count
            // up to 9 PCI devices.
            assert!(check_lines_count(
                guest
                    .ssh_command_l2_1("ls /sys/bus/pci/devices")
                    .unwrap()
                    .trim(),
                9
            ));

            // Let's now verify that we can correctly remove the virtio-net
            // device through the "remove-device" command responsible for
            // unplugging VFIO devices.
            guest
                .ssh_command_l1(
                    "sudo /mnt/ch-remote \
                 --api-socket=/tmp/ch_api.sock \
                 remove-device vfio123",
                )
                .unwrap();
            assert!(wait_until(Duration::from_secs(10), || {
                guest
                    .ssh_command_l2_1("ls /sys/bus/pci/devices")
                    .is_ok_and(|output| check_lines_count(output.trim(), 8))
            }));

            // Check the amount of PCI devices appearing in L2 VM is back down
            // to 8 devices.
            assert!(check_lines_count(
                guest
                    .ssh_command_l2_1("ls /sys/bus/pci/devices")
                    .unwrap()
                    .trim(),
                8
            ));

            // Perform memory hotplug in L2 and validate the memory is showing
            // up as expected. In order to check, we will use the virtio-net
            // device already passed through L2 as a VFIO device, this will
            // verify that VFIO devices are functional with memory hotplug.
            assert!(guest.get_total_memory_l2().unwrap_or_default() > 480_000);
            guest
                .ssh_command_l2_1(
                    "sudo bash -c 'echo online > /sys/devices/system/memory/auto_online_blocks'",
                )
                .unwrap();
            guest
                .ssh_command_l1(
                    "sudo /mnt/ch-remote \
                 --api-socket=/tmp/ch_api.sock \
                 resize --memory=1073741824",
                )
                .unwrap();
            assert!(guest.get_total_memory_l2().unwrap_or_default() > 960_000);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        cleanup_vfio_network_interfaces();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_direct_kernel_boot_noacpi() {
        let mut guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        guest.kernel_cmdline = Some(format!("{DIRECT_KERNEL_BOOT_CMDLINE} acpi=off"));
        _test_direct_kernel_boot_noacpi(&guest);
    }

    #[test]
    fn test_virtio_vsock() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_vsock(&guest, false);
    }

    #[test]
    fn test_virtio_vsock_hotplug() {
        #[cfg(target_arch = "x86_64")]
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        #[cfg(target_arch = "aarch64")]
        let guest =
            basic_regular_guest!(JAMMY_IMAGE_NAME).with_kernel_path(edk2_path().to_str().unwrap());
        _test_virtio_vsock(&guest, true);
    }

    #[test]
    fn test_api_http_shutdown() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_shutdown(&target_api, &guest);
    }

    #[test]
    fn test_api_http_delete() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_delete(&target_api, &guest);
    }

    #[test]
    fn test_api_http_pause_resume() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_pause_resume(&target_api, &guest);
    }

    #[test]
    fn test_api_http_create_boot() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_create_boot(&target_api, &guest);
    }

    #[test]
    fn test_virtio_iommu() {
        _test_virtio_iommu(cfg!(target_arch = "x86_64"));
    }

    #[test]
    // We cannot force the software running in the guest to reprogram the BAR
    // with some different addresses, but we have a reliable way of testing it
    // with a standard Linux kernel.
    // By removing a device from the PCI tree, and then rescanning the tree,
    // Linux consistently chooses to reorganize the PCI device BARs to other
    // locations in the guest address space.
    // This test creates a dedicated PCI network device to be checked as being
    // properly probed first, then removing it, and adding it again by doing a
    // rescan.
    fn test_pci_bar_reprogramming() {
        #[cfg(target_arch = "aarch64")]
        let guest =
            basic_regular_guest!(JAMMY_IMAGE_NAME).with_kernel_path(edk2_path().to_str().unwrap());
        #[cfg(target_arch = "x86_64")]
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_pci_bar_reprogramming(&guest);
    }

    #[test]
    fn test_memory_mergeable_off() {
        test_memory_mergeable(false);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See issue #7435
    #[cfg(target_arch = "x86_64")]
    fn test_cpu_hotplug() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);
        let console_str = "console=ttyS0";

        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=2,max=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--cmdline",
                DIRECT_KERNEL_BOOT_CMDLINE
                    .replace("console=hvc0", console_str)
                    .as_str(),
            ])
            .args(["--serial", "tty"])
            .args(["--console", "off"])
            .default_disks()
            .default_net()
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);

            // Resize the VM
            let desired_vcpus = 4;
            resize_command(&api_socket, Some(desired_vcpus), None, None, None);

            guest
                .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")
                .unwrap();
            guest
                .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")
                .unwrap();
            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_cpu_count().unwrap_or_default() == u32::from(desired_vcpus)
            }));

            guest.reboot_linux(0);

            assert_eq!(
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            // Resize the VM
            let desired_vcpus = 2;
            resize_command(&api_socket, Some(desired_vcpus), None, None, None);

            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_cpu_count().unwrap_or_default() == u32::from(desired_vcpus)
            }));

            // Resize the VM back up to 4
            let desired_vcpus = 4;
            resize_command(&api_socket, Some(desired_vcpus), None, None, None);

            guest
                .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")
                .unwrap();
            guest
                .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")
                .unwrap();
            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_cpu_count().unwrap_or_default() == u32::from(desired_vcpus)
            }));
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_memory_hotplug() {
        #[cfg(target_arch = "aarch64")]
        let focal_image = FOCAL_IMAGE_UPDATE_KERNEL_NAME.to_string();
        #[cfg(target_arch = "x86_64")]
        let focal_image = FOCAL_IMAGE_NAME.to_string();
        let disk_config = UbuntuDiskConfig::new(focal_image);
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();
        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=2,max=4"])
            .args(["--memory", "size=512M,hotplug_size=8192M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args(["--balloon", "size=0"])
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

            guest.enable_memory_hotplug();

            // Add RAM to the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_total_memory().unwrap_or_default() > 960_000
            }));

            // Use balloon to remove RAM from the VM
            let desired_balloon = 512 << 20;
            resize_command(&api_socket, None, None, Some(desired_balloon), None);

            assert!(wait_until(Duration::from_secs(10), || {
                let total_memory = guest.get_total_memory().unwrap_or_default();
                total_memory > 480_000 && total_memory < 960_000
            }));

            guest.reboot_linux(0);

            assert!(guest.get_total_memory().unwrap_or_default() < 960_000);

            // Use balloon add RAM to the VM
            let desired_balloon = 0;
            resize_command(&api_socket, None, None, Some(desired_balloon), None);

            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_total_memory().unwrap_or_default() > 960_000
            }));

            guest.enable_memory_hotplug();

            // Add RAM to the VM
            let desired_ram = 2048 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_total_memory().unwrap_or_default() > 1_920_000
            }));

            // Remove RAM to the VM (only applies after reboot)
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            guest.reboot_linux(1);

            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
            assert!(guest.get_total_memory().unwrap_or_default() < 1_920_000);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See #7456
    fn test_virtio_mem() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=2,max=4"])
            .args([
                "--memory",
                "size=512M,hotplug_method=virtio-mem,hotplug_size=8192M",
            ])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

            guest.enable_memory_hotplug();

            // Add RAM to the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_total_memory().unwrap_or_default() > 960_000
            }));

            // Add RAM to the VM
            let desired_ram = 2048 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_total_memory().unwrap_or_default() > 1_920_000
            }));

            // Remove RAM from the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            assert!(wait_until(Duration::from_secs(10), || {
                let total_memory = guest.get_total_memory().unwrap_or_default();
                total_memory > 960_000 && total_memory < 1_920_000
            }));

            guest.reboot_linux(0);

            // Check the amount of memory after reboot is 1GiB
            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
            assert!(guest.get_total_memory().unwrap_or_default() < 1_920_000);

            // Check we can still resize to 512MiB
            let desired_ram = 512 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);
            assert!(wait_until(Duration::from_secs(10), || {
                let total_memory = guest.get_total_memory().unwrap_or_default();
                total_memory > 480_000 && total_memory < 960_000
            }));
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    // Test both vCPU and memory resizing together
    fn test_resize() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=2,max=4"])
            .args(["--memory", "size=512M,hotplug_size=8192M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);
            assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

            guest.enable_memory_hotplug();

            // Resize the VM
            let desired_vcpus = 4;
            let desired_ram = 1024 << 20;
            resize_command(
                &api_socket,
                Some(desired_vcpus),
                Some(desired_ram),
                None,
                None,
            );

            guest
                .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")
                .unwrap();
            guest
                .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")
                .unwrap();
            assert!(wait_until(Duration::from_secs(10), || {
                guest.get_cpu_count().unwrap_or_default() == u32::from(desired_vcpus)
            }));

            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_memory_overhead() {
        let guest_memory_size_kb: u32 = 512 * 1024;
        let guest =
            basic_regular_guest!(JAMMY_IMAGE_NAME).with_memory(&format!("{guest_memory_size_kb}K"));
        _test_memory_overhead(&guest, guest_memory_size_kb);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    // This test runs a guest with Landlock enabled and hotplugs a new disk. As
    // the path for the hotplug disk is not pre-added to Landlock rules, this
    // the test will result in a failure.
    fn test_landlock() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_landlock(&guest);
    }

    #[test]
    fn test_disk_hotplug() {
        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();
        let guest =
            basic_regular_guest!(JAMMY_IMAGE_NAME).with_kernel_path(kernel_path.to_str().unwrap());
        _test_disk_hotplug(&guest, false);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_disk_hotplug_with_landlock() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_disk_hotplug(&guest, true);
    }

    #[test]
    fn test_disk_resize() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        // Create a disk image that we can write to
        assert!(
            exec_host_command_output("sudo dd if=/dev/zero of=/tmp/resize.img bs=1M count=16")
                .status
                .success()
        );

        let mut cmd = GuestCommand::new(&guest);

        cmd.args(["--api-socket", &api_socket])
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Add the disk to the VM
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-disk",
                Some("path=/tmp/resize.img,id=test0"),
            );

            assert!(cmd_success);
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}")
            );

            // Check that /dev/vdc exists and the block size is 16M.
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );
            // And check the block device can be written to.
            guest
                .ssh_command("sudo dd if=/dev/zero of=/dev/vdc bs=1M count=16")
                .unwrap();

            // Resize disk to 32M
            let resize_up_success =
                resize_disk_command(&api_socket, "test0", "33554432" /* 32M */);
            assert!(resize_up_success);

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 32M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // And check all blocks can be written to
            guest
                .ssh_command("sudo dd if=/dev/zero of=/dev/vdc bs=1M count=32")
                .unwrap();

            // Resize down to original size
            let resize_down_success =
                resize_disk_command(&api_socket, "test0", "16777216" /* 16M */);
            assert!(resize_down_success);

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // And check all blocks can be written to, again
            guest
                .ssh_command("sudo dd if=/dev/zero of=/dev/vdc bs=1M count=16")
                .unwrap();
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_disk_resize_qcow2() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        let test_disk_path = guest.tmp_dir.as_path().join("resize-test.qcow2");

        // Create a 16MB QCOW2 disk image
        assert!(
            exec_host_command_output(&format!(
                "qemu-img create -f qcow2 {} 16M",
                test_disk_path.to_str().unwrap()
            ))
            .status
            .success()
        );

        let mut cmd = GuestCommand::new(&guest);

        cmd.args(["--api-socket", &api_socket])
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Add the QCOW2 disk to the VM
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-disk",
                Some(&format!(
                    "path={},id=test0",
                    test_disk_path.to_str().unwrap()
                )),
            );

            assert!(cmd_success);
            assert!(String::from_utf8_lossy(&cmd_output).contains("\"id\":\"test0\""));

            // Check that /dev/vdc exists and the block size is 16M
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Write some data to verify it persists after resize
            guest
                .ssh_command("sudo dd if=/dev/urandom of=/dev/vdc bs=1M count=8")
                .unwrap();

            // Resize disk up to 32M
            let resize_up_success =
                resize_disk_command(&api_socket, "test0", "33554432" /* 32M */);
            assert!(resize_up_success);

            // Check new size is visible
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 32M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Write to the expanded area to verify it works
            guest
                .ssh_command("sudo dd if=/dev/zero of=/dev/vdc bs=1M count=32")
                .unwrap();

            // Resize to 64M to exercise L1 table growth
            let resize_up_again_success =
                resize_disk_command(&api_socket, "test0", "67108864" /* 64M */);
            assert!(resize_up_again_success);

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 64M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Write to the full disk
            guest
                .ssh_command("sudo dd if=/dev/zero of=/dev/vdc bs=1M count=64")
                .unwrap();

            // QCOW2 does not support shrinking, no resize down test here.
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        disk_check_consistency(&test_disk_path, None);

        handle_child_output(r, &output);
    }

    fn create_loop_device(backing_file_path: &str, block_size: u32, num_retries: usize) -> String {
        const LOOP_CONFIGURE: u64 = 0x4c0a;
        const LOOP_CTL_GET_FREE: u64 = 0x4c82;
        const LOOP_CTL_PATH: &str = "/dev/loop-control";
        const LOOP_DEVICE_PREFIX: &str = "/dev/loop";

        #[repr(C)]
        struct LoopInfo64 {
            lo_device: u64,
            lo_inode: u64,
            lo_rdevice: u64,
            lo_offset: u64,
            lo_sizelimit: u64,
            lo_number: u32,
            lo_encrypt_type: u32,
            lo_encrypt_key_size: u32,
            lo_flags: u32,
            lo_file_name: [u8; 64],
            lo_crypt_name: [u8; 64],
            lo_encrypt_key: [u8; 32],
            lo_init: [u64; 2],
        }

        impl Default for LoopInfo64 {
            fn default() -> Self {
                LoopInfo64 {
                    lo_device: 0,
                    lo_inode: 0,
                    lo_rdevice: 0,
                    lo_offset: 0,
                    lo_sizelimit: 0,
                    lo_number: 0,
                    lo_encrypt_type: 0,
                    lo_encrypt_key_size: 0,
                    lo_flags: 0,
                    lo_file_name: [0; 64],
                    lo_crypt_name: [0; 64],
                    lo_encrypt_key: [0; 32],
                    lo_init: [0; 2],
                }
            }
        }

        #[derive(Default)]
        #[repr(C)]
        struct LoopConfig {
            fd: u32,
            block_size: u32,
            info: LoopInfo64,
            _reserved: [u64; 8],
        }

        // Open loop-control device
        let loop_ctl_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(LOOP_CTL_PATH)
            .unwrap();

        // Open backing file
        let backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(backing_file_path)
            .unwrap();

        // Retry the whole get free -> open -> configure sequence so that a
        // race with another parallel test claiming the same loop device
        // is resolved by requesting a new free device on each attempt.
        let mut loop_device_path = String::new();
        for i in 0..num_retries {
            // Request a free loop device
            let loop_device_number =
                unsafe { libc::ioctl(loop_ctl_file.as_raw_fd(), LOOP_CTL_GET_FREE as _) };

            if loop_device_number < 0 {
                panic!("Couldn't find a free loop device");
            }

            loop_device_path = format!("{LOOP_DEVICE_PREFIX}{loop_device_number}");

            // Open loop device
            let loop_device_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&loop_device_path)
                .unwrap();

            let loop_config = LoopConfig {
                fd: backing_file.as_raw_fd() as u32,
                block_size,
                ..Default::default()
            };

            let ret = unsafe {
                libc::ioctl(
                    loop_device_file.as_raw_fd(),
                    LOOP_CONFIGURE as _,
                    &loop_config,
                )
            };
            if ret == 0 {
                break;
            }

            if i < num_retries - 1 {
                println!(
                    "Iteration {}: Failed to configure loop device {}: {}",
                    i,
                    loop_device_path,
                    io::Error::last_os_error()
                );
                let jitter_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
                    % 500
                    + 100;
                thread::sleep(Duration::from_millis(jitter_ms as u64));
            } else {
                panic!(
                    "Failed {} times trying to configure the loop device {}: {}",
                    num_retries,
                    loop_device_path,
                    io::Error::last_os_error()
                );
            }
        }

        loop_device_path
    }

    #[test]
    fn test_virtio_block_topology() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        let test_disk_path = guest.tmp_dir.as_path().join("test.img");

        let output = exec_host_command_output(
            format!(
                "qemu-img create -f raw {} 16M",
                test_disk_path.to_str().unwrap()
            )
            .as_str(),
        );
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("qemu-img command failed\nstdout\n{stdout}\nstderr\n{stderr}");
        }

        let loop_dev = create_loop_device(test_disk_path.to_str().unwrap(), 4096, 5);
        _test_virtio_block_topology(&guest, &loop_dev);
        Command::new("losetup")
            .args(["-d", &loop_dev])
            .output()
            .expect("loop device not found");
    }

    #[test]
    fn test_virtio_block_direct_io_block_device_alignment_4k() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        // The backing file for the loop device must live on a filesystem that
        // supports O_DIRECT (e.g. ext4).  guest.tmp_dir is on tmpfs inside
        // Docker, and the loop driver forwards I/O to the backing file.
        let mut workloads_path = dirs::home_dir().unwrap();
        workloads_path.push("workloads");
        let img_dir = TempDir::new_in(workloads_path.as_path()).unwrap();
        let test_disk_path = img_dir.as_path().join("directio_test.img");
        // Preallocate the backing file -- a sparse file can deadlock when
        // O_DIRECT writes through a loop device trigger block allocation
        // in the backing filesystem.
        assert!(
            exec_host_command_output(&format!(
                "fallocate -l 64M {}",
                test_disk_path.to_str().unwrap()
            ))
            .status
            .success(),
            "fallocate failed"
        );

        let loop_dev = create_loop_device(test_disk_path.to_str().unwrap(), 4096, 5);

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=1"])
            .args(["--memory", "size=512M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={},direct=on,image_type=raw", &loop_dev).as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk -t | grep vdc | awk '{print $6}'")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4096
            );

            guest
                .ssh_command(
                    "sudo dd if=/dev/urandom of=/tmp/pattern bs=4096 count=1 && \
                     sudo dd if=/tmp/pattern of=/dev/vdc bs=4096 count=1 seek=1 oflag=direct && \
                     sudo dd if=/dev/vdc of=/tmp/readback bs=4096 count=1 skip=1 iflag=direct && \
                     cmp /tmp/pattern /tmp/readback",
                )
                .unwrap();
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);

        Command::new("losetup")
            .args(["-d", &loop_dev])
            .output()
            .expect("loop device cleanup failed");
    }

    #[test]
    fn test_virtio_block_direct_io_file_backed_alignment_4k() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let mut workloads_path = dirs::home_dir().unwrap();
        workloads_path.push("workloads");
        let img_dir = TempDir::new_in(workloads_path.as_path()).unwrap();
        let fs_img_path = img_dir.as_path().join("fs_4ksec.img");

        assert!(
            exec_host_command_output(&format!(
                "truncate -s 512M {}",
                fs_img_path.to_str().unwrap()
            ))
            .status
            .success(),
            "truncate failed"
        );

        let loop_dev_path = create_loop_device(fs_img_path.to_str().unwrap(), 4096, 5);

        assert!(
            exec_host_command_output(&format!("mkfs.ext4 -q {loop_dev_path}"))
                .status
                .success(),
            "mkfs.ext4 failed"
        );

        let mnt_dir = img_dir.as_path().join("mnt");
        fs::create_dir_all(&mnt_dir).unwrap();
        assert!(
            exec_host_command_output(&format!(
                "mount {} {}",
                &loop_dev_path,
                mnt_dir.to_str().unwrap()
            ))
            .status
            .success(),
            "mount failed"
        );

        let test_disk_path = mnt_dir.join("dio_file_test.raw");
        assert!(
            exec_host_command_output(&format!(
                "truncate -s 64M {}",
                test_disk_path.to_str().unwrap()
            ))
            .status
            .success(),
            "truncate test disk failed"
        );

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=1"])
            .args(["--memory", "size=512M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!(
                    "path={},direct=on,image_type=raw",
                    test_disk_path.to_str().unwrap()
                )
                .as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let log_sec: u32 = guest
                .ssh_command("lsblk -t | grep vdc | awk '{print $6}'")
                .unwrap()
                .trim()
                .parse()
                .unwrap_or_default();
            assert_eq!(
                log_sec, 4096,
                "expected 4096-byte logical sector for file on 4k-sector fs, got {log_sec}"
            );

            guest
                .ssh_command(
                    "sudo dd if=/dev/urandom of=/tmp/pattern bs=4096 count=8 && \
                     sudo dd if=/tmp/pattern of=/dev/vdc bs=4096 count=8 seek=1 oflag=direct && \
                     sudo dd if=/dev/vdc of=/tmp/readback bs=4096 count=8 skip=1 iflag=direct && \
                     cmp /tmp/pattern /tmp/readback",
                )
                .unwrap();
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);

        let _ = exec_host_command_output(&format!("umount {}", mnt_dir.to_str().unwrap()));
        let _ = exec_host_command_output(&format!("losetup -d {loop_dev_path}"));
    }

    // Helper function to verify sparse file
    fn verify_sparse_file(test_disk_path: &str, expected_ratio: f64) {
        let res = exec_host_command_output(&format!("ls -s --block-size=1 {test_disk_path}"));
        assert!(res.status.success(), "ls -s command failed");
        let out = String::from_utf8_lossy(&res.stdout);
        let actual_bytes: u64 = out
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse ls -s output");

        let res = exec_host_command_output(&format!("ls -l {test_disk_path}"));
        assert!(res.status.success(), "ls -l command failed");
        let out = String::from_utf8_lossy(&res.stdout);
        let apparent_size: u64 = out
            .split_whitespace()
            .nth(4)
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse ls -l output");

        let threshold = (apparent_size as f64 * expected_ratio) as u64;
        assert!(
            actual_bytes < threshold,
            "Expected file to be sparse: apparent_size={apparent_size} bytes, actual_disk_usage={actual_bytes} bytes (threshold={threshold})"
        );
    }

    // Helper function to count zero flagged regions in QCOW2 image
    fn count_qcow2_zero_regions(test_disk_path: &str) -> Option<usize> {
        let res =
            exec_host_command_output(&format!("qemu-img map --output=json -U {test_disk_path}"));
        if !res.status.success() {
            return None;
        }

        let out = String::from_utf8_lossy(&res.stdout);
        let map_json = serde_json::from_str::<serde_json::Value>(&out).ok()?;
        let regions = map_json.as_array()?;

        Some(
            regions
                .iter()
                .filter(|r| {
                    let data = r["data"].as_bool().unwrap_or(true);
                    let zero = r["zero"].as_bool().unwrap_or(false);
                    // holes - data: false
                    // zero flagged regions - data: true, zero: true
                    !data || zero
                })
                .count(),
        )
    }

    // Helper function to verify file extents using FIEMAP after DISCARD
    // TODO: Make verification more format-specific:
    //   - QCOW2: Check for fragmentation patterns showing deallocated clusters
    //   - RAW: Verify actual holes (unallocated extents) exist in sparse regions
    //   - Could parse extent output to count holes vs allocated regions
    fn verify_fiemap_extents(test_disk_path: &str, format_type: &str) {
        let blocksize_output = exec_host_command_output(&format!("stat -f -c %S {test_disk_path}"));
        let blocksize = if blocksize_output.status.success() {
            String::from_utf8_lossy(&blocksize_output.stdout)
                .trim()
                .parse::<u64>()
                .unwrap_or(4096)
        } else {
            4096
        };

        let fiemap_output =
            exec_host_command_output(&format!("filefrag -b {blocksize} -v {test_disk_path}"));
        if fiemap_output.status.success() {
            let fiemap_str = String::from_utf8_lossy(&fiemap_output.stdout);

            // Verify we have extent information indicating sparse regions
            let has_extents = fiemap_str.contains("extent") || fiemap_str.contains("extents");
            let has_holes = fiemap_str.contains("hole");

            assert!(
                has_extents || has_holes,
                "FIEMAP should show extent information or holes for {format_type} file"
            );
        }
    }

    /// Helper function to verify a disk region reads as all zeros from within the guest
    fn assert_guest_disk_region_is_zero(guest: &Guest, device: &str, offset: u64, length: u64) {
        let result = guest
            .ssh_command(&format!(
                "sudo hexdump -v -s {offset} -n {length} -e '1/1 \"%02x\"' {device} | grep -qv '^00*$' && echo 'NONZERO' || echo 'ZEROS'"
            ))
            .unwrap();

        assert!(
            result.trim() == "ZEROS",
            "Expected {} region at offset {} length {} to read as zeros, but got: {}",
            device,
            offset,
            length,
            result.trim()
        );
    }

    // Common test sizes for discard/fstrim tests (all formats): 9 small (≤256KB), then one 4MB
    const BLOCK_DISCARD_TEST_SIZES_KB: &[u64] = &[64, 128, 256, 64, 128, 256, 64, 128, 256, 4096];

    fn _test_virtio_block_discard(
        format_name: &str,
        qemu_img_format: &str,
        extra_create_args: &[&str],
        expect_discard_success: bool,
        verify_disk: bool,
    ) {
        _test_virtio_block_discard_with_backend(
            format_name,
            qemu_img_format,
            extra_create_args,
            expect_discard_success,
            verify_disk,
            false,
        );
    }

    fn _test_virtio_block_discard_with_backend(
        format_name: &str,
        qemu_img_format: &str,
        extra_create_args: &[&str],
        expect_discard_success: bool,
        verify_disk: bool,
        disable_io_uring: bool,
    ) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_disk_path = guest
            .tmp_dir
            .as_path()
            .join(format!("discard_test.{}", format_name.to_lowercase()));

        let mut cmd = format!("qemu-img create -f {qemu_img_format} ");
        if !extra_create_args.is_empty() {
            cmd.push_str(&extra_create_args.join(" "));
            cmd.push(' ');
        }
        cmd.push_str(&format!("{} 2G", test_disk_path.to_str().unwrap()));

        let res = exec_host_command_output(&cmd);
        assert!(
            res.status.success(),
            "Failed to create {format_name} test image"
        );

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!(
                    "path={},num_queues=4,image_type={}{}",
                    test_disk_path.to_str().unwrap(),
                    format_name.to_lowercase(),
                    if disable_io_uring {
                        ",_disable_io_uring=on"
                    } else {
                        ""
                    }
                )
                .as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        const CLUSTER_SIZE_BYTES: u64 = 64 * 1024; // One QCOW2 cluster
        const WRITE_SIZE_MB: u64 = 4;
        const WRITE_OFFSET_MB: u64 = 1;

        // Build discard operations within the written region
        let write_start = WRITE_OFFSET_MB * 1024 * 1024;
        let mut discard_operations: Vec<(u64, u64)> = Vec::new();
        let mut current_offset = write_start;

        for &size_kb in BLOCK_DISCARD_TEST_SIZES_KB {
            let size = size_kb * 1024;
            discard_operations.push((current_offset, size));
            current_offset += size + CLUSTER_SIZE_BYTES; // Add gap between operations
        }

        let size_after_write = std::cell::Cell::new(0u64);

        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Write one 4MB block at offset 1MB
            guest
                .ssh_command(&format!(
                    "sudo dd if=/dev/zero of=/dev/vdc bs=1M count={WRITE_SIZE_MB} seek={WRITE_OFFSET_MB} oflag=direct"
                ))
                .unwrap();
            guest.ssh_command("sync").unwrap();

            // For QCOW2, measure file size after write to verify deallocation later
            let write_size = if qemu_img_format == "qcow2" {
                let res = exec_host_command_output(&format!(
                    "ls -s --block-size=1 {}",
                    test_disk_path.to_str().unwrap()
                ));
                assert!(res.status.success());
                String::from_utf8_lossy(&res.stdout)
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .expect("Failed to parse file size after write")
            } else {
                0
            };
            size_after_write.set(write_size);

            if expect_discard_success {
                for (i, (offset, length)) in discard_operations.iter().enumerate() {
                    let result = guest
                        .ssh_command(&format!(
                            "sudo blkdiscard -v -o {offset} -l {length} /dev/vdc 2>&1 || true"
                        ))
                        .unwrap();

                    assert!(
                        !result.contains("Operation not supported")
                            && !result.contains("BLKDISCARD"),
                        "blkdiscard #{i} at offset {offset} length {length} failed: {result}"
                    );
                }

                // Force sync to ensure async DISCARD operations complete
                guest.ssh_command("sync").unwrap();

                // Verify VM sees zeros in discarded regions
                for (offset, length) in discard_operations.iter() {
                    assert_guest_disk_region_is_zero(&guest, "/dev/vdc", *offset, *length);
                }

                guest.ssh_command("echo test").unwrap();
            } else {
                // For unsupported formats, blkdiscard should fail with "not supported"
                use test_infra::ssh_command_ip;
                let result = ssh_command_ip(
                    "sudo blkdiscard -o 0 -l 4096 /dev/vdc 2>&1",
                    &guest.network.guest_ip0,
                    0,
                    5,
                );
                assert!(
                    result.is_err(),
                    "blkdiscard should fail on unsupported format"
                );
                guest.ssh_command("echo test").unwrap();
            }

            if expect_discard_success {
                if qemu_img_format == "qcow2" {
                    let res = exec_host_command_output(&format!(
                        "ls -s --block-size=1 {}",
                        test_disk_path.to_str().unwrap()
                    ));
                    assert!(res.status.success());
                    let size_after_discard: u64 = String::from_utf8_lossy(&res.stdout)
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .expect("Failed to parse file size after discard");

                    assert!(
                        size_after_discard < size_after_write.get(),
                        "QCOW2 file should shrink after DISCARD with sparse=true: after_write={} bytes, after_discard={} bytes",
                        size_after_write.get(),
                        size_after_discard
                    );

                    verify_fiemap_extents(test_disk_path.to_str().unwrap(), "QCOW2");
                } else if qemu_img_format == "raw" {
                    let mut file = File::open(&test_disk_path)
                        .expect("Failed to open test disk for verification");

                    // Verify each discarded region contains all zeros
                    for (offset, length) in &discard_operations {
                        file.seek(SeekFrom::Start(*offset))
                            .expect("Failed to seek to discarded region");

                        let mut buffer = vec![0u8; *length as usize];
                        file.read_exact(&mut buffer)
                            .expect("Failed to read discarded region");

                        let all_zeros = buffer.iter().all(|&b| b == 0);
                        assert!(
                            all_zeros,
                            "Expected discarded region at offset {offset} length {length} to contain all zeros"
                        );
                    }

                    verify_sparse_file(test_disk_path.to_str().unwrap(), 1.0);

                    verify_fiemap_extents(test_disk_path.to_str().unwrap(), "RAW");
                }
            }
        }));

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        if verify_disk {
            disk_check_consistency(&test_disk_path, None);
        }
    }

    #[test]
    fn test_virtio_block_discard_qcow2() {
        _test_virtio_block_discard("qcow2", "qcow2", &[], true, true);
    }

    #[test]
    fn test_virtio_block_discard_raw() {
        _test_virtio_block_discard("raw", "raw", &[], true, false);
    }

    #[test]
    fn test_virtio_block_discard_raw_aio() {
        _test_virtio_block_discard_with_backend("raw", "raw", &[], true, false, true);
    }

    #[test]
    fn test_virtio_block_write_zeroes_unmap_raw() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let test_disk_path = guest.tmp_dir.as_path().join("write_zeroes_unmap_test.raw");

        let res = exec_host_command_output(&format!(
            "dd if=/dev/zero of={} bs=1M count=128",
            test_disk_path.to_str().unwrap()
        ));
        assert!(res.status.success(), "Failed to create raw test image");

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .default_kernel_cmdline()
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={},image_type=raw", test_disk_path.to_str().unwrap()).as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            let wz_max = guest
                .ssh_command("cat /sys/block/vdc/queue/write_zeroes_max_bytes")
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap_or_default();
            assert!(
                wz_max > 0,
                "write_zeroes_max_bytes={wz_max}, VIRTIO_BLK_F_WRITE_ZEROES not negotiated"
            );

            guest
                .ssh_command("sudo dd if=/dev/urandom of=/dev/vdc bs=1M count=64 oflag=direct")
                .unwrap();
            guest.ssh_command("sync").unwrap();

            // fallocate --punch-hole on a block device sends
            // WRITE_ZEROES with VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP set.
            let result = guest
                .ssh_command("sudo fallocate -p -o 0 -l 67108864 /dev/vdc 2>&1 || true")
                .unwrap();
            assert!(
                !result.contains("Operation not supported") && !result.contains("not supported"),
                "fallocate --punch-hole failed: {result}"
            );
            guest.ssh_command("sync").unwrap();

            assert_guest_disk_region_is_zero(&guest, "/dev/vdc", 0, 4096 * 256);

            let test_disk_str = test_disk_path.to_str().unwrap();
            verify_sparse_file(test_disk_str, 1.0);
            verify_fiemap_extents(test_disk_str, "raw");
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);
    }

    #[test]
    fn test_virtio_block_discard_unsupported_vhd() {
        _test_virtio_block_discard("vhd", "vpc", &["-o", "subformat=fixed"], false, false);
    }

    #[test]
    fn test_virtio_block_discard_unsupported_vhdx() {
        _test_virtio_block_discard("vhdx", "vhdx", &[], false, false);
    }

    #[test]
    fn test_virtio_block_discard_loop_device() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_disk_path = guest.tmp_dir.as_path().join("loop_discard_test.raw");
        let res = run_qemu_img(&test_disk_path, &["create", "-f", "raw"], Some(&["128M"]));
        assert!(
            res.status.success(),
            "Failed to create raw backing image: {}",
            String::from_utf8_lossy(&res.stderr)
        );

        let loop_dev = create_loop_device(test_disk_path.to_str().unwrap(), 4096, 5);

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=1"])
            .args(["--memory", "size=512M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={},image_type=raw", &loop_dev).as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            assert_eq!(
                guest
                    .ssh_command("lsblk -t | grep vdc | awk '{print $6}'")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4096
            );

            let discard_max = guest
                .ssh_command("cat /sys/block/vdc/queue/discard_max_bytes")
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap_or_default();
            assert!(
                discard_max > 0,
                "discard_max_bytes={discard_max}, VIRTIO_BLK_F_DISCARD not negotiated"
            );

            guest
                .ssh_command("sudo dd if=/dev/urandom of=/dev/vdc bs=4096 count=1024 oflag=direct")
                .unwrap();
            guest.ssh_command("sync").unwrap();

            let result = guest
                .ssh_command("sudo blkdiscard -v -o 0 -l 4194304 /dev/vdc 2>&1 || true")
                .unwrap();
            assert!(
                !result.contains("Operation not supported")
                    && !result.contains("BLKDISCARD ioctl failed"),
                "blkdiscard failed on loop device: {result}"
            );

            guest.ssh_command("sync").unwrap();

            assert_guest_disk_region_is_zero(&guest, "/dev/vdc", 0, 4194304);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        Command::new("losetup")
            .args(["-d", &loop_dev])
            .output()
            .expect("loop device not found");
    }

    #[test]
    fn test_virtio_block_discard_dm_snapshot() {
        // Verify that the guest remains stable when BLKDISCARD fails on the
        // host backend.  DM snapshot targets do not support discard, so the
        // VMM returns VIRTIO_BLK_S_IOERR.  The guest must handle this
        // gracefully even under repeated attempts.
        //
        // DM topology follows the same pattern used by WindowsDiskConfig.
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let origin_path = guest.tmp_dir.as_path().join("dm_origin.raw");
        let cow_path = guest.tmp_dir.as_path().join("dm_cow.raw");

        let res = run_qemu_img(&origin_path, &["create", "-f", "raw"], Some(&["128M"]));
        assert!(
            res.status.success(),
            "Failed to create origin image: {}",
            String::from_utf8_lossy(&res.stderr)
        );

        let cow_size: u64 = 128 << 20;
        let cow_sectors = cow_size / 512;
        let cow_file = File::create(&cow_path).expect("Expect creating COW image to succeed");
        cow_file
            .set_len(cow_size)
            .expect("Expect truncating COW image to succeed");

        let origin_sectors: u64 = 128 * 1024 * 1024 / 512;
        let origin_loop = create_loop_device(origin_path.to_str().unwrap(), 4096, 5);
        let cow_loop = create_loop_device(cow_path.to_str().unwrap(), 512, 5);

        let unique = format!(
            "ch-test-{}",
            guest
                .tmp_dir
                .as_path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        );
        let cow_dm_name = format!("{unique}-cow");
        let snap_dm_name = format!("{unique}-snap");

        let output = Command::new("dmsetup")
            .args([
                "create",
                &cow_dm_name,
                "--table",
                &format!("0 {cow_sectors} linear {cow_loop} 0"),
            ])
            .output()
            .expect("Failed to run dmsetup");
        assert!(
            output.status.success(),
            "dmsetup create (cow linear) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Command::new("dmsetup")
            .arg("mknodes")
            .output()
            .expect("dmsetup mknodes failed");

        // dm-snapshot: origin + COW, non-persistent, chunk size 8 sectors.
        let output = Command::new("dmsetup")
            .args([
                "create",
                &snap_dm_name,
                "--table",
                &format!("0 {origin_sectors} snapshot {origin_loop} /dev/mapper/{cow_dm_name} N 8"),
            ])
            .output()
            .expect("Failed to run dmsetup");
        assert!(
            output.status.success(),
            "dmsetup create (snapshot) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Command::new("dmsetup")
            .arg("mknodes")
            .output()
            .expect("dmsetup mknodes failed");

        let dm_dev = format!("/dev/mapper/{snap_dm_name}");

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=1"])
            .args(["--memory", "size=512M"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={},image_type=raw", &dm_dev).as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            let discard_max = guest
                .ssh_command("cat /sys/block/vdc/queue/discard_max_bytes")
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap_or_default();
            assert!(
                discard_max > 0,
                "discard_max_bytes={discard_max}, VIRTIO_BLK_F_DISCARD not negotiated"
            );

            guest
                .ssh_command("sudo dd if=/dev/urandom of=/dev/vdc bs=4096 count=1024 oflag=direct")
                .unwrap();
            guest.ssh_command("sync").unwrap();

            // Discard is expected to fail on DM snapshot because the
            // snapshot target does not support BLKDISCARD.
            for attempt in 1..=3 {
                let result = guest
                    .ssh_command("sudo blkdiscard -o 0 -l 4194304 /dev/vdc 2>&1; echo rc=$?")
                    .unwrap();
                println!("blkdiscard attempt {attempt}: {result}");

                let uptime = guest.ssh_command("uptime").unwrap();
                assert!(
                    !uptime.is_empty(),
                    "Guest unresponsive after blkdiscard attempt {attempt}"
                );
            }

            guest
                .ssh_command("sudo dd if=/dev/urandom of=/dev/vdc bs=4096 count=256 oflag=direct")
                .unwrap();
            let readback = guest
                .ssh_command("sudo dd if=/dev/vdc bs=4096 count=1 iflag=direct 2>/dev/null | od -A n -t x1 | head -1")
                .unwrap();
            assert!(
                !readback.trim().is_empty(),
                "Failed to read back from device after discard errors"
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let _ = Command::new("dmsetup")
            .args(["remove", &snap_dm_name])
            .output();
        let _ = Command::new("dmsetup")
            .args(["remove", &cow_dm_name])
            .output();
        let _ = Command::new("losetup").args(["-d", &origin_loop]).output();
        let _ = Command::new("losetup").args(["-d", &cow_loop]).output();
    }

    fn _test_virtio_block_fstrim(
        format_name: &str,
        qemu_img_format: &str,
        extra_create_args: &[&str],
        expect_fstrim_success: bool,
        verify_disk: bool,
    ) {
        _test_virtio_block_fstrim_with_backend(
            format_name,
            qemu_img_format,
            extra_create_args,
            expect_fstrim_success,
            verify_disk,
            false,
        );
    }

    fn _test_virtio_block_fstrim_with_backend(
        format_name: &str,
        qemu_img_format: &str,
        extra_create_args: &[&str],
        expect_fstrim_success: bool,
        verify_disk: bool,
        disable_io_uring: bool,
    ) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_disk_path = guest
            .tmp_dir
            .as_path()
            .join(format!("fstrim_test.{}", format_name.to_lowercase()));

        let mut cmd = format!("qemu-img create -f {qemu_img_format} ");
        if !extra_create_args.is_empty() {
            cmd.push_str(&extra_create_args.join(" "));
            cmd.push(' ');
        }
        cmd.push_str(&format!("{} 2G", test_disk_path.to_str().unwrap()));

        let res = exec_host_command_output(&cmd);
        assert!(
            res.status.success(),
            "Failed to create {format_name} test image"
        );

        const WRITE_SIZE_MB: u64 = 4;
        const CLUSTER_SIZE_BYTES: u64 = 64 * 1024;

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!(
                    "path={},num_queues=4,image_type={}{}",
                    test_disk_path.to_str().unwrap(),
                    format_name.to_lowercase(),
                    if disable_io_uring {
                        ",_disable_io_uring=on"
                    } else {
                        ""
                    }
                )
                .as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let max_size_during_writes = std::cell::Cell::new(0u64);

        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            guest.ssh_command("sudo mkfs.ext4 -F /dev/vdc").unwrap();

            guest
                .ssh_command("sudo mkdir -p /mnt/test && sudo mount /dev/vdc /mnt/test")
                .unwrap();

            for (iteration, &write_size_kb) in BLOCK_DISCARD_TEST_SIZES_KB.iter().enumerate() {
                guest
                    .ssh_command(&format!(
                        "sudo dd if=/dev/zero of=/mnt/test/testfile{iteration} bs=1K count={write_size_kb}"
                    ))
                    .unwrap();

                guest.ssh_command("sync").unwrap();

                // Measure QCOW2 file size after writing
                if qemu_img_format == "qcow2" {
                    let res = exec_host_command_output(&format!(
                        "ls -s --block-size=1 {}",
                        test_disk_path.to_str().unwrap()
                    ));
                    if res.status.success()
                        && let Some(size) = String::from_utf8_lossy(&res.stdout)
                            .split_whitespace()
                            .next()
                            .and_then(|s| s.parse::<u64>().ok())
                    {
                        max_size_during_writes.set(max_size_during_writes.get().max(size));
                    }
                }

                // Make blocks available for discard
                guest
                    .ssh_command(&format!("sudo rm /mnt/test/testfile{iteration}"))
                    .unwrap();

                guest.ssh_command("sync").unwrap();

                if expect_fstrim_success {
                    let fstrim_result = guest.ssh_command("sudo fstrim -v /mnt/test 2>&1").unwrap();

                    // Would output like "/mnt/test: X bytes (Y MB) trimmed"
                    assert!(
                        fstrim_result.contains("trimmed") || fstrim_result.contains("bytes"),
                        "fstrim iteration {iteration} ({write_size_kb}KB) should report trimmed bytes: {fstrim_result}"
                    );
                } else {
                    // For unsupported formats, expect fstrim to fail
                    use test_infra::ssh_command_ip;
                    let result = ssh_command_ip(
                        "sudo fstrim -v /mnt/test 2>&1",
                        &guest.network.guest_ip0,
                        0,
                        5,
                    );
                    assert!(result.is_err(), "fstrim should fail on unsupported format");
                    guest.ssh_command("echo 'VM responsive'").unwrap();
                }
            }

            guest.ssh_command("sudo umount /mnt/test").unwrap();

            guest.ssh_command("echo test").unwrap();
        }));

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        if expect_fstrim_success {
            if qemu_img_format == "qcow2" {
                // Verify QCOW2 file shrank after fstrim (sparse=true deallocates clusters)
                let res = exec_host_command_output(&format!(
                    "ls -s --block-size=1 {}",
                    test_disk_path.to_str().unwrap()
                ));
                assert!(res.status.success());
                let size_after_fstrim: u64 = String::from_utf8_lossy(&res.stdout)
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("Failed to parse file size after fstrim");

                assert!(
                    size_after_fstrim < max_size_during_writes.get(),
                    "QCOW2 file should shrink after fstrim with sparse=true: max_during_writes={} bytes, after_fstrim={} bytes",
                    max_size_during_writes.get(),
                    size_after_fstrim
                );
            } else if qemu_img_format == "raw" {
                verify_sparse_file(test_disk_path.to_str().unwrap(), 0.5);
            }
        }

        handle_child_output(r, &output);

        if verify_disk {
            disk_check_consistency(&test_disk_path, None);
        }
    }

    #[test]
    fn test_virtio_block_fstrim_qcow2() {
        _test_virtio_block_fstrim("qcow2", "qcow2", &[], true, true);
    }

    #[test]
    fn test_virtio_block_fstrim_raw() {
        _test_virtio_block_fstrim("raw", "raw", &[], true, false);
    }

    #[test]
    fn test_virtio_block_fstrim_raw_aio() {
        _test_virtio_block_fstrim_with_backend("raw", "raw", &[], true, false, true);
    }

    #[test]
    fn test_virtio_block_fstrim_unsupported_vhd() {
        _test_virtio_block_fstrim("vhd", "vpc", &["-o", "subformat=fixed"], false, false);
    }

    #[test]
    fn test_virtio_block_fstrim_unsupported_vhdx() {
        _test_virtio_block_fstrim("vhdx", "vhdx", &[], false, false);
    }

    #[test]
    #[ignore = "fallocate() preallocation requires native filesystem support (fails on overlay/tmpfs in CI)"]
    fn test_virtio_block_sparse_off_raw() {
        const TEST_DISK_SIZE: &str = "2G";
        const TEST_DISK_SIZE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
        const INITIAL_ALLOCATION_THRESHOLD: u64 = 1024 * 1024;

        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_disk_path = guest.tmp_dir.as_path().join("sparse_off_test.raw");
        let test_disk_path = test_disk_path.to_str().unwrap();

        let res =
            exec_host_command_output(&format!("truncate -s {TEST_DISK_SIZE} {test_disk_path}"));
        assert!(res.status.success(), "Failed to create sparse test file");

        let res = exec_host_command_output(&format!("ls -s --block-size=1 {test_disk_path}"));
        assert!(res.status.success());
        let initial_bytes: u64 = String::from_utf8_lossy(&res.stdout)
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse initial disk usage");
        assert!(
            initial_bytes < INITIAL_ALLOCATION_THRESHOLD,
            "File should be initially sparse: {initial_bytes} bytes allocated"
        );

        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={test_disk_path},sparse=off").as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        // After VM starts with sparse=off, verify file is fully allocated.
        // Strategy is to compare compare physical vs logical bytes
        // - physical >= logical is fully allocated, modulo block alignment
        // - physical < logical is still sparse

        let res = exec_host_command_output(&format!("ls -l {test_disk_path}"));
        assert!(res.status.success());
        let logical_size: u64 = String::from_utf8_lossy(&res.stdout)
            .split_whitespace()
            .nth(4)
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse logical size");

        let res = exec_host_command_output(&format!("ls -s --block-size=1 {test_disk_path}"));
        assert!(res.status.success());
        let physical_size: u64 = String::from_utf8_lossy(&res.stdout)
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse physical size");

        assert_eq!(
            logical_size, TEST_DISK_SIZE_BYTES,
            "Logical size should be exactly {TEST_DISK_SIZE_BYTES} bytes, got {logical_size}"
        );

        let res = exec_host_command_output(&format!("stat -c '%o' {test_disk_path}"));
        assert!(res.status.success());
        let block_size: u64 = String::from_utf8_lossy(&res.stdout)
            .trim()
            .parse()
            .expect("Failed to parse block size from stat");

        let expected_max = logical_size.div_ceil(block_size) * block_size;

        assert!(
            physical_size >= logical_size,
            "File should be fully allocated with sparse=off: logical={logical_size} bytes, physical={physical_size} bytes (physical < logical means still sparse)"
        );

        assert!(
            physical_size <= expected_max,
            "Physical size seems too large: logical={logical_size} bytes, physical={physical_size} bytes, expected_max={expected_max} bytes (block_size={block_size})"
        );
    }

    #[test]
    fn test_virtio_block_sparse_off_qcow2() {
        const TEST_DISK_SIZE: &str = "2G";

        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let test_disk_path = guest.tmp_dir.as_path().join("sparse_off_test.qcow2");
        let test_disk_path = test_disk_path.to_str().unwrap();

        let res = exec_host_command_output(&format!(
            "qemu-img create -f qcow2 {test_disk_path} {TEST_DISK_SIZE}"
        ));
        assert!(res.status.success(), "Failed to create QCOW2 test image");

        let zero_regions_before = count_qcow2_zero_regions(test_disk_path)
            .expect("Failed to get initial zero regions count");

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                format!("path={test_disk_path},sparse=off,num_queues=4").as_str(),
            ])
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c vdc")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // With sparse=off, DISCARD should NOT be advertised.
            // blkdiscard is expected to fail.
            let discard_result =
                guest.ssh_command("sudo blkdiscard -o 1048576 -l 1048576 /dev/vdc 2>&1; echo $?");
            let exit_code = discard_result
                .unwrap()
                .trim()
                .lines()
                .last()
                .unwrap_or("1")
                .parse::<u32>()
                .unwrap_or(1);
            assert_ne!(
                exit_code, 0,
                "blkdiscard should fail with sparse=off (DISCARD not advertised)"
            );

            // WRITE_ZEROES should still work via blkdiscard --zeroout
            guest
                .ssh_command(
                    "sudo dd if=/dev/urandom of=/dev/vdc bs=1K count=64 seek=1024 oflag=direct",
                )
                .unwrap();
            guest.ssh_command("sync").unwrap();
            guest
                .ssh_command("sudo blkdiscard -z -o 1048576 -l 65536 /dev/vdc")
                .unwrap();
            guest.ssh_command("sync").unwrap();

            assert_guest_disk_region_is_zero(&guest, "/dev/vdc", 1048576, 65536);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        let zero_regions_after = count_qcow2_zero_regions(test_disk_path)
            .expect("Failed to get final zero regions count");

        handle_child_output(r, &output);

        // WRITE_ZEROES should still produce zero-flagged regions
        assert!(
            zero_regions_after > zero_regions_before,
            "Expected zero-flagged regions to increase via WRITE_ZEROES: before={zero_regions_before}, after={zero_regions_after}"
        );

        disk_check_consistency(test_disk_path, None);
    }

    #[test]
    fn test_virtio_balloon_deflate_on_oom() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let kernel_path = direct_kernel_boot_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        //Let's start a 4G guest with balloon occupied 2G memory
        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket])
            .default_cpus()
            .args(["--memory", "size=4G"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(["--balloon", "size=2G,deflate_on_oom=on"])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Wait for balloon memory's initialization and check its size.
            // The virtio-balloon driver might take a few seconds to report the
            // balloon effective size back to the VMM.
            assert!(wait_until(Duration::from_secs(20), || {
                balloon_size(&api_socket) == 2147483648
            }));
            let orig_balloon = balloon_size(&api_socket);
            println!("The original balloon memory size is {orig_balloon} bytes");
            assert!(orig_balloon == 2147483648);

            // Two steps to verify if the 'deflate_on_oom' parameter works.
            // 1st: run a command to trigger an OOM in the guest.
            guest
                .ssh_command("echo f | sudo tee /proc/sysrq-trigger")
                .unwrap();

            // Give some time for the OOM to happen in the guest and be reported
            // back to the host.
            assert!(wait_until(Duration::from_secs(20), || {
                balloon_size(&api_socket) < 2147483648
            }));

            // 2nd: check balloon_mem's value to verify balloon has been automatically deflated
            let deflated_balloon = balloon_size(&api_socket);
            println!("After deflating, balloon memory size is {deflated_balloon} bytes");
            // Verify the balloon size deflated
            assert!(deflated_balloon < 2147483648);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See #7456
    fn test_virtio_balloon_free_page_reporting() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        //Let's start a 4G guest with balloon occupied 2G memory
        let mut child = GuestCommand::new(&guest)
            .default_cpus()
            .args(["--memory", "size=4G"])
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(["--balloon", "size=0,free_page_reporting=on"])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let pid = child.id();
        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Check the initial RSS is less than 1GiB
            let rss = process_rss_kib(pid);
            println!("RSS {rss} < 1048576");
            assert!(rss < 1048576);

            // Spawn a command inside the guest to consume 2GiB of RAM for 60
            // seconds
            let guest_ip = guest.network.guest_ip0.clone();
            thread::spawn(move || {
                ssh_command_ip(
                    "stress --vm 1 --vm-bytes 2G --vm-keep --timeout 60",
                    &guest_ip,
                    DEFAULT_SSH_RETRIES,
                    DEFAULT_SSH_TIMEOUT,
                )
                .unwrap();
            });

            // Wait for guest memory consumption to reach the expected level.
            assert!(wait_until(Duration::from_secs(60), || process_rss_kib(pid) >= 2097152));
            let rss = process_rss_kib(pid);
            println!("RSS {rss} >= 2097152");
            assert!(rss >= 2097152);

            // Wait for stress to complete and free-page reporting to shrink RSS again.
            assert!(wait_until(Duration::from_secs(120), || process_rss_kib(
                pid
            ) < 2097152));
            let rss = process_rss_kib(pid);
            println!("RSS {rss} < 2097152");
            assert!(rss < 2097152);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_pmem_hotplug() {
        _test_pmem_hotplug(None);
    }

    #[test]
    fn test_pmem_multi_segment_hotplug() {
        _test_pmem_hotplug(Some(15));
    }

    fn _test_pmem_hotplug(pci_segment: Option<u16>) {
        #[cfg(target_arch = "aarch64")]
        let focal_image = FOCAL_IMAGE_UPDATE_KERNEL_NAME.to_string();
        #[cfg(target_arch = "x86_64")]
        let focal_image = FOCAL_IMAGE_NAME.to_string();
        let disk_config = UbuntuDiskConfig::new(focal_image);
        let guest = Guest::new(Box::new(disk_config));

        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut cmd = GuestCommand::new(&guest);

        cmd.args(["--api-socket", &api_socket])
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .capture_output();

        if pci_segment.is_some() {
            cmd.args([
                "--platform",
                &format!("num_pci_segments={MAX_NUM_PCI_SEGMENTS}"),
            ]);
        }

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Check /dev/pmem0 is not there
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c pmem0 || true")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1),
                0
            );

            let pmem_temp_file = TempFile::new().unwrap();
            pmem_temp_file.as_file().set_len(128 << 20).unwrap();
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-pmem",
                Some(&format!(
                    "file={},id=test0{}",
                    pmem_temp_file.as_path().to_str().unwrap(),
                    if let Some(pci_segment) = pci_segment {
                        format!(",pci_segment={pci_segment}")
                    } else {
                        String::new()
                    }
                )),
            );
            assert!(cmd_success);
            if let Some(pci_segment) = pci_segment {
                assert!(String::from_utf8_lossy(&cmd_output).contains(&format!(
                    "{{\"id\":\"test0\",\"bdf\":\"{pci_segment:04x}:00:01.0\"}}"
                )));
            } else {
                assert!(
                    String::from_utf8_lossy(&cmd_output)
                        .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}")
                );
            }

            // Check that /dev/pmem0 exists and the block size is 128M
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            guest.reboot_linux(0);

            // Check still there after reboot
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            assert!(remote_command(&api_socket, "remove-device", Some("test0")));

            // Wait for the pmem device to disappear from lsblk.
            assert!(wait_until(Duration::from_secs(20), || {
                guest
                    .ssh_command("lsblk | grep -c pmem0.*128M || true")
                    .is_ok_and(|output| output.trim().parse::<u32>().unwrap_or(1) == 0)
            }));

            guest.reboot_linux(1);

            // Check still absent after reboot
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep -c pmem0.*128M || true")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1),
                0
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_net_hotplug() {
        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();
        let guest =
            basic_regular_guest!(JAMMY_IMAGE_NAME).with_kernel_path(kernel_path.to_str().unwrap());

        _test_net_hotplug(&guest, MAX_NUM_PCI_SEGMENTS, None);
    }

    #[test]
    fn test_net_multi_segment_hotplug() {
        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();
        let guest =
            basic_regular_guest!(JAMMY_IMAGE_NAME).with_kernel_path(kernel_path.to_str().unwrap());
        _test_net_hotplug(&guest, MAX_NUM_PCI_SEGMENTS, Some(15));
    }

    #[test]
    fn test_initramfs() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        #[cfg(target_arch = "x86_64")]
        let mut kernels = vec![direct_kernel_boot_path()];
        #[cfg(target_arch = "aarch64")]
        let kernels = [direct_kernel_boot_path()];

        #[cfg(target_arch = "x86_64")]
        {
            let mut pvh_kernel_path = workload_path.clone();
            pvh_kernel_path.push("vmlinux-x86_64");
            kernels.push(pvh_kernel_path);
        }

        let mut initramfs_path = workload_path;
        initramfs_path.push("alpine_initramfs.img");

        let test_string = String::from("axz34i9rylotd8n50wbv6kcj7f2qushme1pg");
        let cmdline = format!("console=hvc0 quiet TEST_STRING={test_string}");

        kernels.iter().for_each(|k_path| {
            let mut child = GuestCommand::new(&guest)
                .args(["--kernel", k_path.to_str().unwrap()])
                .args(["--initramfs", initramfs_path.to_str().unwrap()])
                .args(["--cmdline", &cmdline])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            kill_child(&mut child);
            let output = child.wait_with_output().unwrap();

            let r = std::panic::catch_unwind(|| {
                let s = String::from_utf8_lossy(&output.stdout);

                assert_ne!(s.lines().position(|line| line == test_string), None);
            });

            handle_child_output(r, &output);
        });
    }

    #[test]
    fn test_counters() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_counters(&guest);
    }

    #[test]
    #[cfg(feature = "guest_debug")]
    fn test_coredump() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut cmd = GuestCommand::new(&guest);
        cmd.args(["--cpus", "boot=4"])
            .args(["--memory", "size=1G"])
            .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
            .default_disks()
            .args(["--net", guest.default_net_string().as_str()])
            .args(["--api-socket", &api_socket])
            .capture_output();

        let mut child = cmd.spawn().unwrap();
        let vmcore_file = temp_vmcore_file_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(remote_command(&api_socket, "pause", None));

            assert!(remote_command(
                &api_socket,
                "coredump",
                Some(format!("file://{vmcore_file}").as_str()),
            ));

            // the num of CORE notes should equals to vcpu
            let readelf_core_num_cmd =
                format!("readelf --all {vmcore_file} |grep CORE |grep -v Type |wc -l");
            let core_num_in_elf = exec_host_command_output(&readelf_core_num_cmd);
            assert_eq!(String::from_utf8_lossy(&core_num_in_elf.stdout).trim(), "4");

            // the num of QEMU notes should equals to vcpu
            let readelf_vmm_num_cmd = format!("readelf --all {vmcore_file} |grep QEMU |wc -l");
            let vmm_num_in_elf = exec_host_command_output(&readelf_vmm_num_cmd);
            assert_eq!(String::from_utf8_lossy(&vmm_num_in_elf.stdout).trim(), "4");
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(feature = "guest_debug")]
    fn test_coredump_no_pause() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut cmd = GuestCommand::new(&guest);
        cmd.args(["--cpus", "boot=4"])
            .args(["--memory", "size=1G"])
            .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
            .default_disks()
            .args(["--net", guest.default_net_string().as_str()])
            .args(["--api-socket", &api_socket])
            .capture_output();

        let mut child = cmd.spawn().unwrap();
        let vmcore_file = temp_vmcore_file_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(remote_command(
                &api_socket,
                "coredump",
                Some(format!("file://{vmcore_file}").as_str()),
            ));

            assert_eq!(vm_state(&api_socket), "Running");
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_watchdog() {
        let guest = basic_regular_guest!(FOCAL_IMAGE_NAME);
        _test_watchdog(&guest);
    }

    #[test]
    fn test_pvpanic() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME);
        _test_pvpanic(&guest);
    }

    #[test]
    fn test_tap_from_fd() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_tap_from_fd(&guest);
    }

    #[test]
    #[cfg_attr(target_arch = "aarch64", ignore = "See #5443")]
    fn test_macvtap() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_macvtap(&guest, false, "guestmacvtap0", "hostmacvtap0");
    }

    #[test]
    #[cfg_attr(target_arch = "aarch64", ignore = "See #5443")]
    fn test_macvtap_hotplug() {
        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_macvtap(&guest, true, "guestmacvtap1", "hostmacvtap1");
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_ovs_dpdk() {
        let disk_config1 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest1 = Guest::new(Box::new(disk_config1));

        let disk_config2 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest2 = Guest::new(Box::new(disk_config2));
        let api_socket_source = format!("{}.1", temp_api_path(&guest2.tmp_dir));

        let (mut child1, mut child2) =
            setup_ovs_dpdk_guests(&guest1, &guest2, &api_socket_source, false);

        // Create the snapshot directory
        let snapshot_dir = temp_snapshot_dir_path(&guest2.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            // Remove one of the two ports from the OVS bridge
            assert!(exec_host_command_status("ovs-vsctl del-port vhost-user1").success());

            // Spawn a new netcat listener in the first VM
            let guest_ip = guest1.network.guest_ip0.clone();
            thread::spawn(move || {
                ssh_command_ip(
                    "nc -l 12345",
                    &guest_ip,
                    DEFAULT_SSH_RETRIES,
                    DEFAULT_SSH_TIMEOUT,
                )
                .unwrap();
            });

            guest1
                .wait_for_ssh_command(
                    "ss -ltnH | awk '{print $4}' | grep -q ':12345$'",
                    Duration::from_secs(20),
                )
                .unwrap();

            // Check the connection fails this time
            guest2.ssh_command("nc -vz 172.100.0.1 12345").unwrap_err();

            // Add the OVS port back
            assert!(exec_host_command_status("ovs-vsctl add-port ovsbr0 vhost-user1 -- set Interface vhost-user1 type=dpdkvhostuserclient options:vhost-server-path=/tmp/dpdkvhostclient1").success());

            // And finally check the connection is functional again
            guest2.ssh_command("nc -vz 172.100.0.1 12345").unwrap();

            // Pause the VM
            assert!(remote_command(&api_socket_source, "pause", None));

            // Take a snapshot from the VM
            assert!(remote_command(
                &api_socket_source,
                "snapshot",
                Some(format!("file://{snapshot_dir}").as_str()),
            ));

            // Wait for the source VM snapshot artifacts to be ready.
            assert!(wait_until(Duration::from_secs(10), || {
                std::path::Path::new(&snapshot_dir).exists()
            }));
        });

        // Shutdown the source VM
        kill_child(&mut child2);
        let output = child2.wait_with_output().unwrap();
        handle_child_output(r, &output);

        // Remove the vhost-user socket file.
        Command::new("rm")
            .arg("-f")
            .arg("/tmp/dpdkvhostclient2")
            .output()
            .unwrap();

        let api_socket_restored = format!("{}.2", temp_api_path(&guest2.tmp_dir));
        // Restore the VM from the snapshot
        let mut child2 = GuestCommand::new(&guest2)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--restore",
                format!("source_url=file://{snapshot_dir}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        // Wait for the restored VM to accept SSH again after resume.

        let r = std::panic::catch_unwind(|| {
            // Resume the VM
            assert!(wait_until(Duration::from_secs(30), || remote_command(
                &api_socket_restored,
                "info",
                None
            )));
            assert!(remote_command(&api_socket_restored, "resume", None));
            guest2.wait_for_ssh(Duration::from_secs(30)).unwrap();

            // Spawn a new netcat listener in the first VM
            let guest_ip = guest1.network.guest_ip0.clone();
            thread::spawn(move || {
                ssh_command_ip(
                    "nc -l 12345",
                    &guest_ip,
                    DEFAULT_SSH_RETRIES,
                    DEFAULT_SSH_TIMEOUT,
                )
                .unwrap();
            });

            guest1
                .wait_for_ssh_command(
                    "ss -ltnH | awk '{print $4}' | grep -q ':12345$'",
                    Duration::from_secs(20),
                )
                .unwrap();

            // And check the connection is still functional after restore
            guest2.ssh_command("nc -vz 172.100.0.1 12345").unwrap();
        });

        kill_child(&mut child1);
        kill_child(&mut child2);

        let output = child1.wait_with_output().unwrap();
        child2.wait().unwrap();

        cleanup_ovs_dpdk();

        handle_child_output(r, &output);
    }

    fn setup_spdk_nvme(nvme_dir: &std::path::Path) -> Child {
        cleanup_spdk_nvme();

        assert!(
            exec_host_command_status(&format!(
                "mkdir -p {}",
                nvme_dir.join("nvme-vfio-user").to_str().unwrap()
            ))
            .success()
        );
        assert!(
            exec_host_command_status(&format!(
                "truncate {} -s 128M",
                nvme_dir.join("test-disk.raw").to_str().unwrap()
            ))
            .success()
        );
        assert!(
            exec_host_command_status(&format!(
                "mkfs.ext4 {}",
                nvme_dir.join("test-disk.raw").to_str().unwrap()
            ))
            .success()
        );

        // Start the SPDK nvmf_tgt daemon to present NVMe device as a VFIO user device
        let child = Command::new("/usr/local/bin/spdk-nvme/nvmf_tgt")
            .args(["-i", "0", "-m", "0x1"])
            .spawn()
            .unwrap();
        thread::sleep(std::time::Duration::new(2, 0));

        assert!(exec_host_command_with_retries(
            "/usr/local/bin/spdk-nvme/rpc.py nvmf_create_transport -t VFIOUSER",
            3,
            std::time::Duration::new(5, 0),
        ));
        assert!(
            exec_host_command_status(&format!(
                "/usr/local/bin/spdk-nvme/rpc.py bdev_aio_create {} test 512",
                nvme_dir.join("test-disk.raw").to_str().unwrap()
            ))
            .success()
        );
        assert!(exec_host_command_status(
                "/usr/local/bin/spdk-nvme/rpc.py nvmf_create_subsystem nqn.2019-07.io.spdk:cnode -a -s test"
            )
            .success());
        assert!(exec_host_command_status(
            "/usr/local/bin/spdk-nvme/rpc.py nvmf_subsystem_add_ns nqn.2019-07.io.spdk:cnode test"
        )
        .success());
        assert!(exec_host_command_status(&format!(
                "/usr/local/bin/spdk-nvme/rpc.py nvmf_subsystem_add_listener nqn.2019-07.io.spdk:cnode -t VFIOUSER -a {} -s 0",
                nvme_dir.join("nvme-vfio-user").to_str().unwrap()
            ))
            .success());

        child
    }

    fn cleanup_spdk_nvme() {
        exec_host_command_status("pkill -f nvmf_tgt");
    }

    #[test]
    fn test_vfio_user() {
        let jammy_image = JAMMY_IMAGE_NAME.to_string();
        let disk_config = UbuntuDiskConfig::new(jammy_image);
        let guest = Guest::new(Box::new(disk_config));

        let spdk_nvme_dir = guest.tmp_dir.as_path().join("test-vfio-user");
        let mut spdk_child = setup_spdk_nvme(spdk_nvme_dir.as_path());

        let api_socket = temp_api_path(&guest.tmp_dir);
        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket])
            .default_cpus()
            .args(["--memory", "size=1G,shared=on,hugepages=on"])
            .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
            .args(["--serial", "tty", "--console", "off"])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Hotplug the SPDK-NVMe device to the VM
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-user-device",
                Some(&format!(
                    "socket={},id=vfio_user0",
                    spdk_nvme_dir
                        .as_path()
                        .join("nvme-vfio-user/cntrl")
                        .to_str()
                        .unwrap(),
                )),
            );
            assert!(cmd_success);
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"vfio_user0\",\"bdf\":\"0000:00:05.0\"}")
            );

            // Check both if /dev/nvme exists and if the block size is 128M.
            assert!(wait_until(Duration::from_secs(10), || {
                guest
                    .ssh_command("lsblk | grep nvme0n1 | grep -c 128M")
                    .ok()
                    .and_then(|output| output.trim().parse::<u32>().ok())
                    == Some(1)
            }));

            // Check changes persist after reboot
            assert_eq!(
                guest.ssh_command("sudo mount /dev/nvme0n1 /mnt").unwrap(),
                ""
            );
            assert_eq!(guest.ssh_command("ls /mnt").unwrap(), "lost+found\n");
            guest
                .ssh_command("echo test123 | sudo tee /mnt/test")
                .unwrap();
            assert_eq!(guest.ssh_command("sudo umount /mnt").unwrap(), "");
            assert_eq!(guest.ssh_command("ls /mnt").unwrap(), "");

            guest.reboot_linux(0);
            assert_eq!(
                guest.ssh_command("sudo mount /dev/nvme0n1 /mnt").unwrap(),
                ""
            );
            assert_eq!(
                guest.ssh_command("sudo cat /mnt/test").unwrap().trim(),
                "test123"
            );
        });

        let _ = spdk_child.kill();
        let _ = spdk_child.wait();

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_vdpa_block() {
        // Before trying to run the test, verify the vdpa_sim_blk module is correctly loaded.
        assert!(exec_host_command_status("lsmod | grep vdpa_sim_blk").success());

        let guest = basic_regular_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_vdpa_block(&guest);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_vdpa_net() {
        // Before trying to run the test, verify the vdpa_sim_net module is correctly loaded.
        if !exec_host_command_status("lsmod | grep vdpa_sim_net").success() {
            return;
        }

        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let kernel_path = direct_kernel_boot_path();

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=2"])
            .args(["--memory", "size=512M,hugepages=on"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args(["--vdpa", "path=/dev/vhost-vdpa-2,num_queues=3"])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Check we can find network interface related to vDPA device
            assert_eq!(
                guest
                    .ssh_command("ip -o link | grep -c ens6")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(0),
                1
            );

            guest
                .ssh_command("sudo ip link set dev ens6 address 00:e8:ca:33:ba:06")
                .unwrap();
            guest
                .ssh_command("sudo ip addr add 172.16.1.2/24 dev ens6")
                .unwrap();
            guest.ssh_command("sudo ip link set up dev ens6").unwrap();

            // Check there is no packet yet on both TX/RX of the network interface
            assert_eq!(
                guest
                    .ssh_command("ip -j -p -s link show ens6 | grep -c '\"packets\": 0'")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(0),
                2
            );

            // Send 6 packets with ping command
            guest.ssh_command("ping 172.16.1.10 -c 6 || true").unwrap();

            // Check we can find 6 packets on both TX/RX of the network interface
            assert_eq!(
                guest
                    .ssh_command("ip -j -p -s link show ens6 | grep -c '\"packets\": 6'")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(0),
                2
            );

            // No need to check for hotplug as we already tested it through
            // test_vdpa_block()
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See issue #7439
    #[cfg(target_arch = "x86_64")]
    fn test_tpm() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let (mut swtpm_command, swtpm_socket_path) = prepare_swtpm_daemon(&guest.tmp_dir);

        let mut guest_cmd = GuestCommand::new(&guest);
        guest_cmd
            .default_cpus()
            .args(["--memory", "size=1G"])
            .args(["--kernel", fw_path(FwType::RustHypervisorFirmware).as_str()])
            .args(["--tpm", &format!("socket={swtpm_socket_path}")])
            .capture_output()
            .default_disks()
            .default_net();

        // Start swtpm daemon
        let mut swtpm_child = swtpm_command.spawn().unwrap();
        assert!(wait_until(Duration::from_secs(10), || {
            std::path::Path::new(&swtpm_socket_path).exists()
        }));
        let mut child = guest_cmd.spawn().unwrap();
        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            assert_eq!(
                guest.ssh_command("ls /dev/tpm0").unwrap().trim(),
                "/dev/tpm0"
            );
            guest.ssh_command("sudo tpm2_selftest -f").unwrap();
            guest
                .ssh_command("echo 'hello' > /tmp/checksum_test;  ")
                .unwrap();
            guest.ssh_command("cmp <(sudo tpm2_pcrevent  /tmp/checksum_test | grep sha256 | awk '{print $2}') <(sha256sum /tmp/checksum_test| awk '{print $1}')").unwrap();
        });

        let _ = swtpm_child.kill();
        let _d_out = swtpm_child.wait_with_output().unwrap();

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_double_tty() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut cmd = GuestCommand::new(&guest);
        let api_socket = temp_api_path(&guest.tmp_dir);
        let tty_str: &str = "console=hvc0 earlyprintk=ttyS0 ";
        // linux printk module enable console log.
        let con_dis_str: &str = "console [hvc0] enabled";
        // linux printk module disable console log.
        let con_enb_str: &str = "bootconsole [earlyser0] disabled";

        let kernel_path = direct_kernel_boot_path();

        cmd.default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--cmdline",
                DIRECT_KERNEL_BOOT_CMDLINE
                    .replace("console=hvc0", tty_str)
                    .as_str(),
            ])
            .capture_output()
            .default_disks()
            .default_net()
            .args(["--serial", "tty"])
            .args(["--console", "tty"])
            .args(["--api-socket", &api_socket]);

        let mut child = cmd.spawn().unwrap();

        let mut r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        if r.is_ok() {
            r = std::panic::catch_unwind(|| {
                let s = String::from_utf8_lossy(&output.stdout);
                assert!(s.contains(tty_str));
                assert!(s.contains(con_dis_str));
                assert!(s.contains(con_enb_str));
            });
        }

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_nmi() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);
        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();
        let cmd_line = format!("{} {}", DIRECT_KERNEL_BOOT_CMDLINE, "unknown_nmi_panic=1");

        let mut cmd = GuestCommand::new(&guest);
        cmd.args(["--cpus", "boot=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", cmd_line.as_str()])
            .default_disks()
            .args(["--net", guest.default_net_string().as_str()])
            .args(["--pvpanic"])
            .args(["--api-socket", &api_socket])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert!(remote_command(&api_socket, "nmi", None));

            let expected_sequential_events = [&MetaEvent {
                event: "panic".to_string(),
                device_id: None,
            }];
            assert!(wait_until(Duration::from_secs(3), || {
                check_latest_events_exact(&expected_sequential_events, &event_path)
            }));
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_pci_device_id() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        // Boot without network
        let mut cmd = GuestCommand::new(&guest);

        cmd.args(["--api-socket", &api_socket])
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_net()
            .default_disks()
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        guest.wait_vm_boot().unwrap();

        // Add a network device with non-static device id request
        let r = std::panic::catch_unwind(|| {
            let (cmd_success, cmd_stdout, _) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test0,tap=,mac={},ip={},mask=255.255.255.128",
                        guest.network.guest_mac1, guest.network.host_ip1,
                    )
                    .as_str(),
                ),
            );
            assert!(cmd_success);
            // We now know the first free device ID on the bus
            let output = String::from_utf8(cmd_stdout).expect("should work");
            let (_, _, first_free_device_id, _) = bdf_from_hotplug_response(output.as_str());
            assert_ne!(first_free_device_id, 0);

            // Wait for the hotplugged device to appear in the guest
            assert!(wait_until(Duration::from_secs(10), || {
                ssh_command_ip_with_auth(
                    &format!("lspci -n | grep \"00:{first_free_device_id:02x}.0\""),
                    &default_guest_auth(),
                    &guest.network.guest_ip0,
                    Some(Duration::from_secs(1)),
                )
                .is_ok()
            }));
            // Calculate the succeeding device ID
            let device_id_to_allocate = first_free_device_id + 1;
            // We expect the succeeding device ID to be free.
            assert!(wait_until(Duration::from_secs(10), || {
                matches!(
                    ssh_command_ip_with_auth(
                        &format!("lspci -n | grep \"00:{device_id_to_allocate:02x}.0\""),
                        &default_guest_auth(),
                        &guest.network.guest_ip0,
                        Some(Duration::from_secs(5)),
                    ),
                    Err(SshCommandError::NonZeroExitStatus(1))
                )
            }));

            // Add a device to the next device slot explicitly
            let (cmd_success, cmd_stdout, _) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test1337,tap=,mac={},ip={},mask=255.255.255.128,pci_device_id={}",
                        guest.network.guest_mac1, guest.network.host_ip1, device_id_to_allocate,
                    )
                    .as_str(),
                ),
            );
            assert!(cmd_success);
            // Retrieve what BDF we actually reserved and assert it's equal to that we wanted to reserve
            let output = String::from_utf8(cmd_stdout).expect("should work");
            let (_, _, allocated_device_id, _) = bdf_from_hotplug_response(output.as_str());
            assert_eq!(device_id_to_allocate, allocated_device_id);
            // Wait for the hotplugged device to appear in the guest
            assert!(wait_until(Duration::from_secs(10), || {
                ssh_command_ip_with_auth(
                    &format!("lspci -n | grep \"00:{allocated_device_id:02x}.0\""),
                    &default_guest_auth(),
                    &guest.network.guest_ip0,
                    Some(Duration::from_secs(1)),
                )
                .is_ok()
            }));
            // Remove the first device to create a hole
            let cmd_success = remote_command(&api_socket, "remove-device", Some("test0"));
            assert!(cmd_success);
            // Wait for the device to disappear from the guest
            assert!(wait_until(Duration::from_secs(10), || {
                matches!(
                    ssh_command_ip_with_auth(
                        &format!("lspci -n | grep \"00:{first_free_device_id:02x}.0\""),
                        &default_guest_auth(),
                        &guest.network.guest_ip0,
                        Some(Duration::from_secs(1)),
                    ),
                    Err(SshCommandError::NonZeroExitStatus(1))
                )
            }));
            // Reuse the device ID hole by dynamically coalescing with the first free ID
            let (cmd_success, cmd_stdout, _) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test0,tap=,mac={},ip={},mask=255.255.255.128",
                        guest.network.guest_mac1, guest.network.host_ip1,
                    )
                    .as_str(),
                ),
            );
            assert!(cmd_success);
            // Check that CHV reports that we added the same device to the same ID
            let output = String::from_utf8(cmd_stdout).expect("should work");
            let (_, _, allocated_device_id, _) = bdf_from_hotplug_response(output.as_str());
            assert_eq!(first_free_device_id, allocated_device_id);

            // Wait for the re-added device to appear in the guest
            assert!(wait_until(Duration::from_secs(10), || {
                ssh_command_ip_with_auth(
                    &format!("lspci -n | grep \"00:{allocated_device_id:02x}.0\""),
                    &default_guest_auth(),
                    &guest.network.guest_ip0,
                    Some(Duration::from_secs(1)),
                )
                .is_ok()
            }));
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    // Test that adding a duplicate PCI device ID fails
    fn test_duplicate_pci_device_id() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        // Boot without network
        let mut cmd = GuestCommand::new(&guest);

        cmd.args(["--api-socket", &api_socket])
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_net()
            .default_disks()
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        guest.wait_vm_boot().unwrap();

        // Add a network device with non-static device ID request
        let r = std::panic::catch_unwind(|| {
            let (cmd_success, cmd_stdout, _) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test0,tap=,mac={},ip={},mask=255.255.255.128",
                        guest.network.guest_mac1, guest.network.host_ip1,
                    )
                    .as_str(),
                ),
            );
            assert!(cmd_success);

            // We now know the first free device ID on the bus
            let output = String::from_utf8(cmd_stdout).expect("should work");
            let (_, _, first_free_device_id, _) = bdf_from_hotplug_response(output.as_str());
            assert_ne!(first_free_device_id, 0);

            let (cmd_success, _, cmd_stderr) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test1337,tap=,mac={},ip={},mask=255.255.255.128,pci_device_id={first_free_device_id}",
                        guest.network.guest_mac1, guest.network.host_ip1,
                    )
                    .as_str(),
                ),
            );
            // Check for fail; Allocating the same device ID for two devices is disallowed
            assert!(!cmd_success);
            // Check that the error message contains the expected error
            let std_err_str = String::from_utf8(cmd_stderr).unwrap();
            assert!(
                std_err_str.contains(&format!(
                    "Valid PCI device identifier but already used: {first_free_device_id}"
                )),
                "Command return was: {std_err_str}"
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    // Test that requesting an invalid device ID fails.
    fn test_invalid_pci_device_id() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        #[cfg(target_arch = "x86_64")]
        let kernel_path = direct_kernel_boot_path();
        #[cfg(target_arch = "aarch64")]
        let kernel_path = edk2_path();

        let api_socket = temp_api_path(&guest.tmp_dir);

        // Boot without network
        let mut cmd = GuestCommand::new(&guest);

        cmd.args(["--api-socket", &api_socket])
            .default_cpus()
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_net()
            .default_disks()
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        guest.wait_vm_boot().unwrap();

        let r = std::panic::catch_unwind(|| {
            // Invalid API call because the PCI device ID is out of range
            let (cmd_success, _, cmd_stderr) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test0,tap=,mac={},ip={},mask=255.255.255.128,pci_device_id=188",
                        guest.network.guest_mac1, guest.network.host_ip1,
                    )
                    .as_str(),
                ),
            );
            // Check for fail
            assert!(!cmd_success);
            // Check that the error message contains the expected error
            let std_err_str = String::from_utf8(cmd_stderr).unwrap();
            assert!(
                std_err_str
                    .contains("Given PCI device ID (188) is out of the supported range of 0..32"),
                "Command return was: {std_err_str}",
            );

            // Use the reserved device ID 0 (root device)
            let (cmd_success, _, cmd_stderr) = remote_command_w_output(
                &api_socket,
                "add-net",
                Some(
                    format!(
                        "id=test0,tap=,mac={},ip={},mask=255.255.255.128,pci_device_id=0",
                        guest.network.guest_mac1, guest.network.host_ip1,
                    )
                    .as_str(),
                ),
            );
            // Check for fail
            assert!(!cmd_success);
            // Check that the error message contains the expected error
            let std_err_str = String::from_utf8(cmd_stderr).unwrap();
            assert!(
                std_err_str.contains("Given PCI device ID (0) is reserved"),
                "Command return was: {std_err_str}"
            );
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }
}

mod dbus_api {
    use crate::*;

    // Start cloud-hypervisor with no VM parameters, running both the HTTP
    // and DBus APIs. Alternate calls to the external APIs (HTTP and DBus)
    // to create a VM, boot it, and verify that it can be shut down and then
    // booted again.
    #[test]
    fn test_api_dbus_and_http_interleaved() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let dbus_api = TargetApi::new_dbus_api(&guest.tmp_dir);
        let http_api = TargetApi::new_http_api(&guest.tmp_dir);

        let mut child = GuestCommand::new(&guest)
            .args(dbus_api.guest_args())
            .args(http_api.guest_args())
            .capture_output()
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(1, 0));

        // Verify API servers are running
        assert!(dbus_api.remote_command("ping", None));
        assert!(http_api.remote_command("ping", None));

        // Create the VM first
        let request_body = guest.api_create_body();

        let temp_config_path = guest.tmp_dir.as_path().join("config");
        std::fs::write(&temp_config_path, request_body).unwrap();
        let create_config = temp_config_path.as_os_str().to_str().unwrap();

        let r = std::panic::catch_unwind(|| {
            // Create the VM
            assert!(dbus_api.remote_command("create", Some(create_config),));

            // Then boot it
            assert!(http_api.remote_command("boot", None));
            guest.wait_vm_boot().unwrap();

            // Check that the VM booted as expected
            guest.validate_cpu_count(None);
            guest.validate_memory(None);

            // Sync and shutdown without powering off to prevent filesystem
            // corruption.
            guest.ssh_command("sync").unwrap();
            guest.ssh_command("sudo shutdown -H now").unwrap();

            // Wait for the guest to be fully shutdown
            assert!(guest.wait_for_ssh_unresponsive(Duration::from_secs(20)));

            // Then shutdown the VM
            assert!(dbus_api.remote_command("shutdown", None));

            // Then boot it again
            assert!(http_api.remote_command("boot", None));
            guest.wait_vm_boot().unwrap();

            // Check that the VM booted as expected
            guest.validate_cpu_count(None);
            guest.validate_memory(None);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    fn test_api_dbus_create_boot() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_regular_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);

        let target_api = TargetApi::new_dbus_api(&guest.tmp_dir);
        _test_api_create_boot(&target_api, &guest);
    }

    #[test]
    fn test_api_dbus_shutdown() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_regular_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);

        let target_api = TargetApi::new_dbus_api(&guest.tmp_dir);
        _test_api_shutdown(&target_api, &guest);
    }

    #[test]
    fn test_api_dbus_delete() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_regular_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);

        let target_api = TargetApi::new_dbus_api(&guest.tmp_dir);
        _test_api_delete(&target_api, &guest);
    }

    #[test]
    fn test_api_dbus_pause_resume() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_regular_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);

        let target_api = TargetApi::new_dbus_api(&guest.tmp_dir);
        _test_api_pause_resume(&target_api, &guest);
    }
}

mod ivshmem {
    #[cfg(not(feature = "mshv"))]
    use std::fs::remove_dir_all;
    use std::process::Command;

    use test_infra::{Guest, GuestCommand, UbuntuDiskConfig, handle_child_output, kill_child};

    use crate::*;

    fn _test_live_migration_ivshmem(local: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );

        let memory_param: &[&str] = if local {
            &["--memory", "size=4G,shared=on"]
        } else {
            &["--memory", "size=4G"]
        };

        let boot_vcpus = 2;
        let max_vcpus = 4;

        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();
        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
            .output()
            .expect("Expect creating disk image to succeed");
        let pmem_path = String::from("/dev/pmem0");

        let ivshmem_file_path = String::from(
            guest
                .tmp_dir
                .as_path()
                .join("ivshmem.data")
                .to_str()
                .unwrap(),
        );
        let file_size = "1M";

        // Create a file to be used as the shared memory
        Command::new("dd")
            .args([
                "if=/dev/zero",
                format!("of={ivshmem_file_path}").as_str(),
                format!("bs={file_size}").as_str(),
                "count=1",
            ])
            .status()
            .unwrap();

        // Start the source VM
        let src_vm_path = clh_command("cloud-hypervisor");
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .args([
                "--pmem",
                format!("file={}", pmem_temp_file.as_path().to_str().unwrap(),).as_str(),
            ])
            .args([
                "--ivshmem",
                format!("path={ivshmem_file_path},size={file_size}").as_str(),
            ]);
        let mut src_child = src_vm_cmd.capture_output().spawn().unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Make sure the source VM is functional
            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);
            // Check the guest virtio-devices, e.g. block, rng, console, and net
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));
            // x86_64: Following what's done in the `test_snapshot_restore`, we need
            // to make sure that removing and adding back the virtio-net device does
            // not break the live-migration support for virtio-pci.
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &src_api_socket,
                    "remove-device",
                    Some(net_id),
                ));
                thread::sleep(Duration::new(10, 0));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &src_api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                thread::sleep(Duration::new(10, 0));
            }

            // Check ivshmem device in src guest.
            _test_ivshmem(&guest, &ivshmem_file_path, file_size);
            // Allow some normal time to elapse to check we don't get spurious reboots
            thread::sleep(std::time::Duration::new(40, 0));

            // Start the live-migration
            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                live_migration::start_live_migration(
                    &migration_socket,
                    &src_api_socket,
                    &dest_api_socket,
                    local
                ),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            live_migration::print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            live_migration::print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functional
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);

            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // Check ivshmem device
            _test_ivshmem(&guest, &ivshmem_file_path, file_size);
        });

        // Clean-up the destination VM and make sure it terminated correctly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);

        // Check the destination VM has the expected 'console_text' from its output
        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&dest_output.stdout).contains(&console_text));
        });
        handle_child_output(r, &dest_output);
    }

    #[test]
    fn test_ivshmem() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();

        let ivshmem_file_path = String::from(
            guest
                .tmp_dir
                .as_path()
                .join("ivshmem.data")
                .to_str()
                .unwrap(),
        );
        let file_size = "1M";

        // Create a file to be used as the shared memory
        Command::new("dd")
            .args([
                "if=/dev/zero",
                format!("of={ivshmem_file_path}").as_str(),
                format!("bs={file_size}").as_str(),
                "count=1",
            ])
            .status()
            .unwrap();

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", "boot=2"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args([
                "--ivshmem",
                format!("path={ivshmem_file_path},size={file_size}").as_str(),
            ])
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            _test_ivshmem(&guest, &ivshmem_file_path, file_size);
        });
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_ivshmem() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let api_socket_source = format!("{}.1", temp_api_path(&guest.tmp_dir));

        let ivshmem_file_path = String::from(
            guest
                .tmp_dir
                .as_path()
                .join("ivshmem.data")
                .to_str()
                .unwrap(),
        );
        let file_size = "1M";

        // Create a file to be used as the shared memory
        Command::new("dd")
            .args([
                "if=/dev/zero",
                format!("of={ivshmem_file_path}").as_str(),
                format!("bs={file_size}").as_str(),
                "count=1",
            ])
            .status()
            .unwrap();

        let socket = temp_vsock_path(&guest.tmp_dir);
        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_source])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .args(["--cpus", "boot=2"])
            .args(["--memory", "size=1G"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .default_disks()
            .default_net()
            .args(["--vsock", format!("cid=3,socket={socket}").as_str()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--ivshmem",
                format!("path={ivshmem_file_path},size={file_size}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let console_text = String::from("On a branch floating down river a cricket, singing.");
        // Create the snapshot directory
        let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);

            snapshot_restore_common::snapshot_and_check_events(
                &api_socket_source,
                &snapshot_dir,
                &event_path,
            );
        });

        // Shutdown the source VM and check console output
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        // Remove the vsock socket file.
        Command::new("rm")
            .arg("-f")
            .arg(socket.as_str())
            .output()
            .unwrap();

        let api_socket_restored = format!("{}.2", temp_api_path(&guest.tmp_dir));
        let event_path_restored = format!("{}.2", temp_event_monitor_path(&guest.tmp_dir));

        // Restore the VM from the snapshot
        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--event-monitor",
                format!("path={event_path_restored}").as_str(),
            ])
            .args([
                "--restore",
                format!("source_url=file://{snapshot_dir}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let latest_events = [&MetaEvent {
            event: "restored".to_string(),
            device_id: None,
        }];
        // Wait for the restored event to show up in the monitor file.
        assert!(wait_until(Duration::from_secs(30), || {
            check_latest_events_exact(&latest_events, &event_path_restored)
        }));

        // Remove the snapshot dir
        let _ = remove_dir_all(snapshot_dir.as_str());

        let r = std::panic::catch_unwind(|| {
            // Resume the VM
            assert!(wait_until(Duration::from_secs(30), || remote_command(
                &api_socket_restored,
                "info",
                None
            )));
            assert!(remote_command(&api_socket_restored, "resume", None));
            let latest_events = [
                &MetaEvent {
                    event: "resuming".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "resumed".to_string(),
                    device_id: None,
                },
            ];
            assert!(wait_until(Duration::from_secs(30), || {
                check_latest_events_exact(&latest_events, &event_path_restored)
            }));

            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);
            guest.check_devices_common(Some(&socket), Some(&console_text), None);
            _test_ivshmem(&guest, &ivshmem_file_path, file_size);
        });
        // Shutdown the target VM and check console output
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_live_migration_ivshmem() {
        _test_live_migration_ivshmem(false);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_live_migration_ivshmem_local() {
        _test_live_migration_ivshmem(true);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_hotplug_virtiomem() {
        snapshot_restore_common::_test_snapshot_restore(true, false);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See issue #7437
    fn test_snapshot_restore_basic() {
        snapshot_restore_common::_test_snapshot_restore(false, false);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_with_resume() {
        snapshot_restore_common::_test_snapshot_restore(false, true);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_uffd() {
        snapshot_restore_common::_test_snapshot_restore_uffd("size=2G", &[], 1_920_000);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_uffd_shared_memory() {
        snapshot_restore_common::_test_snapshot_restore_uffd("size=512M,shared=on", &[], 480_000);
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See issue #7437
    #[cfg(target_arch = "x86_64")]
    fn test_snapshot_restore_pvpanic() {
        snapshot_restore_common::_test_snapshot_restore_devices(true);
    }

    #[test]
    fn test_virtio_pmem_persist_writes() {
        test_virtio_pmem(false, false);
    }
}

#[cfg(not(feature = "mshv"))]
mod snapshot_restore_common {
    use std::fs::remove_dir_all;
    use std::process::Command;

    use crate::*;

    pub(crate) fn snapshot_and_check_events(
        api_socket: &str,
        snapshot_dir: &str,
        event_path: &str,
    ) {
        // Pause the VM
        assert!(remote_command(api_socket, "pause", None));
        let latest_events: [&MetaEvent; 2] = [
            &MetaEvent {
                event: "pausing".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "paused".to_string(),
                device_id: None,
            },
        ];

        assert!(wait_until(Duration::from_secs(30), || {
            check_latest_events_exact(&latest_events, event_path)
        }));

        // Take a snapshot from the VM
        assert!(remote_command(
            api_socket,
            "snapshot",
            Some(format!("file://{snapshot_dir}").as_str()),
        ));

        let latest_events = [
            &MetaEvent {
                event: "snapshotting".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "snapshotted".to_string(),
                device_id: None,
            },
        ];

        assert!(wait_until(Duration::from_secs(30), || {
            check_latest_events_exact(&latest_events, event_path)
        }));
    }

    pub(crate) fn _test_snapshot_restore(use_hotplug: bool, use_resume_option: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let api_socket_source = format!("{}.1", temp_api_path(&guest.tmp_dir));

        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );
        let mut mem_params = "size=1G";

        if use_hotplug {
            mem_params = "size=2G,hotplug_method=virtio-mem,hotplug_size=32G";
        }

        let cloudinit_params = format!(
            "path={},iommu=on",
            guest.disk_config.disk(DiskType::CloudInit).unwrap()
        );

        let socket = temp_vsock_path(&guest.tmp_dir);
        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_source])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .args(["--cpus", "boot=4"])
            .args(["--memory", mem_params])
            .args(["--balloon", "size=0"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                cloudinit_params.as_str(),
            ])
            .args(["--net", net_params.as_str()])
            .args(["--vsock", format!("cid=3,socket={socket}").as_str()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .capture_output()
            .spawn()
            .unwrap();

        let console_text = String::from("On a branch floating down river a cricket, singing.");
        // Create the snapshot directory
        let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 4);
            // Check the guest RAM
            let total_memory = guest.get_total_memory().unwrap_or_default();
            if use_hotplug {
                assert!(total_memory > 1_900_000, "total memory: {total_memory}");
            } else {
                assert!(total_memory > 900_000, "total memory: {total_memory}");
            }
            if use_hotplug {
                // Increase guest RAM with virtio-mem
                resize_command(
                    &api_socket_source,
                    None,
                    Some(6 << 30),
                    None,
                    Some(&event_path),
                );
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);
                // Use balloon to remove RAM from the VM
                resize_command(
                    &api_socket_source,
                    None,
                    None,
                    Some(1 << 30),
                    Some(&event_path),
                );
                thread::sleep(std::time::Duration::new(5, 0));
                let total_memory = guest.get_total_memory().unwrap_or_default();
                assert!(total_memory > 4_800_000, "total_memory is {total_memory}");
                assert!(total_memory < 5_760_000, "total_memory is {total_memory}");
            }
            // Check the guest virtio-devices, e.g. block, rng, vsock, console, and net
            guest.check_devices_common(Some(&socket), Some(&console_text), None);

            // x86_64: We check that removing and adding back the virtio-net device
            // does not break the snapshot/restore support for virtio-pci.
            // This is an important thing to test as the hotplug will
            // trigger a PCI BAR reprogramming, which is a good way of
            // checking if the stored resources are correctly restored.
            // Unplug the virtio-net device
            // AArch64: Device hotplug is currently not supported, skipping here.
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &api_socket_source,
                    "remove-device",
                    Some(net_id),
                ));
                thread::sleep(std::time::Duration::new(10, 0));
                let latest_events = [&MetaEvent {
                    event: "device-removed".to_string(),
                    device_id: Some(net_id.to_string()),
                }];
                assert!(wait_until(Duration::from_secs(30), || {
                    check_latest_events_exact(&latest_events, &event_path)
                }));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &api_socket_source,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                thread::sleep(std::time::Duration::new(10, 0));
            }

            snapshot_restore_common::snapshot_and_check_events(
                &api_socket_source,
                &snapshot_dir,
                &event_path,
            );
        });

        // Shutdown the source VM and check console output
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });

        handle_child_output(r, &output);

        // Remove the vsock socket file.
        Command::new("rm")
            .arg("-f")
            .arg(socket.as_str())
            .output()
            .unwrap();

        let api_socket_restored = format!("{}.2", temp_api_path(&guest.tmp_dir));
        let event_path_restored = format!("{}.2", temp_event_monitor_path(&guest.tmp_dir));

        // Restore the VM from the snapshot
        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--event-monitor",
                format!("path={event_path_restored}").as_str(),
            ])
            .args([
                "--restore",
                format!("source_url=file://{snapshot_dir},resume={use_resume_option}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let expected_events = [
            &MetaEvent {
                event: "starting".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "activated".to_string(),
                device_id: Some("__console".to_string()),
            },
            &MetaEvent {
                event: "activated".to_string(),
                device_id: Some("__rng".to_string()),
            },
            &MetaEvent {
                event: "restoring".to_string(),
                device_id: None,
            },
        ];
        assert!(wait_until(Duration::from_secs(30), || {
            check_sequential_events(&expected_events, &event_path_restored)
        }));
        if use_resume_option {
            let latest_events = [
                &MetaEvent {
                    event: "restored".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "resuming".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "resumed".to_string(),
                    device_id: None,
                },
            ];
            assert!(wait_until(Duration::from_secs(30), || {
                check_latest_events_exact(&latest_events, &event_path_restored)
            }));
        } else {
            let latest_events = [&MetaEvent {
                event: "restored".to_string(),
                device_id: None,
            }];
            assert!(wait_until(Duration::from_secs(30), || {
                check_latest_events_exact(&latest_events, &event_path_restored)
            }));
        }

        // Wait until the restored VM API is ready before issuing follow-up requests.
        assert!(wait_until(Duration::from_secs(30), || remote_command(
            &api_socket_restored,
            "info",
            None
        )));

        // Remove the snapshot dir
        let _ = remove_dir_all(snapshot_dir.as_str());

        let r = std::panic::catch_unwind(|| {
            if use_resume_option {
                // VM was automatically resumed via restore option, just wait for events
                thread::sleep(std::time::Duration::new(1, 0));
            } else {
                // Resume the VM manually
                assert!(wait_until(Duration::from_secs(30), || remote_command(
                    &api_socket_restored,
                    "info",
                    None
                )));
                assert!(remote_command(&api_socket_restored, "resume", None));

                let latest_events = [
                    &MetaEvent {
                        event: "resuming".to_string(),
                        device_id: None,
                    },
                    &MetaEvent {
                        event: "resumed".to_string(),
                        device_id: None,
                    },
                ];
                assert!(wait_until(Duration::from_secs(30), || {
                    check_latest_events_exact(&latest_events, &event_path_restored)
                }));
            }

            // Perform same checks to validate VM has been properly restored
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 4);
            let total_memory = guest.get_total_memory().unwrap_or_default();
            if use_hotplug {
                assert!(total_memory > 4_800_000, "total_memory is {total_memory}");
                assert!(total_memory < 5_760_000, "total_memory is {total_memory}");
                // Deflate balloon to restore entire RAM to the VM
                resize_command(&api_socket_restored, None, None, Some(0), None);
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);
                // Decrease guest RAM with virtio-mem
                resize_command(&api_socket_restored, None, Some(5 << 30), None, None);
                thread::sleep(std::time::Duration::new(5, 0));
                let total_memory = guest.get_total_memory().unwrap_or_default();
                assert!(total_memory > 4_800_000, "total_memory is {total_memory}");
                assert!(total_memory < 5_760_000, "total_memory is {total_memory}");
            } else {
                assert!(total_memory > 900_000, "total memory: {total_memory}");
            }

            guest.check_devices_common(Some(&socket), Some(&console_text), None);
        });
        // Shutdown the target VM and check console output
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });

        handle_child_output(r, &output);
    }

    pub(crate) fn _test_snapshot_restore_uffd(
        memory_config: &str,
        memory_zone_config: &[&str],
        min_total_memory_kib: u32,
    ) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let api_socket_source = format!("{}.1", temp_api_path(&guest.tmp_dir));

        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);
        let socket = temp_vsock_path(&guest.tmp_dir);
        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let mut source_cmd = GuestCommand::new(&guest);
        source_cmd
            .args(["--api-socket", &api_socket_source])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .args(["--cpus", "boot=4"])
            .args(["--memory", memory_config]);

        if !memory_zone_config.is_empty() {
            source_cmd.args(["--memory-zone"]).args(memory_zone_config);
        }

        let mut child = source_cmd
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args(["--vsock", format!("cid=3,socket={socket}").as_str()])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 4);
            assert!(guest.get_total_memory().unwrap_or_default() > min_total_memory_kib);

            guest.check_devices_common(Some(&socket), Some(&console_text), None);

            snapshot_and_check_events(&api_socket_source, &snapshot_dir, &event_path);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });
        handle_child_output(r, &output);

        Command::new("rm")
            .arg("-f")
            .arg(socket.as_str())
            .output()
            .unwrap();

        let api_socket_restored = format!("{}.2", temp_api_path(&guest.tmp_dir));
        let event_path_restored = format!("{}.2", temp_event_monitor_path(&guest.tmp_dir));

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--event-monitor",
                format!("path={event_path_restored}").as_str(),
            ])
            .args([
                "--restore",
                format!("source_url=file://{snapshot_dir},memory_restore_mode=ondemand").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let latest_events = [&MetaEvent {
            event: "restored".to_string(),
            device_id: None,
        }];

        assert!(wait_until(Duration::from_secs(30), || {
            check_latest_events_exact(&latest_events, &event_path_restored)
        }));

        let r = std::panic::catch_unwind(|| {
            assert!(wait_until(Duration::from_secs(30), || remote_command(
                &api_socket_restored,
                "info",
                None
            )));
            assert!(remote_command(&api_socket_restored, "resume", None));

            let latest_events = [
                &MetaEvent {
                    event: "resuming".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "resumed".to_string(),
                    device_id: None,
                },
            ];
            assert!(wait_until(Duration::from_secs(30), || {
                check_latest_events_exact(&latest_events, &event_path_restored)
            }));

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 4);
            assert!(guest.get_total_memory().unwrap_or_default() > min_total_memory_kib);

            guest.check_devices_common(Some(&socket), Some(&console_text), None);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));

            let logs = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                logs.contains("UFFD restore: demand-paged restore enabled"),
                "Expected UFFD restore path to be enabled. output: {logs}"
            );
        });
        handle_child_output(r, &output);

        let _ = remove_dir_all(snapshot_dir.as_str());
    }

    pub(crate) fn _test_snapshot_restore_devices(pvpanic: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let api_socket_source = format!("{}.1", temp_api_path(&guest.tmp_dir));

        let device_params = {
            let mut data = vec![];
            if pvpanic {
                data.push(String::from("--pvpanic"));
            }
            data
        };

        let socket = temp_vsock_path(&guest.tmp_dir);
        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_source])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .args(["--cpus", "boot=2"])
            .args(["--memory", "size=1G"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .default_disks()
            .default_net()
            .args(["--vsock", format!("cid=3,socket={socket}").as_str()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(device_params)
            .capture_output()
            .spawn()
            .unwrap();

        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);

            snapshot_and_check_events(&api_socket_source, &snapshot_dir, &event_path);
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        Command::new("rm")
            .arg("-f")
            .arg(socket.as_str())
            .output()
            .unwrap();

        let api_socket_restored = format!("{}.2", temp_api_path(&guest.tmp_dir));
        let event_path_restored = format!("{}.2", temp_event_monitor_path(&guest.tmp_dir));

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--event-monitor",
                format!("path={event_path_restored}").as_str(),
            ])
            .args([
                "--restore",
                format!("source_url=file://{snapshot_dir}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        let latest_events = [&MetaEvent {
            event: "restored".to_string(),
            device_id: None,
        }];
        assert!(wait_until(Duration::from_secs(30), || {
            check_latest_events_exact(&latest_events, &event_path_restored)
        }));

        let _ = remove_dir_all(snapshot_dir.as_str());

        let r = std::panic::catch_unwind(|| {
            assert!(wait_until(Duration::from_secs(30), || remote_command(
                &api_socket_restored,
                "info",
                None
            )));
            assert!(remote_command(&api_socket_restored, "resume", None));
            let latest_events = [
                &MetaEvent {
                    event: "resuming".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "resumed".to_string(),
                    device_id: None,
                },
            ];
            assert!(wait_until(Duration::from_secs(30), || {
                check_latest_events_exact(&latest_events, &event_path_restored)
            }));

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);
            guest.check_devices_common(Some(&socket), Some(&console_text), None);

            if pvpanic {
                make_guest_panic(&guest);
                thread::sleep(std::time::Duration::new(10, 0));

                let expected_sequential_events = [&MetaEvent {
                    event: "panic".to_string(),
                    device_id: None,
                }];
                assert!(check_latest_events_exact(
                    &expected_sequential_events,
                    &event_path_restored
                ));
            }
        });
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });

        handle_child_output(r, &output);
    }
}

mod common_sequential {
    #[cfg(not(feature = "mshv"))]
    use std::fs::remove_dir_all;

    #[cfg(not(feature = "mshv"))]
    use crate::*;

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_memory_mergeable_on() {
        test_memory_mergeable(true);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_uffd_hugepage_zone() {
        if !exec_host_command_status(
            "grep -q '^Hugepagesize:[[:space:]]*2048 kB' /proc/meminfo && test $(awk '/HugePages_Free/ {print $2}' /proc/meminfo) -ge 256",
        )
        .success()
        {
            println!("SKIPPED: not enough free 2MiB hugepages for UFFD restore test");
            return;
        }

        snapshot_restore_common::_test_snapshot_restore_uffd(
            "size=0",
            &["id=mem0,size=512M,hugepages=on,hugepage_size=2M"],
            480_000,
        );
    }

    #[test]
    #[cfg(not(feature = "mshv"))] // See issue #7437
    #[ignore = "See #6970"]
    fn test_snapshot_restore_with_fd() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let api_socket_source = format!("{}.1", temp_api_path(&guest.tmp_dir));

        let net_id = "net123";
        let num_queue_pairs: usize = 2;
        // use a name that does not conflict with tap dev created from other tests
        let tap_name = "chtap999";
        use std::str::FromStr;
        let taps = net_util::open_tap(
            Some(tap_name),
            Some(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from_str(&guest.network.host_ip0).unwrap(),
            )),
            None,
            &mut None,
            None,
            num_queue_pairs,
            Some(libc::O_RDWR | libc::O_NONBLOCK),
        )
        .unwrap();
        let net_params = format!(
            "id={},fd=[{},{}],mac={},ip={},mask=255.255.255.128,num_queues={}",
            net_id,
            taps[0].as_raw_fd(),
            taps[1].as_raw_fd(),
            guest.network.guest_mac0,
            guest.network.host_ip0,
            num_queue_pairs * 2
        );

        let cloudinit_params = format!(
            "path={},iommu=on",
            guest.disk_config.disk(DiskType::CloudInit).unwrap()
        );

        let n_cpu = 2;
        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_source])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .args(["--cpus", format!("boot={n_cpu}").as_str()])
            .args(["--memory", "size=1G"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                cloudinit_params.as_str(),
            ])
            .args(["--net", net_params.as_str()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .capture_output()
            .spawn()
            .unwrap();

        let console_text = String::from("On a branch floating down river a cricket, singing.");
        // Create the snapshot directory
        let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // close the fds after VM boots, as CH duplicates them before using
            for tap in taps.iter() {
                unsafe { libc::close(tap.as_raw_fd()) };
            }

            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), n_cpu);
            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

            // Check the guest virtio-devices, e.g. block, rng, vsock, console, and net
            guest.check_devices_common(None, Some(&console_text), None);

            snapshot_restore_common::snapshot_and_check_events(
                &api_socket_source,
                &snapshot_dir,
                &event_path,
            );
        });

        // Shutdown the source VM and check console output
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });

        handle_child_output(r, &output);

        let api_socket_restored = format!("{}.2", temp_api_path(&guest.tmp_dir));
        let event_path_restored = format!("{}.2", temp_event_monitor_path(&guest.tmp_dir));

        // Restore the VM from the snapshot
        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--event-monitor",
                format!("path={event_path_restored}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();
        thread::sleep(std::time::Duration::new(2, 0));

        let taps = net_util::open_tap(
            Some(tap_name),
            Some(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from_str(&guest.network.host_ip0).unwrap(),
            )),
            None,
            &mut None,
            None,
            num_queue_pairs,
            Some(libc::O_RDWR | libc::O_NONBLOCK),
        )
        .unwrap();
        let restore_params = format!(
            "source_url=file://{},net_fds=[{}@[{},{}]]",
            snapshot_dir,
            net_id,
            taps[0].as_raw_fd(),
            taps[1].as_raw_fd()
        );
        assert!(remote_command(
            &api_socket_restored,
            "restore",
            Some(restore_params.as_str())
        ));

        // Wait for the VM to be restored
        assert!(wait_until(Duration::from_secs(20), || {
            remote_command(&api_socket_restored, "info", None)
        }));

        // close the fds as CH duplicates them before using
        for tap in taps.iter() {
            unsafe { libc::close(tap.as_raw_fd()) };
        }

        let expected_events = [
            &MetaEvent {
                event: "starting".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "activated".to_string(),
                device_id: Some("__console".to_string()),
            },
            &MetaEvent {
                event: "activated".to_string(),
                device_id: Some("__rng".to_string()),
            },
            &MetaEvent {
                event: "restoring".to_string(),
                device_id: None,
            },
        ];
        // Wait for the restore event sequence to be recorded.
        assert!(wait_until(Duration::from_secs(30), || {
            check_sequential_events(&expected_events, &event_path_restored)
        }));
        let latest_events = [&MetaEvent {
            event: "restored".to_string(),
            device_id: None,
        }];
        assert!(wait_until(Duration::from_secs(30), || {
            check_latest_events_exact(&latest_events, &event_path_restored)
        }));

        // Remove the snapshot dir
        let _ = remove_dir_all(snapshot_dir.as_str());

        let r = std::panic::catch_unwind(|| {
            // Resume the VM
            assert!(wait_until(Duration::from_secs(20), || remote_command(
                &api_socket_restored,
                "info",
                None
            )));
            assert!(remote_command(&api_socket_restored, "resume", None));

            let latest_events = [
                &MetaEvent {
                    event: "resuming".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "resumed".to_string(),
                    device_id: None,
                },
            ];
            assert!(wait_until(Duration::from_secs(30), || {
                check_latest_events_exact(&latest_events, &event_path_restored)
            }));

            // Perform same checks to validate VM has been properly restored
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), n_cpu);
            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

            guest.check_devices_common(None, Some(&console_text), None);
        });
        // Shutdown the target VM and check console output
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
        });

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg(not(feature = "mshv"))]
    fn test_snapshot_restore_virtio_fs() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let api_socket_source = format!("{}.1", temp_api_path(&guest.tmp_dir));

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");
        let mut shared_dir = workload_path;
        shared_dir.push("shared_dir");

        let (mut daemon_child, virtiofsd_socket_path) =
            prepare_virtiofsd(&guest.tmp_dir, shared_dir.to_str().unwrap());

        let event_path = temp_event_monitor_path(&guest.tmp_dir);

        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_source])
            .args(["--event-monitor", format!("path={event_path}").as_str()])
            .args(["--cpus", "boot=2"])
            .args(["--memory", "size=512M,shared=on"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .default_disks()
            .default_net()
            .args([
                "--fs",
                format!("socket={virtiofsd_socket_path},tag=myfs,num_queues=1,queue_size=1024")
                    .as_str(),
            ])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .capture_output()
            .spawn()
            .unwrap();

        let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Mount virtiofs and write a test file
            guest
                .ssh_command("mkdir -p mount_dir && sudo mount -t virtiofs myfs mount_dir/")
                .unwrap();

            // Verify the shared directory is accessible
            assert_eq!(
                guest.ssh_command("cat mount_dir/file1").unwrap().trim(),
                "foo"
            );

            // Write a file from the guest
            guest
                .ssh_command(
                    "sudo bash -c 'echo snapshot_test_data > mount_dir/snapshot_test_file'",
                )
                .unwrap();
            snapshot_restore_common::snapshot_and_check_events(
                &api_socket_source,
                &snapshot_dir,
                &event_path,
            );
        });

        // Shutdown the source VM
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        // Kill the old virtiofsd
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();

        // Start a fresh virtiofsd (reusing the same socket path)
        let (mut daemon_child, _) = prepare_virtiofsd(&guest.tmp_dir, shared_dir.to_str().unwrap());

        let api_socket_restored = format!("{}.2", temp_api_path(&guest.tmp_dir));
        let event_path_restored = format!("{}.2", temp_event_monitor_path(&guest.tmp_dir));

        // Restore the VM from the snapshot
        let mut child = GuestCommand::new(&guest)
            .args(["--api-socket", &api_socket_restored])
            .args([
                "--event-monitor",
                format!("path={event_path_restored}").as_str(),
            ])
            .args([
                "--restore",
                format!("source_url=file://{snapshot_dir}").as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        // Wait for the VM to be restored
        assert!(wait_until(Duration::from_secs(30), || {
            remote_command(&api_socket_restored, "info", None)
        }));

        let latest_events = [&MetaEvent {
            event: "restored".to_string(),
            device_id: None,
        }];
        assert!(check_latest_events_exact(
            &latest_events,
            &event_path_restored
        ));

        // Remove the snapshot dir
        let _ = remove_dir_all(snapshot_dir.as_str());

        let r = std::panic::catch_unwind(|| {
            // Resume the VM
            assert!(wait_until(Duration::from_secs(30), || remote_command(
                &api_socket_restored,
                "info",
                None
            )));
            assert!(remote_command(&api_socket_restored, "resume", None));
            thread::sleep(std::time::Duration::new(5, 0));

            // Verify virtiofs still works after restore
            // Read the file written before snapshot
            assert_eq!(
                guest
                    .ssh_command("cat mount_dir/snapshot_test_file")
                    .unwrap()
                    .trim(),
                "snapshot_test_data"
            );

            // Read the pre-existing shared file
            assert_eq!(
                guest.ssh_command("cat mount_dir/file1").unwrap().trim(),
                "foo"
            );

            // Write a new file after restore
            guest
                .ssh_command("sudo bash -c 'echo post_restore_data > mount_dir/post_restore_file'")
                .unwrap();

            // Verify the new file exists on the host
            let post_restore_content =
                std::fs::read_to_string(shared_dir.join("post_restore_file")).unwrap();
            assert_eq!(post_restore_content.trim(), "post_restore_data");
        });

        // Shutdown the target VM
        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);

        // Clean up virtiofsd and test files
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();
        let _ = std::fs::remove_file(shared_dir.join("snapshot_test_file"));
        let _ = std::fs::remove_file(shared_dir.join("post_restore_file"));
    }
}

// Windows tests have been moved to integration_windows.rs

#[cfg(target_arch = "x86_64")]
mod vfio {
    use crate::*;
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
                .ssh_command(
                    "cat /sys/devices/system/node/has_generic_initiator 2>/dev/null || echo 0",
                )
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
                .ssh_command(
                    "[ -f /sys/firmware/acpi/tables/SRAT ] && echo 'exists' || echo 'missing'",
                )
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
}

mod live_migration {
    use std::num::NonZeroU32;

    use vmm::api::TimeoutStrategy;

    use crate::*;

    pub fn start_live_migration(
        migration_socket: &str,
        src_api_socket: &str,
        dest_api_socket: &str,
        local: bool,
    ) -> bool {
        // Start to receive migration from the destination VM
        let mut receive_migration = Command::new(clh_command("ch-remote"))
            .args([
                &format!("--api-socket={dest_api_socket}"),
                "receive-migration",
                &format! {"unix:{migration_socket}"},
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Give it '1s' to make sure the 'migration_socket' file is properly created
        thread::sleep(std::time::Duration::new(1, 0));
        // Start to send migration from the source VM

        let args = [
            format!("--api-socket={}", &src_api_socket),
            "send-migration".to_string(),
            format!(
                "destination_url=unix:{migration_socket},local={}",
                if local { "on" } else { "off" }
            ),
        ]
        .to_vec();

        let mut send_migration = Command::new(clh_command("ch-remote"))
            .args(&args)
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        // The 'send-migration' command should be executed successfully within the given timeout
        let send_success = if let Some(status) = send_migration
            .wait_timeout(std::time::Duration::from_secs(30))
            .unwrap()
        {
            status.success()
        } else {
            false
        };

        if !send_success {
            let _ = send_migration.kill();
            let output = send_migration.wait_with_output().unwrap();
            eprintln!(
                "\n\n==== Start 'send_migration' output ==== \
                \n\n---stdout---\n{}\n\n---stderr---\n{} \
                \n\n==== End 'send_migration' output ====\n\n",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // The 'receive-migration' command should be executed successfully within the given timeout
        let receive_success = if let Some(status) = receive_migration
            .wait_timeout(std::time::Duration::from_secs(30))
            .unwrap()
        {
            status.success()
        } else {
            false
        };

        if !receive_success {
            let _ = receive_migration.kill();
            let output = receive_migration.wait_with_output().unwrap();
            eprintln!(
                "\n\n==== Start 'receive_migration' output ==== \
                \n\n---stdout---\n{}\n\n---stderr---\n{} \
                \n\n==== End 'receive_migration' output ====\n\n",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        send_success && receive_success
    }

    pub fn print_and_panic(
        src_vm: Child,
        dest_vm: Child,
        ovs_vm: Option<Child>,
        message: &str,
    ) -> ! {
        let mut src_vm = src_vm;
        let mut dest_vm = dest_vm;

        let _ = src_vm.kill();
        let src_output = src_vm.wait_with_output().unwrap();
        eprintln!(
            "\n\n==== Start 'source_vm' stdout ====\n\n{}\n\n==== End 'source_vm' stdout ====",
            String::from_utf8_lossy(&src_output.stdout)
        );
        eprintln!(
            "\n\n==== Start 'source_vm' stderr ====\n\n{}\n\n==== End 'source_vm' stderr ====",
            String::from_utf8_lossy(&src_output.stderr)
        );
        let _ = dest_vm.kill();
        let dest_output = dest_vm.wait_with_output().unwrap();
        eprintln!(
            "\n\n==== Start 'destination_vm' stdout ====\n\n{}\n\n==== End 'destination_vm' stdout ====",
            String::from_utf8_lossy(&dest_output.stdout)
        );
        eprintln!(
            "\n\n==== Start 'destination_vm' stderr ====\n\n{}\n\n==== End 'destination_vm' stderr ====",
            String::from_utf8_lossy(&dest_output.stderr)
        );

        if let Some(ovs_vm) = ovs_vm {
            let mut ovs_vm = ovs_vm;
            let _ = ovs_vm.kill();
            let ovs_output = ovs_vm.wait_with_output().unwrap();
            eprintln!(
                "\n\n==== Start 'ovs_vm' stdout ====\n\n{}\n\n==== End 'ovs_vm' stdout ====",
                String::from_utf8_lossy(&ovs_output.stdout)
            );
            eprintln!(
                "\n\n==== Start 'ovs_vm' stderr ====\n\n{}\n\n==== End 'ovs_vm' stderr ====",
                String::from_utf8_lossy(&ovs_output.stderr)
            );

            cleanup_ovs_dpdk();
        }

        panic!("Test failed: {message}")
    }

    // This test exercises the local live-migration between two Cloud Hypervisor VMs on the
    // same host. It ensures the following behaviors:
    // 1. The source VM is up and functional (including various virtio-devices are working properly);
    // 2. The 'send-migration' and 'receive-migration' command finished successfully;
    // 3. The source VM terminated gracefully after live migration;
    // 4. The destination VM is functional (including various virtio-devices are working properly) after
    //    live migration;
    // Note: This test does not use vsock as we can't create two identical vsock on the same host.
    fn _test_live_migration(upgrade_test: bool, local: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );

        let memory_param: &[&str] = if local {
            &["--memory", "size=1500M,shared=on"]
        } else {
            &["--memory", "size=1500M"]
        };

        let boot_vcpus = 2;
        let max_vcpus = 4;

        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();
        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
            .output()
            .expect("Expect creating disk image to succeed");
        let pmem_path = String::from("/dev/pmem0");

        // Start the source VM
        let src_vm_path = if upgrade_test {
            cloud_hypervisor_release_path()
        } else {
            clh_command("cloud-hypervisor")
        };
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .args([
                "--pmem",
                format!("file={}", pmem_temp_file.as_path().to_str().unwrap(),).as_str(),
            ]);
        let mut src_child = src_vm_cmd.capture_output().spawn().unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Make sure the source VM is functional
            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);

            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);

            // Check the guest virtio-devices, e.g. block, rng, console, and net
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // x86_64: Following what's done in the `test_snapshot_restore`, we need
            // to make sure that removing and adding back the virtio-net device does
            // not break the live-migration support for virtio-pci.
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &src_api_socket,
                    "remove-device",
                    Some(net_id),
                ));
                assert!(wait_until(Duration::from_secs(10), || {
                    guest.wait_for_ssh(Duration::from_secs(1)).is_err()
                }));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &src_api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                guest.wait_for_ssh(Duration::from_secs(10)).unwrap();
            }

            // Start the live-migration
            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, local),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functional
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);

            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));
        });

        // Clean-up the destination VM and make sure it terminated correctly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);

        // Check the destination VM has the expected 'console_text' from its output
        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&dest_output.stdout).contains(&console_text));
        });
        handle_child_output(r, &dest_output);
    }

    fn _test_live_migration_balloon(upgrade_test: bool, local: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );

        let memory_param: &[&str] = if local {
            &[
                "--memory",
                "size=4G,hotplug_method=virtio-mem,hotplug_size=8G,shared=on",
                "--balloon",
                "size=0",
            ]
        } else {
            &[
                "--memory",
                "size=4G,hotplug_method=virtio-mem,hotplug_size=8G",
                "--balloon",
                "size=0",
            ]
        };

        let boot_vcpus = 2;
        let max_vcpus = 4;

        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();
        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
            .output()
            .expect("Expect creating disk image to succeed");
        let pmem_path = String::from("/dev/pmem0");

        // Start the source VM
        let src_vm_path = if upgrade_test {
            cloud_hypervisor_release_path()
        } else {
            clh_command("cloud-hypervisor")
        };
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .args([
                "--pmem",
                format!("file={}", pmem_temp_file.as_path().to_str().unwrap(),).as_str(),
            ]);
        let mut src_child = src_vm_cmd.capture_output().spawn().unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Make sure the source VM is functional
            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);

            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);
            // Increase the guest RAM
            resize_command(&src_api_socket, None, Some(6 << 30), None, None);
            assert!(wait_until(Duration::from_secs(30), || {
                guest.get_total_memory().unwrap_or_default() > 5_760_000
            }));
            assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);
            // Use balloon to remove RAM from the VM
            resize_command(&src_api_socket, None, None, Some(1 << 30), None);
            assert!(wait_until(Duration::from_secs(5), || {
                let total_memory = guest.get_total_memory().unwrap_or_default();
                total_memory > 4_800_000 && total_memory < 5_760_000
            }));
            let total_memory = guest.get_total_memory().unwrap_or_default();
            assert!(total_memory > 4_800_000);
            assert!(total_memory < 5_760_000);

            // Check the guest virtio-devices, e.g. block, rng, console, and net
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // x86_64: Following what's done in the `test_snapshot_restore`, we need
            // to make sure that removing and adding back the virtio-net device does
            // not break the live-migration support for virtio-pci.
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &src_api_socket,
                    "remove-device",
                    Some(net_id),
                ));
                assert!(wait_until(Duration::from_secs(10), || {
                    guest.wait_for_ssh(Duration::from_secs(1)).is_err()
                }));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &src_api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                guest.wait_for_ssh(Duration::from_secs(10)).unwrap();
            }

            // Start the live-migration
            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, local),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functional
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);

            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // Perform checks on guest RAM using balloon
            let total_memory = guest.get_total_memory().unwrap_or_default();
            assert!(total_memory > 4_800_000);
            assert!(total_memory < 5_760_000);
            // Deflate balloon to restore entire RAM to the VM
            resize_command(&dest_api_socket, None, None, Some(0), None);
            thread::sleep(std::time::Duration::new(5, 0));
            assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);
            // Decrease guest RAM with virtio-mem
            resize_command(&dest_api_socket, None, Some(5 << 30), None, None);
            thread::sleep(std::time::Duration::new(5, 0));
            let total_memory = guest.get_total_memory().unwrap_or_default();
            assert!(total_memory > 4_800_000);
            assert!(total_memory < 5_760_000);
        });

        // Clean-up the destination VM and make sure it terminated correctly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);

        // Check the destination VM has the expected 'console_text' from its output
        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&dest_output.stdout).contains(&console_text));
        });
        handle_child_output(r, &dest_output);
    }

    fn _test_live_migration_numa(upgrade_test: bool, local: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );

        let memory_param: &[&str] = if local {
            &[
                "--memory",
                "size=0,hotplug_method=virtio-mem,shared=on",
                "--memory-zone",
                "id=mem0,size=1G,hotplug_size=4G,shared=on",
                "id=mem1,size=1G,hotplug_size=4G,shared=on",
                "id=mem2,size=2G,hotplug_size=4G,shared=on",
                "--numa",
                "guest_numa_id=0,cpus=[0-2,9],distances=[1@15,2@20],memory_zones=mem0",
                "guest_numa_id=1,cpus=[3-4,6-8],distances=[0@20,2@25],memory_zones=mem1",
                "guest_numa_id=2,cpus=[5,10-11],distances=[0@25,1@30],memory_zones=mem2",
            ]
        } else {
            &[
                "--memory",
                "size=0,hotplug_method=virtio-mem",
                "--memory-zone",
                "id=mem0,size=1G,hotplug_size=4G",
                "id=mem1,size=1G,hotplug_size=4G",
                "id=mem2,size=2G,hotplug_size=4G",
                "--numa",
                "guest_numa_id=0,cpus=[0-2,9],distances=[1@15,2@20],memory_zones=mem0",
                "guest_numa_id=1,cpus=[3-4,6-8],distances=[0@20,2@25],memory_zones=mem1",
                "guest_numa_id=2,cpus=[5,10-11],distances=[0@25,1@30],memory_zones=mem2",
            ]
        };

        let boot_vcpus = 6;
        let max_vcpus = 12;

        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();
        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
            .output()
            .expect("Expect creating disk image to succeed");
        let pmem_path = String::from("/dev/pmem0");

        // Start the source VM
        let src_vm_path = if upgrade_test {
            cloud_hypervisor_release_path()
        } else {
            clh_command("cloud-hypervisor")
        };
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .args([
                "--pmem",
                format!("file={}", pmem_temp_file.as_path().to_str().unwrap(),).as_str(),
            ]);
        let mut src_child = src_vm_cmd.capture_output().spawn().unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Make sure the source VM is functional
            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);

            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 2_880_000);

            // Check the guest virtio-devices, e.g. block, rng, console, and net
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // Check the NUMA parameters are applied correctly and resize
            // each zone to test the case where we migrate a VM with the
            // virtio-mem regions being used.
            {
                guest.check_numa_common(
                    Some(&[960_000, 960_000, 1_920_000]),
                    Some(&[&[0, 1, 2], &[3, 4], &[5]]),
                    Some(&["10 15 20", "20 10 25", "25 30 10"]),
                );

                // AArch64 currently does not support hotplug, and therefore we only
                // test hotplug-related function on x86_64 here.
                #[cfg(target_arch = "x86_64")]
                {
                    guest.enable_memory_hotplug();

                    // Resize every memory zone and check each associated NUMA node
                    // has been assigned the right amount of memory.
                    resize_zone_command(&src_api_socket, "mem0", "2G");
                    resize_zone_command(&src_api_socket, "mem1", "2G");
                    resize_zone_command(&src_api_socket, "mem2", "3G");
                    thread::sleep(std::time::Duration::new(5, 0));

                    guest.check_numa_common(Some(&[1_920_000, 1_920_000, 1_920_000]), None, None);
                }
            }

            // x86_64: Following what's done in the `test_snapshot_restore`, we need
            // to make sure that removing and adding back the virtio-net device does
            // not break the live-migration support for virtio-pci.
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &src_api_socket,
                    "remove-device",
                    Some(net_id),
                ));
                assert!(wait_until(Duration::from_secs(10), || {
                    guest.wait_for_ssh(Duration::from_secs(1)).is_err()
                }));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &src_api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                guest.wait_for_ssh(Duration::from_secs(10)).unwrap();
            }

            // Start the live-migration
            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, local),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functional
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            #[cfg(target_arch = "x86_64")]
            assert!(guest.get_total_memory().unwrap_or_default() > 6_720_000);
            #[cfg(target_arch = "aarch64")]
            assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);

            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // Perform NUMA related checks
            {
                #[cfg(target_arch = "aarch64")]
                {
                    guest.check_numa_common(
                        Some(&[960_000, 960_000, 1_920_000]),
                        Some(&[&[0, 1, 2], &[3, 4], &[5]]),
                        Some(&["10 15 20", "20 10 25", "25 30 10"]),
                    );
                }

                // AArch64 currently does not support hotplug, and therefore we only
                // test hotplug-related function on x86_64 here.
                #[cfg(target_arch = "x86_64")]
                {
                    guest.check_numa_common(
                        Some(&[1_920_000, 1_920_000, 2_880_000]),
                        Some(&[&[0, 1, 2], &[3, 4], &[5]]),
                        Some(&["10 15 20", "20 10 25", "25 30 10"]),
                    );

                    guest.enable_memory_hotplug();

                    // Resize every memory zone and check each associated NUMA node
                    // has been assigned the right amount of memory.
                    resize_zone_command(&dest_api_socket, "mem0", "4G");
                    resize_zone_command(&dest_api_socket, "mem1", "4G");
                    resize_zone_command(&dest_api_socket, "mem2", "4G");
                    // Resize to the maximum amount of CPUs and check each NUMA
                    // node has been assigned the right CPUs set.
                    resize_command(&dest_api_socket, Some(max_vcpus), None, None, None);
                    thread::sleep(std::time::Duration::new(5, 0));

                    guest.check_numa_common(
                        Some(&[3_840_000, 3_840_000, 3_840_000]),
                        Some(&[&[0, 1, 2, 9], &[3, 4, 6, 7, 8], &[5, 10, 11]]),
                        None,
                    );
                }
            }
        });

        // Clean-up the destination VM and make sure it terminated correctly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);

        // Check the destination VM has the expected 'console_text' from its output
        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&dest_output.stdout).contains(&console_text));
        });
        handle_child_output(r, &dest_output);
    }

    fn _test_live_migration_watchdog(upgrade_test: bool, local: bool) {
        let disk_config = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );

        let memory_param: &[&str] = if local {
            &["--memory", "size=1500M,shared=on"]
        } else {
            &["--memory", "size=1500M"]
        };

        let boot_vcpus = 2;
        let max_vcpus = 4;

        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();
        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
            .output()
            .expect("Expect creating disk image to succeed");
        let pmem_path = String::from("/dev/pmem0");

        // Start the source VM
        let src_vm_path = if upgrade_test {
            cloud_hypervisor_release_path()
        } else {
            clh_command("cloud-hypervisor")
        };
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .args([
                "--pmem",
                format!("file={}", pmem_temp_file.as_path().to_str().unwrap(),).as_str(),
            ])
            .args(["--watchdog"]);
        let mut src_child = src_vm_cmd.capture_output().spawn().unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Make sure the source VM is functional
            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);
            // Check the guest virtio-devices, e.g. block, rng, console, and net
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));
            // x86_64: Following what's done in the `test_snapshot_restore`, we need
            // to make sure that removing and adding back the virtio-net device does
            // not break the live-migration support for virtio-pci.
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &src_api_socket,
                    "remove-device",
                    Some(net_id),
                ));
                assert!(wait_until(Duration::from_secs(10), || {
                    guest.wait_for_ssh(Duration::from_secs(1)).is_err()
                }));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &src_api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                guest.wait_for_ssh(Duration::from_secs(10)).unwrap();
            }

            // Enable watchdog and ensure its functional
            let expected_reboot_count = 1;
            // Enable the watchdog with a 15s timeout
            enable_guest_watchdog(&guest, 15);

            assert_eq!(get_reboot_count(&guest), expected_reboot_count);
            assert_eq!(
                guest
                    .ssh_command("sudo journalctl | grep -c -- \"Watchdog started\"")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );
            // Allow some normal time to elapse to check we don't get spurious reboots
            thread::sleep(std::time::Duration::new(40, 0));
            // Check no reboot
            assert_eq!(get_reboot_count(&guest), expected_reboot_count);

            // Start the live-migration
            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, local),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functional
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);

            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // Perform checks on watchdog
            let mut expected_reboot_count = 1;

            // Allow some normal time to elapse to check we don't get spurious reboots
            thread::sleep(std::time::Duration::new(40, 0));
            // Check no reboot
            assert_eq!(get_reboot_count(&guest), expected_reboot_count);

            // Trigger a panic (sync first). We need to do this inside a screen with a delay so the SSH command returns.
            guest.ssh_command("screen -dmS reboot sh -c \"sleep 5; echo s | tee /proc/sysrq-trigger; echo c | sudo tee /proc/sysrq-trigger\"").unwrap();
            // Allow some time for the watchdog to trigger (max 30s) and reboot to happen
            guest.wait_vm_boot_custom_timeout(50).unwrap();
            // Check a reboot is triggered by the watchdog
            expected_reboot_count += 1;
            assert_eq!(get_reboot_count(&guest), expected_reboot_count);

            #[cfg(target_arch = "x86_64")]
            {
                // Now pause the VM and remain offline for 30s
                assert!(remote_command(&dest_api_socket, "pause", None));
                thread::sleep(std::time::Duration::new(30, 0));
                assert!(remote_command(&dest_api_socket, "resume", None));

                // Check no reboot
                assert_eq!(get_reboot_count(&guest), expected_reboot_count);
            }
        });

        // Clean-up the destination VM and make sure it terminated correctly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);

        // Check the destination VM has the expected 'console_text' from its output
        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&dest_output.stdout).contains(&console_text));
        });
        handle_child_output(r, &dest_output);
    }

    fn _test_live_migration_ovs_dpdk(upgrade_test: bool, local: bool) {
        let ovs_disk_config = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let ovs_guest = Guest::new(Box::new(ovs_disk_config));

        let migration_disk_config = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let migration_guest = Guest::new(Box::new(migration_disk_config));
        let src_api_socket = temp_api_path(&migration_guest.tmp_dir);

        // Start two VMs that are connected through ovs-dpdk and one of the VMs is the source VM for live-migration
        let (mut ovs_child, mut src_child) =
            setup_ovs_dpdk_guests(&ovs_guest, &migration_guest, &src_api_socket, upgrade_test);

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&migration_guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&migration_guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            // Give it '1s' to make sure the 'dest_api_socket' file is properly created
            thread::sleep(std::time::Duration::new(1, 0));

            // Start the live-migration
            let migration_socket = String::from(
                migration_guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, local),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                Some(ovs_child),
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                Some(ovs_child),
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functional
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            // Spawn a new netcat listener in the OVS VM
            let guest_ip = ovs_guest.network.guest_ip0.clone();
            thread::spawn(move || {
                ssh_command_ip(
                    "nc -l 12345",
                    &guest_ip,
                    DEFAULT_SSH_RETRIES,
                    DEFAULT_SSH_TIMEOUT,
                )
                .unwrap();
            });

            // Wait for the server to be listening
            thread::sleep(std::time::Duration::new(5, 0));

            // And check the connection is still functional after live-migration
            migration_guest
                .ssh_command("nc -vz 172.100.0.1 12345")
                .unwrap();
        });

        // Clean-up the destination VM and OVS VM, and make sure they terminated correctly
        let _ = dest_child.kill();
        let _ = ovs_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        let ovs_output = ovs_child.wait_with_output().unwrap();

        cleanup_ovs_dpdk();

        handle_child_output(r, &dest_output);
        handle_child_output(Ok(()), &ovs_output);
    }

    // This test exercises the local live-migration between two Cloud Hypervisor VMs on the
    // same host with Landlock enabled on both VMs. The test validates the following:
    // 1. The source VM is up and functional
    // 2. Ensure Landlock is enabled on source VM by hotplugging a disk. As the path for this
    //    disk is not known to the source VM this step will fail.
    // 3. The 'send-migration' and 'receive-migration' command finished successfully;
    // 4. The source VM terminated gracefully after live migration;
    // 5. The destination VM is functional after live migration;
    // 6. Ensure Landlock is enabled on destination VM by hotplugging a disk. As the path for
    //    this disk is not known to the destination VM this step will fail.
    fn _test_live_migration_with_landlock() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );

        let boot_vcpus = 2;
        let max_vcpus = 4;

        let mut blk_file_path = dirs::home_dir().unwrap();
        blk_file_path.push("workloads");
        blk_file_path.push("blk.img");

        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_child = GuestCommand::new(&guest)
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(["--memory", "size=1500M,shared=on"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--api-socket", &src_api_socket])
            .args(["--landlock"])
            .args(["--net", net_params.as_str()])
            .args([
                "--landlock-rules",
                format!("path={:?},access=rw", guest.tmp_dir.as_path()).as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Make sure the source VM is functaionl
            // Check the number of vCPUs
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);

            // Check the guest RAM
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);

            // Check Landlock is enabled by hot-plugging a disk.
            assert!(!remote_command(
                &src_api_socket,
                "add-disk",
                Some(format!("path={},id=test0", blk_file_path.to_str().unwrap()).as_str()),
            ));

            // Start the live-migration
            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, true),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration check to make sure the destination VM is functioning
        let r = std::panic::catch_unwind(|| {
            // Perform same checks to validate VM has been properly migrated
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);
        });

        // Check Landlock is enabled on destination VM by hot-plugging a disk.
        assert!(!remote_command(
            &dest_api_socket,
            "add-disk",
            Some(format!("path={},id=test0", blk_file_path.to_str().unwrap()).as_str()),
        ));

        // Clean-up the destination VM and make sure it terminated correctly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);
    }

    // Function to get an available port
    fn get_available_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("Failed to bind to address")
            .local_addr()
            .unwrap()
            .port()
    }

    fn start_live_migration_tcp(
        src_api_socket: &str,
        dest_api_socket: &str,
        connections: NonZeroU32,
    ) -> bool {
        // Get an available TCP port
        let migration_port = get_available_port();
        let host_ip = "127.0.0.1";

        // Start the 'receive-migration' command on the destination
        let mut receive_migration = Command::new(clh_command("ch-remote"))
            .args([
                &format!("--api-socket={dest_api_socket}"),
                "receive-migration",
                &format!("tcp:0.0.0.0:{migration_port}"),
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        // Give the destination some time to start listening
        thread::sleep(Duration::from_secs(1));

        // Start the 'send-migration' command on the source
        let connections = connections.get();
        let mut send_migration = Command::new(clh_command("ch-remote"))
            .args([
                &format!("--api-socket={src_api_socket}"),
                "send-migration",
                &format!(
                    "destination_url=tcp:{host_ip}:{migration_port},connections={connections}"
                ),
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        // Check if the 'send-migration' command executed successfully
        let send_success = if let Some(status) = send_migration
            .wait_timeout(Duration::from_secs(60))
            .unwrap()
        {
            status.success()
        } else {
            false
        };

        if !send_success {
            let _ = send_migration.kill();
            let output = send_migration.wait_with_output().unwrap();
            eprintln!(
                "\n\n==== Start 'send_migration' output ====\n\n---stdout---\n{}\n\n---stderr---\n{}\n\n==== End 'send_migration' output ====\n\n",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Check if the 'receive-migration' command executed successfully
        let receive_success = if let Some(status) = receive_migration
            .wait_timeout(Duration::from_secs(60))
            .unwrap()
        {
            status.success()
        } else {
            false
        };

        if !receive_success {
            let _ = receive_migration.kill();
            let output = receive_migration.wait_with_output().unwrap();
            eprintln!(
                "\n\n==== Start 'receive_migration' output ====\n\n---stdout---\n{}\n\n---stderr---\n{}\n\n==== End 'receive_migration' output ====\n\n",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        send_success && receive_success
    }

    fn _test_live_migration_tcp(connections: NonZeroU32) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let console_text = String::from("On a branch floating down river a cricket, singing.");
        let net_id = "net123";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );
        let memory_param: &[&str] = &["--memory", "size=1500M,shared=on"];
        let boot_vcpus = 2;
        let max_vcpus = 4;
        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();
        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
            .output()
            .expect("Expect creating disk image to succeed");
        let pmem_path = String::from("/dev/pmem0");

        // Start the source VM
        let src_vm_path = clh_command("cloud-hypervisor");
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args([
                "--cpus",
                format!("boot={boot_vcpus},max={max_vcpus}").as_str(),
            ])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .args([
                "--pmem",
                format!(
                    "file={},discard_writes=on",
                    pmem_temp_file.as_path().to_str().unwrap(),
                )
                .as_str(),
            ])
            .capture_output();
        let mut src_child = src_vm_cmd.spawn().unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            // Ensure the source VM is running normally
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));

            // On x86_64 architecture, remove and re-add the virtio-net device
            #[cfg(target_arch = "x86_64")]
            {
                assert!(remote_command(
                    &src_api_socket,
                    "remove-device",
                    Some(net_id),
                ));
                assert!(wait_until(Duration::from_secs(10), || {
                    guest.wait_for_ssh(Duration::from_secs(1)).is_err()
                }));
                // Re-add the virtio-net device
                assert!(remote_command(
                    &src_api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                guest.wait_for_ssh(Duration::from_secs(10)).unwrap();
            }
            // Start TCP live migration
            assert!(
                start_live_migration_tcp(&src_api_socket, &dest_api_socket, connections),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors that occurred during live migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration",
            );
        }

        // Check the source vm has been terminated successful (give it '3s' to settle)
        thread::sleep(std::time::Duration::new(3, 0));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Source VM was not terminated successfully.",
            );
        }

        // After live migration, ensure the destination VM is running normally
        let r = std::panic::catch_unwind(|| {
            // Perform the same checks to ensure the VM has migrated correctly
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
            assert!(guest.get_total_memory().unwrap_or_default() > 1_400_000);
            guest.check_devices_common(None, Some(&console_text), Some(&pmem_path));
        });

        // Clean up the destination VM and ensure it terminates properly
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        handle_child_output(r, &dest_output);

        // Check if the expected `console_text` is present in the destination VM's output
        let r = std::panic::catch_unwind(|| {
            assert!(String::from_utf8_lossy(&dest_output.stdout).contains(&console_text));
        });
        handle_child_output(r, &dest_output);
    }

    fn _test_live_migration_tcp_timeout(timeout_strategy: TimeoutStrategy) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();
        let net_id = "net1337";
        let net_params = format!(
            "id={},tap=,mac={},ip={},mask=255.255.255.128",
            net_id, guest.network.guest_mac0, guest.network.host_ip0
        );
        let memory_param: &[&str] = &["--memory", "size=1500M,shared=on"];
        let boot_vcpus = 2;

        let src_vm_path = clh_command("cloud-hypervisor");
        let src_api_socket = temp_api_path(&guest.tmp_dir);
        let mut src_vm_cmd = GuestCommand::new_with_binary_path(&guest, &src_vm_path);
        src_vm_cmd
            .args(["--cpus", format!("boot={boot_vcpus}").as_str()])
            .args(memory_param)
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .args(["--api-socket", &src_api_socket])
            .capture_output();
        let mut src_child = src_vm_cmd.spawn().unwrap();

        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guest.wait_vm_boot().unwrap();

            assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);

            // Start a memory stressor in the background to keep pages dirty,
            // ensuring the precopy loop cannot converge within the 1s timeout.
            guest
                .ssh_command("nohup stress --vm 2 --vm-bytes 220M --vm-keep &>/dev/null &")
                .unwrap();
            // Give stress a moment to actually start dirtying memory
            thread::sleep(Duration::from_secs(3));

            let migration_port = get_available_port();
            let host_ip = "127.0.0.1";

            let mut receive_migration = Command::new(clh_command("ch-remote"))
                .args([
                    &format!("--api-socket={dest_api_socket}"),
                    "receive-migration",
                    &format!("tcp:0.0.0.0:{migration_port}"),
                ])
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            thread::sleep(Duration::from_secs(1));

            // Use a tight downtime budget (1ms) combined with a 1s timeout so the
            // migration practically cannot converge regardless of strategy.
            let mut send_migration = Command::new(clh_command("ch-remote"))
                .args([
                    &format!("--api-socket={src_api_socket}"),
                    "send-migration",
                    &format!(
                        "destination_url=tcp:{host_ip}:{migration_port},downtime_ms=1,timeout_s=1,timeout_strategy={timeout_strategy:?}"
                    ),
                ])
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            let send_status = send_migration
                .wait_timeout(Duration::from_secs(60))
                .unwrap();
            let receive_status = receive_migration
                .wait_timeout(Duration::from_secs(60))
                .unwrap();

            // Clean up receive-migration regardless of its outcome
            if receive_status.is_none() {
                let _ = receive_migration.kill();
            }

            // Kill the stressor now that migration has completed or aborted,
            // to reduce system load during post-migration checks.
            let _ = guest.ssh_command("pkill -f 'stress --vm'");

            match timeout_strategy {
                TimeoutStrategy::Cancel => {
                    // With cancel strategy the send must fail and the source VM
                    // must keep running.
                    let send_failed = match send_status {
                        Some(status) => !status.success(),
                        None => {
                            let _ = send_migration.kill();
                            false
                        }
                    };
                    assert!(
                        send_failed,
                        "send-migration should have failed due to 1s timeout with cancel strategy"
                    );

                    thread::sleep(Duration::from_secs(2));
                    assert!(
                        src_child.try_wait().unwrap().is_none(),
                        "Source VM should still be running after a cancelled migration"
                    );

                    // Confirm the source VM is still responsive over SSH
                    assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
                }
                TimeoutStrategy::Ignore => {
                    // With Ignore strategy the send must succeed despite the timeout
                    // being reached, and the source VM must have terminated.
                    let send_succeeded = match send_status {
                        Some(status) => status.success(),
                        None => {
                            let _ = send_migration.kill();
                            false
                        }
                    };
                    assert!(
                        send_succeeded,
                        "send-migration should have succeeded with timeout_strategy=ignore"
                    );

                    thread::sleep(Duration::from_secs(3));
                    assert!(
                        src_child.try_wait().unwrap().is_some(),
                        "Source VM should have terminated after a forced migration"
                    );

                    // Confirm the VM is still responsive over SSH on the new host
                    assert_eq!(guest.get_cpu_count().unwrap_or_default(), boot_vcpus);
                }
            }
        }));

        let _ = src_child.kill();
        let src_output = src_child.wait_with_output().unwrap();
        let _ = dest_child.kill();
        let _dest_output = dest_child.wait_with_output().unwrap();

        handle_child_output(r, &src_output);
    }

    fn _test_live_migration_virtio_fs(local: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let kernel_path = direct_kernel_boot_path();

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");
        let mut shared_dir = workload_path;
        shared_dir.push("shared_dir");

        let (daemon_child, virtiofsd_socket_path) =
            prepare_virtiofsd(&guest.tmp_dir, shared_dir.to_str().unwrap());

        let src_api_socket = temp_api_path(&guest.tmp_dir);

        // Start the source VM
        let mut src_child = GuestCommand::new(&guest)
            .args(["--api-socket", &src_api_socket])
            .args(["--cpus", "boot=2"])
            .args(["--memory", "size=512M,shared=on"])
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args([
                "--fs",
                format!("socket={virtiofsd_socket_path},tag=myfs,num_queues=1,queue_size=1024")
                    .as_str(),
            ])
            .capture_output()
            .spawn()
            .unwrap();

        // Start the destination VM
        let mut dest_api_socket = temp_api_path(&guest.tmp_dir);
        dest_api_socket.push_str(".dest");
        let mut dest_child = GuestCommand::new(&guest)
            .args(["--api-socket", &dest_api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        // Spawn a thread that waits for the old virtiofsd to exit then
        // starts a replacement.  During migration the source saves
        // DEVICE_STATE then disconnects, causing virtiofsd to exit.
        // The destination needs a fresh virtiofsd to load DEVICE_STATE.
        // We remove the socket file first so the destination cannot
        // accidentally connect to the old instance.
        let virtiofsd_socket_clone = virtiofsd_socket_path.clone();
        let shared_dir_str = shared_dir.to_str().unwrap().to_string();
        let (restart_tx, restart_rx) = std::sync::mpsc::channel();
        let _monitor = thread::spawn(move || {
            let mut child = daemon_child;
            let _ = child.wait();
            let mut path = dirs::home_dir().unwrap();
            path.push("workloads");
            path.push("virtiofsd");
            let new_child = Command::new(path)
                .args(["--shared-dir", &shared_dir_str])
                .args(["--socket-path", &virtiofsd_socket_clone])
                .args(["--cache", "never"])
                .args(["--tag", "myfs"])
                .spawn()
                .unwrap();
            wait_for_virtiofsd_socket(&virtiofsd_socket_clone);
            let _ = restart_tx.send(new_child);
        });

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            // Mount virtiofs and verify it works
            guest
                .ssh_command("mkdir -p mount_dir && sudo mount -t virtiofs myfs mount_dir/")
                .unwrap();

            // Write a test file through virtiofs before migration
            guest
                .ssh_command(
                    "sudo bash -c 'echo pre_migration_data > mount_dir/migration_test_file'",
                )
                .unwrap();

            // Verify the file is accessible
            assert_eq!(
                guest
                    .ssh_command("cat mount_dir/migration_test_file")
                    .unwrap()
                    .trim(),
                "pre_migration_data"
            );

            let migration_socket = String::from(
                guest
                    .tmp_dir
                    .as_path()
                    .join("live-migration.sock")
                    .to_str()
                    .unwrap(),
            );

            // Remove the socket so the destination cannot connect to
            // the old virtiofsd (which is still running).  The source's
            // existing connection uses an already-accepted fd.
            let _ = std::fs::remove_file(&virtiofsd_socket_path);

            assert!(
                start_live_migration(&migration_socket, &src_api_socket, &dest_api_socket, local),
                "Unsuccessful command: 'send-migration' or 'receive-migration'."
            );
        });

        // Check and report any errors occurred during the live-migration
        if r.is_err() {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "Error occurred during live-migration with virtio-fs",
            );
        }

        // Check the source vm has been terminated successfully (give it '3s' to settle)
        thread::sleep(Duration::from_secs(3));
        if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
            print_and_panic(
                src_child,
                dest_child,
                None,
                "source VM was not terminated successfully.",
            );
        }

        // Post live-migration checks
        let r = std::panic::catch_unwind(|| {
            // Verify virtiofs still works after migration
            // Read the file written before migration
            assert_eq!(
                guest
                    .ssh_command("cat mount_dir/migration_test_file")
                    .unwrap()
                    .trim(),
                "pre_migration_data"
            );

            // Write a new file after migration
            guest
                .ssh_command(
                    "sudo bash -c 'echo post_migration_data > mount_dir/post_migration_file'",
                )
                .unwrap();

            // Verify the new file exists on the host
            let post_content =
                std::fs::read_to_string(shared_dir.join("post_migration_file")).unwrap();
            assert_eq!(post_content.trim(), "post_migration_data");
        });

        // Clean up
        let _ = dest_child.kill();
        let dest_output = dest_child.wait_with_output().unwrap();
        if let Ok(mut new_daemon) = restart_rx.try_recv() {
            let _ = new_daemon.kill();
            let _ = new_daemon.wait();
        }
        let _ = std::fs::remove_file(shared_dir.join("migration_test_file"));
        let _ = std::fs::remove_file(shared_dir.join("post_migration_file"));

        handle_child_output(r, &dest_output);
    }

    mod live_migration_parallel {
        use vmm::api::TimeoutStrategy;

        use super::*;
        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_basic() {
            _test_live_migration(false, false);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_local() {
            _test_live_migration(false, true);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_tcp() {
            _test_live_migration_tcp(NonZeroU32::new(1).unwrap());
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_tcp_parallel_connections() {
            _test_live_migration_tcp(NonZeroU32::new(8).unwrap());
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_tcp_timeout_cancel() {
            _test_live_migration_tcp_timeout(TimeoutStrategy::Cancel);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_tcp_timeout_ignore() {
            _test_live_migration_tcp_timeout(TimeoutStrategy::Ignore);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_watchdog() {
            _test_live_migration_watchdog(false, false);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_watchdog_local() {
            _test_live_migration_watchdog(false, true);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_basic() {
            _test_live_migration(true, false);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_local() {
            _test_live_migration(true, true);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_watchdog() {
            _test_live_migration_watchdog(true, false);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_watchdog_local() {
            _test_live_migration_watchdog(true, true);
        }
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_live_migration_with_landlock() {
            _test_live_migration_with_landlock();
        }
    }

    mod live_migration_sequential {
        use super::*;

        // NUMA, balloon, and virtio-fs live migration tests run sequentially

        #[test]
        #[cfg(not(feature = "mshv"))]
        fn test_live_migration_virtio_fs() {
            _test_live_migration_virtio_fs(false);
        }

        #[test]
        #[cfg(not(feature = "mshv"))]
        fn test_live_migration_virtio_fs_local() {
            _test_live_migration_virtio_fs(true);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_balloon() {
            _test_live_migration_balloon(false, false);
        }

        #[test]
        #[cfg_attr(
            all(feature = "mshv", target_arch = "aarch64"),
            ignore = "live migration not yet supported on mshv arm64"
        )]
        fn test_live_migration_balloon_local() {
            _test_live_migration_balloon(false, true);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_balloon() {
            _test_live_migration_balloon(true, false);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_balloon_local() {
            _test_live_migration_balloon(true, true);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_migration_numa() {
            _test_live_migration_numa(false, false);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_migration_numa_local() {
            _test_live_migration_numa(false, true);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_numa() {
            _test_live_migration_numa(true, false);
        }

        #[test]
        #[cfg_attr(feature = "mshv", ignore = "See #7542")]
        fn test_live_upgrade_numa_local() {
            _test_live_migration_numa(true, true);
        }

        // Require to run ovs-dpdk tests sequentially because they rely on the same ovs-dpdk setup
        #[test]
        #[ignore = "See #5532"]
        #[cfg(target_arch = "x86_64")]
        #[cfg(not(feature = "mshv"))]
        fn test_live_migration_ovs_dpdk() {
            _test_live_migration_ovs_dpdk(false, false);
        }

        #[test]
        #[ignore = "See #5532 and #7689"]
        #[cfg(target_arch = "x86_64")]
        #[cfg(not(feature = "mshv"))]
        fn test_live_migration_ovs_dpdk_local() {
            _test_live_migration_ovs_dpdk(false, true);
        }

        #[test]
        #[ignore = "See #5532"]
        #[cfg(target_arch = "x86_64")]
        #[cfg(not(feature = "mshv"))]
        fn test_live_upgrade_ovs_dpdk() {
            _test_live_migration_ovs_dpdk(true, false);
        }

        #[test]
        #[ignore = "See #5532"]
        #[cfg(target_arch = "x86_64")]
        #[cfg(not(feature = "mshv"))]
        fn test_live_upgrade_ovs_dpdk_local() {
            _test_live_migration_ovs_dpdk(true, true);
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64_acpi {
    use crate::*;

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
}

mod rate_limiter {
    use super::*;

    const NET_RATE_LIMITER_RUNTIME: u32 = 20;
    const BLOCK_RATE_LIMITER_RUNTIME: u32 = 20;
    const BLOCK_RATE_LIMITER_RAMP_TIME: u32 = 5;

    // Check if the 'measured' rate is within the expected 'difference' (in percentage)
    // compared to given 'limit' rate.
    fn check_rate_limit(measured: f64, limit: f64, difference: f64) -> bool {
        let upper_limit = limit * (1_f64 + difference);
        let lower_limit = limit * (1_f64 - difference);

        if measured > lower_limit && measured < upper_limit {
            return true;
        }

        eprintln!(
            "\n\n==== Start 'check_rate_limit' failed ==== \
            \n\nmeasured={measured}, , lower_limit={lower_limit}, upper_limit={upper_limit} \
            \n\n==== End 'check_rate_limit' failed ====\n\n"
        );

        false
    }

    fn _test_rate_limiter_net(rx: bool) {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));

        let num_queues = 2;
        let queue_size = 256;
        let bw_size = 104857600_u64; // bytes
        let bw_refill_time = 1000; // ms
        let limit_bps = (bw_size * 8 * 1000) as f64 / bw_refill_time as f64;

        let net_params = format!(
            "tap=,mac={},ip={},mask=255.255.255.128,num_queues={},queue_size={},bw_size={},bw_one_time_burst=0,bw_refill_time={}",
            guest.network.guest_mac0,
            guest.network.host_ip0,
            num_queues,
            queue_size,
            bw_size,
            bw_refill_time,
        );

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", &format!("boot={}", num_queues / 2)])
            .args(["--memory", "size=1G"])
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(["--net", net_params.as_str()])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            let measured_bps = measure_virtio_net_throughput(
                NET_RATE_LIMITER_RUNTIME,
                num_queues / 2,
                &guest,
                rx,
                true,
            )
            .unwrap();
            assert!(check_rate_limit(measured_bps, limit_bps, 0.1));
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);
    }

    #[test]
    fn test_rate_limiter_net_rx() {
        _test_rate_limiter_net(true);
    }

    #[test]
    fn test_rate_limiter_net_tx() {
        _test_rate_limiter_net(false);
    }

    fn _test_rate_limiter_block(bandwidth: bool, num_queues: u32) {
        let fio_ops = FioOps::RandRW;

        let bw_size = if bandwidth {
            104857600_u64 // bytes
        } else {
            1000_u64 // I/O
        };
        let bw_refill_time = 1000; // ms
        let limit_rate = (bw_size * 1000) as f64 / bw_refill_time as f64;

        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);
        let test_img_dir = TempDir::new_with_prefix("/var/tmp/ch").unwrap();
        let blk_rate_limiter_test_img =
            String::from(test_img_dir.as_path().join("blk.img").to_str().unwrap());

        // Create the test block image
        assert!(
            exec_host_command_output(&format!(
                "dd if=/dev/zero of={blk_rate_limiter_test_img} bs=1M count=1024"
            ))
            .status
            .success()
        );

        let test_blk_params = if bandwidth {
            format!(
                "path={blk_rate_limiter_test_img},num_queues={num_queues},bw_size={bw_size},bw_one_time_burst=0,bw_refill_time={bw_refill_time},image_type=raw"
            )
        } else {
            format!(
                "path={blk_rate_limiter_test_img},num_queues={num_queues},ops_size={bw_size},ops_one_time_burst=0,ops_refill_time={bw_refill_time},image_type=raw"
            )
        };

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", &format!("boot={num_queues}")])
            .args(["--memory", "size=1G"])
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args([
                "--disk",
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
                test_blk_params.as_str(),
            ])
            .default_net()
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let fio_command = format!(
                "sudo fio --filename=/dev/vdc --name=test --output-format=json \
                --direct=1 --bs=4k --ioengine=io_uring --iodepth=64 \
                --rw={fio_ops} --runtime={BLOCK_RATE_LIMITER_RUNTIME} \
                --ramp_time={BLOCK_RATE_LIMITER_RAMP_TIME} --numjobs={num_queues}",
            );
            let output = guest.ssh_command(&fio_command).unwrap();

            // Parse fio output
            let measured_rate = if bandwidth {
                parse_fio_output(&output, &fio_ops, num_queues).unwrap()
            } else {
                parse_fio_output_iops(&output, &fio_ops, num_queues).unwrap()
            };
            assert!(check_rate_limit(measured_rate, limit_rate, 0.1));
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);
    }

    fn _test_rate_limiter_group_block(bandwidth: bool, num_queues: u32, num_disks: u32) {
        let fio_ops = FioOps::RandRW;

        let bw_size = if bandwidth {
            104857600_u64 // bytes
        } else {
            1000_u64 // I/O
        };
        let bw_refill_time = 1000; // ms
        let limit_rate = (bw_size * 1000) as f64 / bw_refill_time as f64;

        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let api_socket = temp_api_path(&guest.tmp_dir);
        let test_img_dir = TempDir::new_with_prefix("/var/tmp/ch").unwrap();

        let rate_limit_group_arg = if bandwidth {
            format!(
                "id=group0,bw_size={bw_size},bw_one_time_burst=0,bw_refill_time={bw_refill_time}"
            )
        } else {
            format!(
                "id=group0,ops_size={bw_size},ops_one_time_burst=0,ops_refill_time={bw_refill_time}"
            )
        };

        let mut disk_args = vec![
            "--disk".to_string(),
            format!(
                "path={}",
                guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
            ),
            format!(
                "path={}",
                guest.disk_config.disk(DiskType::CloudInit).unwrap()
            ),
        ];

        for i in 0..num_disks {
            let test_img_path = String::from(
                test_img_dir
                    .as_path()
                    .join(format!("blk{i}.img"))
                    .to_str()
                    .unwrap(),
            );

            assert!(
                exec_host_command_output(&format!(
                    "dd if=/dev/zero of={test_img_path} bs=1M count=1024"
                ))
                .status
                .success()
            );

            disk_args.push(format!(
                "path={test_img_path},num_queues={num_queues},rate_limit_group=group0,image_type=raw"
            ));
        }

        let mut child = GuestCommand::new(&guest)
            .args(["--cpus", &format!("boot={}", num_queues * num_disks)])
            .args(["--memory", "size=1G"])
            .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(["--rate-limit-group", &rate_limit_group_arg])
            .args(disk_args)
            .default_net()
            .args(["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();

            let mut fio_command = format!(
                "sudo fio --name=global --output-format=json \
                --direct=1 --bs=4k --ioengine=io_uring --iodepth=64 \
                --rw={fio_ops} --runtime={BLOCK_RATE_LIMITER_RUNTIME} \
                --ramp_time={BLOCK_RATE_LIMITER_RAMP_TIME} --numjobs={num_queues}",
            );

            // Generate additional argument for each disk:
            // --name=job0 --filename=/dev/vdc \
            // --name=job1 --filename=/dev/vdd \
            // --name=job2 --filename=/dev/vde \
            // ...
            for i in 0..num_disks {
                let c: char = 'c';
                let arg = format!(
                    " --name=job{i} --filename=/dev/vd{}",
                    char::from_u32((c as u32) + i).unwrap()
                );
                fio_command += &arg;
            }
            let output = guest.ssh_command(&fio_command).unwrap();

            // Parse fio output
            let measured_rate = if bandwidth {
                parse_fio_output(&output, &fio_ops, num_queues * num_disks).unwrap()
            } else {
                parse_fio_output_iops(&output, &fio_ops, num_queues * num_disks).unwrap()
            };
            assert!(check_rate_limit(measured_rate, limit_rate, 0.2));
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        handle_child_output(r, &output);
    }

    #[test]
    fn test_rate_limiter_block_bandwidth() {
        _test_rate_limiter_block(true, 1);
        _test_rate_limiter_block(true, 2);
    }

    #[test]
    fn test_rate_limiter_group_block_bandwidth() {
        _test_rate_limiter_group_block(true, 1, 1);
        _test_rate_limiter_group_block(true, 2, 1);
        _test_rate_limiter_group_block(true, 1, 2);
        _test_rate_limiter_group_block(true, 2, 2);
    }

    #[test]
    fn test_rate_limiter_block_iops() {
        _test_rate_limiter_block(false, 1);
        _test_rate_limiter_block(false, 2);
    }

    #[test]
    fn test_rate_limiter_group_block_iops() {
        _test_rate_limiter_group_block(false, 1, 1);
        _test_rate_limiter_group_block(false, 2, 1);
        _test_rate_limiter_group_block(false, 1, 2);
        _test_rate_limiter_group_block(false, 2, 2);
    }
}

#[cfg(not(target_arch = "riscv64"))]
mod fw_cfg {
    use crate::*;

    #[test]
    #[cfg_attr(feature = "mshv", ignore = "See #7434")]
    fn test_fw_cfg() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut cmd = GuestCommand::new(&guest);

        let kernel_path = direct_kernel_boot_path();
        let cmd_line = DIRECT_KERNEL_BOOT_CMDLINE;

        let test_file = guest.tmp_dir.as_path().join("test-file");
        std::fs::write(&test_file, "test-file-content").unwrap();

        cmd.args(["--cpus", "boot=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", cmd_line])
            .default_disks()
            .default_net()
            .args([
                "--fw-cfg-config",
                &format!(
                    "initramfs=off,items=[name=opt/org.test/test-file,file={}]",
                    test_file.to_str().unwrap()
                ),
            ])
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            // Wait a while for guest
            thread::sleep(std::time::Duration::new(3, 0));
            let result = guest
                .ssh_command(
                    "sudo cat /sys/firmware/qemu_fw_cfg/by_name/opt/org.test/test-file/raw",
                )
                .unwrap();
            assert_eq!(result, "test-file-content");
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    #[test]
    #[cfg_attr(feature = "mshv", ignore = "See #7434")]
    fn test_fw_cfg_string() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk_config));
        let mut cmd = GuestCommand::new(&guest);

        let kernel_path = direct_kernel_boot_path();
        let cmd_line = DIRECT_KERNEL_BOOT_CMDLINE;

        cmd.args(["--cpus", "boot=4"])
            .default_memory()
            .args(["--kernel", kernel_path.to_str().unwrap()])
            .args(["--cmdline", cmd_line])
            .default_disks()
            .default_net()
            .args([
                "--fw-cfg-config",
                "initramfs=off,items=[name=opt/org.test/test-string,string=hello-from-vmm]",
            ])
            .capture_output();

        let mut child = cmd.spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot().unwrap();
            thread::sleep(std::time::Duration::new(3, 0));
            let result = guest
                .ssh_command(
                    "sudo cat /sys/firmware/qemu_fw_cfg/by_name/opt/org.test/test-string/raw",
                )
                .unwrap();
            assert_eq!(result, "hello-from-vmm");
        });

        kill_child(&mut child);
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }
}
