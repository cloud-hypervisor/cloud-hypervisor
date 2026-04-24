// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
// When enabling the `mshv` feature, we skip quite some tests and
// hence have known dead-code. This annotation silences dead-code
// related warnings for our quality workflow to pass.
#![allow(dead_code)]
use std::net::TcpListener;
use std::num::NonZeroU32;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use test_infra::*;
use vmm::api::TimeoutStrategy;
use vmm_sys_util::tempfile::TempFile;
use wait_timeout::ChildExt;

mod common;
use common::live_migration::*;
use common::utils::*;

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
            &format!("destination_url=tcp:{host_ip}:{migration_port},connections={connections}"),
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
            .ssh_command("sudo bash -c 'echo pre_migration_data > mount_dir/migration_test_file'")
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
            .ssh_command("sudo bash -c 'echo post_migration_data > mount_dir/post_migration_file'")
            .unwrap();

        // Verify the new file exists on the host
        let post_content = std::fs::read_to_string(shared_dir.join("post_migration_file")).unwrap();
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
