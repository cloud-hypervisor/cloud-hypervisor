// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
#[cfg(not(feature = "mshv"))]
use std::fs::remove_dir_all;
use std::process::Command;
use std::thread;
#[cfg(any(target_arch = "x86_64", not(feature = "mshv")))]
use std::time::Duration;

use test_infra::*;
use vmm_sys_util::tempfile::TempFile;

mod common;
use common::tests_wrappers::*;
use common::utils::*;

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
            common::live_migration::start_live_migration(
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
        common::live_migration::print_and_panic(
            src_child,
            dest_child,
            None,
            "Error occurred during live-migration",
        );
    }

    // Check the source vm has been terminated successful (give it '3s' to settle)
    thread::sleep(std::time::Duration::new(3, 0));
    if !src_child.try_wait().unwrap().is_some_and(|s| s.success()) {
        common::live_migration::print_and_panic(
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

        common::snapshot_restore_common::snapshot_and_check_events(
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
    common::snapshot_restore_common::_test_snapshot_restore(true, false);
}

#[test]
#[cfg(not(feature = "mshv"))] // See issue #7437
fn test_snapshot_restore_basic() {
    common::snapshot_restore_common::_test_snapshot_restore(false, false);
}

#[test]
#[cfg(not(feature = "mshv"))]
fn test_snapshot_restore_with_resume() {
    common::snapshot_restore_common::_test_snapshot_restore(false, true);
}

#[test]
#[cfg(not(feature = "mshv"))]
fn test_snapshot_restore_uffd() {
    common::snapshot_restore_common::_test_snapshot_restore_uffd("size=2G", &[], 1_920_000);
}

#[test]
#[cfg(not(feature = "mshv"))]
fn test_snapshot_restore_uffd_shared_memory() {
    common::snapshot_restore_common::_test_snapshot_restore_uffd(
        "size=512M,shared=on",
        &[],
        480_000,
    );
}

#[test]
#[cfg(not(feature = "mshv"))] // See issue #7437
#[cfg(target_arch = "x86_64")]
fn test_snapshot_restore_pvpanic() {
    common::snapshot_restore_common::_test_snapshot_restore_devices(true);
}

#[test]
fn test_virtio_pmem_persist_writes() {
    test_virtio_pmem(false, false);
}
