// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
#[cfg(not(feature = "mshv"))]
use std::fs::remove_dir_all;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

use test_infra::*;

mod common;
use common::tests_wrappers::*;
use common::utils::*;
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

    common::snapshot_restore_common::_test_snapshot_restore_uffd(
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
            .ssh_command("sudo bash -c 'echo snapshot_test_data > mount_dir/snapshot_test_file'")
            .unwrap();
        common::snapshot_restore_common::snapshot_and_check_events(
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
