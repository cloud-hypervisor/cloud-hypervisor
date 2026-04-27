// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
use std::fs::remove_dir_all;
use std::process::Command;
use std::thread;
use std::time::Duration;

use test_infra::*;

use crate::common::utils::{
    check_latest_events_exact, check_sequential_events, make_guest_panic, resize_command,
    temp_api_path, temp_event_monitor_path, temp_snapshot_dir_path, temp_vsock_path,
};

pub(crate) fn snapshot_and_check_events(api_socket: &str, snapshot_dir: &str, event_path: &str) {
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

        snapshot_and_check_events(&api_socket_source, &snapshot_dir, &event_path);
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
