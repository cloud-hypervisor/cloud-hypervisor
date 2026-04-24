// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
use std::thread;
use std::time::Duration;

use test_infra::*;

mod common;
use common::tests_wrappers::*;
use common::utils::*;
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
