// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
#![cfg(not(target_arch = "riscv64"))]
use std::thread;

use test_infra::*;

mod common;

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
            .ssh_command("sudo cat /sys/firmware/qemu_fw_cfg/by_name/opt/org.test/test-file/raw")
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
            .ssh_command("sudo cat /sys/firmware/qemu_fw_cfg/by_name/opt/org.test/test-string/raw")
            .unwrap();
        assert_eq!(result, "hello-from-vmm");
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}
