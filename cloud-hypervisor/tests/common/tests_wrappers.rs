// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::mpsc;
use std::thread;

use block::ImageType;
use net_util::MacAddr;
use test_infra::*;
use vmm_sys_util::tempdir::TempDir;
use vmm_sys_util::tempfile::TempFile;
use wait_timeout::ChildExt;

use crate::common::utils::{TargetApi, *};

// Start cloud-hypervisor with no VM parameters, only the API server running.
// From the API: Create a VM, boot it and check that it looks as expected.
pub(crate) fn _test_api_create_boot(target_api: &TargetApi, guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .args(target_api.guest_args())
        .capture_output()
        .spawn()
        .unwrap();

    thread::sleep(std::time::Duration::new(1, 0));

    // Verify API server is running
    assert!(target_api.remote_command("ping", None));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    std::fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    assert!(target_api.remote_command("create", Some(create_config),));

    // Then boot it
    assert!(target_api.remote_command("boot", None));

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();
        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

// Start cloud-hypervisor with no VM parameters, only the API server running.
// From the API: Create a VM, boot it and check it can be shutdown and then
// booted again
pub(crate) fn _test_api_shutdown(target_api: &TargetApi, guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .args(target_api.guest_args())
        .capture_output()
        .spawn()
        .unwrap();

    thread::sleep(std::time::Duration::new(1, 0));

    // Verify API server is running
    assert!(target_api.remote_command("ping", None));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    std::fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    let r = std::panic::catch_unwind(|| {
        assert!(target_api.remote_command("create", Some(create_config)));

        // Then boot it
        assert!(target_api.remote_command("boot", None));

        guest.wait_vm_boot().unwrap();

        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);

        // Sync and shutdown without powering off to prevent filesystem
        // corruption.
        guest.ssh_command("sync").unwrap();
        guest.ssh_command("sudo shutdown -H now").unwrap();

        // Wait for the guest to be fully shutdown
        thread::sleep(std::time::Duration::new(20, 0));

        // Then shut it down
        assert!(target_api.remote_command("shutdown", None));

        // Then boot it again
        assert!(target_api.remote_command("boot", None));

        guest.wait_vm_boot().unwrap();

        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

// Start cloud-hypervisor with no VM parameters, only the API server running.
// From the API: Create a VM, boot it and check it can be deleted and then recreated
// booted again.
pub(crate) fn _test_api_delete(target_api: &TargetApi, guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .args(target_api.guest_args())
        .capture_output()
        .spawn()
        .unwrap();

    thread::sleep(std::time::Duration::new(1, 0));

    // Verify API server is running
    assert!(target_api.remote_command("ping", None));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    std::fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    let r = std::panic::catch_unwind(|| {
        assert!(target_api.remote_command("create", Some(create_config)));

        // Then boot it
        assert!(target_api.remote_command("boot", None));

        guest.wait_vm_boot().unwrap();

        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);

        // Sync and shutdown without powering off to prevent filesystem
        // corruption.
        guest.ssh_command("sync").unwrap();
        guest.ssh_command("sudo shutdown -H now").unwrap();

        // Wait for the guest to be fully shutdown
        thread::sleep(std::time::Duration::new(20, 0));

        // Then delete it
        assert!(target_api.remote_command("delete", None));

        assert!(target_api.remote_command("create", Some(create_config)));

        // Then boot it again
        assert!(target_api.remote_command("boot", None));

        guest.wait_vm_boot().unwrap();

        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

// Start cloud-hypervisor with no VM parameters, only the API server running.
// From the API: Create a VM, boot it and check that it looks as expected.
// Then we pause the VM, check that it's no longer available.
// Finally we resume the VM and check that it's available.
pub(crate) fn _test_api_pause_resume(target_api: &TargetApi, guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .args(target_api.guest_args())
        .capture_output()
        .spawn()
        .unwrap();

    thread::sleep(std::time::Duration::new(1, 0));

    // Verify API server is running
    assert!(target_api.remote_command("ping", None));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    std::fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    assert!(target_api.remote_command("create", Some(create_config)));

    // Then boot it
    assert!(target_api.remote_command("boot", None));
    thread::sleep(std::time::Duration::new(20, 0));

    let r = std::panic::catch_unwind(|| {
        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);

        // We now pause the VM
        assert!(target_api.remote_command("pause", None));

        // Check pausing again fails
        assert!(!target_api.remote_command("pause", None));

        thread::sleep(std::time::Duration::new(2, 0));

        // SSH into the VM should fail
        ssh_command_ip(
            "grep -c processor /proc/cpuinfo",
            &guest.network.guest_ip0,
            2,
            5,
        )
        .unwrap_err();

        // Resume the VM
        assert!(target_api.remote_command("resume", None));

        // Check resuming again fails
        assert!(!target_api.remote_command("resume", None));

        thread::sleep(std::time::Duration::new(2, 0));

        // Now we should be able to SSH back in and get the right number of CPUs
        guest.validate_cpu_count(None);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_pty_interaction(pty_path: PathBuf) {
    let mut cf = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(pty_path)
        .unwrap();

    // Some dumb sleeps but we don't want to write
    // before the console is up and we don't want
    // to try and write the next line before the
    // login process is ready.
    thread::sleep(std::time::Duration::new(5, 0));
    assert_eq!(cf.write(b"cloud\n").unwrap(), 6);
    thread::sleep(std::time::Duration::new(2, 0));
    assert_eq!(cf.write(b"cloud123\n").unwrap(), 9);
    thread::sleep(std::time::Duration::new(2, 0));
    assert_eq!(cf.write(b"echo test_pty_console\n").unwrap(), 22);
    thread::sleep(std::time::Duration::new(2, 0));

    // read pty and ensure they have a login shell
    // some fairly hacky workarounds to avoid looping
    // forever in case the channel is blocked getting output
    let ptyc = pty_read(cf);
    let mut empty = 0;
    let mut prev = String::new();
    loop {
        thread::sleep(std::time::Duration::new(2, 0));
        match ptyc.try_recv() {
            Ok(line) => {
                empty = 0;
                prev = prev + &line;
                if prev.contains("test_pty_console") {
                    break;
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                empty += 1;
                assert!(empty <= 5, "No login on pty");
            }
            _ => {
                panic!("No login on pty")
            }
        }
    }
}

pub(crate) fn test_cpu_topology(
    threads_per_core: u8,
    cores_per_package: u8,
    packages: u8,
    use_fw: bool,
) {
    let disk_config = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let total_vcpus = threads_per_core * cores_per_package * packages;
    let direct_kernel_boot_path = direct_kernel_boot_path();
    let mut kernel_path = direct_kernel_boot_path.to_str().unwrap();
    let fw_path = fw_path(FwType::RustHypervisorFirmware);
    if use_fw {
        kernel_path = fw_path.as_str();
    }

    let mut child = GuestCommand::new(&guest)
        .args([
            "--cpus",
            &format!(
                "boot={total_vcpus},topology={threads_per_core}:{cores_per_package}:1:{packages}"
            ),
        ])
        .default_memory()
        .args(["--kernel", kernel_path])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();
        assert_eq!(
            guest.get_cpu_count().unwrap_or_default(),
            u32::from(total_vcpus)
        );
        assert_eq!(
            guest
                .ssh_command("lscpu | grep \"per core\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                .unwrap()
                .trim()
                .parse::<u8>()
                .unwrap_or(0),
            threads_per_core
        );

        assert_eq!(
            guest
                .ssh_command("lscpu | grep \"per socket\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                .unwrap()
                .trim()
                .parse::<u8>()
                .unwrap_or(0),
            cores_per_package
        );

        assert_eq!(
            guest
                .ssh_command("lscpu | grep \"Socket\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                .unwrap()
                .trim()
                .parse::<u8>()
                .unwrap_or(0),
            packages
        );

        #[cfg(target_arch = "x86_64")]
        {
            let mut cpu_id = 0;
            for package_id in 0..packages {
                for core_id in 0..cores_per_package {
                    for _ in 0..threads_per_core {
                        assert_eq!(
                            guest
                                .ssh_command(&format!("cat /sys/devices/system/cpu/cpu{cpu_id}/topology/physical_package_id"))
                                .unwrap()
                                .trim()
                                .parse::<u8>()
                                .unwrap_or(0),
                            package_id
                        );

                        assert_eq!(
                            guest
                                .ssh_command(&format!(
                                    "cat /sys/devices/system/cpu/cpu{cpu_id}/topology/core_id"
                                ))
                                .unwrap()
                                .trim()
                                .parse::<u8>()
                                .unwrap_or(0),
                            core_id
                        );

                        cpu_id += 1;
                    }
                }
            }
        }
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[allow(unused_variables)]
pub(crate) fn _test_guest_numa_nodes(acpi: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);
    #[cfg(target_arch = "x86_64")]
    let kernel_path = direct_kernel_boot_path();
    #[cfg(target_arch = "aarch64")]
    let kernel_path = if acpi {
        edk2_path()
    } else {
        direct_kernel_boot_path()
    };

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", "boot=6,max=12"])
        .args(["--memory", "size=0,hotplug_method=virtio-mem"])
        .args([
            "--memory-zone",
            "id=mem0,size=1G,hotplug_size=3G",
            "id=mem1,size=2G,hotplug_size=3G",
            "id=mem2,size=3G,hotplug_size=3G",
        ])
        .args([
            "--numa",
            "guest_numa_id=0,cpus=[0-2,9],distances=[1@15,2@20],memory_zones=mem0",
            "guest_numa_id=1,cpus=[3-4,6-8],distances=[0@20,2@25],memory_zones=mem1",
            "guest_numa_id=2,cpus=[5,10-11],distances=[0@25,1@30],memory_zones=mem2",
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

        guest.check_numa_common(
            Some(&[960_000, 1_920_000, 2_880_000]),
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
            resize_zone_command(&api_socket, "mem0", "4G");
            resize_zone_command(&api_socket, "mem1", "4G");
            resize_zone_command(&api_socket, "mem2", "4G");
            // Resize to the maximum amount of CPUs and check each NUMA
            // node has been assigned the right CPUs set.
            resize_command(&api_socket, Some(12), None, None, None);
            thread::sleep(std::time::Duration::new(5, 0));

            guest.check_numa_common(
                Some(&[3_840_000, 3_840_000, 3_840_000]),
                Some(&[&[0, 1, 2, 9], &[3, 4, 6, 7, 8], &[5, 10, 11]]),
                None,
            );
        }
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[allow(unused_variables)]
pub(crate) fn _test_power_button(guest: &Guest) {
    let mut cmd = GuestCommand::new(guest);
    let api_socket = temp_api_path(&guest.tmp_dir);

    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .capture_output()
        .default_disks()
        .default_net()
        .args(["--api-socket", &api_socket]);

    let child = cmd.spawn().unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();
        assert!(remote_command(&api_socket, "power-button", None));
    });

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    handle_child_output(r, &output);
}

pub(crate) fn test_vhost_user_net(
    tap: Option<&str>,
    num_queues: usize,
    prepare_daemon: &PrepareNetDaemon,
    generate_host_mac: bool,
    client_mode_daemon: bool,
) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let kernel_path = direct_kernel_boot_path();

    let host_mac = if generate_host_mac {
        Some(MacAddr::local_random())
    } else {
        None
    };

    let mtu = Some(3000);

    let (mut daemon_command, vunet_socket_path) = prepare_daemon(
        &guest.tmp_dir,
        &guest.network.host_ip0,
        tap,
        mtu,
        num_queues,
        client_mode_daemon,
    );

    let net_params = format!(
        "vhost_user=true,mac={},socket={},num_queues={},queue_size=1024{},vhost_mode={},mtu=3000",
        guest.network.guest_mac0,
        vunet_socket_path,
        num_queues,
        if let Some(host_mac) = host_mac {
            format!(",host_mac={host_mac}")
        } else {
            String::new()
        },
        if client_mode_daemon {
            "server"
        } else {
            "client"
        },
    );

    let mut ch_command = GuestCommand::new(&guest);
    ch_command
        .args(["--cpus", format!("boot={}", num_queues / 2).as_str()])
        .args(["--memory", "size=512M,hotplug_size=2048M,shared=on"])
        .args(["--kernel", kernel_path.to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .args(["--net", net_params.as_str()])
        .args(["--api-socket", &api_socket])
        .capture_output();

    let mut daemon_child: std::process::Child;
    let mut child: std::process::Child;

    if client_mode_daemon {
        child = ch_command.spawn().unwrap();
        // Make sure the VMM is waiting for the backend to connect
        thread::sleep(std::time::Duration::new(10, 0));
        daemon_child = daemon_command.spawn().unwrap();
    } else {
        daemon_child = daemon_command.spawn().unwrap();
        // Make sure the backend is waiting for the VMM to connect
        thread::sleep(std::time::Duration::new(10, 0));
        child = ch_command.spawn().unwrap();
    }

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        if let Some(tap_name) = tap {
            let tap_count = exec_host_command_output(&format!("ip link | grep -c {tap_name}"));
            assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");
        }

        if let Some(host_mac) = tap {
            let mac_count = exec_host_command_output(&format!("ip link | grep -c {host_mac}"));
            assert_eq!(String::from_utf8_lossy(&mac_count.stdout).trim(), "1");
        }

        #[cfg(target_arch = "aarch64")]
        let iface = "enp0s4";
        #[cfg(target_arch = "x86_64")]
        let iface = "ens4";

        assert_eq!(
            guest
                .ssh_command(format!("cat /sys/class/net/{iface}/mtu").as_str())
                .unwrap()
                .trim(),
            "3000"
        );

        // 1 network interface + default localhost ==> 2 interfaces
        // It's important to note that this test is fully exercising the
        // vhost-user-net implementation and the associated backend since
        // it does not define any --net network interface. That means all
        // the ssh communication in that test happens through the network
        // interface backed by vhost-user-net.
        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            2
        );

        // The following pci devices will appear on guest with PCI-MSI
        // interrupt vectors assigned.
        // 1 virtio-console with 3 vectors: config, Rx, Tx
        // 1 virtio-blk     with 2 vectors: config, Request
        // 1 virtio-blk     with 2 vectors: config, Request
        // 1 virtio-rng     with 2 vectors: config, Request
        // Since virtio-net has 2 queue pairs, its vectors is as follows:
        // 1 virtio-net     with 5 vectors: config, Rx (2), Tx (2)
        // Based on the above, the total vectors should 14.
        let grep_cmd = format!("grep -c {} /proc/interrupts", get_msi_interrupt_pattern());

        assert_eq!(
            guest
                .ssh_command(&grep_cmd)
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            10 + (num_queues as u32)
        );

        // ACPI feature is needed.
        #[cfg(target_arch = "x86_64")]
        {
            guest.enable_memory_hotplug();

            // Add RAM to the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            thread::sleep(std::time::Duration::new(10, 0));

            // Here by simply checking the size (through ssh), we validate
            // the connection is still working, which means vhost-user-net
            // keeps working after the resize.
            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
        }
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    thread::sleep(std::time::Duration::new(5, 0));
    let _ = daemon_child.kill();
    let _ = daemon_child.wait();

    handle_child_output(r, &output);
}

type PrepareBlkDaemon = dyn Fn(&TempDir, &str, usize, bool, bool) -> (std::process::Child, String);

pub(crate) fn test_vhost_user_blk(
    num_queues: usize,
    readonly: bool,
    direct: bool,
    prepare_vhost_user_blk_daemon: Option<&PrepareBlkDaemon>,
) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let kernel_path = direct_kernel_boot_path();

    let (blk_params, daemon_child) = {
        let prepare_daemon = prepare_vhost_user_blk_daemon.unwrap();
        // Start the daemon
        let (daemon_child, vubd_socket_path) =
            prepare_daemon(&guest.tmp_dir, "blk.img", num_queues, readonly, direct);

        (
            format!(
                "vhost_user=true,socket={vubd_socket_path},num_queues={num_queues},queue_size=128",
            ),
            Some(daemon_child),
        )
    };

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", format!("boot={num_queues}").as_str()])
        .args(["--memory", "size=512M,hotplug_size=2048M,shared=on"])
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
            blk_params.as_str(),
        ])
        .default_net()
        .args(["--api-socket", &api_socket])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check both if /dev/vdc exists and if the block size is 16M.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | grep -c 16M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Check if this block is RO or RW.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | awk '{print $5}'")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            readonly as u32
        );

        // Check if the number of queues in /sys/block/vdc/mq matches the
        // expected num_queues.
        assert_eq!(
            guest
                .ssh_command("ls -ll /sys/block/vdc/mq | grep ^d | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            num_queues as u32
        );

        // Mount the device
        let mount_ro_rw_flag = if readonly { "ro,noload" } else { "rw" };
        guest.ssh_command("mkdir mount_image").unwrap();
        guest
            .ssh_command(
                format!("sudo mount -o {mount_ro_rw_flag} -t ext4 /dev/vdc mount_image/").as_str(),
            )
            .unwrap();

        // Check the content of the block device. The file "foo" should
        // contain "bar".
        assert_eq!(
            guest.ssh_command("cat mount_image/foo").unwrap().trim(),
            "bar"
        );

        // ACPI feature is needed.
        #[cfg(target_arch = "x86_64")]
        {
            guest.enable_memory_hotplug();

            // Add RAM to the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            thread::sleep(std::time::Duration::new(10, 0));

            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

            // Check again the content of the block device after the resize
            // has been performed.
            assert_eq!(
                guest.ssh_command("cat mount_image/foo").unwrap().trim(),
                "bar"
            );
        }

        // Unmount the device
        guest.ssh_command("sudo umount /dev/vdc").unwrap();
        guest.ssh_command("rm -r mount_image").unwrap();
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    if let Some(mut daemon_child) = daemon_child {
        thread::sleep(std::time::Duration::new(5, 0));
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();
    }

    handle_child_output(r, &output);
}

pub(crate) fn test_boot_from_vhost_user_blk(
    num_queues: usize,
    readonly: bool,
    direct: bool,
    prepare_vhost_user_blk_daemon: Option<&PrepareBlkDaemon>,
) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));

    let kernel_path = direct_kernel_boot_path();

    let disk_path = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();

    let (blk_boot_params, daemon_child) = {
        let prepare_daemon = prepare_vhost_user_blk_daemon.unwrap();
        // Start the daemon
        let (daemon_child, vubd_socket_path) = prepare_daemon(
            &guest.tmp_dir,
            disk_path.as_str(),
            num_queues,
            readonly,
            direct,
        );

        (
            format!(
                "vhost_user=true,socket={vubd_socket_path},num_queues={num_queues},queue_size=128",
            ),
            Some(daemon_child),
        )
    };

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", format!("boot={num_queues}").as_str()])
        .args(["--memory", "size=512M,shared=on"])
        .args(["--kernel", kernel_path.to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .args([
            "--disk",
            blk_boot_params.as_str(),
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

        // Just check the VM booted correctly.
        assert_eq!(guest.get_cpu_count().unwrap_or_default(), num_queues as u32);
        assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
    });
    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    if let Some(mut daemon_child) = daemon_child {
        thread::sleep(std::time::Duration::new(5, 0));
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();
    }

    handle_child_output(r, &output);
}

pub(crate) fn _test_virtio_fs(
    prepare_daemon: &dyn Fn(&TempDir, &str) -> (std::process::Child, String),
    hotplug: bool,
    use_generic_vhost_user: bool,
    pci_segment: Option<u16>,
) {
    #[cfg(target_arch = "aarch64")]
    let focal_image = if hotplug {
        FOCAL_IMAGE_UPDATE_KERNEL_NAME.to_string()
    } else {
        FOCAL_IMAGE_NAME.to_string()
    };
    #[cfg(target_arch = "x86_64")]
    let focal_image = FOCAL_IMAGE_NAME.to_string();
    let disk_config = UbuntuDiskConfig::new(focal_image);
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut workload_path = dirs::home_dir().unwrap();
    workload_path.push("workloads");

    let mut shared_dir = workload_path;
    shared_dir.push("shared_dir");

    #[cfg(target_arch = "x86_64")]
    let kernel_path = direct_kernel_boot_path();
    #[cfg(target_arch = "aarch64")]
    let kernel_path = if hotplug {
        edk2_path()
    } else {
        direct_kernel_boot_path()
    };

    let (mut daemon_child, virtiofsd_socket_path) =
        prepare_daemon(&guest.tmp_dir, shared_dir.to_str().unwrap());

    let mut guest_command = GuestCommand::new(&guest);
    guest_command
        .default_cpus()
        .args(["--memory", "size=512M,hotplug_size=2048M,shared=on"])
        .args(["--kernel", kernel_path.to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .default_net()
        .args(["--api-socket", &api_socket]);
    if pci_segment.is_some() {
        guest_command.args([
            "--platform",
            &format!("num_pci_segments={MAX_NUM_PCI_SEGMENTS}"),
        ]);
    }

    let fs_params = format!(
        "socket={},id=myfs0,{}{}",
        virtiofsd_socket_path,
        if use_generic_vhost_user {
            "queue_sizes=[1024,1024],virtio_id=26"
        } else {
            "tag=myfs,num_queues=1,queue_size=1024"
        },
        if let Some(pci_segment) = pci_segment {
            format!(",pci_segment={pci_segment}")
        } else {
            String::new()
        }
    );

    if !hotplug {
        guest_command.args([
            if use_generic_vhost_user {
                "--generic-vhost-user"
            } else {
                "--fs"
            },
            fs_params.as_str(),
        ]);
    }

    let mut child = guest_command.capture_output().spawn().unwrap();
    let add_arg = if use_generic_vhost_user {
        "add-generic-vhost-user"
    } else {
        "add-fs"
    };

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        if hotplug {
            // Add fs to the VM
            let (cmd_success, cmd_output) =
                remote_command_w_output(&api_socket, add_arg, Some(&fs_params));
            assert!(cmd_success);

            if let Some(pci_segment) = pci_segment {
                assert!(String::from_utf8_lossy(&cmd_output).contains(&format!(
                    "{{\"id\":\"myfs0\",\"bdf\":\"{pci_segment:04x}:00:01.0\"}}"
                )));
            } else {
                assert!(
                    String::from_utf8_lossy(&cmd_output)
                        .contains("{\"id\":\"myfs0\",\"bdf\":\"0000:00:06.0\"}")
                );
            }

            thread::sleep(std::time::Duration::new(10, 0));
        }

        // Mount shared directory through virtio_fs filesystem
        guest
            .ssh_command("mkdir -p mount_dir && sudo mount -t virtiofs myfs mount_dir/")
            .unwrap();

        // Check file1 exists and its content is "foo"
        assert_eq!(
            guest.ssh_command("cat mount_dir/file1").unwrap().trim(),
            "foo"
        );
        // Check file2 does not exist
        guest
            .ssh_command("[ ! -f 'mount_dir/file2' ] || true")
            .unwrap();

        // Check file3 exists and its content is "bar"
        assert_eq!(
            guest.ssh_command("cat mount_dir/file3").unwrap().trim(),
            "bar"
        );

        // ACPI feature is needed.
        #[cfg(target_arch = "x86_64")]
        {
            guest.enable_memory_hotplug();

            // Add RAM to the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram), None, None);

            thread::sleep(std::time::Duration::new(30, 0));
            assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

            // After the resize, check again that file1 exists and its
            // content is "foo".
            assert_eq!(
                guest.ssh_command("cat mount_dir/file1").unwrap().trim(),
                "foo"
            );
        }

        if hotplug {
            // Remove from VM
            guest.ssh_command("sudo umount mount_dir").unwrap();
            assert!(remote_command(&api_socket, "remove-device", Some("myfs0")));
        }
    });

    let (r, hotplug_daemon_child) = if r.is_ok() && hotplug {
        thread::sleep(std::time::Duration::new(10, 0));
        let (daemon_child, virtiofsd_socket_path) =
            prepare_daemon(&guest.tmp_dir, shared_dir.to_str().unwrap());

        let r = std::panic::catch_unwind(|| {
            thread::sleep(std::time::Duration::new(10, 0));
            let fs_params = format!(
                "id=myfs0,socket={},{}{}",
                virtiofsd_socket_path,
                if use_generic_vhost_user {
                    "queue_sizes=[1024,1024],virtio_id=26"
                } else {
                    "tag=myfs,num_queues=1,queue_size=1024"
                },
                if let Some(pci_segment) = pci_segment {
                    format!(",pci_segment={pci_segment}")
                } else {
                    String::new()
                }
            );

            // Add back and check it works
            let (cmd_success, cmd_output) =
                remote_command_w_output(&api_socket, add_arg, Some(&fs_params));
            assert!(cmd_success);
            if let Some(pci_segment) = pci_segment {
                assert!(String::from_utf8_lossy(&cmd_output).contains(&format!(
                    "{{\"id\":\"myfs0\",\"bdf\":\"{pci_segment:04x}:00:01.0\"}}"
                )));
            } else {
                assert!(
                    String::from_utf8_lossy(&cmd_output)
                        .contains("{\"id\":\"myfs0\",\"bdf\":\"0000:00:06.0\"}")
                );
            }

            thread::sleep(std::time::Duration::new(10, 0));
            // Mount shared directory through virtio_fs filesystem
            guest
                .ssh_command("mkdir -p mount_dir && sudo mount -t virtiofs myfs mount_dir/")
                .unwrap();

            // Check file1 exists and its content is "foo"
            assert_eq!(
                guest.ssh_command("cat mount_dir/file1").unwrap().trim(),
                "foo"
            );
        });

        (r, Some(daemon_child))
    } else {
        (r, None)
    };

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    let _ = daemon_child.kill();
    let _ = daemon_child.wait();

    if let Some(mut daemon_child) = hotplug_daemon_child {
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();
    }

    handle_child_output(r, &output);
}

pub(crate) fn test_virtio_pmem(discard_writes: bool, specify_size: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));

    let kernel_path = direct_kernel_boot_path();

    let pmem_temp_file = TempFile::new().unwrap();
    pmem_temp_file.as_file().set_len(128 << 20).unwrap();

    std::process::Command::new("mkfs.ext4")
        .arg(pmem_temp_file.as_path())
        .output()
        .expect("Expect creating disk image to succeed");

    let mut child = GuestCommand::new(&guest)
        .default_cpus()
        .default_memory()
        .args(["--kernel", kernel_path.to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .default_net()
        .args([
            "--pmem",
            format!(
                "file={}{}{}",
                pmem_temp_file.as_path().to_str().unwrap(),
                if specify_size { ",size=128M" } else { "" },
                if discard_writes {
                    ",discard_writes=on"
                } else {
                    ""
                }
            )
            .as_str(),
        ])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check for the presence of /dev/pmem0
        assert_eq!(
            guest.ssh_command("ls /dev/pmem0").unwrap().trim(),
            "/dev/pmem0"
        );

        // Check changes persist after reboot
        assert_eq!(guest.ssh_command("sudo mount /dev/pmem0 /mnt").unwrap(), "");
        assert_eq!(guest.ssh_command("ls /mnt").unwrap(), "lost+found\n");
        guest
            .ssh_command("echo test123 | sudo tee /mnt/test")
            .unwrap();
        assert_eq!(guest.ssh_command("sudo umount /mnt").unwrap(), "");
        assert_eq!(guest.ssh_command("ls /mnt").unwrap(), "");

        guest.reboot_linux(0);
        assert_eq!(guest.ssh_command("sudo mount /dev/pmem0 /mnt").unwrap(), "");
        assert_eq!(
            guest
                .ssh_command("sudo cat /mnt/test || true")
                .unwrap()
                .trim(),
            if discard_writes { "" } else { "test123" }
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_virtio_vsock(guest: &Guest, hotplug: bool) {
    let socket = temp_vsock_path(&guest.tmp_dir);
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut cmd = GuestCommand::new(guest);
    cmd.args(["--api-socket", &api_socket]);
    cmd.default_cpus();
    cmd.default_memory();
    cmd.default_kernel_cmdline();
    cmd.default_disks();
    cmd.default_net();

    if !hotplug {
        cmd.args(["--vsock", format!("cid=3,socket={socket}").as_str()]);
    }

    let mut child = cmd.capture_output().spawn().unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        if hotplug {
            let (cmd_success, cmd_output) = remote_command_w_output(
                &api_socket,
                "add-vsock",
                Some(format!("cid=3,socket={socket},id=test0").as_str()),
            );
            assert!(cmd_success);
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}")
            );
            thread::sleep(std::time::Duration::new(10, 0));
            // Check adding a second one fails
            assert!(!remote_command(
                &api_socket,
                "add-vsock",
                Some("cid=1234,socket=/tmp/fail")
            ));
        }

        // Validate vsock works as expected.
        guest.check_vsock(socket.as_str());
        guest.reboot_linux(0);
        // Validate vsock still works after a reboot.
        guest.check_vsock(socket.as_str());

        if hotplug {
            assert!(remote_command(&api_socket, "remove-device", Some("test0")));
        }
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn test_memory_mergeable(mergeable: bool) {
    let memory_param = if mergeable {
        "mergeable=on"
    } else {
        "mergeable=off"
    };

    // We assume the number of shared pages in the rest of the system to be constant
    let ksm_ps_init = get_ksm_pages_shared();

    let disk_config1 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
    let guest1 = Guest::new(Box::new(disk_config1));
    let mut child1 = GuestCommand::new(&guest1)
        .default_cpus()
        .args(["--memory", format!("size=512M,{memory_param}").as_str()])
        .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .args(["--net", guest1.default_net_string().as_str()])
        .args(["--serial", "tty", "--console", "off"])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest1.wait_vm_boot().unwrap();
    });
    if r.is_err() {
        kill_child(&mut child1);
        let output = child1.wait_with_output().unwrap();
        handle_child_output(r, &output);
        panic!("Test should already be failed/panicked"); // To explicitly mark this block never return
    }

    let ksm_ps_guest1 = get_ksm_pages_shared();

    let disk_config2 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
    let guest2 = Guest::new(Box::new(disk_config2));
    let mut child2 = GuestCommand::new(&guest2)
        .default_cpus()
        .args(["--memory", format!("size=512M,{memory_param}").as_str()])
        .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .args(["--net", guest2.default_net_string().as_str()])
        .args(["--serial", "tty", "--console", "off"])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest2.wait_vm_boot().unwrap();
        let ksm_ps_guest2 = get_ksm_pages_shared();

        if mergeable {
            println!(
                "ksm pages_shared after vm1 booted '{ksm_ps_guest1}', ksm pages_shared after vm2 booted '{ksm_ps_guest2}'"
            );
            // We are expecting the number of shared pages to increase as the number of VM increases
            assert!(ksm_ps_guest1 < ksm_ps_guest2);
        } else {
            assert!(ksm_ps_guest1 == ksm_ps_init);
            assert!(ksm_ps_guest2 == ksm_ps_init);
        }
    });

    kill_child(&mut child1);
    kill_child(&mut child2);

    let output = child1.wait_with_output().unwrap();
    child2.wait().unwrap();

    handle_child_output(r, &output);
}

// This test validates that it can find the virtio-iommu device at first.
// It also verifies that both disks and the network card are attached to
// the virtual IOMMU by looking at /sys/kernel/iommu_groups directory.
// The last interesting part of this test is that it exercises the network
// interface attached to the virtual IOMMU since this is the one used to
// send all commands through SSH.
pub(crate) fn _test_virtio_iommu(_acpi: bool /* not needed on x86_64 */) {
    // Virtio-iommu support is ready in recent kernel (v5.14). But the kernel in
    // Focal image is still old.
    // So if ACPI is enabled on AArch64, we use a modified Focal image in which
    // the kernel binary has been updated.
    #[cfg(target_arch = "aarch64")]
    let focal_image = FOCAL_IMAGE_UPDATE_KERNEL_NAME.to_string();
    #[cfg(target_arch = "x86_64")]
    let focal_image = FOCAL_IMAGE_NAME.to_string();
    let disk_config = UbuntuDiskConfig::new(focal_image);
    let guest = Guest::new(Box::new(disk_config));

    #[cfg(target_arch = "x86_64")]
    let kernel_path = direct_kernel_boot_path();
    #[cfg(target_arch = "aarch64")]
    let kernel_path = if _acpi {
        edk2_path()
    } else {
        direct_kernel_boot_path()
    };

    let mut child = GuestCommand::new(&guest)
        .default_cpus()
        .default_memory()
        .args(["--kernel", kernel_path.to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .args([
            "--disk",
            format!(
                "path={},iommu=on",
                guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
            )
            .as_str(),
            format!(
                "path={},iommu=on",
                guest.disk_config.disk(DiskType::CloudInit).unwrap()
            )
            .as_str(),
        ])
        .args(["--net", guest.default_net_string_w_iommu().as_str()])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Verify the virtio-iommu device is present.
        assert!(
            guest
                .does_device_vendor_pair_match("0x1057", "0x1af4")
                .unwrap_or_default()
        );

        // On AArch64, if the guest system boots from FDT, the behavior of IOMMU is a bit
        // different with ACPI.
        // All devices on the PCI bus will be attached to the virtual IOMMU, except the
        // virtio-iommu device itself. So these devices will all be added to IOMMU groups,
        // and appear under folder '/sys/kernel/iommu_groups/'.
        //
        // Verify the first disk is in an iommu group.
        assert!(
            guest
                .ssh_command("ls /sys/kernel/iommu_groups/*/devices")
                .unwrap()
                .contains("0000:00:02.0")
        );

        // Verify the second disk is in an iommu group.
        assert!(
            guest
                .ssh_command("ls /sys/kernel/iommu_groups/*/devices")
                .unwrap()
                .contains("0000:00:03.0")
        );

        // Verify the network card is in an iommu group.
        assert!(
            guest
                .ssh_command("ls /sys/kernel/iommu_groups/*/devices")
                .unwrap()
                .contains("0000:00:04.0")
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

// ivshmem test
// This case validates that read data from host(host write data to ivshmem backend file,
// guest read data from ivshmem pci bar2 memory)
// and write data to host(guest write data to ivshmem pci bar2 memory, host read it from
// ivshmem backend file).
// It also checks the size of the shared memory region.
pub(crate) fn _test_ivshmem(guest: &Guest, ivshmem_file_path: impl AsRef<Path>, file_size: &str) {
    let ivshmem_file_path = ivshmem_file_path.as_ref();
    let test_message_read = String::from("ivshmem device test data read");
    // Modify backend file data before function test
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(ivshmem_file_path)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(test_message_read.as_bytes()).unwrap();
    file.write_all(b"\0").unwrap();
    file.flush().unwrap();

    let output = fs::read_to_string(ivshmem_file_path).unwrap();
    let nul_pos = output.as_bytes().iter().position(|&b| b == 0).unwrap();
    let c_str = CStr::from_bytes_until_nul(&output.as_bytes()[..=nul_pos]).unwrap();
    let file_message = c_str.to_string_lossy().to_string();
    // Check if the backend file data is correct
    assert_eq!(test_message_read, file_message);

    let device_id_line = String::from(
        guest
            .ssh_command("lspci -D | grep \"Inter-VM shared memory\"")
            .unwrap()
            .trim(),
    );
    // Check if ivshmem exists
    assert!(!device_id_line.is_empty());
    let device_id = device_id_line.split(" ").next().unwrap();
    // Check shard memory size
    assert_eq!(
        guest
            .ssh_command(
                format!("lspci -vv -s {device_id} | grep -c \"Region 2.*size={file_size}\"")
                    .as_str(),
            )
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap_or_default(),
        1
    );

    // guest don't have gcc or g++, try to use python to test :(
    // This python program try to mmap the ivshmem pci bar2 memory and read the data from it.
    let ivshmem_test_read = format!(
        r#"
import os
import mmap
from ctypes import create_string_buffer, c_char, memmove

if __name__ == "__main__":
    device_path = f"/sys/bus/pci/devices/{device_id}/resource2"
    fd = os.open(device_path, os.O_RDWR | os.O_SYNC)

    PAGE_SIZE = os.sysconf('SC_PAGESIZE')

    with mmap.mmap(fd, PAGE_SIZE, flags=mmap.MAP_SHARED,
                      prot=mmap.PROT_READ | mmap.PROT_WRITE, offset=0) as shmem:
        c_buf = (c_char * PAGE_SIZE).from_buffer(shmem)
        null_pos = c_buf.raw.find(b'\x00')
        valid_data = c_buf.raw[:null_pos] if null_pos != -1 else c_buf.raw
        print(valid_data.decode('utf-8', errors='replace'), end="")
        shmem.flush()
        del c_buf

    os.close(fd)
    "#
    );
    guest
        .ssh_command(
            format!(
                r#"cat << EOF > test_read.py
{ivshmem_test_read}
EOF
"#
            )
            .as_str(),
        )
        .unwrap();
    let guest_message = guest.ssh_command("sudo python3 test_read.py").unwrap();

    // Check the probe message in host and guest
    assert_eq!(test_message_read, guest_message);

    let test_message_write = "ivshmem device test data write";
    // Then the program writes a test message to the memory and flush it.
    let ivshmem_test_write = format!(
        r#"
import os
import mmap
from ctypes import create_string_buffer, c_char, memmove

if __name__ == "__main__":
    device_path = f"/sys/bus/pci/devices/{device_id}/resource2"
    test_message = "{test_message_write}"
    fd = os.open(device_path, os.O_RDWR | os.O_SYNC)

    PAGE_SIZE = os.sysconf('SC_PAGESIZE')

    with mmap.mmap(fd, PAGE_SIZE, flags=mmap.MAP_SHARED,
                      prot=mmap.PROT_READ | mmap.PROT_WRITE, offset=0) as shmem:
        shmem.flush()
        c_buf = (c_char * PAGE_SIZE).from_buffer(shmem)
        encoded_msg = test_message.encode('utf-8').ljust(1000, b'\x00')
        memmove(c_buf, encoded_msg, len(encoded_msg))
        shmem.flush()
        del c_buf

    os.close(fd)
    "#
    );

    guest
        .ssh_command(
            format!(
                r#"cat << EOF > test_write.py
{ivshmem_test_write}
EOF
"#
            )
            .as_str(),
        )
        .unwrap();

    let _ = guest.ssh_command("sudo python3 test_write.py").unwrap();

    let output = fs::read_to_string(ivshmem_file_path).unwrap();
    let nul_pos = output.as_bytes().iter().position(|&b| b == 0).unwrap();
    let c_str = CStr::from_bytes_until_nul(&output.as_bytes()[..=nul_pos]).unwrap();
    let file_message = c_str.to_string_lossy().to_string();
    // Check to send data from guest to host
    assert_eq!(test_message_write, file_message);
}

pub(crate) fn _test_simple_launch(guest: &Guest) {
    let event_path = temp_event_monitor_path(&guest.tmp_dir);

    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .args(["--serial", "tty", "--console", "off"])
        .args(["--event-monitor", format!("path={event_path}").as_str()])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        guest.validate_cpu_count(None);
        guest.validate_memory(None);
        assert_eq!(guest.get_pci_bridge_class().unwrap_or_default(), "0x060000");
        assert!(check_sequential_events(
            &guest
                .get_expected_seq_events_for_simple_launch()
                .iter()
                .collect::<Vec<_>>(),
            &event_path
        ));

        // It's been observed on the Bionic image that udev and snapd
        // services can cause some delay in the VM's shutdown. Disabling
        // them improves the reliability of this test.
        let _ = guest.ssh_command("sudo systemctl disable udev");
        let _ = guest.ssh_command("sudo systemctl stop udev");
        let _ = guest.ssh_command("sudo systemctl disable snapd");
        let _ = guest.ssh_command("sudo systemctl stop snapd");

        guest.ssh_command("sudo poweroff").unwrap();
        thread::sleep(std::time::Duration::new(20, 0));
        let latest_events = [
            &MetaEvent {
                event: "shutdown".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "deleted".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "shutdown".to_string(),
                device_id: None,
            },
        ];
        assert!(check_latest_events_exact(&latest_events, &event_path));
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_multi_cpu(guest: &Guest) {
    let mut cmd = GuestCommand::new(guest);
    cmd.args(["--cpus", "boot=2,max=4"])
        .default_memory()
        .default_kernel_cmdline()
        .capture_output()
        .default_disks()
        .default_net();

    let mut child = cmd.spawn().unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);

        assert_eq!(
            guest
                .ssh_command(r#"sudo dmesg | grep "smp: Brought up" | sed "s/\[\ *[0-9.]*\] //""#)
                .unwrap()
                .trim(),
            "smp: Brought up 1 node, 2 CPUs"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_cpu_affinity(guest: &Guest) {
    // We need the host to have at least 4 CPUs if we want to be able
    // to run this test.
    let host_cpus_count = exec_host_command_output("nproc");
    assert!(
        String::from_utf8_lossy(&host_cpus_count.stdout)
            .trim()
            .parse::<u16>()
            .unwrap_or(0)
            >= 4
    );

    let mut child = GuestCommand::new(guest)
        .default_cpus_with_affinity()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();
        let pid = child.id();
        let taskset_vcpu0 = exec_host_command_output(format!("taskset -pc $(ps -T -p {pid} | grep vcpu0 | xargs | cut -f 2 -d \" \") | cut -f 6 -d \" \"").as_str());
        assert_eq!(String::from_utf8_lossy(&taskset_vcpu0.stdout).trim(), "0,2");
        let taskset_vcpu1 = exec_host_command_output(format!("taskset -pc $(ps -T -p {pid} | grep vcpu1 | xargs | cut -f 2 -d \" \") | cut -f 6 -d \" \"").as_str());
        assert_eq!(String::from_utf8_lossy(&taskset_vcpu1.stdout).trim(), "1,3");
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}

pub(crate) fn _test_virtio_queue_affinity(guest: &Guest) {
    // We need the host to have at least 4 CPUs if we want to be able
    // to run this test.
    let host_cpus_count = exec_host_command_output("nproc");
    assert!(
        String::from_utf8_lossy(&host_cpus_count.stdout)
            .trim()
            .parse::<u16>()
            .unwrap_or(0)
            >= 4
    );

    let mut child = GuestCommand::new(guest)
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
                "path={},num_queues=4,queue_affinity=[0@[0,2],1@[1,3],2@[1],3@[3]]",
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
        let pid = child.id();
        let taskset_q0 = exec_host_command_output(format!("taskset -pc $(ps -T -p {pid} | grep disk1_q0 | xargs | cut -f 2 -d \" \") | cut -f 6 -d \" \"").as_str());
        assert_eq!(String::from_utf8_lossy(&taskset_q0.stdout).trim(), "0,2");
        let taskset_q1 = exec_host_command_output(format!("taskset -pc $(ps -T -p {pid} | grep disk1_q1 | xargs | cut -f 2 -d \" \") | cut -f 6 -d \" \"").as_str());
        assert_eq!(String::from_utf8_lossy(&taskset_q1.stdout).trim(), "1,3");
        let taskset_q2 = exec_host_command_output(format!("taskset -pc $(ps -T -p {pid} | grep disk1_q2 | xargs | cut -f 2 -d \" \") | cut -f 6 -d \" \"").as_str());
        assert_eq!(String::from_utf8_lossy(&taskset_q2.stdout).trim(), "1");
        let taskset_q3 = exec_host_command_output(format!("taskset -pc $(ps -T -p {pid} | grep disk1_q3 | xargs | cut -f 2 -d \" \") | cut -f 6 -d \" \"").as_str());
        assert_eq!(String::from_utf8_lossy(&taskset_q3.stdout).trim(), "3");
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}

pub(crate) fn _test_pci_msi(guest: &Guest) {
    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .capture_output()
        .default_disks()
        .default_net();

    let mut child = cmd.spawn().unwrap();

    guest.wait_vm_boot().unwrap();

    let grep_cmd = format!("grep -c {} /proc/interrupts", get_msi_interrupt_pattern());

    let r = std::panic::catch_unwind(|| {
        assert_eq!(
            guest
                .ssh_command(&grep_cmd)
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

pub(crate) fn _test_virtio_net_ctrl_queue(guest: &Guest) {
    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .args(["--net", guest.default_net_string_w_mtu(3000).as_str()])
        .capture_output()
        .default_disks();

    let mut child = cmd.spawn().unwrap();

    guest.wait_vm_boot().unwrap();

    #[cfg(target_arch = "aarch64")]
    let iface = "enp0s4";
    #[cfg(target_arch = "x86_64")]
    let iface = "ens4";

    let r = std::panic::catch_unwind(|| {
        assert_eq!(
            guest
                .ssh_command(
                    format!("sudo ethtool -K {iface} rx-gro-hw off && echo success").as_str()
                )
                .unwrap()
                .trim(),
            "success"
        );
        assert_eq!(
            guest
                .ssh_command(format!("cat /sys/class/net/{iface}/mtu").as_str())
                .unwrap()
                .trim(),
            "3000"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_pci_multiple_segments(
    guest: &Guest,
    max_num_pci_segments: u16,
    pci_segments_for_disk: u16,
) {
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

    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline_with_platform(Some(&format!(
            "num_pci_segments={max_num_pci_segments}"
        )))
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
            format!("path={test_disk_path},pci_segment={pci_segments_for_disk},image_type=raw")
                .as_str(),
        ])
        .capture_output()
        .default_net();

    let mut child = cmd.spawn().unwrap();

    guest.wait_vm_boot().unwrap();

    let grep_cmd = "lspci | grep \"Host bridge\" | wc -l";

    let r = std::panic::catch_unwind(|| {
        // There should be MAX_NUM_PCI_SEGMENTS PCI host bridges in the guest.
        assert_eq!(
            guest
                .ssh_command(grep_cmd)
                .unwrap()
                .trim()
                .parse::<u16>()
                .unwrap_or_default(),
            max_num_pci_segments
        );

        // Check both if /dev/vdc exists and if the block size is 4M.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | grep -c 4M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Mount the device.
        guest.ssh_command("mkdir mount_image").unwrap();
        guest
            .ssh_command("sudo mount -o rw -t ext4 /dev/vdc mount_image/")
            .unwrap();
        // Grant all users with write permission.
        guest.ssh_command("sudo chmod a+w mount_image/").unwrap();

        // Write something to the device.
        guest
            .ssh_command("sudo echo \"bar\" >> mount_image/foo")
            .unwrap();

        // Check the content of the block device. The file "foo" should
        // contain "bar".
        assert_eq!(
            guest
                .ssh_command("sudo cat mount_image/foo")
                .unwrap()
                .trim(),
            "bar"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_direct_kernel_boot(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        guest.validate_cpu_count(None);
        guest.validate_memory(None);

        let grep_cmd = format!("grep -c {} /proc/interrupts", get_msi_interrupt_pattern());
        assert_eq!(
            guest
                .ssh_command(&grep_cmd)
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

pub(crate) fn _test_virtio_block(
    guest: &Guest,
    disable_io_uring: bool,
    disable_aio: bool,
    verify_os_disk: bool,
    backing_files: bool,
    image_type: ImageType,
) {
    let mut workload_path = dirs::home_dir().unwrap();
    workload_path.push("workloads");

    let mut blk_file_path = workload_path;
    blk_file_path.push("blk.img");

    let initial_backing_checksum = if verify_os_disk {
        compute_backing_checksum(guest.disk_config.disk(DiskType::OperatingSystem).unwrap())
    } else {
        None
    };
    assert!(
        guest.num_cpu >= 4,
        "_test_virtio_block requires at least 4 CPUs to match num_queues=4"
    );
    let mut cloud_child = GuestCommand::new(guest)
        .default_cpus()
        .args(["--memory", "size=512M,shared=on"])
        .default_kernel_cmdline()
        .args([
            "--disk",
            format!(
                "path={},backing_files={},image_type={image_type}",
                guest.disk_config.disk(DiskType::OperatingSystem).unwrap(),
                if backing_files { "on" } else { "off" },
            )
            .as_str(),
            format!(
                "path={}",
                guest.disk_config.disk(DiskType::CloudInit).unwrap()
            )
            .as_str(),
            format!(
                "path={},readonly=on,direct=on,num_queues=4,_disable_io_uring={},_disable_aio={}",
                blk_file_path.to_str().unwrap(),
                disable_io_uring,
                disable_aio,
            )
            .as_str(),
        ])
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check both if /dev/vdc exists and if the block size is 16M.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | grep -c 16M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Check both if /dev/vdc exists and if this block is RO.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | awk '{print $5}'")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Check if the number of queues is 4.
        assert_eq!(
            guest
                .ssh_command("ls -ll /sys/block/vdc/mq | grep ^d | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            4
        );
    });

    if verify_os_disk {
        // Use clean shutdown to allow cloud-hypervisor to clear
        // the dirty bit in the QCOW2 v3 image.
        kill_child(&mut cloud_child);
    } else {
        let _ = cloud_child.kill();
    }
    let output = cloud_child.wait_with_output().unwrap();

    handle_child_output(r, &output);

    if verify_os_disk {
        disk_check_consistency(
            guest.disk_config.disk(DiskType::OperatingSystem).unwrap(),
            initial_backing_checksum,
        );
    }
}

pub fn _test_virtio_block_dynamic_vhdx_expand(guest: &Guest) {
    const VIRTUAL_DISK_SIZE: u64 = 100 << 20;
    const EMPTY_VHDX_FILE_SIZE: u64 = 8 << 20;
    const FULL_VHDX_FILE_SIZE: u64 = 112 << 20;
    const DYNAMIC_VHDX_NAME: &str = "dynamic.vhdx";

    let vhdx_pathbuf = guest.tmp_dir.as_path().join(DYNAMIC_VHDX_NAME);
    let vhdx_path = vhdx_pathbuf.to_str().unwrap();

    // Generate a 100 MiB dynamic VHDX file
    std::process::Command::new("qemu-img")
        .arg("create")
        .args(["-f", "vhdx"])
        .arg(vhdx_path)
        .arg(VIRTUAL_DISK_SIZE.to_string())
        .output()
        .expect("Expect generating dynamic VHDX image");

    // Check if the size matches with empty VHDx file size
    assert_eq!(vhdx_image_size(vhdx_path), EMPTY_VHDX_FILE_SIZE);

    let mut cloud_child = GuestCommand::new(guest)
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
            format!("path={vhdx_path}").as_str(),
        ])
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check both if /dev/vdc exists and if the block size is 100 MiB.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | grep -c 100M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Write 100 MB of data to the VHDx disk
        guest
            .ssh_command("sudo dd if=/dev/urandom of=/dev/vdc bs=1M count=100")
            .unwrap();
    });

    // Check if the size matches with expected expanded VHDx file size
    assert_eq!(vhdx_image_size(vhdx_path), FULL_VHDX_FILE_SIZE);

    kill_child(&mut cloud_child);
    let output = cloud_child.wait_with_output().unwrap();

    handle_child_output(r, &output);

    disk_check_consistency(vhdx_path, None);
}

fn vhdx_image_size(disk_name: &str) -> u64 {
    std::fs::File::open(disk_name)
        .unwrap()
        .seek(SeekFrom::End(0))
        .unwrap()
}

#[cfg(target_arch = "x86_64")]
pub fn _test_split_irqchip(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(
            guest
                .ssh_command("grep -c IO-APIC.*timer /proc/interrupts || true")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or(1),
            0
        );
        assert_eq!(
            guest
                .ssh_command("grep -c IO-APIC.*cascade /proc/interrupts || true")
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

#[cfg(target_arch = "x86_64")]
pub(crate) fn _test_dmi_serial_number(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline_with_platform(Some("serial_number=a=b;c=d"))
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(
            guest
                .ssh_command("sudo cat /sys/class/dmi/id/product_serial")
                .unwrap()
                .trim(),
            "a=b;c=d"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_dmi_uuid(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline_with_platform(Some("uuid=1e8aa28a-435d-4027-87f4-40dceff1fa0a"))
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(
            guest
                .ssh_command("sudo cat /sys/class/dmi/id/product_uuid")
                .unwrap()
                .trim(),
            "1e8aa28a-435d-4027-87f4-40dceff1fa0a"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_dmi_oem_strings(guest: &Guest) {
    let s1 = "io.systemd.credential:xx=yy";
    let s2 = "This is a test string";

    let oem_strings = format!("oem_strings=[{s1},{s2}]");

    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline_with_platform(Some(&oem_strings))
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(
            guest
                .ssh_command("sudo dmidecode --oem-string count")
                .unwrap()
                .trim(),
            "2"
        );

        assert_eq!(
            guest
                .ssh_command("sudo dmidecode --oem-string 1")
                .unwrap()
                .trim(),
            s1
        );

        assert_eq!(
            guest
                .ssh_command("sudo dmidecode --oem-string 2")
                .unwrap()
                .trim(),
            s2
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_serial_off(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .args(["--serial", "off"])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Test that there is no ttyS0
        assert_eq!(
            guest
                .ssh_command(GREP_SERIAL_IRQ_CMD)
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

pub(crate) fn _test_multiple_network_interfaces(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args([
            "--net",
            guest.default_net_string().as_str(),
            "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.128",
            "tap=mytap1,mac=fe:1f:9e:e1:60:f2,ip=192.168.4.1,mask=255.255.255.128",
        ])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        let tap_count = exec_host_command_output("ip link | grep -c mytap1");
        assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");

        // 3 network interfaces + default localhost ==> 4 interfaces
        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            4
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_virtio_console(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .args(["--console", "tty"])
        .args(["--serial", "null"])
        .capture_output()
        .spawn()
        .unwrap();

    let text = String::from("On a branch floating down river a cricket, singing.");
    let cmd = format!("echo {text} | sudo tee /dev/hvc0");

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert!(
            guest
                .does_device_vendor_pair_match("0x1043", "0x1af4")
                .unwrap_or_default()
        );

        guest.ssh_command(&cmd).unwrap();
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);

    let r = std::panic::catch_unwind(|| {
        assert!(String::from_utf8_lossy(&output.stdout).contains(&text));
    });

    handle_child_output(r, &output);
}

pub(crate) fn _test_console_file(guest: &Guest) {
    let console_path = guest.tmp_dir.as_path().join("console-output");
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .args([
            "--console",
            format!("file={}", console_path.to_str().unwrap()).as_str(),
        ])
        .capture_output()
        .spawn()
        .unwrap();

    guest.wait_vm_boot().unwrap();

    guest.ssh_command("sudo shutdown -h now").unwrap();

    let _ = child.wait_timeout(std::time::Duration::from_secs(20));
    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    let r = std::panic::catch_unwind(|| {
        // Check that the cloud-hypervisor binary actually terminated
        assert!(output.status.success());

        // Do this check after shutdown of the VM as an easy way to ensure
        // all writes are flushed to disk
        let mut f = std::fs::File::open(console_path).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();

        if !buf.contains(CONSOLE_TEST_STRING) {
            eprintln!(
                "\n\n==== Console file output ====\n\n{buf}\n\n==== End console file output ===="
            );
        }
        assert!(buf.contains(CONSOLE_TEST_STRING));
    });

    handle_child_output(r, &output);
}

pub(crate) fn _test_direct_kernel_boot_noacpi(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
        assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_pci_bar_reprogramming(guest: &Guest) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args([
            "--net",
            guest.default_net_string().as_str(),
            "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.128",
        ])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // 2 network interfaces + default localhost ==> 3 interfaces
        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            3
        );

        let init_bar_addr = guest
            .ssh_command("sudo awk '{print $1; exit}' /sys/bus/pci/devices/0000:00:05.0/resource")
            .unwrap();

        // Remove the PCI device
        guest
            .ssh_command("echo 1 | sudo tee /sys/bus/pci/devices/0000:00:05.0/remove")
            .unwrap();

        // Only 1 network interface left + default localhost ==> 2 interfaces
        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            2
        );

        // Remove the PCI device
        guest
            .ssh_command("echo 1 | sudo tee /sys/bus/pci/rescan")
            .unwrap();

        // Back to 2 network interface + default localhost ==> 3 interfaces
        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            3
        );

        let new_bar_addr = guest
            .ssh_command("sudo awk '{print $1; exit}' /sys/bus/pci/devices/0000:00:05.0/resource")
            .unwrap();

        // Let's compare the BAR addresses for our virtio-net device.
        // They should be different as we expect the BAR reprogramming
        // to have happened.
        assert_ne!(init_bar_addr, new_bar_addr);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_memory_overhead(guest: &Guest, guest_memory_size_kb: u32) {
    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_net()
        .default_disks()
        .capture_output()
        .spawn()
        .unwrap();

    guest.wait_vm_boot().unwrap();

    let r = std::panic::catch_unwind(|| {
        let overhead = get_vmm_overhead(child.id(), guest_memory_size_kb);
        eprintln!("Guest memory overhead: {overhead} vs {MAXIMUM_VMM_OVERHEAD_KB}");
        assert!(overhead <= MAXIMUM_VMM_OVERHEAD_KB);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_landlock(guest: &Guest) {
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut child = GuestCommand::new(guest)
        .args(["--api-socket", &api_socket])
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .args(["--landlock"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check /dev/vdc is not there
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc.*16M || true")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or(1),
            0
        );

        // Now let's add the extra disk.
        let mut blk_file_path = dirs::home_dir().unwrap();
        blk_file_path.push("workloads");
        blk_file_path.push("blk.img");
        // As the path to the hotplug disk is not pre-added, this remote
        // command will fail.
        assert!(!remote_command(
            &api_socket,
            "add-disk",
            Some(
                format!(
                    "path={},id=test0,readonly=true",
                    blk_file_path.to_str().unwrap()
                )
                .as_str()
            ),
        ));
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_disk_hotplug(guest: &Guest, landlock_enabled: bool) {
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut blk_file_path = dirs::home_dir().unwrap();
    blk_file_path.push("workloads");
    blk_file_path.push("blk.img");

    let mut cmd = GuestCommand::new(guest);
    if landlock_enabled {
        cmd.args(["--landlock"]).args([
            "--landlock-rules",
            format!("path={blk_file_path:?},access=rw").as_str(),
        ]);
    }

    cmd.args(["--api-socket", &api_socket])
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .capture_output();

    let mut child = cmd.spawn().unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check /dev/vdc is not there
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc.*16M || true")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or(1),
            0
        );

        // Now let's add the extra disk.
        let (cmd_success, cmd_output) = remote_command_w_output(
            &api_socket,
            "add-disk",
            Some(
                format!(
                    "path={},id=test0,readonly=true",
                    blk_file_path.to_str().unwrap()
                )
                .as_str(),
            ),
        );
        assert!(cmd_success);
        assert!(
            String::from_utf8_lossy(&cmd_output)
                .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}")
        );

        thread::sleep(std::time::Duration::new(10, 0));

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
        // And check the block device can be read.
        guest
            .ssh_command("sudo dd if=/dev/vdc of=/dev/null bs=1M iflag=direct count=16")
            .unwrap();

        // Let's remove it the extra disk.
        assert!(remote_command(&api_socket, "remove-device", Some("test0")));
        thread::sleep(std::time::Duration::new(5, 0));
        // And check /dev/vdc is not there
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc.*16M || true")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or(1),
            0
        );

        // And add it back to validate unplug did work correctly.
        let (cmd_success, cmd_output) = remote_command_w_output(
            &api_socket,
            "add-disk",
            Some(
                format!(
                    "path={},id=test0,readonly=true",
                    blk_file_path.to_str().unwrap()
                )
                .as_str(),
            ),
        );
        assert!(cmd_success);
        assert!(
            String::from_utf8_lossy(&cmd_output)
                .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}")
        );

        thread::sleep(std::time::Duration::new(10, 0));

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
        // And check the block device can be read.
        guest
            .ssh_command("sudo dd if=/dev/vdc of=/dev/null bs=1M iflag=direct count=16")
            .unwrap();

        // Reboot the VM.
        guest.reboot_linux(0);

        // Check still there after reboot
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | grep -c 16M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        assert!(remote_command(&api_socket, "remove-device", Some("test0")));

        thread::sleep(std::time::Duration::new(20, 0));

        // Check device has gone away
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc.*16M || true")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or(1),
            0
        );

        guest.reboot_linux(1);

        // Check device still absent
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc.*16M || true")
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
