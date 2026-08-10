// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{self, Error, Read, Seek, SeekFrom, Write};
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::string::String;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{panic, ptr, thread};

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

    // Wait for API server to be ready
    assert!(wait_until(Duration::from_secs(5), || target_api
        .remote_command("ping", None)));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    assert!(target_api.remote_command("create", Some(create_config),));

    // Then boot it
    assert!(target_api.remote_command("boot", None));

    let r = panic::catch_unwind(|| {
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

    // Wait for API server to be ready
    assert!(wait_until(Duration::from_secs(5), || target_api
        .remote_command("ping", None)));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    let r = panic::catch_unwind(|| {
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
        assert!(guest.wait_for_ssh_unresponsive(Duration::from_secs(20)));

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

    // Wait for API server to be ready
    assert!(wait_until(Duration::from_secs(5), || target_api
        .remote_command("ping", None)));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    let r = panic::catch_unwind(|| {
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
        assert!(guest.wait_for_ssh_unresponsive(Duration::from_secs(20)));

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

    // Wait for API server to be ready
    assert!(wait_until(Duration::from_secs(5), || target_api
        .remote_command("ping", None)));

    // Create the VM first
    let request_body = guest.api_create_body();

    let temp_config_path = guest.tmp_dir.as_path().join("config");
    fs::write(&temp_config_path, request_body).unwrap();
    let create_config = temp_config_path.as_os_str().to_str().unwrap();

    assert!(target_api.remote_command("create", Some(create_config)));

    // Then boot it
    assert!(target_api.remote_command("boot", None));

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check that the VM booted as expected
        guest.validate_cpu_count(None);
        guest.validate_memory(None);

        // We now pause the VM
        assert!(target_api.remote_command("pause", None));

        // Check pausing again fails
        assert!(!target_api.remote_command("pause", None));

        thread::sleep(Duration::new(2, 0));

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

        thread::sleep(Duration::new(2, 0));

        // Now we should be able to SSH back in and get the right number of CPUs
        guest.validate_cpu_count(None);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_pty_interaction(pty_path: PathBuf) {
    let mut cf = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(pty_path)
        .unwrap();

    // Read concurrently so we drain the replayed backlog instead of leaving
    // it stranded behind a non-reading client (which would back-pressure the
    // sender and never let the login keystrokes through).
    let ptyc = pty_read(cf.try_clone().unwrap());

    // Some dumb sleeps but we don't want to write
    // before the console is up and we don't want
    // to try and write the next line before the
    // login process is ready.
    thread::sleep(Duration::new(5, 0));
    assert_eq!(cf.write(b"cloud\n").unwrap(), 6);
    thread::sleep(Duration::new(2, 0));
    assert_eq!(cf.write(b"cloud123\n").unwrap(), 9);
    thread::sleep(Duration::new(2, 0));
    assert_eq!(cf.write(b"echo test_pty_console\n").unwrap(), 22);
    thread::sleep(Duration::new(2, 0));

    let mut prev = String::new();
    // The console can stream continuously (e.g. journald forwarded to it), so
    // bound the wait: a missing marker must not loop until the harness timeout.
    for _ in 0..20 {
        thread::sleep(Duration::new(2, 0));
        // Drain everything available this round so a large replayed backlog
        // does not take one 2s tick per chunk to get through.
        loop {
            match ptyc.try_recv() {
                Ok(line) => {
                    prev = prev + &line;
                    if prev.contains("test_pty_console") {
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(_) => panic!("No login on pty"),
            }
        }
    }
    // Bounded out without ever seeing the marker: the login never completed.
    panic!("No login on pty");
}

pub(crate) fn test_cpu_topology(
    threads_per_core: u8,
    cores_per_package: u8,
    packages: u8,
    use_fw: bool,
) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
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

    let r = panic::catch_unwind(|| {
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

        #[cfg(target_arch = "x86_64")]
        let cores_per_package_grep = "per socket";
        #[cfg(target_arch = "aarch64")]
        let cores_per_package_grep = if use_fw { "per socket" } else { "per cluster" };

        assert_eq!(
            guest
                .ssh_command(&format!(
                    "lscpu | grep \"{cores_per_package_grep}\" | cut -f 2 -d \":\" | sed \"s# *##\""
                ))
                .unwrap()
                .trim()
                .parse::<u8>()
                .unwrap_or(0),
            cores_per_package
        );

        #[cfg(target_arch = "x86_64")]
        let packages_grep = "Socket";
        #[cfg(target_arch = "aarch64")]
        let packages_grep = if use_fw { "Socket" } else { "Cluster" };

        assert_eq!(
            guest
                .ssh_command(&format!(
                    "lscpu | grep \"{packages_grep}\" | cut -f 2 -d \":\" | sed \"s# *##\""
                ))
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

    let r = panic::catch_unwind(|| {
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
            thread::sleep(Duration::new(5, 0));

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

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();
        assert!(remote_command(&api_socket, "power-button", None));
    });

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    handle_child_output(r, &output);
}

// A MAC address for the backend to advertise when the test wants the address
// supplied to the frontend to take precedence over it.
pub(crate) const OVERRIDDEN_MAC: &str = "de:ad:be:ef:00:01";

pub(crate) fn test_vhost_user_net(
    tap: Option<&str>,
    num_queues: usize,
    prepare_daemon: &PrepareNetDaemon,
    generate_host_mac: bool,
    client_mode_daemon: bool,
    backend_mac: Option<&str>,
    frontend_mtu: Option<u16>,
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

    // The backend always advertises an MTU, both so that the host side of the
    // tap is never smaller than the guest's and so that a frontend supplied
    // MTU can be seen to take precedence over it.
    let backend_mtu = 9000;
    let expected_mtu = frontend_mtu.unwrap_or(backend_mtu);

    // The backend always advertises a MAC address, and the guest is expected
    // to end up with the guest MAC of the test network since that is the
    // address its cloud-init configuration matches on. So when the backend is
    // given a different address the frontend supplies the guest MAC and must
    // take precedence, otherwise the guest never reaches the network at all.
    let (backend_mac, frontend_mac) = match backend_mac {
        Some(mac) => (
            mac.to_string(),
            format!(",mac={}", guest.network.guest_mac0),
        ),
        None => (guest.network.guest_mac0.clone(), String::new()),
    };

    let (mut daemon_command, vunet_socket_path) = prepare_daemon(
        &guest.tmp_dir,
        &guest.network.host_ip0,
        tap,
        Some(backend_mac.as_str()),
        Some(backend_mtu),
        num_queues,
        client_mode_daemon,
    );

    let net_params = format!(
        "vhost_user=true{},socket={},num_queues={},queue_size=1024{},vhost_mode={}{}",
        frontend_mac,
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
        if let Some(mtu) = frontend_mtu {
            format!(",mtu={mtu}")
        } else {
            String::new()
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

    let mut daemon_child: Child;
    let mut child: Child;

    if client_mode_daemon {
        child = ch_command.spawn().unwrap();
        // Wait for the VMM to create the socket before starting the daemon
        assert!(wait_until(Duration::from_secs(10), || Path::new(
            &vunet_socket_path
        )
        .exists()));
        daemon_child = daemon_command.spawn().unwrap();
    } else {
        daemon_child = daemon_command.spawn().unwrap();
        // Wait for the daemon to create the socket before starting the VMM
        assert!(wait_until(Duration::from_secs(10), || Path::new(
            &vunet_socket_path
        )
        .exists()));
        child = ch_command.spawn().unwrap();
    }

    let r = panic::catch_unwind(|| {
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
            expected_mtu.to_string()
        );

        assert_eq!(
            guest
                .ssh_command(format!("cat /sys/class/net/{iface}/address").as_str())
                .unwrap()
                .trim(),
            guest.network.guest_mac0
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

            // Here by simply checking the size (through ssh), we validate
            // the connection is still working, which means vhost-user-net
            // keeps working after the resize.
            assert!(wait_until(Duration::from_secs(10), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 960_000));
        }
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    let _ = daemon_child.kill();
    let _ = daemon_child.wait();

    handle_child_output(r, &output);
}

type PrepareBlkDaemon = dyn Fn(&TempDir, &str, usize, bool, bool) -> (Child, String);

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

    let r = panic::catch_unwind(|| {
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

            assert!(wait_until(Duration::from_secs(10), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 960_000));

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

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Just check the VM booted correctly.
        assert_eq!(guest.get_cpu_count().unwrap_or_default(), num_queues as u32);
        assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
    });
    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    if let Some(mut daemon_child) = daemon_child {
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();
    }

    handle_child_output(r, &output);
}

pub(crate) fn _test_virtio_fs(
    prepare_daemon: &dyn Fn(&TempDir, &str) -> (Child, String),
    hotplug: bool,
    use_generic_vhost_user: bool,
    pci_segment: Option<u16>,
) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);
    let event_path = temp_event_monitor_path(&guest.tmp_dir);

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
        .args(["--api-socket", &api_socket])
        .args(["--event-monitor", format!("path={event_path}").as_str()]);
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
            "queue_sizes=[1024,1024],device_type=26"
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

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        if hotplug {
            // Add fs to the VM
            let (cmd_success, cmd_output, _) =
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
        }

        // Mount shared directory through virtio_fs filesystem
        guest
            .wait_for_ssh_command(
                "mkdir -p mount_dir && sudo mount -t virtiofs myfs mount_dir/",
                Duration::from_secs(10),
            )
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

            assert!(wait_until(Duration::from_secs(30), || guest
                .get_total_memory()
                .unwrap_or_default()
                > 960_000));

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

            // Wait for the device to be fully removed before re-adding
            let removed_event = MetaEvent {
                event: "device-removed".to_string(),
                device_id: Some("myfs0".to_string()),
            };
            assert!(wait_for_sequential_events(
                Duration::from_secs(10),
                &[&removed_event],
                &event_path
            ));
        }
    });

    let (r, hotplug_daemon_child) = if r.is_ok() && hotplug {
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();
        // Remove the stale socket so wait_for_virtiofsd_socket actually waits
        let _ = fs::remove_file(&virtiofsd_socket_path);

        let (daemon_child, virtiofsd_socket_path) =
            prepare_daemon(&guest.tmp_dir, shared_dir.to_str().unwrap());

        let r = panic::catch_unwind(|| {
            // Wait for the daemon socket to be ready
            assert!(wait_until(Duration::from_secs(10), || Path::new(
                &virtiofsd_socket_path
            )
            .exists()));
            let fs_params = format!(
                "id=myfs0,socket={},{}{}",
                virtiofsd_socket_path,
                if use_generic_vhost_user {
                    "queue_sizes=[1024,1024],device_type=26"
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
            let (cmd_success, cmd_output, _) =
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

            // Mount shared directory through virtio_fs filesystem, retrying
            // until the hotplugged device is recognized by the guest
            guest
                .wait_for_ssh_command(
                    "mkdir -p mount_dir && sudo mount -t virtiofs myfs mount_dir/",
                    Duration::from_secs(10),
                )
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

    Command::new("mkfs.ext4")
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        if hotplug {
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-vsock",
                Some(format!("cid=3,socket={socket},id=test0").as_str()),
            );
            assert!(cmd_success);
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}")
            );
            thread::sleep(Duration::new(10, 0));
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

    let disk_config1 = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
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

    let r = panic::catch_unwind(|| {
        guest1.wait_vm_boot().unwrap();
    });
    if r.is_err() {
        kill_child(&mut child1);
        let output = child1.wait_with_output().unwrap();
        handle_child_output(r, &output);
        panic!("Test should already be failed/panicked"); // To explicitly mark this block never return
    }

    let ksm_ps_guest1 = get_ksm_pages_shared();

    let disk_config2 = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
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

    let r = panic::catch_unwind(|| {
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
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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
        assert!(wait_for_latest_events_exact(
            Duration::from_secs(20),
            &latest_events,
            &event_path
        ));
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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
    Command::new("qemu-img")
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

    let r = panic::catch_unwind(|| {
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

pub(crate) fn _test_virtio_block_vmdk(guest: &Guest, subformat: &str) {
    let raw_os_disk = guest.disk_config.disk(DiskType::OperatingSystem).unwrap();
    let vmdk_path = guest.tmp_dir.as_path().join("osdisk.vmdk");
    let vmdk_path_str = vmdk_path.to_str().unwrap();

    // Convert the prepared RAW OS disk into a flat VMDK. qemu-img writes the
    // extent file(s) next to the descriptor automatically.
    let convert = Command::new("qemu-img")
        .arg("convert")
        .args(["-f", "raw"])
        .args(["-O", "vmdk"])
        .args(["-o", &format!("subformat={subformat}")])
        .arg(&raw_os_disk)
        .arg(vmdk_path_str)
        .output()
        .expect("Expect generating flat VMDK image from RAW image");
    assert!(
        convert.status.success(),
        "qemu-img convert to VMDK (subformat={subformat}) failed: {}",
        String::from_utf8_lossy(&convert.stderr)
    );

    let mut cloud_child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .args([
            "--disk",
            // Force the flat VMDK backend explicitly instead of relying on
            // image-format auto-detection.
            format!("path={vmdk_path_str},image_type=vmdk").as_str(),
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

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
        assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

        // Exercise the flat VMDK write + read paths through the guest root
        // filesystem: write a marker file, flush, and read it back.
        guest
            .ssh_command(
                "echo cloud-hypervisor-vmdk | sudo tee /root/vmdk_marker > /dev/null && sync",
            )
            .unwrap();
        assert_eq!(
            guest
                .ssh_command("sudo cat /root/vmdk_marker")
                .unwrap()
                .trim(),
            "cloud-hypervisor-vmdk"
        );
    });

    kill_child(&mut cloud_child);
    let output = cloud_child.wait_with_output().unwrap();

    handle_child_output(r, &output);

    disk_check_consistency(vmdk_path_str, None);
}

pub(crate) fn _test_virtio_block_vmdk_enospc(guest: &Guest, subformat: &str) {
    const DISK_SIZE_MIB: u64 = 16;

    let vmdk_path = guest.tmp_dir.as_path().join("data.vmdk");
    let vmdk_path_str = vmdk_path.to_str().unwrap();

    let create = Command::new("qemu-img")
        .arg("create")
        .args(["-f", "vmdk"])
        .args(["-o", &format!("subformat={subformat}")])
        .arg(vmdk_path_str)
        .arg(format!("{DISK_SIZE_MIB}M"))
        .output()
        .expect("Expect creating flat VMDK data disk");
    assert!(
        create.status.success(),
        "qemu-img create VMDK (subformat={subformat}) failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

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
            // Force the flat VMDK backend explicitly.
            format!("path={vmdk_path_str},image_type=vmdk").as_str(),
        ])
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // The flat VMDK data disk shows up as vdc.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // 1) In-bounds direct-IO round trip: write a random pattern near the
        //    start of the device and read it back to confirm the VMDK I/O
        //    path is correct.
        guest
            .ssh_command(
                "sudo dd if=/dev/urandom of=/tmp/pattern bs=1M count=4 && \
                 sudo dd if=/tmp/pattern of=/dev/vdc bs=1M count=4 seek=0 \
                     oflag=direct conv=fsync && \
                 sudo dd if=/dev/vdc of=/tmp/readback bs=1M count=4 skip=0 \
                     iflag=direct && \
                 cmp /tmp/pattern /tmp/readback",
            )
            .expect("in-bounds flat VMDK direct IO round trip failed");

        // 2) Writing past the fixed virtual capacity must fail with ENOSPC:
        //    a flat VMDK is pre-allocated and cannot grow. dd exits non-zero
        //    once the device is full, so `|| true` keeps ssh_command happy
        //    while we assert on the reported error.
        let enospc = guest
            .ssh_command(&format!(
                "sudo dd if=/dev/zero of=/dev/vdc bs=1M count={} oflag=direct 2>&1 || true",
                DISK_SIZE_MIB + 8
            ))
            .unwrap();
        assert!(
            enospc.contains("No space left on device"),
            "expected ENOSPC writing past end of pre-allocated flat VMDK, got: {enospc}"
        );
    });

    kill_child(&mut cloud_child);
    let output = cloud_child.wait_with_output().unwrap();

    handle_child_output(r, &output);

    disk_check_consistency(vmdk_path_str, None);
}

pub(crate) fn _test_virtio_block_vmdk_extent_spanning(guest: &Guest, direct: bool) {
    // 3 GiB virtual size => a 2 GiB first extent + a 1 GiB second extent.
    // `direct=on` opens the extents with `O_DIRECT`, which tmpfs rejects with
    // EINVAL. guest.tmp_dir is backed by tmpfs, so for the direct
    // case place the VMDK on ~/workloads instead (same rationale as
    // test_virtio_block_direct_and_firmware).
    let workloads_tmp_dir;
    let base_dir = if direct {
        let mut workloads_path = dirs::home_dir().unwrap();
        workloads_path.push("workloads");
        workloads_tmp_dir = TempDir::new_in(workloads_path.as_path()).unwrap();
        workloads_tmp_dir.as_path()
    } else {
        guest.tmp_dir.as_path()
    };
    let vmdk_path = base_dir.join("spanning.vmdk");
    let vmdk_path_str = vmdk_path.to_str().unwrap();

    let create = Command::new("qemu-img")
        .arg("create")
        .args(["-f", "vmdk"])
        .args(["-o", "subformat=twoGbMaxExtentFlat"])
        .arg(vmdk_path_str)
        .arg("3G")
        .output()
        .expect("Expect creating twoGbMaxExtentFlat VMDK data disk");
    assert!(
        create.status.success(),
        "qemu-img create twoGbMaxExtentFlat VMDK failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let descriptor = fs::read_to_string(&vmdk_path).expect("read VMDK descriptor");
    let extent_lines: Vec<&str> = descriptor
        .lines()
        .filter(|l| l.starts_with("RW ") && l.contains("FLAT"))
        .collect();
    assert!(
        extent_lines.len() >= 2,
        "twoGbMaxExtentFlat should produce >= 2 extents, descriptor was:\n{descriptor}"
    );
    let first_extent_sectors: u64 = extent_lines[0]
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("parse first extent sector count from descriptor");
    let boundary_bytes = first_extent_sectors * 512;

    // Straddle the boundary with a 2 MiB, 4 KiB-aligned direct-IO window
    // (~1 MiB in each extent). Round the start down to the O_DIRECT alignment
    // without assuming the extent size itself is 4 KiB aligned.
    const BS: u64 = 4096;
    const HALF: u64 = 1024 * 1024;
    let raw_start = boundary_bytes - HALF;
    let start = raw_start - (raw_start % BS);
    let seek = start / BS;
    let count = (2 * HALF) / BS;
    assert!(
        start < boundary_bytes && boundary_bytes < start + count * BS,
        "write window [{start}, {}) does not straddle extent boundary {boundary_bytes}",
        start + count * BS
    );

    // Force the flat VMDK backend explicitly, and honor the requested cache
    // mode. `direct=on` opens the extents with `O_DIRECT` on the host.
    let data_disk = if direct {
        format!("path={vmdk_path_str},image_type=vmdk,direct=on")
    } else {
        format!("path={vmdk_path_str},image_type=vmdk")
    };

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
            data_disk.as_str(),
        ])
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // The twoGbMaxExtentFlat data disk shows up as vdc.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep -c vdc")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Write a random pattern that spans the 2 GiB extent boundary.
        guest
            .ssh_command(&format!(
                "sudo dd if=/dev/urandom of=/tmp/pattern bs={BS} count={count} && \
                 sudo dd if=/tmp/pattern of=/dev/vdc bs={BS} count={count} seek={seek} \
                     oflag=direct conv=fsync && \
                 sudo dd if=/dev/vdc of=/tmp/readback bs={BS} count={count} skip={seek} \
                     iflag=direct && \
                 cmp /tmp/pattern /tmp/readback",
            ))
            .expect("extent-spanning direct IO round trip across the 2 GiB boundary failed");
    });

    kill_child(&mut cloud_child);
    let output = cloud_child.wait_with_output().unwrap();

    handle_child_output(r, &output);

    disk_check_consistency(vmdk_path_str, None);
}

fn vhdx_image_size(disk_name: &str) -> u64 {
    fs::File::open(disk_name)
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

    let r = panic::catch_unwind(|| {
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
        .default_kernel_cmdline_with_platform(Some("system_serial_number=a=b;c=d"))
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
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
        .default_kernel_cmdline_with_platform(Some(
            "system_uuid=1e8aa28a-435d-4027-87f4-40dceff1fa0a",
        ))
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

#[cfg(target_arch = "x86_64")]
pub(crate) fn _test_dmi_system_and_chassis(guest: &Guest) {
    let fields = [
        ("system_manufacturer", "system-manufacturer", "Manufacturer"),
        ("system_product_name", "system-product-name", "ProductName"),
        ("system_version", "system-version", "Version"),
        ("system_family", "system-family", "Family"),
        ("system_sku_number", "system-sku-number", "SkuNumber"),
        ("chassis_asset_tag", "chassis-asset-tag", "AssetTag"),
    ];

    let platform = fields
        .iter()
        .map(|(key, _, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");

    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline_with_platform(Some(&platform))
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        for (_, dmidecode_field, expected) in fields {
            assert_eq!(
                guest
                    .ssh_command(&format!("sudo dmidecode -s {dmidecode_field}"))
                    .unwrap()
                    .trim(),
                expected,
                "DMI field {dmidecode_field} mismatch"
            );
        }
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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

    let _ = child.wait_timeout(Duration::from_secs(20));
    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    let r = panic::catch_unwind(|| {
        // Check that the cloud-hypervisor binary actually terminated
        assert!(output.status.success());

        // Do this check after shutdown of the VM as an easy way to ensure
        // all writes are flushed to disk
        let mut f = fs::File::open(console_path).unwrap();
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

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
        guest.validate_memory(None);
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

    let r = panic::catch_unwind(|| {
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

    let max_overhead = if on_kvm_sev_snp() {
        MAXIMUM_VMM_OVERHEAD_KB_SEV_SNP
    } else {
        MAXIMUM_VMM_OVERHEAD_KB
    };

    let r = panic::catch_unwind(|| {
        let overhead = get_vmm_overhead(child.id(), guest_memory_size_kb);
        eprintln!("Guest memory overhead: {overhead} vs {max_overhead}");
        assert!(overhead <= max_overhead);
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

    let r = panic::catch_unwind(|| {
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

    let r = panic::catch_unwind(|| {
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
        let (cmd_success, cmd_output, _) = remote_command_w_output(
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

        // Wait for the hotplugged disk to appear in the guest
        assert!(wait_until(Duration::from_secs(10), || {
            guest
                .ssh_command("lsblk | grep vdc | grep -c 16M")
                .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or_default() == 1)
        }));
        // And check the block device can be read.
        guest
            .ssh_command("sudo dd if=/dev/vdc of=/dev/null bs=1M iflag=direct count=16")
            .unwrap();

        // Let's remove it the extra disk.
        assert!(remote_command(&api_socket, "remove-device", Some("test0")));
        // Wait for the disk to disappear
        assert!(wait_until(Duration::from_secs(10), || guest
            .ssh_command("lsblk | grep -c vdc.*16M || true")
            .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or(1) == 0)));

        // And add it back to validate unplug did work correctly.
        let (cmd_success, cmd_output, _) = remote_command_w_output(
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

        // Wait for the hotplugged disk to appear in the guest
        assert!(wait_until(Duration::from_secs(10), || {
            guest
                .ssh_command("lsblk | grep vdc | grep -c 16M")
                .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or_default() == 1)
        }));
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

        // Wait for the disk to disappear
        assert!(wait_until(Duration::from_secs(20), || guest
            .ssh_command("lsblk | grep -c vdc.*16M || true")
            .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or(1) == 0)));

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

pub(crate) fn _test_virtio_block_topology(guest: &Guest, loop_dev: &str) {
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
                "path={}",
                guest.disk_config.disk(DiskType::CloudInit).unwrap()
            )
            .as_str(),
            format!("path={loop_dev}").as_str(),
        ])
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // MIN-IO column
        assert_eq!(
            guest
                .ssh_command("lsblk -t| grep vdc | awk '{print $3}'")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            4096
        );
        // PHY-SEC column
        assert_eq!(
            guest
                .ssh_command("lsblk -t| grep vdc | awk '{print $5}'")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            4096
        );
        // LOG-SEC column
        assert_eq!(
            guest
                .ssh_command("lsblk -t| grep vdc | awk '{print $6}'")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            4096
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_net_hotplug(
    guest: &Guest,
    max_num_pci_segments: u16,
    pci_segment: Option<u16>,
) {
    let api_socket = temp_api_path(&guest.tmp_dir);

    // Boot without network
    let mut cmd = GuestCommand::new(guest);

    cmd.args(["--api-socket", &api_socket])
        .default_cpus()
        .default_memory()
        .default_net()
        .default_disks()
        .capture_output();

    if pci_segment.is_some() {
        cmd.default_kernel_cmdline_with_platform(Some(&format!(
            "num_pci_segments={max_num_pci_segments}"
        )));
    } else {
        cmd.default_kernel_cmdline();
    }

    let mut child = cmd.spawn().unwrap();

    guest.wait_vm_boot().unwrap();

    let r = panic::catch_unwind(|| {
        // Add network
        let (cmd_success, cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-net",
            Some(
                format!(
                    "id=test0,tap=,mac={},ip={},mask=255.255.255.128{}",
                    guest.network.guest_mac1,
                    guest.network.host_ip1,
                    if let Some(pci_segment) = pci_segment {
                        format!(",pci_segment={pci_segment}")
                    } else {
                        String::new()
                    }
                )
                .as_str(),
            ),
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

        // Wait for the hotplugged network interface to appear
        assert!(wait_until(Duration::from_secs(10), || {
            guest
                .ssh_command("ip -o link | wc -l")
                .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or_default() == 3)
        }));

        // Test the same using the added network interface's IP
        assert_eq!(
            ssh_command_ip(
                "ip -o link | wc -l",
                &guest.network.guest_ip1,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT
            )
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap_or_default(),
            3
        );

        // Remove network and wait for it to disappear
        assert!(remote_command(&api_socket, "remove-device", Some("test0"),));
        assert!(wait_until(Duration::from_secs(10), || {
            guest
                .ssh_command("ip -o link | wc -l")
                .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or_default() == 2)
        }));

        // Add network
        let (cmd_success, cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-net",
            Some(
                format!(
                    "id=test1,tap=,mac={},ip={},mask=255.255.255.128{}",
                    guest.network.guest_mac1,
                    guest.network.host_ip1,
                    if let Some(pci_segment) = pci_segment {
                        format!(",pci_segment={pci_segment}")
                    } else {
                        String::new()
                    }
                )
                .as_str(),
            ),
        );
        assert!(cmd_success);

        if let Some(pci_segment) = pci_segment {
            assert!(String::from_utf8_lossy(&cmd_output).contains(&format!(
                "{{\"id\":\"test1\",\"bdf\":\"{pci_segment:04x}:00:01.0\"}}"
            )));
        } else {
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test1\",\"bdf\":\"0000:00:06.0\"}")
            );
        }

        // Wait for the hotplugged network interface to appear
        assert!(wait_until(Duration::from_secs(10), || {
            guest
                .ssh_command("ip -o link | wc -l")
                .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or_default() == 3)
        }));

        guest.reboot_linux(0);

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

        // Test the same using the added network interface's IP
        assert_eq!(
            ssh_command_ip(
                "ip -o link | wc -l",
                &guest.network.guest_ip1,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT
            )
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap_or_default(),
            3
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_counters(guest: &Guest) {
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args(["--net", guest.default_net_string().as_str()])
        .args(["--api-socket", &api_socket])
        .capture_output();

    let mut child = cmd.spawn().unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        let orig_counters = get_counters(&api_socket);
        guest
            .ssh_command("dd if=/dev/zero of=test count=8 bs=1M")
            .unwrap();

        let new_counters = get_counters(&api_socket);

        // Check that all the counters have increased
        assert!(new_counters > orig_counters);
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_watchdog(guest: &Guest) {
    let api_socket = temp_api_path(&guest.tmp_dir);
    let event_path = temp_event_monitor_path(&guest.tmp_dir);

    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args(["--net", guest.default_net_string().as_str()])
        .args(["--watchdog"])
        .args(["--api-socket", &api_socket])
        .args(["--event-monitor", format!("path={event_path}").as_str()])
        .capture_output();

    let mut child = cmd.spawn().unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        let mut expected_reboot_count = 1;

        // Enable the watchdog with a 15s timeout
        enable_guest_watchdog(guest, 15);

        assert_eq!(get_reboot_count(guest), expected_reboot_count);
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
        thread::sleep(Duration::new(40, 0));
        // Check no reboot
        assert_eq!(get_reboot_count(guest), expected_reboot_count);

        // Trigger a panic (sync first). We need to do this inside a screen with a delay so the SSH command returns.
        guest.ssh_command("screen -dmS reboot sh -c \"sleep 5; echo s | tee /proc/sysrq-trigger; echo c | sudo tee /proc/sysrq-trigger\"").unwrap();
        // Allow some time for the watchdog to trigger (max 30s) and reboot to happen
        guest.wait_vm_boot_custom_timeout(120).unwrap();
        // Check a reboot is triggered by the watchdog
        expected_reboot_count += 1;
        assert_eq!(get_reboot_count(guest), expected_reboot_count);

        #[cfg(target_arch = "x86_64")]
        {
            // Now pause the VM and remain offline for 30s
            assert!(remote_command(&api_socket, "pause", None));
            let latest_events = [
                &MetaEvent {
                    event: "pausing".to_string(),
                    device_id: None,
                },
                &MetaEvent {
                    event: "paused".to_string(),
                    device_id: None,
                },
            ];
            assert!(check_latest_events_exact(&latest_events, &event_path));
            assert!(remote_command(&api_socket, "resume", None));

            // Check no reboot
            assert_eq!(get_reboot_count(guest), expected_reboot_count);
        }
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_pvpanic(guest: &Guest) {
    let api_socket = temp_api_path(&guest.tmp_dir);
    let event_path = temp_event_monitor_path(&guest.tmp_dir);

    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args(["--net", guest.default_net_string().as_str()])
        .args(["--pvpanic"])
        .args(["--api-socket", &api_socket])
        .args(["--event-monitor", format!("path={event_path}").as_str()])
        .capture_output();

    let mut child = cmd.spawn().unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Trigger guest a panic
        make_guest_panic(guest);

        // Wait for the panic event to be recorded
        let expected_sequential_events = [&MetaEvent {
            event: "panic".to_string(),
            device_id: None,
        }];
        assert!(wait_for_latest_events_exact(
            Duration::from_secs(10),
            &expected_sequential_events,
            &event_path
        ));
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_tap_from_fd(guest: &Guest) {
    // Create a TAP interface with multi-queue enabled
    let num_queue_pairs: usize = 2;

    use std::str::FromStr;
    let taps = net_util::open_tap(
        Some("chtap0"),
        Some(IpAddr::V4(
            Ipv4Addr::from_str(&guest.network.host_ip0).unwrap(),
        )),
        None,
        None,
        None,
        num_queue_pairs,
        Some(libc::O_RDWR | libc::O_NONBLOCK),
    )
    .unwrap();

    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args([
            "--net",
            &format!(
                "fd=[{},{}],mac={},num_queues={}",
                taps[0].as_raw_fd(),
                taps[1].as_raw_fd(),
                guest.network.guest_mac0,
                num_queue_pairs * 2
            ),
        ])
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            2
        );

        guest.reboot_linux(0);

        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            2
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

// test creates two macvtap interfaces in 'bridge' mode on the
// same physical net interface, one for the guest and one for
// the host. With additional setup on the IP address and the
// routing table, it enables the communications between the
// guest VM and the host machine.
// Details: https://wiki.libvirt.org/page/TroubleshootMacvtapHostFail
pub(crate) fn _test_macvtap(
    guest: &Guest,
    hotplug: bool,
    guest_macvtap_name: &str,
    host_macvtap_name: &str,
) {
    let api_socket = temp_api_path(&guest.tmp_dir);

    let phy_net = "eth0";

    // Clean up any stale macvtap interfaces from previous test runs
    exec_host_command_status(&format!(
        "sudo ip link del {guest_macvtap_name} 2>/dev/null"
    ));
    exec_host_command_status(&format!("sudo ip link del {host_macvtap_name} 2>/dev/null"));

    // Create a macvtap interface for the guest VM to use
    assert!(
        exec_host_command_status(&format!(
            "sudo ip link add link {phy_net} name {guest_macvtap_name} type macvtap mod bridge"
        ))
        .success()
    );
    assert!(
        exec_host_command_status(&format!(
            "sudo ip link set {} address {} up",
            guest_macvtap_name, guest.network.guest_mac0
        ))
        .success()
    );
    assert!(exec_host_command_status(&format!("sudo ip link show {guest_macvtap_name}")).success());

    let tap_index =
        fs::read_to_string(format!("/sys/class/net/{guest_macvtap_name}/ifindex")).unwrap();
    let tap_device = format!("/dev/tap{}", tap_index.trim());

    assert!(exec_host_command_status(&format!("sudo chown $UID.$UID {tap_device}")).success());

    let cstr_tap_device = CString::new(tap_device).unwrap();
    let tap_fd1 = unsafe { libc::open(cstr_tap_device.as_ptr(), libc::O_RDWR) };
    assert!(tap_fd1 > 0);
    let tap_fd2 = unsafe { libc::open(cstr_tap_device.as_ptr(), libc::O_RDWR) };
    assert!(tap_fd2 > 0);

    // Create a macvtap on the same physical net interface for
    // the host machine to use
    assert!(
        exec_host_command_status(&format!(
            "sudo ip link add link {phy_net} name {host_macvtap_name} type macvtap mod bridge"
        ))
        .success()
    );
    // Use default mask "255.255.255.0"
    assert!(
        exec_host_command_status(&format!(
            "sudo ip address add {}/24 dev {}",
            guest.network.host_ip0, host_macvtap_name
        ))
        .success()
    );
    assert!(
        exec_host_command_status(&format!("sudo ip link set dev {host_macvtap_name} up")).success()
    );

    let mut guest_command = GuestCommand::new(guest);
    guest_command
        .default_cpus()
        .default_memory()
        .default_kernel_cmdline()
        .default_disks()
        .args(["--api-socket", &api_socket]);

    let net_params = format!(
        "fd=[{},{}],mac={},num_queues=4",
        tap_fd1, tap_fd2, guest.network.guest_mac0
    );

    if !hotplug {
        guest_command.args(["--net", &net_params]);
    }

    let mut child = guest_command.capture_output().spawn().unwrap();

    if hotplug {
        // Wait for the VMM process to listen to the API socket
        assert!(wait_until(Duration::from_secs(10), || remote_command(
            &api_socket,
            "ping",
            None
        )));
        // Hotplug the virtio-net device
        let (cmd_success, cmd_output, _) =
            remote_command_w_output(&api_socket, "add-net", Some(&net_params));
        assert!(cmd_success);
        #[cfg(target_arch = "x86_64")]
        assert!(
            String::from_utf8_lossy(&cmd_output)
                .contains("{\"id\":\"_net2\",\"bdf\":\"0000:00:05.0\"}")
        );
        #[cfg(target_arch = "aarch64")]
        assert!(
            String::from_utf8_lossy(&cmd_output)
                .contains("{\"id\":\"_net0\",\"bdf\":\"0000:00:05.0\"}")
        );
    }

    // The functional connectivity provided by the virtio-net device
    // gets tested through wait_vm_boot() as it expects to receive a
    // HTTP request, and through the SSH command as well.
    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            2
        );

        guest.reboot_linux(0);

        assert_eq!(
            guest
                .ssh_command("ip -o link | wc -l")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            2
        );
    });

    kill_child(&mut child);

    exec_host_command_status(&format!("sudo ip link del {guest_macvtap_name}"));
    exec_host_command_status(&format!("sudo ip link del {host_macvtap_name}"));

    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

pub(crate) fn _test_vdpa_block(guest: &Guest) {
    let api_socket = temp_api_path(&guest.tmp_dir);

    let mut child = GuestCommand::new(guest)
        .default_cpus()
        .args(["--memory", "size=512M,hugepages=on"])
        .default_kernel_cmdline_with_platform(Some("num_pci_segments=2,iommu_segments=1"))
        .default_disks()
        .default_net()
        .args(["--vdpa", "path=/dev/vhost-vdpa-0,num_queues=1"])
        .args(["--api-socket", &api_socket])
        .capture_output()
        .spawn()
        .unwrap();

    let r = panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        // Check both if /dev/vdc exists and if the block size is 128M.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdc | grep -c 128M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Check the content of the block device after we wrote to it.
        // The vpda-sim-blk should let us read what we previously wrote.
        guest
            .ssh_command("sudo bash -c 'echo foobar > /dev/vdc'")
            .unwrap();
        assert_eq!(
            guest.ssh_command("sudo head -1 /dev/vdc").unwrap().trim(),
            "foobar"
        );

        // Hotplug an extra vDPA block device behind the vIOMMU
        // Add a new vDPA device to the VM
        let (cmd_success, cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-vdpa",
            Some("id=myvdpa0,path=/dev/vhost-vdpa-1,num_queues=1,pci_segment=1,iommu=on"),
        );
        assert!(cmd_success);
        assert!(
            String::from_utf8_lossy(&cmd_output)
                .contains("{\"id\":\"myvdpa0\",\"bdf\":\"0001:00:01.0\"}")
        );

        // Wait for the hotplugged device to appear
        assert!(wait_until(Duration::from_secs(10), || guest
            .does_device_vendor_pair_match("0x1057", "0x1af4")
            .unwrap_or_default()));
        assert!(
            guest
                .ssh_command("ls /sys/kernel/iommu_groups/*/devices")
                .unwrap()
                .contains("0001:00:01.0")
        );

        // Check both if /dev/vdd exists and if the block size is 128M.
        assert_eq!(
            guest
                .ssh_command("lsblk | grep vdd | grep -c 128M")
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default(),
            1
        );

        // Write some content to the block device we've just plugged.
        guest
            .ssh_command("sudo bash -c 'echo foobar > /dev/vdd'")
            .unwrap();

        // Check we can read the content back.
        assert_eq!(
            guest.ssh_command("sudo head -1 /dev/vdd").unwrap().trim(),
            "foobar"
        );

        // Unplug the device
        let cmd_success = remote_command(&api_socket, "remove-device", Some("myvdpa0"));
        assert!(cmd_success);

        // Wait for the device to disappear
        assert!(wait_until(Duration::from_secs(10), || guest
            .ssh_command("lsblk | grep -c vdd || true")
            .is_ok_and(|s| s.trim().parse::<u32>().unwrap_or(1) == 0)));
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

/// Receive one framed handoff/notify message from the VMM. Returns
/// (fds, body_bytes) where `body_bytes` is the JSON payload with the
/// 4-byte length header stripped, and `fds` is the SCM_RIGHTS array.
///
/// Wire format: each message is `<u32 LE body length><JSON body>`,
/// sent as two iovecs in one sendmsg so the ancillary fds attach to
/// the right message. For the initial `handoff` message the fds are
/// `[uffd, region0_memfd, region1_memfd, ...]`; for an `add_region`
/// message it's just the new region's backing fd (or empty).
fn recv_fds_with_body(stream: &UnixStream) -> (Vec<i32>, Vec<u8>) {
    use std::os::unix::io::AsRawFd;

    // 64KB body buffer; cmsg sized to hold up to 16 fds (plenty for
    // any VM the integration tests construct).
    let mut buf = vec![0u8; 64 * 1024];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    const MAX_FDS: usize = 16;
    let cmsg_space = unsafe { libc::CMSG_SPACE((mem::size_of::<i32>() * MAX_FDS) as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_space as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    assert!(n > 0, "recvmsg failed: {}", Error::last_os_error());
    let n = n as usize;
    assert!(n >= 4, "framed message too short: {n} bytes");
    let body_len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    assert_eq!(
        n,
        4 + body_len,
        "framed message size mismatch: recvmsg returned {n}, header says {body_len}"
    );
    // Drop the header; callers want only the JSON body.
    buf.drain(..4);
    buf.truncate(body_len);

    // MSG_CTRUNC means the kernel silently dropped some of the
    // ancillary data because our cmsg buffer was too small. For
    // SCM_RIGHTS that's catastrophic: the dropped fds are leaked
    // (never installed in this process) and the surviving fd array
    // we'd decode is partial garbage. Better to fail loudly here
    // than silently operate on the wrong fd.
    assert_eq!(
        msg.msg_flags & libc::MSG_CTRUNC,
        0,
        "ancillary data truncated — VMM sent more than {MAX_FDS} fds"
    );

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    assert!(!cmsg.is_null(), "no cmsg received");
    // Defensive: the helper only knows how to decode SCM_RIGHTS. If
    // the VMM ever attaches credentials or other cmsg types the byte
    // payload would be misinterpreted as fd integers, and the
    // teardown `libc::close()` on a "received fd" would close an
    // unrelated open file in this process.
    assert_eq!(
        unsafe { (*cmsg).cmsg_level },
        libc::SOL_SOCKET,
        "unexpected cmsg_level"
    );
    assert_eq!(
        unsafe { (*cmsg).cmsg_type },
        libc::SCM_RIGHTS,
        "unexpected cmsg_type"
    );
    let cmsg_hdr_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let payload_len = unsafe { (*cmsg).cmsg_len as usize - cmsg_hdr_len };
    let n_fds = payload_len / mem::size_of::<i32>();
    assert!(n_fds > 0, "no fds in cmsg");
    let mut fds = vec![-1i32; n_fds];
    unsafe {
        ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            fds.as_mut_ptr() as *mut u8,
            payload_len,
        );
    }
    for fd in &fds {
        assert!(*fd >= 0, "received invalid fd");
    }
    (fds, buf)
}

const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFDIO_API: u64 = 0xc018_aa3f;
const UFFDIO_ZEROPAGE: u64 = 0xc020_aa04;
const UFFD_API_VERSION: u64 = 0xAA;
const PAGEMAP_SCAN: u64 = 0xc060_6610;
// Documented PAGEMAP_SCAN categories and flags (uapi/linux/fs.h).
const PAGE_IS_WRITTEN: u64 = 1 << 1;
const PAGE_IS_PRESENT: u64 = 1 << 3;
const PAGE_IS_HUGE: u64 = 1 << 6;
const PM_SCAN_WP_MATCHING: u64 = 1 << 0;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdMsg {
    event: u8,
    _reserved1: u8,
    _reserved2: u16,
    _reserved3: u32,
    pf_flags: u64,
    pf_address: u64,
    _pad: [u8; 8],
}

#[repr(C)]
struct UffdioZeropage {
    range_start: u64,
    range_len: u64,
    mode: u64,
    zeropage: i64,
}

/// Create a blocking eventfd usable as a thread-stop signal. Writing
/// any non-zero u64 to it makes a `poll(POLLIN)` on the fd return
/// immediately; the test code uses this to unblock a fault handler
/// thread *before* closing the uffd it was polling, so the handler
/// never operates on a stale fd value (close-while-polling race).
fn make_stop_fd() -> i32 {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    assert!(fd >= 0, "eventfd: {}", Error::last_os_error());
    fd
}

/// Signal the handler to exit via `stop_fd`. Caller must `join()` the
/// handler before closing any fds the handler was polling.
fn signal_stop(stop_fd: i32) {
    let one: u64 = 1;
    let n = unsafe {
        libc::write(
            stop_fd,
            &one as *const u64 as *const libc::c_void,
            mem::size_of::<u64>(),
        )
    };
    assert_eq!(n, mem::size_of::<u64>() as isize);
}

/// Minimal fault handler: resolves MISSING faults with UFFDIO_ZEROPAGE.
/// Exits when `stop_fd` becomes readable (caller writes to it during
/// teardown) or when the uffd's `POLLHUP` fires. Returns the number
/// of faults handled.
fn run_fault_handler(uffd_fd: i32, stop_fd: i32) -> u64 {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let mut faults: u64 = 0;

    loop {
        let mut pfds = [
            libc::pollfd {
                fd: uffd_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
        if ret < 0 {
            break;
        }
        if pfds[1].revents & libc::POLLIN != 0 {
            break;
        }
        if pfds[0].revents & libc::POLLHUP != 0 {
            break;
        }
        if pfds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        let mut msg = MaybeUninit::<UffdMsg>::uninit();
        let n = unsafe {
            libc::read(
                uffd_fd,
                msg.as_mut_ptr() as *mut libc::c_void,
                mem::size_of::<UffdMsg>(),
            )
        };
        if n != mem::size_of::<UffdMsg>() as isize {
            break;
        }
        let msg = unsafe { msg.assume_init() };
        if msg.event != UFFD_EVENT_PAGEFAULT {
            continue;
        }

        let addr = msg.pf_address & !(page_size - 1);

        // MISSING fault: allocate a zero page. The VMM's pending write
        // (kernel data, ACPI tables, etc.) completes on the new page.
        let mut zp = UffdioZeropage {
            range_start: addr,
            range_len: page_size,
            mode: 0,
            zeropage: 0,
        };
        unsafe {
            libc::ioctl(uffd_fd, UFFDIO_ZEROPAGE as libc::Ioctl, &mut zp);
        }
        faults += 1;
    }
    faults
}

/// Wait for the VM to reach "Running" state by polling vm.info.
fn wait_vm_running(api_socket: &str, timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let (ok, output, _) = remote_command_w_output(api_socket, "info", None);
        if ok {
            let info: serde_json::Value = serde_json::from_slice(&output).unwrap_or_default();
            if info["state"].as_str() == Some("Running") {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "VM did not reach Running state within {timeout_secs}s"
        );
        thread::sleep(Duration::from_millis(500));
    }
}

/// Test the boot-time uffd-handoff flow:
/// 1. Start cloud-hypervisor with only the API socket
/// 2. Bind the handoff socket and create the VM with
///    `uffd_handoff` set in the memory config
/// 3. Trigger boot in a background thread; CH dials the handoff socket
///    during MemoryManager construction
/// 4. Accept the connection, recv the uffd + regions JSON, start a
///    fault handler thread, send the ACK byte
/// 5. Boot completes; verify VM running and fault handler saw faults
pub(crate) fn _test_uffd_handoff(guest: &Guest) {
    use std::io::Write;

    let api_socket = temp_api_path(&guest.tmp_dir);
    let kernel_path = direct_kernel_boot_path();
    let handoff_sock_path = guest
        .tmp_dir
        .as_path()
        .join("uffd-handoff.sock")
        .to_str()
        .unwrap()
        .to_string();

    let mut child = GuestCommand::new(guest)
        .args(["--api-socket", &api_socket])
        .capture_output()
        .spawn()
        .unwrap();

    thread::sleep(Duration::new(1, 0));

    let r = panic::catch_unwind(|| {
        assert!(remote_command(&api_socket, "ping", None));

        // 1. Bind the handoff socket BEFORE asking CH to boot.
        let listener = UnixListener::bind(&handoff_sock_path).unwrap();

        // 2. Create the VM with uffd_handoff set.
        let config = serde_json::json!({
            "payload": {
                "kernel": kernel_path.to_str().unwrap(),
                "cmdline": DIRECT_KERNEL_BOOT_CMDLINE,
            },
            "cpus": { "boot_vcpus": 1, "max_vcpus": 1 },
            "memory": {
                "size": 536_870_912u64,
                "shared": true,
                "uffd_handoff": {
                    "socket": handoff_sock_path,
                    "mode": "MISSING",
                },
            },
            "disks": [
                { "path": guest.disk_config.disk(DiskType::OperatingSystem).unwrap() },
            ],
            "serial": { "mode": "Null" },
            "console": { "mode": "Tty" },
        });
        let config_path = guest.tmp_dir.as_path().join("vm-config.json");
        fs::write(&config_path, config.to_string()).unwrap();
        assert!(remote_command(
            &api_socket,
            "create",
            Some(config_path.to_str().unwrap()),
        ));

        // 3. Boot runs in a background thread because it blocks on the
        //    handoff socket — the manager (this thread) needs to accept
        //    the connection and ACK before boot can proceed.
        let api_sock_clone = api_socket.clone();
        let boot_thread = thread::spawn(move || remote_command(&api_sock_clone, "boot", None));

        // 4. Accept handoff: recv (fds, JSON body), spawn fault handler,
        //    send ACK so CH can finish creating the VM. fds[0] is the
        //    uffd; remaining fds are per-region backing memfds (we
        //    don't use them here).
        let (mut stream, _) = listener.accept().unwrap();
        let (fds, body) = recv_fds_with_body(&stream);
        let uffd_fd = fds[0];
        for &extra in &fds[1..] {
            unsafe { libc::close(extra) };
        }
        drop(listener);

        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid handoff JSON");
        // Handshake is self-describing: it carries the protocol version
        // and the register mode the fd was configured with, so a manager
        // need not agree the mode out of band.
        assert_eq!(parsed["type"].as_str(), Some("handoff"), "handoff type");
        assert_eq!(parsed["version"].as_u64(), Some(0), "handoff version");
        assert_eq!(
            parsed["mode"].as_str(),
            Some("MISSING"),
            "handoff advertises the configured mode"
        );
        let regions = parsed["regions"].as_array().expect("regions array");
        assert!(!regions.is_empty(), "handoff carried no regions");

        let stop_fd = make_stop_fd();
        let fault_handler = thread::spawn(move || run_fault_handler(uffd_fd, stop_fd));

        stream.write_all(b"A").expect("send ACK");
        drop(stream);

        // 5. Boot must succeed and VM must reach Running.
        assert!(boot_thread.join().unwrap(), "vm.boot failed");
        wait_vm_running(&api_socket, 30);
        thread::sleep(Duration::from_secs(5));

        let (ok, output, _) = remote_command_w_output(&api_socket, "info", None);
        assert!(ok, "vm.info failed");
        let info: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(info["state"].as_str(), Some("Running"), "VM not running");

        // Order matters: signal first, join the handler, *then* close
        // the fds it was polling. Closing the uffd before the handler
        // returns is racy — the fd integer could be reused for an
        // unrelated open() between close and the next poll/read.
        signal_stop(stop_fd);
        let total_faults = fault_handler.join().unwrap();
        unsafe { libc::close(uffd_fd) };
        unsafe { libc::close(stop_fd) };
        assert!(
            total_faults > 0,
            "fault handler saw no faults (expected faults during boot)"
        );
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();

    handle_child_output(r, &output);
}

#[repr(C)]
struct PmScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PageRegion {
    start: u64,
    end: u64,
    categories: u64,
}

/// One PAGEMAP_SCAN pass over `[start, end)` on `/proc/<pid>/pagemap`,
/// following `walk_end` continuations so the whole range is covered.
/// Returns the number of pages the kernel reported as matching the
/// filter. The mask / flag arguments map 1:1 onto `struct pm_scan_arg`
/// (see uapi/linux/fs.h):
///
/// - `category_mask` page matches only if it has *all* these categories
/// - `category_inverted` categories whose match sense is flipped: a bit
///   listed here matches when its value is *0*. Lets a single scan
///   express e.g. "present AND not written".
/// - `category_anyof_mask` page matches if it has *any* of these
/// - `flags` e.g. `PM_SCAN_WP_MATCHING` to (re-)write-protect every
///   matched page in the same pass
/// - `return_mask` categories reported back in `page_region.categories`
///
/// Page count is the sum of returned region lengths — i.e. the number
/// of pages that matched the filter (not merely those with a given
/// return bit).
#[allow(clippy::too_many_arguments)]
fn pagemap_scan_count(
    pid: u32,
    start: u64,
    end: u64,
    flags: u64,
    category_mask: u64,
    category_inverted: u64,
    category_anyof_mask: u64,
    return_mask: u64,
) -> io::Result<u64> {
    use std::os::fd::AsRawFd;

    let f = OpenOptions::new()
        .read(true)
        .write(flags & PM_SCAN_WP_MATCHING != 0)
        .open(format!("/proc/{pid}/pagemap"))?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let mut vec_buf = vec![PageRegion::default(); 1024];
    let mut matched: u64 = 0;
    let mut cur = start;

    while cur < end {
        let mut arg = PmScanArg {
            size: mem::size_of::<PmScanArg>() as u64,
            flags,
            start: cur,
            end,
            walk_end: 0,
            vec: vec_buf.as_mut_ptr() as u64,
            vec_len: vec_buf.len() as u64,
            max_pages: 0,
            category_inverted,
            category_mask,
            category_anyof_mask,
            return_mask,
        };
        let ret = unsafe { libc::ioctl(f.as_raw_fd(), PAGEMAP_SCAN as libc::Ioctl, &mut arg) };
        if ret < 0 {
            return Err(Error::last_os_error());
        }
        for region in vec_buf.iter().take(ret as usize) {
            matched += (region.end - region.start) / page_size;
        }
        if arg.walk_end <= cur || arg.walk_end >= end {
            break;
        }
        cur = arg.walk_end;
    }
    Ok(matched)
}

/// Count resident pages (`PAGE_IS_PRESENT`) in `[start, end)`.
fn pagemap_present_pages(pid: u32, start: u64, end: u64) -> io::Result<u64> {
    pagemap_scan_count(pid, start, end, 0, PAGE_IS_PRESENT, 0, 0, PAGE_IS_PRESENT)
}

/// Arm write tracking: write-protect every resident page in the range
/// via the documented WP-async engine (`PM_SCAN_WP_MATCHING`). After
/// this, a guest write to any of these pages is resolved silently by
/// the kernel and surfaces as `PAGE_IS_WRITTEN` on the next scan.
/// Returns the number of pages armed.
fn pagemap_arm_wp(pid: u32, start: u64, end: u64) -> io::Result<u64> {
    pagemap_scan_count(
        pid,
        start,
        end,
        PM_SCAN_WP_MATCHING,
        PAGE_IS_PRESENT,
        0,
        0,
        PAGE_IS_PRESENT,
    )
}

/// Hot set: pages written since the last arm (`PAGE_IS_WRITTEN`). When
/// `rearm` is set, matched pages are re-write-protected in the same
/// pass so the next interval starts clean — the documented WSS
/// sampling loop.
fn pagemap_hot_pages(pid: u32, start: u64, end: u64, rearm: bool) -> io::Result<u64> {
    let flags = if rearm { PM_SCAN_WP_MATCHING } else { 0 };
    pagemap_scan_count(
        pid,
        start,
        end,
        flags,
        PAGE_IS_WRITTEN,
        0,
        0,
        PAGE_IS_WRITTEN,
    )
}

/// Reclaimable set: the complement of the hot set among *resident*
/// pages — present but *not active* since the last arm, where "active"
/// is the hot category `PAGE_IS_WRITTEN` (the WP write-set). This is
/// the page set a
/// memory manager would reclaim: track the hot set positively, then
/// reclaim everything else. Unlike a positive "cold" classifier, this
/// has no blind spot for pre-populated-but-unused pages (e.g. a
/// pre-faulted tmpfs file) — they are present-and-not-hot, so they fall
/// into the reclaimable set correctly. Matched directly in one pass via
/// `category_inverted` (`PAGE_IS_PRESENT` set and `active` clear), so it
/// never races a `present - hot` subtraction across two scans.
fn pagemap_reclaimable_pages(pid: u32, start: u64, end: u64, active: u64) -> io::Result<u64> {
    pagemap_scan_count(
        pid,
        start,
        end,
        0,
        PAGE_IS_PRESENT | active, // both bits constrained
        active,                   // ...but `active` matches when 0
        0,
        PAGE_IS_PRESENT | active,
    )
}

/// Hole set: non-resident pages, matched directly via inverted
/// `PAGE_IS_PRESENT` (the bit must be 0).
fn pagemap_hole_pages(pid: u32, start: u64, end: u64) -> io::Result<u64> {
    pagemap_scan_count(pid, start, end, 0, PAGE_IS_PRESENT, PAGE_IS_PRESENT, 0, 0)
}

/// Count pages that are part of a PMD-mapped transparent huge page
/// (`PAGE_IS_HUGE`) in `[start, end)`. Used to confirm THP-backed
/// guest RAM actually survives the uffd-WP handoff as huge pages.
fn pagemap_huge_pages(pid: u32, start: u64, end: u64) -> io::Result<u64> {
    pagemap_scan_count(pid, start, end, 0, PAGE_IS_HUGE, 0, 0, PAGE_IS_HUGE)
}

/// Validate the documented WP-async write-set-tracking interface end to
/// end: attach with `mode=WP|WP_ASYNC`, then use `PAGEMAP_SCAN` on
/// `/proc/<vmm>/pagemap` to classify guest region 0 pages into
/// hot / cold / hole and assert all three are observable.
///
///   - hole = not `PAGE_IS_PRESENT`   (region tail the guest never populated)
///   - cold = `PAGE_IS_PRESENT`, not written since the last arm
///   - hot  = `PAGE_IS_WRITTEN`       (guest wrote it since the last arm)
///
/// Parameterised over the guest-RAM backing:
///   - `shared`: `false` = MAP_PRIVATE memfd (writes land on anon COW
///     pages); `true` = MAP_SHARED memfd / shmem — the representative
///     uffd-handoff deployment, and the backing that needs
///     `UFFD_FEATURE_WP_HUGETLBFS_SHMEM` for WP tracking (CH derives
///     that feature from the shared backing in `do_uffd_handoff`).
///   - `thp`: when `true`, guest RAM is MADV_HUGEPAGE'd; the test then
///     asserts the handed-off region still contains PMD-mapped huge
///     pages (`PAGE_IS_HUGE`) — i.e. THP survives uffd-WP registration
///     and the pagemap machinery reports it. When `false`, asserts no
///     huge pages (MADV_NOHUGEPAGE control).
///
/// This is exactly the interface an external memory manager uses to
/// drive tiering / eviction, built on the standard uffd-WP primitives:
/// `UFFDIO_REGISTER_MODE_WP`, `UFFD_FEATURE_WP_ASYNC`,
/// `UFFD_FEATURE_WP_HUGETLBFS_SHMEM`, `PAGE_IS_WRITTEN`,
/// `PAGE_IS_HUGE` and `PM_SCAN_WP_MATCHING`.
/// Probe the running kernel for `UFFD_FEATURE_WP_ASYNC` (Linux 6.7+). The
/// write-set / resume tests rely on WP-async plus `PAGEMAP_SCAN`, so they
/// skip (rather than fail) on older kernels that lack it.
fn kernel_has_uffd_wp_async() -> bool {
    const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;
    let fd =
        unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) } as i32;
    if fd < 0 {
        return false;
    }
    let mut api = UffdioApi {
        api: UFFD_API_VERSION,
        features: 0,
        ioctls: 0,
    };
    let ret = unsafe { libc::ioctl(fd, UFFDIO_API as libc::Ioctl, &mut api) };
    unsafe { libc::close(fd) };
    ret == 0 && api.features & UFFD_FEATURE_WP_ASYNC != 0
}

/// Return the active token (the one in `[brackets]`) of a THP sysfs knob,
/// e.g. `"always"` from `"always [madvise] never"`.
fn thp_sysfs_active(path: &str) -> Option<String> {
    let s = fs::read_to_string(path).ok()?;
    s.split_whitespace()
        .find(|t| t.starts_with('[') && t.ends_with(']'))
        .map(|t| t.trim_matches(['[', ']']).to_string())
}

/// Whether the host THP policy backs a freshly-faulted 512M guest region
/// with PMD huge pages *without* CH opting in via `MADV_HUGEPAGE`.
///
/// The `thp=off` write-set variants need 4K mappings to exercise 4K-page
/// write-set tracking, but CH's `thp=off` only declines `MADV_HUGEPAGE` —
/// it never sets `MADV_NOHUGEPAGE` — so on a host that forces huge folios
/// the 4K precondition can't hold and the test must skip, not fail.
///
/// - anon (`shared=off`): only `enabled=always` forms THP unadvised.
/// - shmem (`shared=on`): `always`/`within_size`/`force` back a large
///   mapping with huge folios; `advise`/`deny`/`never` stay 4K.
fn host_thp_forces_huge(shared: bool) -> bool {
    if shared {
        matches!(
            thp_sysfs_active("/sys/kernel/mm/transparent_hugepage/shmem_enabled").as_deref(),
            Some("always") | Some("within_size") | Some("force")
        )
    } else {
        thp_sysfs_active("/sys/kernel/mm/transparent_hugepage/enabled").as_deref() == Some("always")
    }
}

fn run_uffd_writeset(guest: &Guest, shared: bool, thp: bool) {
    use std::io::Write;

    if !kernel_has_uffd_wp_async() {
        eprintln!(
            "skipping uffd write-set test: kernel lacks UFFD_FEATURE_WP_ASYNC \
             (needs Linux 6.7+)"
        );
        return;
    }

    let tag = format!(
        "writeset {}/{}",
        if shared { "shmem" } else { "anon" },
        if thp { "thp" } else { "4k" }
    );

    // The thp=off variants require guest RAM to be 4K-mapped. On a host
    // whose THP policy forces huge folios (e.g. enabled=always, or
    // shmem_enabled=within_size/always/force) that can't be guaranteed,
    // so skip rather than fail (see host_thp_forces_huge).
    if !thp && host_thp_forces_huge(shared) {
        let knob = if shared { "shmem_enabled" } else { "enabled" };
        eprintln!(
            "[{tag}] skipping: host THP policy forces huge folios \
             (transparent_hugepage/{knob}); thp=off cannot guarantee 4K \
             mappings on this host"
        );
        return;
    }
    let api_socket = temp_api_path(&guest.tmp_dir);
    let handoff_sock_path = guest
        .tmp_dir
        .as_path()
        .join("uffd-writeset.sock")
        .to_str()
        .unwrap()
        .to_string();

    let mem = format!(
        "size=512M,shared={},thp={}",
        if shared { "on" } else { "off" },
        if thp { "on" } else { "off" }
    );
    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .args(["--memory", &mem])
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .args(["--api-socket", &api_socket])
        .args(["--serial", "tty", "--console", "off"])
        .capture_output();
    if thp {
        // Some hosts disable THP process-wide (PR_SET_THP_DISABLE);
        // clear it in the VMM child so guest RAM can actually be backed
        // by PMD-mapped huge pages.
        cmd.enable_thp_in_child();
    }
    let mut child = cmd.spawn().unwrap();
    let vmm_pid = child.id();

    let r = panic::catch_unwind(|| {
        eprintln!("[{tag}] waiting for VM boot");
        guest.wait_vm_boot().unwrap();
        eprintln!("[{tag}] VM booted");

        // Attach with the documented WP-async mode.
        let listener = UnixListener::bind(&handoff_sock_path).unwrap();
        let api_sock_clone = api_socket.clone();
        let handoff_sock_clone = handoff_sock_path.clone();
        let attach_thread = thread::spawn(move || {
            let body = serde_json::json!({
                "handoff_socket": handoff_sock_clone,
                "mode": "WP|WP_ASYNC",
            })
            .to_string();
            let mut sock = UnixStream::connect(&api_sock_clone).unwrap();
            api_client::simple_api_command(&mut sock, "PUT", "uffd-attach", Some(&body))
        });

        let (mut stream, _) = listener.accept().unwrap();
        let (fds, body) = recv_fds_with_body(&stream);
        let uffd_fd = fds[0];
        for &extra in &fds[1..] {
            unsafe { libc::close(extra) };
        }
        drop(listener);
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid handoff JSON");
        let regions = parsed["regions"].as_array().expect("regions array");
        assert!(!regions.is_empty(), "handoff carried no regions");
        let host_va = regions[0]["host_virt_addr"].as_u64().unwrap();
        let size = regions[0]["size"].as_u64().unwrap();

        // WP-async resolves writes in-kernel, so no fault messages are
        // delivered — no handler thread needed. We still must ACK so CH
        // returns from the attach call.
        stream.write_all(b"A").unwrap();
        drop(stream);
        attach_thread
            .join()
            .unwrap()
            .expect("uffd-attach API call failed");
        eprintln!("[{tag}] attach API succeeded");

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        let total_pages = size / page_size;
        let start = host_va;
        let end = host_va + size;

        // PMD validation: check the THP state of the handed-off region
        // *before* arming (PM_SCAN_WP_MATCHING may split huge pages).
        // This proves PMD-mapped guest RAM survives uffd-WP
        // registration and that PAGEMAP_SCAN reports it.
        let huge = pagemap_huge_pages(vmm_pid, start, end).expect("HUGE scan");
        eprintln!("[{tag}] huge_pages={huge}");
        if thp {
            assert!(
                huge > 0,
                "thp=on but PAGEMAP_SCAN found no PMD-mapped (PAGE_IS_HUGE) \
                 pages — THP did not survive the uffd-WP handoff"
            );
        } else {
            assert_eq!(huge, 0, "thp=off but PAGEMAP_SCAN found {huge} PMD pages");
        }

        // Hole detection: a freshly-booted 512M guest never populates
        // the whole region, so a chunk stays non-resident.
        let present = pagemap_present_pages(vmm_pid, start, end).expect("PRESENT scan");
        eprintln!("[{tag}] total_pages={total_pages} present={present}");
        assert!(present > 0, "no resident pages");
        assert!(
            present < total_pages,
            "expected hole pages but the whole region is resident \
             (present={present}, total={total_pages})"
        );

        // Arm write tracking: WP every resident page, clearing its
        // written state.
        let armed = pagemap_arm_wp(vmm_pid, start, end).expect("arm WP");
        eprintln!("[{tag}] armed={armed}");
        assert!(armed > 0, "armed no pages");

        // Drive a bounded amount of guest writes so some armed pages
        // flip to written (hot) while others stay untouched (and thus
        // fall into the reclaimable set).
        guest
            .ssh_command("dd if=/dev/zero of=/tmp/wss bs=1M count=32 conv=fsync 2>/dev/null; sync")
            .unwrap();

        // Poll the hot set — guest activity plus our dd dirty armed
        // resident pages.
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut hot = 0;
        while Instant::now() < deadline {
            hot = pagemap_hot_pages(vmm_pid, start, end, false).expect("WRITTEN scan");
            if hot > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        // Hot-tracking model: positively track the hot (written) set,
        // then the reclaim policy is "reclaim everything not hot". The
        // reclaimable-resident set is present-and-not-written, matched
        // directly via category_inverted (no present-minus-hot race);
        // `hole` is non-resident (already reclaimed / never populated).
        let reclaimable = pagemap_reclaimable_pages(vmm_pid, start, end, PAGE_IS_WRITTEN)
            .expect("reclaimable scan");
        let hole = pagemap_hole_pages(vmm_pid, start, end).expect("hole scan");
        eprintln!("[{tag}] hot={hot} reclaimable={reclaimable} hole={hole} total={total_pages}");

        assert!(hot > 0, "expected written (hot) pages within 15s, got 0");
        assert!(
            reclaimable > 0,
            "expected resident-but-unwritten (reclaimable) pages, got 0"
        );
        assert!(hole > 0, "expected non-resident (hole) pages, got 0");

        unsafe { libc::close(uffd_fd) };
        eprintln!("[{tag}] hot/reclaimable/hole all observed, shutting down VM");

        guest.ssh_command("sudo poweroff").unwrap();
        thread::sleep(Duration::new(20, 0));
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}

pub(crate) fn _test_uffd_writeset_anon(guest: &Guest) {
    run_uffd_writeset(guest, false, false);
}

pub(crate) fn _test_uffd_writeset_shmem(guest: &Guest) {
    run_uffd_writeset(guest, true, false);
}

pub(crate) fn _test_uffd_writeset_anon_thp(guest: &Guest) {
    run_uffd_writeset(guest, false, true);
}

pub(crate) fn _test_uffd_writeset_shmem_thp(guest: &Guest) {
    run_uffd_writeset(guest, true, true);
}

/// Manager-restart resilience. CH retains its own dup of the uffd for
/// the VM's lifetime, so a manager crash leaves the registrations alive
/// and any guest fault simply blocks (CH never resolves faults itself —
/// no zero-fill, no data loss). `do_uffd_handoff` is idempotent: a
/// second attach re-sends the *same* uffd fd + current region set
/// (resume) instead of creating a new uffd or re-registering.
///
/// This attaches a manager, simulates its death (closes the manager's
/// uffd dup and the socket), re-attaches over a *fresh* socket, and
/// proves the resumed handoff carries a live uffd by running a WP-async
/// write-set cycle against the still-registered region — which only
/// works because CH kept the registration alive across the restart.
pub(crate) fn _test_uffd_resume(guest: &Guest) {
    use std::io::Write;

    if !kernel_has_uffd_wp_async() {
        eprintln!(
            "skipping uffd resume test: kernel lacks UFFD_FEATURE_WP_ASYNC \
             (needs Linux 6.7+)"
        );
        return;
    }

    let tag = "uffd/resume";
    let api_socket = temp_api_path(&guest.tmp_dir);
    let sock_a = guest
        .tmp_dir
        .as_path()
        .join("uffd-resume-a.sock")
        .to_str()
        .unwrap()
        .to_string();
    let sock_b = guest
        .tmp_dir
        .as_path()
        .join("uffd-resume-b.sock")
        .to_str()
        .unwrap()
        .to_string();

    // anon 4k keeps WP-async deterministic (no huge-folio granularity).
    let mem = "size=512M,shared=off,thp=off";
    let mut cmd = GuestCommand::new(guest);
    cmd.default_cpus()
        .args(["--memory", mem])
        .default_kernel_cmdline()
        .default_disks()
        .default_net()
        .args(["--api-socket", &api_socket])
        .args(["--serial", "tty", "--console", "off"])
        .capture_output();
    let mut child = cmd.spawn().unwrap();
    let vmm_pid = child.id();

    let r = panic::catch_unwind(|| {
        eprintln!("[{tag}] waiting for VM boot");
        guest.wait_vm_boot().unwrap();
        eprintln!("[{tag}] VM booted");

        // Trigger a uffd-attach API call against `handoff` in a
        // background thread (the call blocks on the handshake).
        let attach = |handoff: &str| {
            let api = api_socket.clone();
            let handoff = handoff.to_string();
            thread::spawn(move || {
                let body = serde_json::json!({
                    "handoff_socket": handoff,
                    "mode": "WP|WP_ASYNC",
                })
                .to_string();
                let mut sock = UnixStream::connect(&api).unwrap();
                api_client::simple_api_command(&mut sock, "PUT", "uffd-attach", Some(&body))
            })
        };

        // ---- Manager 1: initial attach ----
        let listener_a = UnixListener::bind(&sock_a).unwrap();
        let attach_a = attach(&sock_a);
        let (mut stream_a, _) = listener_a.accept().unwrap();
        let (fds_a, body_a) = recv_fds_with_body(&stream_a);
        let uffd_a = fds_a[0];
        for &extra in &fds_a[1..] {
            unsafe { libc::close(extra) };
        }
        drop(listener_a);
        let parsed_a: serde_json::Value =
            serde_json::from_slice(&body_a).expect("valid handoff JSON");
        let regions_a = parsed_a["regions"]
            .as_array()
            .expect("regions array")
            .clone();
        assert!(!regions_a.is_empty(), "initial handoff carried no regions");
        let host_va = regions_a[0]["host_virt_addr"].as_u64().unwrap();
        let size = regions_a[0]["size"].as_u64().unwrap();
        stream_a.write_all(b"A").unwrap();
        attach_a
            .join()
            .unwrap()
            .expect("initial uffd-attach failed");
        eprintln!("[{tag}] manager 1 attached ({} regions)", regions_a.len());

        // ---- Simulate manager 1 death ----
        // Drop the manager's uffd dup and its socket. CH still holds its
        // own dup, so the uffd and its registrations stay alive.
        unsafe { libc::close(uffd_a) };
        drop(stream_a);
        eprintln!("[{tag}] manager 1 gone; CH retains the uffd");

        // ---- Manager 2: resume over a fresh socket ----
        let listener_b = UnixListener::bind(&sock_b).unwrap();
        let attach_b = attach(&sock_b);
        let (mut stream_b, _) = listener_b.accept().unwrap();
        let (fds_b, body_b) = recv_fds_with_body(&stream_b);
        let uffd_b = fds_b[0];
        for &extra in &fds_b[1..] {
            unsafe { libc::close(extra) };
        }
        drop(listener_b);
        let parsed_b: serde_json::Value =
            serde_json::from_slice(&body_b).expect("valid resume JSON");
        let regions_b = parsed_b["regions"].as_array().expect("regions array");
        assert!(!regions_b.is_empty(), "resume carried no regions");
        assert!(uffd_b >= 0, "resume delivered no uffd fd");
        // Resume must re-send the identical region layout.
        assert_eq!(
            regions_b.len(),
            regions_a.len(),
            "resume region count changed"
        );
        assert_eq!(
            regions_b[0]["host_virt_addr"].as_u64().unwrap(),
            host_va,
            "resume region host_virt_addr changed"
        );
        assert_eq!(
            regions_b[0]["size"].as_u64().unwrap(),
            size,
            "resume region size changed"
        );
        stream_b.write_all(b"A").unwrap();
        attach_b.join().unwrap().expect("resume uffd-attach failed");
        eprintln!("[{tag}] manager 2 resumed ({} regions)", regions_b.len());

        // ---- Prove the resumed uffd is live ----
        // The WP-async write-set only tracks if the VMA is still
        // registered with uffd-WP, which survives only because CH kept
        // its dup across the restart. Arm, drive guest writes, confirm.
        let start = host_va;
        let end = host_va + size;
        let armed = pagemap_arm_wp(vmm_pid, start, end).expect("arm WP");
        assert!(armed > 0, "armed no pages after resume");
        guest
            .ssh_command("dd if=/dev/zero of=/tmp/wss bs=1M count=32 conv=fsync 2>/dev/null; sync")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut hot = 0;
        while Instant::now() < deadline {
            hot = pagemap_hot_pages(vmm_pid, start, end, false).expect("WRITTEN scan");
            if hot > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        eprintln!("[{tag}] post-resume armed={armed} hot={hot}");
        assert!(
            hot > 0,
            "no written pages after resume — registration lost?"
        );

        unsafe { libc::close(uffd_b) };
        eprintln!("[{tag}] resume verified, shutting down VM");
        guest.ssh_command("sudo poweroff").unwrap();
        thread::sleep(Duration::new(20, 0));
    });

    kill_child(&mut child);
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}
