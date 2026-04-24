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
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use std::{fs, thread};

use test_infra::*;
use vmm_sys_util::tempdir::TempDir;
use wait_timeout::ChildExt;

mod common;
use common::utils::*;

static NEXT_DISK_ID: LazyLock<Mutex<u8>> = LazyLock::new(|| Mutex::new(1));

struct WindowsGuest {
    guest: Guest,
    auth: PasswordAuth,
}

trait FsType {
    const FS_FAT: u8;
    const FS_NTFS: u8;
}
impl FsType for WindowsGuest {
    const FS_FAT: u8 = 0;
    const FS_NTFS: u8 = 1;
}

impl WindowsGuest {
    fn new() -> Self {
        let disk = WindowsDiskConfig::new(WINDOWS_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(disk));
        let auth = PasswordAuth {
            username: String::from("administrator"),
            password: String::from("Admin123"),
        };

        WindowsGuest { guest, auth }
    }

    fn guest(&self) -> &Guest {
        &self.guest
    }

    fn ssh_cmd(&self, cmd: &str) -> String {
        ssh_command_ip_with_auth_retry(
            cmd,
            &self.auth,
            &self.guest.network.guest_ip0,
            DEFAULT_SSH_RETRIES,
            DEFAULT_SSH_TIMEOUT,
        )
        .unwrap()
    }

    fn cpu_count(&self) -> u8 {
        self.ssh_cmd("powershell -Command \"(Get-CimInstance win32_computersystem).NumberOfLogicalProcessors\"")
            .trim()
            .parse::<u8>()
            .unwrap_or(0)
    }

    fn ram_size(&self) -> usize {
        self.ssh_cmd(
            "powershell -Command \"(Get-CimInstance win32_computersystem).TotalPhysicalMemory\"",
        )
        .trim()
        .parse::<usize>()
        .unwrap_or(0)
    }

    fn netdev_count(&self) -> u8 {
        self.ssh_cmd("powershell -Command \"netsh int ipv4 show interfaces | Select-String ethernet | Measure-Object -Line | Format-Table -HideTableHeaders\"")
            .trim()
            .parse::<u8>()
            .unwrap_or(0)
    }

    fn disk_count(&self) -> u8 {
        self.ssh_cmd("powershell -Command \"Get-Disk | Measure-Object -Line | Format-Table -HideTableHeaders\"")
            .trim()
            .parse::<u8>()
            .unwrap_or(0)
    }

    fn reboot(&self) {
        let _ = self.ssh_cmd("shutdown /r /t 0");
    }

    fn shutdown(&self) {
        let _ = self.ssh_cmd("shutdown /s /t 0");
    }

    fn run_dnsmasq(&self) -> std::process::Child {
        let listen_address = format!("--listen-address={}", self.guest.network.host_ip0);
        let dhcp_host = format!(
            "--dhcp-host={},{}",
            self.guest.network.guest_mac0, self.guest.network.guest_ip0
        );
        let dhcp_range = format!(
            "--dhcp-range=eth,{},{}",
            self.guest.network.guest_ip0, self.guest.network.guest_ip0
        );

        Command::new("dnsmasq")
            .arg("--no-daemon")
            .arg("--log-queries")
            .arg(listen_address.as_str())
            .arg("--except-interface=lo")
            .arg("--bind-dynamic") // Allow listening to host_ip while the interface is not ready yet.
            .arg("--conf-file=/dev/null")
            .arg(dhcp_host.as_str())
            .arg(dhcp_range.as_str())
            .spawn()
            .unwrap()
    }

    // TODO Cleanup image file explicitly after test, if there's some space issues.
    fn disk_new(&self, fs: u8, sz: usize) -> String {
        let mut guard = NEXT_DISK_ID.lock().unwrap();
        let id = *guard;
        *guard = id + 1;

        let img = PathBuf::from(format!("/tmp/test-hotplug-{id}.raw"));
        let _ = fs::remove_file(&img);

        // Create an image file
        let out = Command::new("qemu-img")
            .args([
                "create",
                "-f",
                "raw",
                img.to_str().unwrap(),
                format!("{sz}m").as_str(),
            ])
            .output()
            .expect("qemu-img command failed")
            .stdout;
        println!("{out:?}");

        // Associate image to a loop device
        let out = Command::new("losetup")
            .args(["--show", "-f", img.to_str().unwrap()])
            .output()
            .expect("failed to create loop device")
            .stdout;
        let _tmp = String::from_utf8_lossy(&out);
        let loop_dev = _tmp.trim();
        println!("{out:?}");

        // Create a partition table
        // echo 'type=7' | sudo sfdisk "${LOOP}"
        let mut child = Command::new("sfdisk")
            .args([loop_dev])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all("type=7".as_bytes())
            .expect("failed to write stdin");
        let out = child.wait_with_output().expect("sfdisk failed").stdout;
        println!("{out:?}");

        // Disengage the loop device
        let out = Command::new("losetup")
            .args(["-d", loop_dev])
            .output()
            .expect("loop device not found")
            .stdout;
        println!("{out:?}");

        // Re-associate loop device pointing to the partition only
        let out = Command::new("losetup")
            .args([
                "--show",
                "--offset",
                (512 * 2048).to_string().as_str(),
                "-f",
                img.to_str().unwrap(),
            ])
            .output()
            .expect("failed to create loop device")
            .stdout;
        let _tmp = String::from_utf8_lossy(&out);
        let loop_dev = _tmp.trim();
        println!("{out:?}");

        // Create filesystem.
        let fs_cmd = match fs {
            WindowsGuest::FS_FAT => "mkfs.msdos",
            WindowsGuest::FS_NTFS => "mkfs.ntfs",
            _ => panic!("Unknown filesystem type '{fs}'"),
        };
        let out = Command::new(fs_cmd)
            .args([&loop_dev])
            .output()
            .unwrap_or_else(|_| panic!("{fs_cmd} failed"))
            .stdout;
        println!("{out:?}");

        // Disengage the loop device
        let out = Command::new("losetup")
            .args(["-d", loop_dev])
            .output()
            .unwrap_or_else(|_| panic!("loop device '{loop_dev}' not found"))
            .stdout;
        println!("{out:?}");

        img.to_str().unwrap().to_string()
    }

    fn disks_set_rw(&self) {
        let _ = self.ssh_cmd("powershell -Command \"Get-Disk | Where-Object IsOffline -eq $True | Set-Disk -IsReadOnly $False\"");
    }

    fn disks_online(&self) {
        let _ = self.ssh_cmd("powershell -Command \"Get-Disk | Where-Object IsOffline -eq $True | Set-Disk -IsOffline $False\"");
    }

    fn disk_file_put(&self, fname: &str, data: &str) {
        let _ = self.ssh_cmd(&format!(
            "powershell -Command \"'{data}' | Set-Content -Path {fname}\""
        ));
    }

    fn disk_file_read(&self, fname: &str) -> String {
        self.ssh_cmd(&format!(
            "powershell -Command \"Get-Content -Path {fname}\""
        ))
    }

    fn wait_for_boot(&self) -> Result<(), WaitForSshError> {
        let out = wait_for_ssh(
            "dir /b c:\\ | find \"Windows\"",
            &self.auth,
            &self.guest.network.guest_ip0,
            Duration::from_secs(180),
        )?;

        if out.trim() == "Windows" {
            Ok(())
        } else {
            panic!("Unexpected Windows boot probe output: {:?}", out.trim());
        }
    }
}

fn vcpu_threads_count(pid: u32) -> u8 {
    // ps -T -p 12345 | grep vcpu | wc -l
    let out = Command::new("ps")
        .args(["-T", "-p", format!("{pid}").as_str()])
        .output()
        .expect("ps command failed")
        .stdout;
    String::from_utf8_lossy(&out).matches("vcpu").count() as u8
}

fn netdev_ctrl_threads_count(pid: u32) -> u8 {
    // ps -T -p 12345 | grep "_net[0-9]*_ctrl" | wc -l
    let out = Command::new("ps")
        .args(["-T", "-p", format!("{pid}").as_str()])
        .output()
        .expect("ps command failed")
        .stdout;
    let mut n = 0;
    String::from_utf8_lossy(&out)
        .split_whitespace()
        .for_each(|s| n += (s.starts_with("_net") && s.ends_with("_ctrl")) as u8); // _net1_ctrl
    n
}

fn disk_ctrl_threads_count(pid: u32) -> u8 {
    // ps -T -p 15782  | grep "_disk[0-9]*_q0" | wc -l
    let out = Command::new("ps")
        .args(["-T", "-p", format!("{pid}").as_str()])
        .output()
        .expect("ps command failed")
        .stdout;
    let mut n = 0;
    String::from_utf8_lossy(&out)
        .split_whitespace()
        .for_each(|s| n += (s.starts_with("_disk") && s.ends_with("_q0")) as u8); // _disk0_q0, don't care about multiple queues as they're related to the same hdd
    n
}

#[test]
fn test_windows_guest() {
    let windows_guest = WindowsGuest::new();

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", edk2_path().to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let fd = child.stdout.as_ref().unwrap().as_raw_fd();
    let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
    let fd = child.stderr.as_ref().unwrap().as_raw_fd();
    let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

    assert!(pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE);

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
fn test_windows_guest_multiple_queues() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--cpus", "boot=4,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .args([
            "--disk",
            format!(
                "path={},num_queues=4",
                windows_guest
                    .guest()
                    .disk_config
                    .disk(DiskType::OperatingSystem)
                    .unwrap()
            )
            .as_str(),
        ])
        .args([
            "--net",
            format!(
                "tap=,mac={},ip={},mask=255.255.255.128,num_queues=8",
                windows_guest.guest().network.guest_mac0,
                windows_guest.guest().network.host_ip0
            )
            .as_str(),
        ])
        .capture_output()
        .spawn()
        .unwrap();

    let fd = child.stdout.as_ref().unwrap().as_raw_fd();
    let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
    let fd = child.stderr.as_ref().unwrap().as_raw_fd();
    let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

    assert!(pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE);

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[cfg(not(feature = "mshv"))]
#[cfg_attr(target_arch = "aarch64", ignore = "See #4327")]
fn test_windows_guest_snapshot_restore() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket_source = format!("{}.1", temp_api_path(&tmp_dir));

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket_source])
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let fd = child.stdout.as_ref().unwrap().as_raw_fd();
    let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
    let fd = child.stderr.as_ref().unwrap().as_raw_fd();
    let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

    assert!(pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE);

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    // Wait to make sure Windows boots up
    windows_guest.wait_for_boot().unwrap();

    let snapshot_dir = temp_snapshot_dir_path(&tmp_dir);

    // Pause the VM
    assert!(remote_command(&api_socket_source, "pause", None));

    // Take a snapshot from the VM
    assert!(remote_command(
        &api_socket_source,
        "snapshot",
        Some(format!("file://{snapshot_dir}").as_str()),
    ));

    let snapshot_state_path = std::path::Path::new(&snapshot_dir).join("state.json");
    let snapshot_config_path = std::path::Path::new(&snapshot_dir).join("config.json");
    assert!(wait_until(Duration::from_secs(30), || {
        snapshot_state_path.exists() && snapshot_config_path.exists()
    }));

    let _ = child.kill();
    child.wait().unwrap();

    let api_socket_restored = format!("{}.2", temp_api_path(&tmp_dir));

    // Restore the VM from the snapshot
    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket_restored])
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

    let r = std::panic::catch_unwind(|| {
        // Resume the VM
        assert!(wait_until(Duration::from_secs(30), || remote_command(
            &api_socket_restored,
            "info",
            None
        )));
        assert!(remote_command(&api_socket_restored, "resume", None));

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[cfg(not(feature = "mshv"))]
#[cfg(not(target_arch = "aarch64"))]
fn test_windows_guest_cpu_hotplug() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket = temp_api_path(&tmp_dir);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket])
        .args(["--cpus", "boot=2,max=8,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        let vcpu_num = 2;
        // Check the initial number of CPUs the guest sees
        assert_eq!(windows_guest.cpu_count(), vcpu_num);
        // Check the initial number of vcpu threads in the CH process
        assert_eq!(vcpu_threads_count(child.id()), vcpu_num);

        let vcpu_num = 6;
        // Hotplug some CPUs
        resize_command(&api_socket, Some(vcpu_num), None, None, None);
        // Wait for Windows to report the hotplugged CPUs.
        assert!(wait_until(Duration::from_secs(10), || windows_guest
            .cpu_count()
            == vcpu_num));
        // Check the guest sees the correct number
        assert_eq!(windows_guest.cpu_count(), vcpu_num);
        // Check the CH process has the correct number of vcpu threads
        assert_eq!(vcpu_threads_count(child.id()), vcpu_num);

        let vcpu_num = 4;
        // Remove some CPUs. Note that Windows doesn't support hot-remove.
        resize_command(&api_socket, Some(vcpu_num), None, None, None);
        thread::sleep(std::time::Duration::new(10, 0));

        // Reboot to let Windows catch up
        windows_guest.reboot();
        // Wait for Windows to come back after the reboot.
        windows_guest.wait_for_boot().unwrap();
        // Wait for Windows to reflect the unplugged CPU count.
        assert!(wait_until(Duration::from_secs(60), || windows_guest
            .cpu_count()
            == vcpu_num));
        // Check the guest sees the correct number
        assert_eq!(windows_guest.cpu_count(), vcpu_num);
        // Check the CH process has the correct number of vcpu threads
        assert_eq!(vcpu_threads_count(child.id()), vcpu_num);

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[cfg(not(feature = "mshv"))]
#[cfg(not(target_arch = "aarch64"))]
fn test_windows_guest_ram_hotplug() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket = temp_api_path(&tmp_dir);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket])
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=2G,hotplug_size=5G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        let ram_size = 2 * 1024 * 1024 * 1024;
        // Check the initial number of RAM the guest sees
        let current_ram_size = windows_guest.ram_size();
        // This size seems to be reserved by the system and thus the
        // reported amount differs by this constant value.
        let reserved_ram_size = ram_size - current_ram_size;
        // Verify that there's not more than 4mb constant diff wasted
        // by the reserved ram.
        assert!(reserved_ram_size < 4 * 1024 * 1024);

        let ram_size = 4 * 1024 * 1024 * 1024;
        // Hotplug some RAM
        resize_command(&api_socket, None, Some(ram_size), None, None);
        // Wait for Windows to report the hotplugged memory.
        assert!(wait_until(Duration::from_secs(10), || windows_guest
            .ram_size()
            == ram_size - reserved_ram_size));

        let ram_size = 3 * 1024 * 1024 * 1024;
        // Unplug some RAM. Note that hot-remove most likely won't work.
        resize_command(&api_socket, None, Some(ram_size), None, None);
        // Reboot to let Windows catch up
        windows_guest.reboot();
        // Wait for Windows to come back after the reboot.
        windows_guest.wait_for_boot().unwrap();
        // Wait for Windows to reflect the unplugged RAM amount.
        assert!(wait_until(Duration::from_secs(60), || windows_guest
            .ram_size()
            == ram_size - reserved_ram_size));
        // Check the guest sees the correct number
        assert_eq!(windows_guest.ram_size(), ram_size - reserved_ram_size);

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[cfg(not(feature = "mshv"))]
fn test_windows_guest_netdev_hotplug() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket = temp_api_path(&tmp_dir);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket])
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        // Initially present network device
        let netdev_num = 1;
        assert_eq!(windows_guest.netdev_count(), netdev_num);
        assert_eq!(netdev_ctrl_threads_count(child.id()), netdev_num);

        // Hotplug network device
        let (cmd_success, cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-net",
            Some(windows_guest.guest().default_net_string().as_str()),
        );
        assert!(cmd_success);
        assert!(String::from_utf8_lossy(&cmd_output).contains("\"id\":\"_net2\""));
        // Wait for Windows to enumerate the added network device.
        assert!(wait_until(Duration::from_secs(5), || windows_guest
            .netdev_count()
            == 2
            && netdev_ctrl_threads_count(child.id()) == 2));
        // Verify the device  is on the system
        let netdev_num = 2;
        assert_eq!(windows_guest.netdev_count(), netdev_num);
        assert_eq!(netdev_ctrl_threads_count(child.id()), netdev_num);

        // Remove network device
        let cmd_success = remote_command(&api_socket, "remove-device", Some("_net2"));
        assert!(cmd_success);
        // Wait for Windows to drop the removed network device.
        assert!(wait_until(Duration::from_secs(5), || windows_guest
            .netdev_count()
            == 1
            && netdev_ctrl_threads_count(child.id()) == 1));
        // Verify the device has been removed
        let netdev_num = 1;
        assert_eq!(windows_guest.netdev_count(), netdev_num);
        assert_eq!(netdev_ctrl_threads_count(child.id()), netdev_num);

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[ignore = "See #6037"]
#[cfg(not(feature = "mshv"))]
#[cfg(not(target_arch = "aarch64"))]
fn test_windows_guest_disk_hotplug() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket = temp_api_path(&tmp_dir);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket])
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let disk = windows_guest.disk_new(WindowsGuest::FS_FAT, 100);

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        // Initially present disk device
        let disk_num = 1;
        assert_eq!(windows_guest.disk_count(), disk_num);
        assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

        // Hotplug disk device
        let (cmd_success, cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-disk",
            Some(format!("path={disk},readonly=off").as_str()),
        );
        assert!(cmd_success);
        assert!(String::from_utf8_lossy(&cmd_output).contains("\"id\":\"_disk2\""));
        // Online disk device
        windows_guest.disks_set_rw();
        windows_guest.disks_online();
        // Wait for Windows to enumerate the added disk.
        assert!(wait_until(Duration::from_secs(5), || windows_guest
            .disk_count()
            == 2
            && disk_ctrl_threads_count(child.id()) == 2));
        // Verify the device is on the system
        let disk_num = 2;
        assert_eq!(windows_guest.disk_count(), disk_num);
        assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

        let data = "hello";
        let fname = "d:\\world";
        windows_guest.disk_file_put(fname, data);

        // Unmount disk device
        let cmd_success = remote_command(&api_socket, "remove-device", Some("_disk2"));
        assert!(cmd_success);
        // Wait for Windows to drop the removed disk.
        assert!(wait_until(Duration::from_secs(5), || windows_guest
            .disk_count()
            == 1
            && disk_ctrl_threads_count(child.id()) == 1));
        // Verify the device has been removed
        let disk_num = 1;
        assert_eq!(windows_guest.disk_count(), disk_num);
        assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

        // Remount and check the file exists with the expected contents
        let (cmd_success, _cmd_output, _) = remote_command_w_output(
            &api_socket,
            "add-disk",
            Some(format!("path={disk},readonly=off").as_str()),
        );
        assert!(cmd_success);
        // Wait for Windows to mount the re-added disk again.
        assert!(wait_until(Duration::from_secs(5), || windows_guest
            .disk_file_read(fname)
            .trim()
            == data));
        let out = windows_guest.disk_file_read(fname);
        assert_eq!(data, out.trim());

        // Intentionally no unmount, it'll happen at shutdown.

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[ignore = "See #6037"]
#[cfg(not(feature = "mshv"))]
#[cfg(not(target_arch = "aarch64"))]
fn test_windows_guest_disk_hotplug_multi() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket = temp_api_path(&tmp_dir);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket])
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=2G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    // Predefined data to used at various test stages
    let disk_test_data: [[String; 4]; 2] = [
        [
            "_disk2".to_string(),
            windows_guest.disk_new(WindowsGuest::FS_FAT, 123),
            "d:\\world".to_string(),
            "hello".to_string(),
        ],
        [
            "_disk3".to_string(),
            windows_guest.disk_new(WindowsGuest::FS_NTFS, 333),
            "e:\\hello".to_string(),
            "world".to_string(),
        ],
    ];

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        // Initially present disk device
        let disk_num = 1;
        assert_eq!(windows_guest.disk_count(), disk_num);
        assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

        for it in &disk_test_data {
            let disk_id = it[0].as_str();
            let disk = it[1].as_str();

            let expected_disk_num = windows_guest.disk_count() + 1;
            let expected_ctrl_threads = disk_ctrl_threads_count(child.id()) + 1;

            // Hotplug disk device
            let (cmd_success, cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-disk",
                Some(format!("path={disk},readonly=off").as_str()),
            );
            assert!(cmd_success);
            assert!(
                String::from_utf8_lossy(&cmd_output)
                    .contains(format!("\"id\":\"{disk_id}\"").as_str())
            );

            // Wait for disk to appear
            assert!(wait_until(Duration::from_secs(5), || {
                windows_guest.disk_count() == expected_disk_num
                    && disk_ctrl_threads_count(child.id()) == expected_ctrl_threads
            }));

            // Online disk devices
            windows_guest.disks_set_rw();
            windows_guest.disks_online();
        }
        // Verify the devices are on the system
        let disk_num = (disk_test_data.len() + 1) as u8;
        assert_eq!(windows_guest.disk_count(), disk_num);
        assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

        // Put test data
        for it in &disk_test_data {
            let fname = it[2].as_str();
            let data = it[3].as_str();
            windows_guest.disk_file_put(fname, data);
        }

        // Unmount disk devices
        for it in &disk_test_data {
            let disk_id = it[0].as_str();
            let cmd_success = remote_command(&api_socket, "remove-device", Some(disk_id));
            assert!(cmd_success);
        }

        // Wait for Windows to drop all removed disks.
        assert!(wait_until(Duration::from_secs(5), || windows_guest
            .disk_count()
            == 1
            && disk_ctrl_threads_count(child.id()) == 1));
        // Verify the devices have been removed
        let disk_num = 1;
        assert_eq!(windows_guest.disk_count(), disk_num);
        assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

        // Remount
        for it in &disk_test_data {
            let disk = it[1].as_str();
            let (cmd_success, _cmd_output, _) = remote_command_w_output(
                &api_socket,
                "add-disk",
                Some(format!("path={disk},readonly=off").as_str()),
            );
            assert!(cmd_success);
        }

        // Wait for Windows to enumerate the re-added disks.
        assert!(wait_until(Duration::from_secs(5), || {
            windows_guest.disk_count() == 4 && disk_ctrl_threads_count(child.id()) == 4
        }));
        // Check the files exists with the expected contents
        for it in &disk_test_data {
            let fname = it[2].as_str();
            let data = it[3].as_str();
            let out = windows_guest.disk_file_read(fname);
            assert_eq!(data, out.trim());
        }

        // Intentionally no unmount, it'll happen at shutdown.

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
#[cfg(not(feature = "mshv"))]
#[cfg(not(target_arch = "aarch64"))]
fn test_windows_guest_netdev_multi() {
    let windows_guest = WindowsGuest::new();

    let mut ovmf_path = dirs::home_dir().unwrap();
    ovmf_path.push("workloads");
    ovmf_path.push(OVMF_NAME);

    let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
    let api_socket = temp_api_path(&tmp_dir);

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--api-socket", &api_socket])
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", ovmf_path.to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .default_disks()
        // The multi net dev config is borrowed from test_multiple_network_interfaces
        .args([
            "--net",
            windows_guest.guest().default_net_string().as_str(),
            "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.0",
            "tap=mytap42,mac=fe:1f:9e:e1:60:f2,ip=192.168.4.1,mask=255.255.255.0",
        ])
        .capture_output()
        .spawn()
        .unwrap();

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        // Wait to make sure Windows boots up
        windows_guest.wait_for_boot().unwrap();

        let netdev_num = 3;
        assert_eq!(windows_guest.netdev_count(), netdev_num);
        assert_eq!(netdev_ctrl_threads_count(child.id()), netdev_num);

        let tap_count = exec_host_command_output("ip link | grep -c mytap42");
        assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}

#[test]
fn test_windows_guest_qcow2_backing_direct() {
    let windows_guest = WindowsGuest::new();

    let qcow2_path = windows_guest.guest().disk_config.qcow2_disk().unwrap();

    let mut child = GuestCommand::new(windows_guest.guest())
        .args(["--cpus", "boot=2,kvm_hyperv=on"])
        .args(["--memory", "size=4G"])
        .args(["--kernel", edk2_path().to_str().unwrap()])
        .args(["--serial", "tty"])
        .args(["--console", "off"])
        .args([
            "--disk",
            format!("path={qcow2_path},image_type=qcow2,backing_files=on,direct=on").as_str(),
        ])
        .default_net()
        .capture_output()
        .spawn()
        .unwrap();

    let fd = child.stdout.as_ref().unwrap().as_raw_fd();
    let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
    let fd = child.stderr.as_ref().unwrap().as_raw_fd();
    let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

    assert!(pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE);

    let mut child_dnsmasq = windows_guest.run_dnsmasq();

    let r = std::panic::catch_unwind(|| {
        windows_guest.wait_for_boot().unwrap();

        // Write and read back files through qcow2 + direct I/O.
        for i in 0..5 {
            let fname = format!("c:\\test-dio-{i}.bin");
            let fname2 = format!("c:\\test-dio-{i}-copy.bin");
            let size = (i + 1) * 4 * 1024 * 1024;
            windows_guest.ssh_cmd(&format!(
                "powershell -Command \"\
                $r = New-Object byte[] {size}; \
                (New-Object Random {i}).NextBytes($r); \
                [IO.File]::WriteAllBytes('{fname}', $r)\""
            ));
            let hash_write = windows_guest.ssh_cmd(&format!(
                "powershell -Command \"(Get-FileHash '{fname}' -Algorithm SHA256).Hash\""
            ));
            windows_guest.ssh_cmd(&format!("copy {fname} {fname2}"));
            let hash_read = windows_guest.ssh_cmd(&format!(
                "powershell -Command \"(Get-FileHash '{fname2}' -Algorithm SHA256).Hash\""
            ));
            assert_eq!(hash_write.trim(), hash_read.trim());
        }

        windows_guest.shutdown();
    });

    let _ = child.wait_timeout(std::time::Duration::from_secs(60));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let _ = child_dnsmasq.kill();
    let _ = child_dnsmasq.wait();

    handle_child_output(r, &output);
}
