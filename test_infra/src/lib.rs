// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use ssh2::Session;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::str::FromStr;
use std::thread;
use vmm_sys_util::tempdir::TempDir;

pub const DEFAULT_TCP_LISTENER_MESSAGE: &str = "booted";

pub struct GuestNetworkConfig {
    pub guest_ip: String,
    pub l2_guest_ip1: String,
    pub l2_guest_ip2: String,
    pub l2_guest_ip3: String,
    pub host_ip: String,
    pub guest_mac: String,
    pub l2_guest_mac1: String,
    pub l2_guest_mac2: String,
    pub l2_guest_mac3: String,
    pub tcp_listener_port: u16,
}

pub const DEFAULT_TCP_LISTENER_PORT: u16 = 8000;
pub const DEFAULT_TCP_LISTENER_TIMEOUT: i32 = 80;

#[derive(Debug)]
pub enum WaitForBootError {
    EpollWait(std::io::Error),
    Listen(std::io::Error),
    EpollWaitTimeout,
    WrongGuestAddr,
    Accept(std::io::Error),
}

impl GuestNetworkConfig {
    pub fn wait_vm_boot(&self, custom_timeout: Option<i32>) -> Result<(), WaitForBootError> {
        let start = std::time::Instant::now();
        // The 'port' is unique per 'GUEST' and listening to wild-card ip avoids retrying on 'TcpListener::bind()'
        let listen_addr = format!("0.0.0.0:{}", self.tcp_listener_port);
        let expected_guest_addr = self.guest_ip.as_str();
        let mut s = String::new();
        let timeout = match custom_timeout {
            Some(t) => t,
            None => DEFAULT_TCP_LISTENER_TIMEOUT,
        };

        match (|| -> Result<(), WaitForBootError> {
            let listener =
                TcpListener::bind(&listen_addr.as_str()).map_err(WaitForBootError::Listen)?;
            listener
                .set_nonblocking(true)
                .expect("Cannot set non-blocking for tcp listener");

            // Reply on epoll w/ timeout to wait for guest connections faithfully
            let epoll_fd = epoll::create(true).expect("Cannot create epoll fd");
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                listener.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, 0),
            )
            .expect("Cannot add 'tcp_listener' event to epoll");
            let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 1];
            loop {
                let num_events = match epoll::wait(epoll_fd, timeout * 1000_i32, &mut events[..]) {
                    Ok(num_events) => Ok(num_events),
                    Err(e) => match e.raw_os_error() {
                        Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                        _ => Err(e),
                    },
                }
                .map_err(WaitForBootError::EpollWait)?;
                if num_events == 0 {
                    return Err(WaitForBootError::EpollWaitTimeout);
                }
                break;
            }

            match listener.accept() {
                Ok((_, addr)) => {
                    // Make sure the connection is from the expected 'guest_addr'
                    if addr.ip() != std::net::IpAddr::from_str(expected_guest_addr).unwrap() {
                        s = format!(
                            "Expecting the guest ip '{}' while being connected with ip '{}'",
                            expected_guest_addr,
                            addr.ip()
                        );
                        return Err(WaitForBootError::WrongGuestAddr);
                    }

                    Ok(())
                }
                Err(e) => {
                    s = "TcpListener::accept() failed".to_string();
                    Err(WaitForBootError::Accept(e))
                }
            }
        })() {
            Err(e) => {
                let duration = start.elapsed();
                eprintln!(
                    "\n\n==== Start 'wait_vm_boot' (FAILED) ====\n\n\
                 duration =\"{:?}, timeout = {}s\"\n\
                 listen_addr=\"{}\"\n\
                 expected_guest_addr=\"{}\"\n\
                 message=\"{}\"\n\
                 error=\"{:?}\"\n\
                 \n==== End 'wait_vm_boot' outout ====\n\n",
                    duration, timeout, listen_addr, expected_guest_addr, s, e
                );

                Err(e)
            }
            Ok(_) => Ok(()),
        }
    }
}

pub enum DiskType {
    OperatingSystem,
    CloudInit,
}

pub trait DiskConfig {
    fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig);
    fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String;
    fn disk(&self, disk_type: DiskType) -> Option<String>;
}

pub struct UbuntuDiskConfig {
    osdisk_path: String,
    cloudinit_path: String,
    image_name: String,
}

impl UbuntuDiskConfig {
    pub fn new(image_name: String) -> Self {
        UbuntuDiskConfig {
            image_name,
            osdisk_path: String::new(),
            cloudinit_path: String::new(),
        }
    }
}

pub struct WindowsDiskConfig {
    image_name: String,
    osdisk_path: String,
    loopback_device: String,
    windows_snapshot_cow: String,
    windows_snapshot: String,
}

impl WindowsDiskConfig {
    pub fn new(image_name: String) -> Self {
        WindowsDiskConfig {
            image_name,
            osdisk_path: String::new(),
            loopback_device: String::new(),
            windows_snapshot_cow: String::new(),
            windows_snapshot: String::new(),
        }
    }
}

impl Drop for WindowsDiskConfig {
    fn drop(&mut self) {
        // dmsetup remove windows-snapshot-1
        std::process::Command::new("dmsetup")
            .arg("remove")
            .arg(self.windows_snapshot.as_str())
            .output()
            .expect("Expect removing Windows snapshot with 'dmsetup' to succeed");

        // dmsetup remove windows-snapshot-cow-1
        std::process::Command::new("dmsetup")
            .arg("remove")
            .arg(self.windows_snapshot_cow.as_str())
            .output()
            .expect("Expect removing Windows snapshot CoW with 'dmsetup' to succeed");

        // losetup -d <loopback_device>
        std::process::Command::new("losetup")
            .args(&["-d", self.loopback_device.as_str()])
            .output()
            .expect("Expect removing loopback device to succeed");
    }
}

impl DiskConfig for UbuntuDiskConfig {
    fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String {
        let cloudinit_file_path =
            String::from(tmp_dir.as_path().join("cloudinit").to_str().unwrap());

        let cloud_init_directory = tmp_dir.as_path().join("cloud-init").join("ubuntu");

        fs::create_dir_all(&cloud_init_directory)
            .expect("Expect creating cloud-init directory to succeed");

        let source_file_dir = std::env::current_dir()
            .unwrap()
            .join("test_data")
            .join("cloud-init")
            .join("ubuntu");

        vec!["meta-data"].iter().for_each(|x| {
            rate_limited_copy(source_file_dir.join(x), cloud_init_directory.join(x))
                .expect("Expect copying cloud-init meta-data to succeed");
        });

        let mut user_data_string = String::new();
        fs::File::open(source_file_dir.join("user-data"))
            .unwrap()
            .read_to_string(&mut user_data_string)
            .expect("Expected reading user-data file in to succeed");
        user_data_string = user_data_string.replace(
            "@DEFAULT_TCP_LISTENER_MESSAGE",
            &DEFAULT_TCP_LISTENER_MESSAGE,
        );
        user_data_string = user_data_string.replace("@HOST_IP", &network.host_ip);
        user_data_string =
            user_data_string.replace("@TCP_LISTENER_PORT", &network.tcp_listener_port.to_string());

        fs::File::create(cloud_init_directory.join("user-data"))
            .unwrap()
            .write_all(&user_data_string.as_bytes())
            .expect("Expected writing out user-data to succeed");

        let mut network_config_string = String::new();

        fs::File::open(source_file_dir.join("network-config"))
            .unwrap()
            .read_to_string(&mut network_config_string)
            .expect("Expected reading network-config file in to succeed");

        network_config_string = network_config_string.replace("192.168.2.1", &network.host_ip);
        network_config_string = network_config_string.replace("192.168.2.2", &network.guest_ip);
        network_config_string = network_config_string.replace("192.168.2.3", &network.l2_guest_ip1);
        network_config_string = network_config_string.replace("192.168.2.4", &network.l2_guest_ip2);
        network_config_string = network_config_string.replace("192.168.2.5", &network.l2_guest_ip3);
        network_config_string =
            network_config_string.replace("12:34:56:78:90:ab", &network.guest_mac);
        network_config_string =
            network_config_string.replace("de:ad:be:ef:12:34", &network.l2_guest_mac1);
        network_config_string =
            network_config_string.replace("de:ad:be:ef:34:56", &network.l2_guest_mac2);
        network_config_string =
            network_config_string.replace("de:ad:be:ef:56:78", &network.l2_guest_mac3);

        fs::File::create(cloud_init_directory.join("network-config"))
            .unwrap()
            .write_all(&network_config_string.as_bytes())
            .expect("Expected writing out network-config to succeed");

        std::process::Command::new("mkdosfs")
            .args(&["-n", "cidata"])
            .args(&["-C", cloudinit_file_path.as_str()])
            .arg("8192")
            .output()
            .expect("Expect creating disk image to succeed");

        vec!["user-data", "meta-data", "network-config"]
            .iter()
            .for_each(|x| {
                std::process::Command::new("mcopy")
                    .arg("-o")
                    .args(&["-i", cloudinit_file_path.as_str()])
                    .args(&["-s", cloud_init_directory.join(x).to_str().unwrap(), "::"])
                    .output()
                    .expect("Expect copying files to disk image to succeed");
            });

        cloudinit_file_path
    }

    fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut osdisk_base_path = workload_path;
        osdisk_base_path.push(&self.image_name);

        let osdisk_path = String::from(tmp_dir.as_path().join("osdisk.img").to_str().unwrap());
        let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

        rate_limited_copy(osdisk_base_path, &osdisk_path)
            .expect("copying of OS source disk image failed");

        self.cloudinit_path = cloudinit_path;
        self.osdisk_path = osdisk_path;
    }

    fn disk(&self, disk_type: DiskType) -> Option<String> {
        match disk_type {
            DiskType::OperatingSystem => Some(self.osdisk_path.clone()),
            DiskType::CloudInit => Some(self.cloudinit_path.clone()),
        }
    }
}

impl DiskConfig for WindowsDiskConfig {
    fn prepare_cloudinit(&self, _tmp_dir: &TempDir, _network: &GuestNetworkConfig) -> String {
        String::new()
    }

    fn prepare_files(&mut self, tmp_dir: &TempDir, _network: &GuestNetworkConfig) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut osdisk_path = workload_path;
        osdisk_path.push(&self.image_name);

        let osdisk_blk_size = fs::metadata(osdisk_path)
            .expect("Expect retrieving Windows image metadata")
            .len()
            >> 9;

        let snapshot_cow_path =
            String::from(tmp_dir.as_path().join("snapshot_cow").to_str().unwrap());

        // Create and truncate CoW file for device mapper
        let cow_file_size: u64 = 1 << 30;
        let cow_file_blk_size = cow_file_size >> 9;
        let cow_file = std::fs::File::create(snapshot_cow_path.as_str())
            .expect("Expect creating CoW image to succeed");
        cow_file
            .set_len(cow_file_size)
            .expect("Expect truncating CoW image to succeed");

        // losetup --find --show /tmp/snapshot_cow
        let loopback_device = std::process::Command::new("losetup")
            .arg("--find")
            .arg("--show")
            .arg(snapshot_cow_path.as_str())
            .output()
            .expect("Expect creating loopback device from snapshot CoW image to succeed");

        self.loopback_device = String::from_utf8_lossy(&loopback_device.stdout)
            .trim()
            .to_string();

        let random_extension = tmp_dir.as_path().file_name().unwrap();
        let windows_snapshot_cow = format!(
            "windows-snapshot-cow-{}",
            random_extension.to_str().unwrap()
        );

        // dmsetup create windows-snapshot-cow-1 --table '0 2097152 linear /dev/loop1 0'
        std::process::Command::new("dmsetup")
            .arg("create")
            .arg(windows_snapshot_cow.as_str())
            .args(&[
                "--table",
                format!("0 {} linear {} 0", cow_file_blk_size, self.loopback_device).as_str(),
            ])
            .output()
            .expect("Expect creating Windows snapshot CoW with 'dmsetup' to succeed");

        let windows_snapshot = format!("windows-snapshot-{}", random_extension.to_str().unwrap());

        // dmsetup mknodes
        std::process::Command::new("dmsetup")
            .arg("mknodes")
            .output()
            .expect("Expect device mapper nodes to be ready");

        // dmsetup create windows-snapshot-1 --table '0 41943040 snapshot /dev/mapper/windows-base /dev/mapper/windows-snapshot-cow-1 P 8'
        std::process::Command::new("dmsetup")
            .arg("create")
            .arg(windows_snapshot.as_str())
            .args(&[
                "--table",
                format!(
                    "0 {} snapshot /dev/mapper/windows-base /dev/mapper/{} P 8",
                    osdisk_blk_size,
                    windows_snapshot_cow.as_str()
                )
                .as_str(),
            ])
            .output()
            .expect("Expect creating Windows snapshot with 'dmsetup' to succeed");

        // dmsetup mknodes
        std::process::Command::new("dmsetup")
            .arg("mknodes")
            .output()
            .expect("Expect device mapper nodes to be ready");

        self.osdisk_path = format!("/dev/mapper/{}", windows_snapshot);
        self.windows_snapshot_cow = windows_snapshot_cow;
        self.windows_snapshot = windows_snapshot;
    }

    fn disk(&self, disk_type: DiskType) -> Option<String> {
        match disk_type {
            DiskType::OperatingSystem => Some(self.osdisk_path.clone()),
            DiskType::CloudInit => None,
        }
    }
}

pub fn rate_limited_copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    for i in 0..10 {
        let free_bytes = unsafe {
            let mut stats = std::mem::MaybeUninit::zeroed();
            let fs_name = std::ffi::CString::new("/tmp").unwrap();
            libc::statvfs(fs_name.as_ptr(), stats.as_mut_ptr());

            let free_blocks = stats.assume_init().f_bfree;
            let block_size = stats.assume_init().f_bsize;

            free_blocks * block_size
        };

        // Make sure there is at least 6 GiB of space
        if free_bytes < 6 << 30 {
            eprintln!(
                "Not enough space on disk ({}). Attempt {} of 10. Sleeping.",
                free_bytes, i
            );
            thread::sleep(std::time::Duration::new(60, 0));
            continue;
        }

        match fs::copy(&from, &to) {
            Err(e) => {
                if let Some(errno) = e.raw_os_error() {
                    if errno == libc::ENOSPC {
                        eprintln!("Copy returned ENOSPC. Attempt {} of 10. Sleeping.", i);
                        thread::sleep(std::time::Duration::new(60, 0));
                        continue;
                    }
                }
                return Err(e);
            }
            Ok(i) => return Ok(i),
        }
    }
    Err(io::Error::last_os_error())
}

pub fn handle_child_output(
    r: Result<(), std::boxed::Box<dyn std::any::Any + std::marker::Send>>,
    output: &std::process::Output,
) {
    use std::os::unix::process::ExitStatusExt;
    if r.is_ok() && output.status.success() {
        return;
    }

    match output.status.code() {
        None => {
            // Don't treat child.kill() as a problem
            if output.status.signal() == Some(9) && r.is_ok() {
                return;
            }

            eprintln!(
                "==== child killed by signal: {} ====",
                output.status.signal().unwrap()
            );
        }
        Some(code) => {
            eprintln!("\n\n==== child exit code: {} ====", code);
        }
    }

    eprintln!(
        "\n\n==== Start child stdout ====\n\n{}\n\n==== End child stdout ====",
        String::from_utf8_lossy(&output.stdout)
    );
    eprintln!(
        "\n\n==== Start child stderr ====\n\n{}\n\n==== End child stderr ====",
        String::from_utf8_lossy(&output.stderr)
    );

    panic!("Test failed")
}

#[derive(Debug)]
pub struct PasswordAuth {
    pub username: String,
    pub password: String,
}

pub const DEFAULT_SSH_RETRIES: u8 = 6;
pub const DEFAULT_SSH_TIMEOUT: u8 = 10;

#[derive(Debug)]
pub enum SshCommandError {
    Connection(std::io::Error),
    Handshake(ssh2::Error),
    Authentication(ssh2::Error),
    ChannelSession(ssh2::Error),
    Command(ssh2::Error),
}

pub fn ssh_command_ip_with_auth(
    command: &str,
    auth: &PasswordAuth,
    ip: &str,
    retries: u8,
    timeout: u8,
) -> Result<String, SshCommandError> {
    let mut s = String::new();

    let mut counter = 0;
    loop {
        match (|| -> Result<(), SshCommandError> {
            let tcp =
                TcpStream::connect(format!("{}:22", ip)).map_err(SshCommandError::Connection)?;
            let mut sess = Session::new().unwrap();
            sess.set_tcp_stream(tcp);
            sess.handshake().map_err(SshCommandError::Handshake)?;

            sess.userauth_password(&auth.username, &auth.password)
                .map_err(SshCommandError::Authentication)?;
            assert!(sess.authenticated());

            let mut channel = sess
                .channel_session()
                .map_err(SshCommandError::ChannelSession)?;
            channel.exec(command).map_err(SshCommandError::Command)?;

            // Intentionally ignore these results here as their failure
            // does not precipitate a repeat
            let _ = channel.read_to_string(&mut s);
            let _ = channel.close();
            let _ = channel.wait_close();
            Ok(())
        })() {
            Ok(_) => break,
            Err(e) => {
                counter += 1;
                if counter >= retries {
                    eprintln!(
                        "\n\n==== Start ssh command output (FAILED) ====\n\n\
                         command=\"{}\"\n\
                         auth=\"{:#?}\"\n\
                         ip=\"{}\"\n\
                         output=\"{}\"\n\
                         error=\"{:?}\"\n\
                         \n==== End ssh command outout ====\n\n",
                        command, auth, ip, s, e
                    );

                    return Err(e);
                }
            }
        };
        thread::sleep(std::time::Duration::new((timeout * counter).into(), 0));
    }
    Ok(s)
}

pub fn ssh_command_ip(
    command: &str,
    ip: &str,
    retries: u8,
    timeout: u8,
) -> Result<String, SshCommandError> {
    ssh_command_ip_with_auth(
        command,
        &PasswordAuth {
            username: String::from("cloud"),
            password: String::from("cloud123"),
        },
        ip,
        retries,
        timeout,
    )
}
