// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod tests {
    #![allow(dead_code)]
    use net_util::MacAddr;
    use ssh2::Session;
    use std::collections::HashMap;
    use std::env;
    use std::ffi::OsStr;
    use std::fs;
    use std::io;
    use std::io::BufRead;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::str::FromStr;
    use std::string::String;
    use std::sync::Mutex;
    use std::thread;
    use tempdir::TempDir;
    use tempfile::NamedTempFile;
    use wait_timeout::ChildExt;

    lazy_static! {
        static ref NEXT_VM_ID: Mutex<u8> = Mutex::new(1);
    }

    struct GuestNetworkConfig {
        guest_ip: String,
        l2_guest_ip1: String,
        l2_guest_ip2: String,
        l2_guest_ip3: String,
        host_ip: String,
        guest_mac: String,
        l2_guest_mac1: String,
        l2_guest_mac2: String,
        l2_guest_mac3: String,
        tcp_listener_port: u16,
    }

    const DEFAULT_TCP_LISTENER_MESSAGE: &str = "booted";
    const DEFAULT_TCP_LISTENER_PORT: u16 = 8000;
    const DEFAULT_TCP_LISTENER_TIMEOUT: i32 = 40;

    struct Guest<'a> {
        tmp_dir: TempDir,
        disk_config: &'a dyn DiskConfig,
        fw_path: String,
        network: GuestNetworkConfig,
    }

    // Safe to implement as we know we have no interior mutability
    impl<'a> std::panic::RefUnwindSafe for Guest<'a> {}

    enum DiskType {
        OperatingSystem,
        RawOperatingSystem,
        CloudInit,
    }

    trait DiskConfig {
        fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig);
        fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String;
        fn disk(&self, disk_type: DiskType) -> Option<String>;
    }

    struct UbuntuDiskConfig {
        osdisk_path: String,
        osdisk_raw_path: String,
        cloudinit_path: String,
        image_name: String,
    }

    #[cfg(target_arch = "x86_64")]
    const BIONIC_IMAGE_NAME: &str = "bionic-server-cloudimg-amd64";
    #[cfg(target_arch = "x86_64")]
    const FOCAL_IMAGE_NAME: &str = "focal-server-cloudimg-amd64-custom";
    #[cfg(target_arch = "x86_64")]
    const FOCAL_SGX_IMAGE_NAME: &str = "focal-server-cloudimg-amd64-sgx";
    #[cfg(target_arch = "aarch64")]
    const BIONIC_IMAGE_NAME: &str = "bionic-server-cloudimg-arm64";
    #[cfg(target_arch = "aarch64")]
    const FOCAL_IMAGE_NAME: &str = "focal-server-cloudimg-arm64-custom";

    const DIRECT_KERNEL_BOOT_CMDLINE: &str = "root=/dev/vda1 console=ttyS0 console=hvc0 quiet rw";

    const PIPE_SIZE: i32 = 32 << 20;

    impl UbuntuDiskConfig {
        fn new(image_name: String) -> Self {
            UbuntuDiskConfig {
                image_name,
                osdisk_path: String::new(),
                osdisk_raw_path: String::new(),
                cloudinit_path: String::new(),
            }
        }
    }

    fn handle_child_output(
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

    fn rate_limited_copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
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

    fn clh_command(cmd: &str) -> String {
        env::var("BUILD_TARGET").map_or(
            format!("target/x86_64-unknown-linux-gnu/release/{}", cmd),
            |target| format!("target/{}/release/{}", target, cmd),
        )
    }

    impl DiskConfig for UbuntuDiskConfig {
        fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String {
            let cloudinit_file_path =
                String::from(tmp_dir.path().join("cloudinit").to_str().unwrap());

            let cloud_init_directory = tmp_dir.path().join("cloud-init").join("ubuntu");

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
            user_data_string = user_data_string
                .replace("@TCP_LISTENER_PORT", &network.tcp_listener_port.to_string());

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
            network_config_string =
                network_config_string.replace("192.168.2.3", &network.l2_guest_ip1);
            network_config_string =
                network_config_string.replace("192.168.2.4", &network.l2_guest_ip2);
            network_config_string =
                network_config_string.replace("192.168.2.5", &network.l2_guest_ip3);
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

            let image_name = format!("{}.qcow2", self.image_name);
            let raw_image_name = format!("{}.raw", self.image_name);

            let mut osdisk_base_path = workload_path.clone();
            osdisk_base_path.push(&image_name);

            let mut osdisk_raw_base_path = workload_path;
            osdisk_raw_base_path.push(&raw_image_name);

            let osdisk_path = String::from(tmp_dir.path().join("osdisk.img").to_str().unwrap());
            let osdisk_raw_path =
                String::from(tmp_dir.path().join("osdisk_raw.img").to_str().unwrap());
            let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

            rate_limited_copy(osdisk_base_path, &osdisk_path)
                .expect("copying of OS source disk image failed");
            rate_limited_copy(osdisk_raw_base_path, &osdisk_raw_path)
                .expect("copying of OS source disk raw image failed");

            self.cloudinit_path = cloudinit_path;
            self.osdisk_path = osdisk_path;
            self.osdisk_raw_path = osdisk_raw_path;
        }

        fn disk(&self, disk_type: DiskType) -> Option<String> {
            match disk_type {
                DiskType::OperatingSystem => Some(self.osdisk_path.clone()),
                DiskType::RawOperatingSystem => Some(self.osdisk_raw_path.clone()),
                DiskType::CloudInit => Some(self.cloudinit_path.clone()),
            }
        }
    }

    fn prepare_virtiofsd(
        tmp_dir: &TempDir,
        shared_dir: &str,
        cache: &str,
    ) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut virtiofsd_path = workload_path;
        virtiofsd_path.push("virtiofsd");
        let virtiofsd_path = String::from(virtiofsd_path.to_str().unwrap());

        let virtiofsd_socket_path =
            String::from(tmp_dir.path().join("virtiofs.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(virtiofsd_path.as_str())
            .args(&[format!("--socket-path={}", virtiofsd_socket_path).as_str()])
            .args(&["-o", format!("source={}", shared_dir).as_str()])
            .args(&["-o", format!("cache={}", cache).as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, virtiofsd_socket_path)
    }

    fn prepare_vhost_user_fs_daemon(
        tmp_dir: &TempDir,
        shared_dir: &str,
        _cache: &str,
    ) -> (std::process::Child, String) {
        let virtiofsd_socket_path =
            String::from(tmp_dir.path().join("virtiofs.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(clh_command("vhost_user_fs"))
            .args(&["--shared-dir", shared_dir])
            .args(&["--socket", virtiofsd_socket_path.as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, virtiofsd_socket_path)
    }

    fn prepare_vubd(
        tmp_dir: &TempDir,
        blk_img: &str,
        num_queues: usize,
        rdonly: bool,
        direct: bool,
    ) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut blk_file_path = workload_path;
        blk_file_path.push(blk_img);
        let blk_file_path = String::from(blk_file_path.to_str().unwrap());

        let vubd_socket_path = String::from(tmp_dir.path().join("vub.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(clh_command("cloud-hypervisor"))
            .args(&[
                "--block-backend",
                format!(
                    "path={},socket={},num_queues={},readonly={},direct={}",
                    blk_file_path, vubd_socket_path, num_queues, rdonly, direct
                )
                .as_str(),
            ])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, vubd_socket_path)
    }

    fn temp_vsock_path(tmp_dir: &TempDir) -> String {
        String::from(tmp_dir.path().join("vsock").to_str().unwrap())
    }

    fn temp_api_path(tmp_dir: &TempDir) -> String {
        String::from(
            tmp_dir
                .path()
                .join("cloud-hypervisor.sock")
                .to_str()
                .unwrap(),
        )
    }

    // Creates the directory and returns the path.
    fn temp_snapshot_dir_path(tmp_dir: &TempDir) -> String {
        let snapshot_dir = String::from(tmp_dir.path().join("snapshot").to_str().unwrap());
        std::fs::create_dir(&snapshot_dir).unwrap();
        snapshot_dir
    }

    // Creates the path for direct kernel boot and return the path.
    // For x86_64, this function returns the vmlinux kernel path.
    // For AArch64, this function returns the PE kernel path.
    fn direct_kernel_boot_path() -> Option<PathBuf> {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut kernel_path = workload_path;
        #[cfg(target_arch = "x86_64")]
        kernel_path.push("vmlinux");
        #[cfg(target_arch = "aarch64")]
        kernel_path.push("Image");

        Some(kernel_path)
    }

    fn prepare_vhost_user_net_daemon(
        tmp_dir: &TempDir,
        ip: &str,
        tap: Option<&str>,
        num_queues: usize,
    ) -> (std::process::Child, String) {
        let vunet_socket_path = String::from(tmp_dir.path().join("vunet.sock").to_str().unwrap());

        // Start the daemon
        let net_params = if let Some(tap_str) = tap {
            format!(
                "tap={},ip={},mask=255.255.255.0,socket={},num_queues={},queue_size=1024",
                tap_str, ip, vunet_socket_path, num_queues
            )
        } else {
            format!(
                "ip={},mask=255.255.255.0,socket={},num_queues={},queue_size=1024",
                ip, vunet_socket_path, num_queues
            )
        };

        let child = Command::new(clh_command("cloud-hypervisor"))
            .args(&["--net-backend", net_params.as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, vunet_socket_path)
    }

    fn curl_command(api_socket: &str, method: &str, url: &str, http_body: Option<&str>) {
        let mut curl_args: Vec<&str> =
            ["--unix-socket", api_socket, "-i", "-X", method, url].to_vec();

        if let Some(body) = http_body {
            curl_args.push("-H");
            curl_args.push("Accept: application/json");
            curl_args.push("-H");
            curl_args.push("Content-Type: application/json");
            curl_args.push("-d");
            curl_args.push(body);
        }

        let status = Command::new("curl")
            .args(curl_args)
            .status()
            .expect("Failed to launch curl command");

        assert!(status.success());
    }

    fn remote_command(api_socket: &str, command: &str, arg: Option<&str>) -> bool {
        let mut cmd = Command::new(clh_command("ch-remote"));
        cmd.args(&[&format!("--api-socket={}", api_socket), command]);

        if let Some(arg) = arg {
            cmd.arg(arg);
        }

        cmd.status().expect("Failed to launch ch-remote").success()
    }

    fn remote_command_w_output(
        api_socket: &str,
        command: &str,
        arg: Option<&str>,
    ) -> (bool, Vec<u8>) {
        let mut cmd = Command::new(clh_command("ch-remote"));
        cmd.args(&[&format!("--api-socket={}", api_socket), command]);

        if let Some(arg) = arg {
            cmd.arg(arg);
        }

        let output = cmd.output().expect("Failed to launch ch-remote");

        (output.status.success(), output.stdout)
    }

    fn resize_command(
        api_socket: &str,
        desired_vcpus: Option<u8>,
        desired_ram: Option<usize>,
        desired_balloon: Option<usize>,
    ) -> bool {
        let mut cmd = Command::new(clh_command("ch-remote"));
        cmd.args(&[&format!("--api-socket={}", api_socket), "resize"]);

        if let Some(desired_vcpus) = desired_vcpus {
            cmd.arg(format!("--cpus={}", desired_vcpus));
        }

        if let Some(desired_ram) = desired_ram {
            cmd.arg(format!("--memory={}", desired_ram));
        }

        if let Some(desired_balloon) = desired_balloon {
            cmd.arg(format!("--balloon={}", desired_balloon));
        }

        cmd.status().expect("Failed to launch ch-remote").success()
    }

    fn resize_zone_command(api_socket: &str, id: &str, desired_size: &str) -> bool {
        let mut cmd = Command::new(clh_command("ch-remote"));
        cmd.args(&[
            &format!("--api-socket={}", api_socket),
            "resize-zone",
            &format!("--id={}", id),
            &format!("--size={}", desired_size),
        ]);

        cmd.status().expect("Failed to launch ch-remote").success()
    }

    #[derive(Debug)]
    struct PasswordAuth {
        username: String,
        password: String,
    }

    const DEFAULT_SSH_RETRIES: u8 = 6;
    const DEFAULT_SSH_TIMEOUT: u8 = 10;
    fn ssh_command_ip_with_auth(
        command: &str,
        auth: &PasswordAuth,
        ip: &str,
        retries: u8,
        timeout: u8,
    ) -> Result<String, Error> {
        let mut s = String::new();

        let mut counter = 0;
        loop {
            match (|| -> Result<(), Error> {
                let tcp = TcpStream::connect(format!("{}:22", ip)).map_err(Error::Connection)?;
                let mut sess = Session::new().unwrap();
                sess.set_tcp_stream(tcp);
                sess.handshake().map_err(Error::Handshake)?;

                sess.userauth_password(&auth.username, &auth.password)
                    .map_err(Error::Authentication)?;
                assert!(sess.authenticated());

                let mut channel = sess.channel_session().map_err(Error::ChannelSession)?;
                channel.exec(command).map_err(Error::Command)?;

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
                             \n==== End ssh command outout ====\n\n",
                            command, auth, ip, s
                        );

                        return Err(e);
                    }
                }
            };
            thread::sleep(std::time::Duration::new((timeout * counter).into(), 0));
        }
        Ok(s)
    }

    fn ssh_command_ip(command: &str, ip: &str, retries: u8, timeout: u8) -> Result<String, Error> {
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

    #[derive(Debug)]
    enum Error {
        Connection(std::io::Error),
        Handshake(ssh2::Error),
        Authentication(ssh2::Error),
        ChannelSession(ssh2::Error),
        Command(ssh2::Error),
        Parsing(std::num::ParseIntError),
        EpollWait(std::io::Error),
        EpollWaitTimeout,
        ReadToString(std::io::Error),
        SetReadTimeout(std::io::Error),
        WrongGuestAddr,
        WrongGuestMsg,
    }

    impl std::error::Error for Error {}

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl<'a> Guest<'a> {
        fn new_from_ip_range(disk_config: &'a mut dyn DiskConfig, class: &str, id: u8) -> Self {
            let tmp_dir = TempDir::new("ch").unwrap();

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut fw_path = workload_path;
            #[cfg(target_arch = "aarch64")]
            fw_path.push("Image");
            #[cfg(target_arch = "x86_64")]
            fw_path.push("hypervisor-fw");
            let fw_path = String::from(fw_path.to_str().unwrap());
            let network = GuestNetworkConfig {
                guest_ip: format!("{}.{}.2", class, id),
                l2_guest_ip1: format!("{}.{}.3", class, id),
                l2_guest_ip2: format!("{}.{}.4", class, id),
                l2_guest_ip3: format!("{}.{}.5", class, id),
                host_ip: format!("{}.{}.1", class, id),
                guest_mac: format!("12:34:56:78:90:{:02x}", id),
                l2_guest_mac1: format!("de:ad:be:ef:12:{:02x}", id),
                l2_guest_mac2: format!("de:ad:be:ef:34:{:02x}", id),
                l2_guest_mac3: format!("de:ad:be:ef:56:{:02x}", id),
                tcp_listener_port: DEFAULT_TCP_LISTENER_PORT + id as u16,
            };

            disk_config.prepare_files(&tmp_dir, &network);

            Guest {
                tmp_dir,
                disk_config,
                fw_path,
                network,
            }
        }

        fn new(disk_config: &'a mut dyn DiskConfig) -> Self {
            let mut guard = NEXT_VM_ID.lock().unwrap();
            let id = *guard;
            *guard = id + 1;

            Self::new_from_ip_range(disk_config, "192.168", id)
        }

        fn default_net_string(&self) -> String {
            format!(
                "tap=,mac={},ip={},mask=255.255.255.0",
                self.network.guest_mac, self.network.host_ip
            )
        }

        fn default_net_string_w_iommu(&self) -> String {
            format!(
                "tap=,mac={},ip={},mask=255.255.255.0,iommu=on",
                self.network.guest_mac, self.network.host_ip
            )
        }

        fn ssh_command(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l1(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2_1(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.l2_guest_ip1,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2_2(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.l2_guest_ip2,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2_3(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.l2_guest_ip3,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn api_create_body(&self, cpu_count: u8) -> String {
            #[cfg(target_arch = "x86_64")]
            format! {"{{\"cpus\":{{\"boot_vcpus\":{},\"max_vcpus\":{}}},\"kernel\":{{\"path\":\"{}\"}},\"cmdline\":{{\"args\": \"\"}},\"net\":[{{\"ip\":\"{}\", \"mask\":\"255.255.255.0\", \"mac\":\"{}\"}}], \"disks\":[{{\"path\":\"{}\"}}, {{\"path\":\"{}\"}}]}}",
                     cpu_count,
                     cpu_count,
                     self.fw_path.as_str(),
                     self.network.host_ip,
                     self.network.guest_mac,
                     self.disk_config.disk(DiskType::OperatingSystem).unwrap().as_str(),
                     self.disk_config.disk(DiskType::CloudInit).unwrap().as_str(),
            }
            #[cfg(target_arch = "aarch64")]
            format! {"{{\"cpus\":{{\"boot_vcpus\":{},\"max_vcpus\":{}}},\"kernel\":{{\"path\":\"{}\"}},\"cmdline\":{{\"args\": \"{}\"}},\"net\":[{{\"ip\":\"{}\", \"mask\":\"255.255.255.0\", \"mac\":\"{}\"}}], \"disks\":[{{\"path\":\"{}\"}}, {{\"path\":\"{}\"}}]}}",
                     cpu_count,
                     cpu_count,
                     direct_kernel_boot_path().unwrap().to_str().unwrap(),
                     DIRECT_KERNEL_BOOT_CMDLINE,
                     self.network.host_ip,
                     self.network.guest_mac,
                     self.disk_config.disk(DiskType::OperatingSystem).unwrap().as_str(),
                     self.disk_config.disk(DiskType::CloudInit).unwrap().as_str(),
            }
        }

        fn get_cpu_count(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep -c processor /proc/cpuinfo")?
                .trim()
                .parse()
                .map_err(Error::Parsing)?)
        }

        fn get_initial_apicid(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep \"initial apicid\" /proc/cpuinfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(Error::Parsing)?)
        }

        fn get_total_memory(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(Error::Parsing)?)
        }

        fn get_total_memory_l2(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command_l2_1("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(Error::Parsing)?)
        }

        fn get_numa_node_memory(&self, node_id: usize) -> Result<u32, Error> {
            Ok(self
                .ssh_command(
                    format!(
                        "grep MemTotal /sys/devices/system/node/node{}/meminfo \
                        | cut -d \":\" -f 2 | grep -o \"[0-9]*\"",
                        node_id
                    )
                    .as_str(),
                )?
                .trim()
                .parse()
                .map_err(Error::Parsing)?)
        }

        fn wait_vm_boot(&self, custom_timeout: Option<i32>) -> Result<(), Error> {
            let start = std::time::Instant::now();
            // The 'port' is unique per 'GUEST' and listening to wild-card ip avoids retrying on 'TcpListener::bind()'
            let listen_addr = format!("0.0.0.0:{}", self.network.tcp_listener_port);
            let expected_guest_addr = self.network.guest_ip.as_str();
            let mut s = String::new();
            let timeout = match custom_timeout {
                Some(t) => t,
                None => DEFAULT_TCP_LISTENER_TIMEOUT,
            };

            match (|| -> Result<(), Error> {
                let listener =
                    TcpListener::bind(&listen_addr.as_str()).map_err(Error::Connection)?;
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
                let num_events = epoll::wait(epoll_fd, timeout * 1000 as i32, &mut events[..])
                    .map_err(Error::EpollWait)?;
                if num_events == 0 {
                    return Err(Error::EpollWaitTimeout);
                }

                match listener.accept() {
                    Ok((mut stream, addr)) => {
                        // Make sure the connection is from the expected 'guest_addr'
                        if addr.ip() != std::net::IpAddr::from_str(expected_guest_addr).unwrap() {
                            s = format!(
                                "Expecting the guest ip '{}' while being connected with ip '{}'",
                                expected_guest_addr,
                                addr.ip()
                            );
                            return Err(Error::WrongGuestAddr);
                        }

                        // Make sure the right message is to notify the guest VM is booted
                        let mut data = String::new();
                        stream
                            .set_read_timeout(Some(std::time::Duration::new(timeout as u64, 0)))
                            .map_err(Error::SetReadTimeout)?;
                        stream
                            .read_to_string(&mut data)
                            .map_err(Error::ReadToString)?;
                        if data != DEFAULT_TCP_LISTENER_MESSAGE {
                            s = format!(
                                "Expecting the guest message '{}' while receiving the message '{}'",
                                DEFAULT_TCP_LISTENER_MESSAGE, data
                            );
                            return Err(Error::WrongGuestMsg);
                        };

                        Ok(())
                    }
                    Err(e) => {
                        s = "TcpListener::accept() failed".to_string();
                        Err(Error::Connection(e))
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
                         message =\"{}\"\n\
                         \n==== End 'wait_vm_boot' outout ====\n\n",
                        duration, timeout, listen_addr, expected_guest_addr, s,
                    );

                    Err(e)
                }
                Ok(_) => Ok(()),
            }
        }

        fn check_numa_node_cpus(&self, node_id: usize, cpus: Vec<usize>) -> Result<bool, Error> {
            for cpu in cpus.iter() {
                let cmd = format!(
                    "[ -d \"/sys/devices/system/node/node{}/cpu{}\" ]  && echo ok",
                    node_id, cpu
                );
                if self.ssh_command(cmd.as_str())?.trim() != "ok" {
                    return Ok(false);
                }
            }

            Ok(true)
        }

        fn check_numa_node_distances(
            &self,
            node_id: usize,
            distances: &str,
        ) -> Result<bool, Error> {
            let cmd = format!("cat /sys/devices/system/node/node{}/distance", node_id);
            if self.ssh_command(cmd.as_str())?.trim() == distances {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn check_sgx_support(&self) -> Result<bool, Error> {
            if self
                .ssh_command(
                    "cpuid -l 0x7 -s 0 | tr -s [:space:] | grep -q 'SGX: \
                    Software Guard Extensions supported = true' && echo ok",
                )?
                .trim()
                != "ok"
            {
                return Ok(false);
            }
            if self
                .ssh_command(
                    "cpuid -l 0x7 -s 0 | tr -s [:space:] | grep -q 'SGX_LC: \
                    SGX launch config supported = true' && echo ok",
                )?
                .trim()
                != "ok"
            {
                return Ok(false);
            }
            if self
                .ssh_command(
                    "cpuid -l 0x12 -s 0 | tr -s [:space:] | grep -q 'SGX1 \
                    supported = true' && echo ok",
                )?
                .trim()
                != "ok"
            {
                return Ok(false);
            }

            Ok(true)
        }

        fn get_entropy(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("cat /proc/sys/kernel/random/entropy_avail")?
                .trim()
                .parse()
                .map_err(Error::Parsing)?)
        }

        fn get_pci_bridge_class(&self) -> Result<String, Error> {
            Ok(self
                .ssh_command("cat /sys/bus/pci/devices/0000:00:00.0/class")?
                .trim()
                .to_string())
        }

        fn get_pci_device_ids(&self) -> Result<String, Error> {
            Ok(self
                .ssh_command("cat /sys/bus/pci/devices/*/device")?
                .trim()
                .to_string())
        }

        fn get_pci_vendor_ids(&self) -> Result<String, Error> {
            Ok(self
                .ssh_command("cat /sys/bus/pci/devices/*/vendor")?
                .trim()
                .to_string())
        }

        fn does_device_vendor_pair_match(
            &self,
            device_id: &str,
            vendor_id: &str,
        ) -> Result<bool, Error> {
            // We are checking if console device's device id and vendor id pair matches
            let devices = self.get_pci_device_ids()?;
            let devices: Vec<&str> = devices.split('\n').collect();
            let vendors = self.get_pci_vendor_ids()?;
            let vendors: Vec<&str> = vendors.split('\n').collect();

            for (index, d_id) in devices.iter().enumerate() {
                if *d_id == device_id {
                    if let Some(v_id) = vendors.get(index) {
                        if *v_id == vendor_id {
                            return Ok(true);
                        }
                    }
                }
            }

            Ok(false)
        }

        fn valid_virtio_fs_cache_size(
            &self,
            dax: bool,
            cache_size: Option<u64>,
        ) -> Result<bool, Error> {
            let shm_region = self
                .ssh_command("sudo grep virtio-pci-shm /proc/iomem")?
                .trim()
                .to_string();

            if shm_region.is_empty() {
                return Ok(!dax);
            }

            // From this point, the region is not empty, hence it is an error
            // if DAX is off.
            if !dax {
                return Ok(false);
            }

            let cache = if let Some(cache) = cache_size {
                cache
            } else {
                // 8Gib by default
                0x0002_0000_0000
            };

            let args: Vec<&str> = shm_region.split(':').collect();
            if args.is_empty() {
                return Ok(false);
            }

            let args: Vec<&str> = args[0].trim().split('-').collect();
            if args.len() != 2 {
                return Ok(false);
            }

            let start_addr = u64::from_str_radix(args[0], 16).map_err(Error::Parsing)?;
            let end_addr = u64::from_str_radix(args[1], 16).map_err(Error::Parsing)?;

            Ok(cache == (end_addr - start_addr + 1))
        }

        fn check_vsock(&self, socket: &str) {
            // Listen from guest on vsock CID=3 PORT=16
            // SOCKET-LISTEN:<domain>:<protocol>:<local-address>
            let guest_ip = self.network.guest_ip.clone();
            let listen_socat = thread::spawn(move || {
                ssh_command_ip("sudo socat - SOCKET-LISTEN:40:0:x00x00x10x00x00x00x03x00x00x00x00x00x00x00 > vsock_log", &guest_ip, DEFAULT_SSH_RETRIES, DEFAULT_SSH_TIMEOUT).unwrap();
            });

            // Make sure socat is listening, which might take a few second on slow systems
            thread::sleep(std::time::Duration::new(10, 0));

            // Write something to vsock from the host
            Command::new("bash")
                .arg("-c")
                .arg(
                    format!(
                        "echo -e \"CONNECT 16\\nHelloWorld!\" | socat - UNIX-CONNECT:{}",
                        socket
                    )
                    .as_str(),
                )
                .output()
                .unwrap();

            // Wait for the thread to terminate.
            listen_socat.join().unwrap();

            assert_eq!(
                self.ssh_command("cat vsock_log").unwrap().trim(),
                "HelloWorld!"
            );
        }
    }

    struct GuestCommand<'a> {
        command: Command,
        guest: &'a Guest<'a>,
        capture_output: bool,
    }

    impl<'a> GuestCommand<'a> {
        fn new(guest: &'a Guest) -> Self {
            Self::new_with_binary_name(guest, "cloud-hypervisor")
        }

        fn new_with_binary_name(guest: &'a Guest, binary_name: &str) -> Self {
            Self {
                command: Command::new(clh_command(binary_name)),
                guest,
                capture_output: false,
            }
        }

        fn capture_output(&mut self) -> &mut Self {
            self.capture_output = true;
            self
        }

        fn spawn(&mut self) -> io::Result<Child> {
            println!(
                "\n\n==== Start cloud-hypervisor command-line ====\n\n\
                 {:?}\n\
                 \n==== End cloud-hypervisor command-line ====\n\n",
                self.command
            );

            if self.capture_output {
                let child = self
                    .command
                    .arg("-v")
                    .stderr(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();

                let fd = child.stdout.as_ref().unwrap().as_raw_fd();
                let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
                let fd = child.stderr.as_ref().unwrap().as_raw_fd();
                let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

                if pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE {
                    Ok(child)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "resizing pipe w/ 'fnctl' failed!",
                    ))
                }
            } else {
                self.command.arg("-v").spawn()
            }
        }

        fn args<I, S>(&mut self, args: I) -> &mut Self
        where
            I: IntoIterator<Item = S>,
            S: AsRef<OsStr>,
        {
            self.command.args(args);
            self
        }

        fn default_disks(&mut self) -> &mut Self {
            self.args(&[
                "--disk",
                format!(
                    "path={}",
                    self.guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    self.guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
            ])
        }

        fn default_raw_disks(&mut self) -> &mut Self {
            self.args(&[
                "--disk",
                format!(
                    "path={}",
                    self.guest
                        .disk_config
                        .disk(DiskType::RawOperatingSystem)
                        .unwrap()
                )
                .as_str(),
                format!(
                    "path={}",
                    self.guest.disk_config.disk(DiskType::CloudInit).unwrap()
                )
                .as_str(),
            ])
        }

        fn default_net(&mut self) -> &mut Self {
            self.args(&["--net", self.guest.default_net_string().as_str()])
        }
    }

    fn test_cpu_topology(threads_per_core: u8, cores_per_package: u8, packages: u8) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);
        let total_vcpus = threads_per_core * cores_per_package * packages;
        let mut child = GuestCommand::new(&guest)
            .args(&[
                "--cpus",
                &format!(
                    "boot={},topology={}:{}:1:{}",
                    total_vcpus, threads_per_core, cores_per_package, packages
                ),
            ])
            .args(&["--memory", "size=512M"])
            .args(&["--kernel", guest.fw_path.as_str()])
            .default_disks()
            .default_net()
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot(None).unwrap();
            assert_eq!(
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(total_vcpus)
            );
            assert_eq!(
                guest
                    .ssh_command("lscpu | grep \"per core\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u8>()
                    .unwrap_or(0),
                threads_per_core
            );

            assert_eq!(
                guest
                    .ssh_command("lscpu | grep \"per socket\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u8>()
                    .unwrap_or(0),
                cores_per_package
            );

            assert_eq!(
                guest
                    .ssh_command("lscpu | grep \"Socket\" | cut -f 2 -d \":\" | sed \"s# *##\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u8>()
                    .unwrap_or(0),
                packages
            );
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    type PrepareNetDaemon =
        dyn Fn(&TempDir, &str, Option<&str>, usize) -> (std::process::Child, String);

    fn test_vhost_user_net(
        tap: Option<&str>,
        num_queues: usize,
        prepare_vhost_user_net_daemon: Option<&PrepareNetDaemon>,
        self_spawned: bool,
        generate_host_mac: bool,
    ) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let kernel_path = direct_kernel_boot_path().unwrap();

        let host_mac = if generate_host_mac {
            Some(MacAddr::local_random())
        } else {
            None
        };

        let (net_params, daemon_child) = if self_spawned {
            (
                    format!(
                        "vhost_user=true,mac={},ip={},mask=255.255.255.0,num_queues={},queue_size=1024{}",
                        guest.network.guest_mac, guest.network.host_ip, num_queues,
                        if let Some(host_mac) =host_mac {
                            format!(",host_mac={}", host_mac)
                        } else {
                            "".to_owned()
                        }
                    ),
                    None,
                )
        } else {
            let prepare_daemon = prepare_vhost_user_net_daemon.unwrap();
            // Start the daemon
            let (daemon_child, vunet_socket_path) =
                prepare_daemon(&guest.tmp_dir, &guest.network.host_ip, tap, num_queues);

            (
                format!(
                    "vhost_user=true,mac={},socket={},num_queues={},queue_size=1024{}",
                    guest.network.guest_mac,
                    vunet_socket_path,
                    num_queues,
                    if let Some(host_mac) = host_mac {
                        format!(",host_mac={}", host_mac)
                    } else {
                        "".to_owned()
                    }
                ),
                Some(daemon_child),
            )
        };

        let mut child = GuestCommand::new(&guest)
            .args(&["--cpus", format!("boot={}", num_queues / 2).as_str()])
            .args(&["--memory", "size=512M,hotplug_size=2048M,shared=on"])
            .args(&["--kernel", kernel_path.to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(&["--net", net_params.as_str()])
            .args(&["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot(None).unwrap();

            if let Some(tap_name) = tap {
                let tap_count = std::process::Command::new("bash")
                    .arg("-c")
                    .arg(format!("ip link | grep -c {}", tap_name))
                    .output()
                    .expect("Expected checking of tap count to succeed");
                assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");
            }

            if let Some(host_mac) = tap {
                let mac_count = std::process::Command::new("bash")
                    .arg("-c")
                    .arg(format!("ip link | grep -c {}", host_mac))
                    .output()
                    .expect("Expected checking of host mac to succeed");
                assert_eq!(String::from_utf8_lossy(&mac_count.stdout).trim(), "1");
            }

            // 1 network interface + default localhost ==> 2 interfaces
            // It's important to note that this test is fully exercising the
            // vhost-user-net implementation and the associated backend since
            // it does not define any --net network interface. That means all
            // the ssh communication in that test happens through the network
            // interface backed by vhost-user-net.
            assert_eq!(
                guest
                    .ssh_command("ip -o link | wc -l")
                    .unwrap_or_default()
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
            #[cfg(target_arch = "x86_64")]
            let grep_cmd = "grep -c PCI-MSI /proc/interrupts";
            #[cfg(target_arch = "aarch64")]
            let grep_cmd = "grep -c ITS-MSI /proc/interrupts";
            assert_eq!(
                guest
                    .ssh_command(grep_cmd)
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                10 + (num_queues as u32)
            );

            // ACPI feature is needed.
            #[cfg(feature = "acpi")]
            {
                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));

                // Here by simply checking the size (through ssh), we validate
                // the connection is still working, which means vhost-user-net
                // keeps working after the resize.
                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
            }
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        if let Some(mut daemon_child) = daemon_child {
            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();
        }

        handle_child_output(r, &output);
    }

    type PrepareBlkDaemon =
        dyn Fn(&TempDir, &str, usize, bool, bool) -> (std::process::Child, String);

    fn test_vhost_user_blk(
        num_queues: usize,
        readonly: bool,
        direct: bool,
        prepare_vhost_user_blk_daemon: Option<&PrepareBlkDaemon>,
        self_spawned: bool,
    ) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let kernel_path = direct_kernel_boot_path().unwrap();

        let (blk_params, daemon_child) = if self_spawned {
            let mut blk_file_path = workload_path;
            blk_file_path.push("blk.img");
            let blk_file_path = String::from(blk_file_path.to_str().unwrap());

            (
                format!(
                    "vhost_user=true,path={},num_queues={},queue_size=128",
                    blk_file_path, num_queues,
                ),
                None,
            )
        } else {
            let prepare_daemon = prepare_vhost_user_blk_daemon.unwrap();
            // Start the daemon
            let (daemon_child, vubd_socket_path) =
                prepare_daemon(&guest.tmp_dir, "blk.img", num_queues, readonly, direct);

            (
                format!(
                    "vhost_user=true,socket={},num_queues={},queue_size=128",
                    vubd_socket_path, num_queues,
                ),
                Some(daemon_child),
            )
        };

        let mut child = GuestCommand::new(&guest)
            .args(&["--cpus", format!("boot={}", num_queues).as_str()])
            .args(&["--memory", "size=512M,hotplug_size=2048M,shared=on"])
            .args(&["--kernel", kernel_path.to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(&[
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
            .args(&["--api-socket", &api_socket])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot(None).unwrap();

            // Check both if /dev/vdc exists and if the block size is 16M.
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Check if this block is RO or RW.
            assert_eq!(
                guest
                    .ssh_command("lsblk | grep vdc | awk '{print $5}'")
                    .unwrap_or_default()
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
                    .unwrap_or_default()
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
                    format!(
                        "sudo mount -o {} -t ext4 /dev/vdc mount_image/",
                        mount_ro_rw_flag
                    )
                    .as_str(),
                )
                .unwrap();

            // Check the content of the block device. The file "foo" should
            // contain "bar".
            assert_eq!(
                guest
                    .ssh_command("cat mount_image/foo")
                    .unwrap_or_default()
                    .trim(),
                "bar"
            );

            // ACPI feature is needed.
            #[cfg(feature = "acpi")]
            {
                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));

                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

                // Check again the content of the block device after the resize
                // has been performed.
                assert_eq!(
                    guest
                        .ssh_command("cat mount_image/foo")
                        .unwrap_or_default()
                        .trim(),
                    "bar"
                );
            }

            // Unmount the device
            guest.ssh_command("sudo umount /dev/vdc").unwrap();
            guest.ssh_command("rm -r mount_image").unwrap();
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        if let Some(mut daemon_child) = daemon_child {
            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();
        }

        handle_child_output(r, &output);
    }

    fn test_boot_from_vhost_user_blk(
        num_queues: usize,
        readonly: bool,
        direct: bool,
        prepare_vhost_user_blk_daemon: Option<&PrepareBlkDaemon>,
        self_spawned: bool,
    ) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let kernel_path = direct_kernel_boot_path().unwrap();

        let disk_path = guest
            .disk_config
            .disk(DiskType::RawOperatingSystem)
            .unwrap();

        let (blk_boot_params, daemon_child) = if self_spawned {
            (
                format!(
                    "vhost_user=true,path={},num_queues={},queue_size=128",
                    disk_path, num_queues,
                ),
                None,
            )
        } else {
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
                    "vhost_user=true,socket={},num_queues={},queue_size=128",
                    vubd_socket_path, num_queues,
                ),
                Some(daemon_child),
            )
        };

        let mut child = GuestCommand::new(&guest)
            .args(&["--cpus", format!("boot={}", num_queues).as_str()])
            .args(&["--memory", "size=512M,shared=on"])
            .args(&["--kernel", kernel_path.to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(&[
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
            guest.wait_vm_boot(None).unwrap();

            // Just check the VM booted correctly.
            assert_eq!(guest.get_cpu_count().unwrap_or_default(), num_queues as u32);
            assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

            if self_spawned {
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1);

                assert_eq!(reboot_count, 0);
                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);
            }
        });
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        if let Some(mut daemon_child) = daemon_child {
            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();
        }

        handle_child_output(r, &output);
    }

    fn test_virtio_fs(
        dax: bool,
        cache_size: Option<u64>,
        virtiofsd_cache: &str,
        prepare_daemon: &dyn Fn(&TempDir, &str, &str) -> (std::process::Child, String),
        hotplug: bool,
    ) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut shared_dir = workload_path;
        shared_dir.push("shared_dir");

        let kernel_path = direct_kernel_boot_path().unwrap();

        let (dax_vmm_param, dax_mount_param) = if dax { ("on", "-o dax") } else { ("off", "") };
        let cache_size_vmm_param = if let Some(cache) = cache_size {
            format!(",cache_size={}", cache)
        } else {
            "".to_string()
        };

        let (mut daemon_child, virtiofsd_socket_path) = prepare_daemon(
            &guest.tmp_dir,
            shared_dir.to_str().unwrap(),
            virtiofsd_cache,
        );

        let mut guest_command = GuestCommand::new(&guest);
        guest_command
            .args(&["--cpus", "boot=1"])
            .args(&["--memory", "size=512M,hotplug_size=2048M,shared=on"])
            .args(&["--kernel", kernel_path.to_str().unwrap()])
            .default_disks()
            .default_net()
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .args(&["--api-socket", &api_socket]);

        let fs_params = format!(
            "id=myfs0,tag=myfs,socket={},num_queues=1,queue_size=1024,dax={}{}",
            virtiofsd_socket_path, dax_vmm_param, cache_size_vmm_param
        );

        if !hotplug {
            guest_command.args(&["--fs", fs_params.as_str()]);
        }

        let mut child = guest_command.capture_output().spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot(None).unwrap();

            if hotplug {
                // Add fs to the VM
                let (cmd_success, cmd_output) =
                    remote_command_w_output(&api_socket, "add-fs", Some(&fs_params));
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"myfs0\",\"bdf\":\"0000:00:06.0\"}"));

                thread::sleep(std::time::Duration::new(10, 0));
            }

            // Mount shared directory through virtio_fs filesystem
            let mount_cmd = format!(
                "mkdir -p mount_dir && \
                 sudo mount -t virtiofs {} myfs mount_dir/ && \
                 echo ok",
                dax_mount_param
            );
            assert_eq!(
                guest.ssh_command(&mount_cmd).unwrap_or_default().trim(),
                "ok"
            );

            assert_eq!(
                guest
                    .valid_virtio_fs_cache_size(dax, cache_size)
                    .unwrap_or_default(),
                true
            );
            // Check file1 exists and its content is "foo"
            assert_eq!(
                guest
                    .ssh_command("cat mount_dir/file1")
                    .unwrap_or_default()
                    .trim(),
                "foo"
            );
            // Check file2 does not exist
            assert_ne!(
                guest
                    .ssh_command("ls mount_dir/file2")
                    .unwrap_or_default()
                    .trim(),
                "mount_dir/file2"
            );
            // Check file3 exists and its content is "bar"
            assert_eq!(
                guest
                    .ssh_command("cat mount_dir/file3")
                    .unwrap_or_default()
                    .trim(),
                "bar"
            );

            // ACPI feature is needed.
            #[cfg(feature = "acpi")]
            {
                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

                // After the resize, check again that file1 exists and its
                // content is "foo".
                assert_eq!(
                    guest
                        .ssh_command("cat mount_dir/file1")
                        .unwrap_or_default()
                        .trim(),
                    "foo"
                );
            }

            if hotplug {
                // Remove from VM
                assert_eq!(
                    guest
                        .ssh_command("sudo umount mount_dir && echo ok")
                        .unwrap_or_default()
                        .trim(),
                    "ok"
                );
                assert!(remote_command(&api_socket, "remove-device", Some("myfs0")));
            }
        });

        let (r, hotplug_daemon_child) = if r.is_ok() && hotplug {
            thread::sleep(std::time::Duration::new(10, 0));
            let (daemon_child, virtiofsd_socket_path) = prepare_daemon(
                &guest.tmp_dir,
                shared_dir.to_str().unwrap(),
                virtiofsd_cache,
            );

            let r = std::panic::catch_unwind(|| {
                thread::sleep(std::time::Duration::new(10, 0));
                let fs_params = format!(
                    "id=myfs0,tag=myfs,socket={},num_queues=1,queue_size=1024,dax={}{}",
                    virtiofsd_socket_path, dax_vmm_param, cache_size_vmm_param
                );

                // Add back and check it works
                let (cmd_success, cmd_output) =
                    remote_command_w_output(&api_socket, "add-fs", Some(&fs_params));
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"myfs0\",\"bdf\":\"0000:00:06.0\"}"));
                thread::sleep(std::time::Duration::new(10, 0));
                // Mount shared directory through virtio_fs filesystem
                let mount_cmd = format!(
                    "mkdir -p mount_dir && \
                     sudo mount -t virtiofs {} myfs mount_dir/ && \
                     echo ok",
                    dax_mount_param
                );
                assert_eq!(
                    guest.ssh_command(&mount_cmd).unwrap_or_default().trim(),
                    "ok"
                );
                // Check file1 exists and its content is "foo"
                assert_eq!(
                    guest
                        .ssh_command("cat mount_dir/file1")
                        .unwrap_or_default()
                        .trim(),
                    "foo"
                );
            });

            (r, Some(daemon_child))
        } else {
            (r, None)
        };

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        let _ = daemon_child.kill();
        let _ = daemon_child.wait();

        if let Some(mut daemon_child) = hotplug_daemon_child {
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();
        }

        handle_child_output(r, &output);
    }

    fn test_virtio_pmem(discard_writes: bool, specify_size: bool) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let kernel_path = direct_kernel_boot_path().unwrap();

        let mut pmem_temp_file = NamedTempFile::new().unwrap();
        pmem_temp_file.as_file_mut().set_len(128 << 20).unwrap();

        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.path())
            .output()
            .expect("Expect creating disk image to succeed");

        let mut child = GuestCommand::new(&guest)
            .args(&["--cpus", "boot=1"])
            .args(&["--memory", "size=512M"])
            .args(&["--kernel", kernel_path.to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
            .args(&[
                "--pmem",
                format!(
                    "file={}{}{}",
                    pmem_temp_file.path().to_str().unwrap(),
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
            guest.wait_vm_boot(None).unwrap();

            // Check for the presence of /dev/pmem0
            assert_eq!(
                guest
                    .ssh_command("ls /dev/pmem0")
                    .unwrap_or_default()
                    .trim(),
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

            guest.ssh_command("sudo reboot").unwrap();
            guest.wait_vm_boot(None).unwrap();
            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            assert_eq!(reboot_count, 1);
            assert_eq!(guest.ssh_command("sudo mount /dev/pmem0 /mnt").unwrap(), "");
            assert_eq!(
                guest
                    .ssh_command("sudo cat /mnt/test")
                    .unwrap_or_default()
                    .trim(),
                if discard_writes { "" } else { "test123" }
            );
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    fn get_fd_count(pid: u32) -> usize {
        fs::read_dir(format!("/proc/{}/fd", pid)).unwrap().count()
    }

    fn _test_virtio_vsock(hotplug: bool) {
        let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(&mut focal);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let kernel_path = direct_kernel_boot_path().unwrap();

        let socket = temp_vsock_path(&guest.tmp_dir);
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut cmd = GuestCommand::new(&guest);
        cmd.args(&["--api-socket", &api_socket]);
        cmd.args(&["--cpus", "boot=1"]);
        cmd.args(&["--memory", "size=512M"]);
        cmd.args(&["--kernel", kernel_path.to_str().unwrap()]);
        cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);
        cmd.default_disks();
        cmd.default_net();

        if !hotplug {
            cmd.args(&["--vsock", format!("cid=3,socket={}", socket).as_str()]);
        }

        let mut child = cmd.capture_output().spawn().unwrap();

        let r = std::panic::catch_unwind(|| {
            guest.wait_vm_boot(None).unwrap();

            if hotplug {
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-vsock",
                    Some(format!("cid=3,socket={},id=test0", socket).as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}"));
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

            // AArch64 currently does not support reboot, and therefore we
            // skip the reboot test here.
            #[cfg(target_arch = "x86_64")]
            {
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1);

                assert_eq!(reboot_count, 0);
                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                // Validate vsock still works after a reboot.
                guest.check_vsock(socket.as_str());
            }
            if hotplug {
                assert!(remote_command(&api_socket, "remove-device", Some("test0")));
            }
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    fn get_pss(pid: u32) -> u32 {
        let smaps = fs::File::open(format!("/proc/{}/smaps", pid)).unwrap();
        let reader = io::BufReader::new(smaps);

        let mut total = 0;
        for line in reader.lines() {
            let l = line.unwrap();
            // Lines look like this:
            // Pss:                 176 kB
            if l.contains("Pss") {
                let values: Vec<&str> = l.rsplit(' ').collect();
                total += values[1].trim().parse::<u32>().unwrap()
            }
        }
        total
    }

    fn test_memory_mergeable(mergeable: bool) {
        let memory_param = if mergeable {
            "mergeable=on"
        } else {
            "mergeable=off"
        };

        let mut focal1 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let mut focal2 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

        let guest1 = Guest::new(&mut focal1 as &mut dyn DiskConfig);

        let mut child1 = GuestCommand::new(&guest1)
            .args(&["--cpus", "boot=1"])
            .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
            .args(&["--kernel", guest1.fw_path.as_str()])
            .default_disks()
            .args(&["--net", guest1.default_net_string().as_str()])
            .args(&["--serial", "tty", "--console", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        // Let enough time for the first VM to be spawned, and to make
        // sure the PSS measurement is accurate.
        thread::sleep(std::time::Duration::new(120, 0));

        // Get initial PSS
        let old_pss = get_pss(child1.id());

        let guest2 = Guest::new(&mut focal2 as &mut dyn DiskConfig);

        let mut child2 = GuestCommand::new(&guest2)
            .args(&["--cpus", "boot=1"])
            .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
            .args(&["--kernel", guest2.fw_path.as_str()])
            .default_disks()
            .args(&["--net", guest2.default_net_string().as_str()])
            .args(&["--serial", "tty", "--console", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        // Let enough time for the second VM to be spawned, and to make
        // sure KSM has enough time to merge identical pages between the
        // 2 VMs.
        thread::sleep(std::time::Duration::new(60, 0));
        let r = std::panic::catch_unwind(|| {
            // Get new PSS
            let new_pss = get_pss(child1.id());

            // Convert PSS from u32 into float.
            let old_pss = old_pss as f32;
            let new_pss = new_pss as f32;

            println!("old PSS {}, new PSS {}", old_pss, new_pss);

            if mergeable {
                assert!(new_pss < (old_pss * 0.95));
            } else {
                assert!((old_pss * 0.95) < new_pss && new_pss < (old_pss * 1.05));
            }
        });

        let _ = child1.kill();
        let _ = child2.kill();

        let output = child1.wait_with_output().unwrap();
        child2.wait().unwrap();

        handle_child_output(r, &output);
    }

    fn _get_vmm_overhead(pid: u32, guest_memory_size: u32) -> HashMap<String, u32> {
        let smaps = fs::File::open(format!("/proc/{}/smaps", pid)).unwrap();
        let reader = io::BufReader::new(smaps);

        let mut skip_map: bool = false;
        let mut region_name: String = "".to_string();
        let mut region_maps = HashMap::new();
        for line in reader.lines() {
            let l = line.unwrap();

            if l.contains('-') {
                let values: Vec<&str> = l.split_whitespace().collect();
                region_name = values.last().unwrap().trim().to_string();
                if region_name == "0" {
                    region_name = "anonymous".to_string()
                }
            }

            // Each section begins with something that looks like:
            // Size:               2184 kB
            if l.starts_with("Size:") {
                let values: Vec<&str> = l.split_whitespace().collect();
                let map_size = values[1].parse::<u32>().unwrap();
                // We skip the assigned guest RAM map, its RSS is only
                // dependent on the guest actual memory usage.
                // Everything else can be added to the VMM overhead.
                skip_map = map_size >= guest_memory_size;
                continue;
            }

            // If this is a map we're taking into account, then we only
            // count the RSS. The sum of all counted RSS is the VMM overhead.
            if !skip_map && l.starts_with("Rss:") {
                let values: Vec<&str> = l.split_whitespace().collect();
                let value = values[1].trim().parse::<u32>().unwrap();
                *region_maps.entry(region_name.clone()).or_insert(0) += value;
            }
        }

        region_maps
    }

    fn get_vmm_overhead(pid: u32, guest_memory_size: u32) -> u32 {
        let mut total = 0;

        for (region_name, value) in &_get_vmm_overhead(pid, guest_memory_size) {
            eprintln!("{}: {}", region_name, value);
            total += value;
        }

        total
    }

    // 10MB is our maximum accepted overhead.
    const MAXIMUM_VMM_OVERHEAD_KB: u32 = 10 * 1024;

    #[derive(PartialEq, PartialOrd)]
    struct Counters {
        rx_bytes: u64,
        rx_frames: u64,
        tx_bytes: u64,
        tx_frames: u64,
        read_bytes: u64,
        write_bytes: u64,
        read_ops: u64,
        write_ops: u64,
    }

    fn get_counters(api_socket: &str) -> Counters {
        // Get counters
        let (cmd_success, cmd_output) = remote_command_w_output(&api_socket, "counters", None);
        assert!(cmd_success);

        let counters: HashMap<&str, HashMap<&str, u64>> =
            serde_json::from_slice(&cmd_output).unwrap_or_default();

        let rx_bytes = *counters.get("_net2").unwrap().get("rx_bytes").unwrap();
        let rx_frames = *counters.get("_net2").unwrap().get("rx_frames").unwrap();
        let tx_bytes = *counters.get("_net2").unwrap().get("tx_bytes").unwrap();
        let tx_frames = *counters.get("_net2").unwrap().get("tx_frames").unwrap();

        let read_bytes = *counters.get("_disk0").unwrap().get("read_bytes").unwrap();
        let write_bytes = *counters.get("_disk0").unwrap().get("write_bytes").unwrap();
        let read_ops = *counters.get("_disk0").unwrap().get("read_ops").unwrap();
        let write_ops = *counters.get("_disk0").unwrap().get("write_ops").unwrap();

        Counters {
            rx_bytes,
            rx_frames,
            tx_bytes,
            tx_frames,
            read_bytes,
            read_ops,
            write_bytes,
            write_ops,
        }
    }

    mod parallel {
        use crate::tests::*;

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_simple_launch() {
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

            vec![
                &mut bionic as &mut dyn DiskConfig,
                &mut focal as &mut dyn DiskConfig,
            ]
            .iter_mut()
            .for_each(|disk_config| {
                let guest = Guest::new(*disk_config);

                let mut child = GuestCommand::new(&guest)
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", guest.fw_path.as_str()])
                    .default_raw_disks()
                    .default_net()
                    .args(&["--serial", "tty", "--console", "off"])
                    .capture_output()
                    .spawn()
                    .unwrap();

                let r = std::panic::catch_unwind(|| {
                    guest.wait_vm_boot(Some(120)).unwrap();

                    assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                    assert_eq!(guest.get_initial_apicid().unwrap_or(1), 0);
                    assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                    assert!(guest.get_entropy().unwrap_or_default() >= 900);
                    assert_eq!(guest.get_pci_bridge_class().unwrap_or_default(), "0x060000");
                });

                let _ = child.kill();
                let output = child.wait_with_output().unwrap();

                handle_child_output(r, &output);
            });
        }

        #[test]
        fn test_multi_cpu() {
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut bionic);
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .capture_output()
                .default_raw_disks()
                .default_net();

            #[cfg(target_arch = "aarch64")]
            cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

            let mut child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(Some(120)).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);

                #[cfg(target_arch = "x86_64")]
                assert_eq!(
                    guest
                        .ssh_command(
                            r#"dmesg | grep "smpboot: Allowing" | sed "s/\[\ *[0-9.]*\] //""#
                        )
                        .unwrap_or_default()
                        .trim(),
                    "smpboot: Allowing 4 CPUs, 2 hotplug CPUs"
                );
                #[cfg(target_arch = "aarch64")]
                assert_eq!(
                    guest
                        .ssh_command(
                            r#"dmesg | grep "smp: Brought up" | sed "s/\[\ *[0-9.]*\] //""#
                        )
                        .unwrap_or_default()
                        .trim(),
                    "smp: Brought up 1 node, 2 CPUs"
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_cpu_topology_421() {
            test_cpu_topology(4, 2, 1);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_cpu_topology_142() {
            test_cpu_topology(1, 4, 2);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_cpu_topology_262() {
            test_cpu_topology(2, 6, 2);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_cpu_physical_bits() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let max_phys_bits: u8 = 36;
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", &format!("max_phys_bits={}", max_phys_bits)])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert!(
                    guest
                        .ssh_command("lscpu | grep \"Address sizes:\" | cut -f 2 -d \":\" | sed \"s# *##\" | cut -f 1 -d \" \"")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u8>()
                        .unwrap_or(max_phys_bits + 1) <= max_phys_bits,
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_large_vm() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=48"])
                .args(&["--memory", "size=5120M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .capture_output()
                .default_disks()
                .default_net();

            // Now AArch64 can only boot from direct kernel, command-line is needed.
            #[cfg(target_arch = "aarch64")]
            cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

            let mut child = cmd.spawn().unwrap();

            guest.wait_vm_boot(None).unwrap();

            let r = std::panic::catch_unwind(|| {
                assert!(guest.get_total_memory().unwrap_or_default() > 5_000_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_huge_memory() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=128G"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .capture_output()
                .default_disks()
                .default_net();

            // Now AArch64 can only boot from direct kernel, command-line is needed.
            #[cfg(target_arch = "aarch64")]
            cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

            let mut child = cmd.spawn().unwrap();

            guest.wait_vm_boot(Some(120)).unwrap();

            let r = std::panic::catch_unwind(|| {
                assert!(guest.get_total_memory().unwrap_or_default() > 128_000_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_user_defined_memory_regions() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=0,hotplug_method=virtio-mem"])
                .args(&[
                    "--memory-zone",
                    "id=mem0,size=1G,hotplug_size=2G",
                    "id=mem1,size=1G,file=/dev/shm",
                    "id=mem2,size=1G,host_numa_node=0,hotplug_size=2G",
                ])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert!(guest.get_total_memory().unwrap_or_default() > 2_880_000);

                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                resize_zone_command(&api_socket, "mem0", "3G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 4_800_000);
                resize_zone_command(&api_socket, "mem2", "3G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 6_720_000);
                resize_zone_command(&api_socket, "mem0", "2G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);
                resize_zone_command(&api_socket, "mem2", "2G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 4_800_000);

                guest.ssh_command("sudo reboot").unwrap();
                guest.wait_vm_boot(None).unwrap();
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                // Check the amount of RAM after reboot
                assert!(guest.get_total_memory().unwrap_or_default() > 4_800_000);
                assert!(guest.get_total_memory().unwrap_or_default() < 5_760_000);

                // Check if we can still resize down to the initial 'boot'size
                resize_zone_command(&api_socket, "mem0", "1G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() < 4_800_000);
                resize_zone_command(&api_socket, "mem2", "1G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_total_memory().unwrap_or_default() < 3_840_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_guest_numa_nodes() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=6"])
                .args(&["--memory", "size=0,hotplug_method=virtio-mem"])
                .args(&[
                    "--memory-zone",
                    "id=mem0,size=1G,hotplug_size=3G",
                    "id=mem1,size=2G,hotplug_size=3G",
                    "id=mem2,size=3G,hotplug_size=3G",
                ])
                .args(&[
                    "--numa",
                    "guest_numa_id=0,cpus=0-2,distances=1@15:2@20,memory_zones=mem0",
                    "guest_numa_id=1,cpus=3-4,distances=0@20:2@25,memory_zones=mem1",
                    "guest_numa_id=2,cpus=5,distances=0@25:1@30,memory_zones=mem2",
                ])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check each NUMA node has been assigned the right amount of
                // memory.
                assert!(guest.get_numa_node_memory(0).unwrap_or_default() > 960_000);
                assert!(guest.get_numa_node_memory(1).unwrap_or_default() > 1_920_000);
                assert!(guest.get_numa_node_memory(2).unwrap_or_default() > 2_880_000);

                // Check each NUMA node has been assigned the right CPUs set.
                assert!(guest.check_numa_node_cpus(0, vec![0, 1, 2]).unwrap());
                assert!(guest.check_numa_node_cpus(1, vec![3, 4]).unwrap());
                assert!(guest.check_numa_node_cpus(2, vec![5]).unwrap());

                // Check each NUMA node has been assigned the right distances.
                assert!(guest.check_numa_node_distances(0, "10 15 20").unwrap());
                assert!(guest.check_numa_node_distances(1, "20 10 25").unwrap());
                assert!(guest.check_numa_node_distances(2, "25 30 10").unwrap());

                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Resize every memory zone and check each associated NUMA node
                // has been assigned the right amount of memory.
                resize_zone_command(&api_socket, "mem0", "4G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_numa_node_memory(0).unwrap_or_default() > 3_840_000);
                resize_zone_command(&api_socket, "mem1", "4G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_numa_node_memory(1).unwrap_or_default() > 3_840_000);
                resize_zone_command(&api_socket, "mem2", "4G");
                thread::sleep(std::time::Duration::new(5, 0));
                assert!(guest.get_numa_node_memory(2).unwrap_or_default() > 3_840_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_pci_msi() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .capture_output()
                .default_disks()
                .default_net();

            #[cfg(target_arch = "aarch64")]
            cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

            let mut child = cmd.spawn().unwrap();

            guest.wait_vm_boot(None).unwrap();

            #[cfg(target_arch = "x86_64")]
            let grep_cmd = "grep -c PCI-MSI /proc/interrupts";
            #[cfg(target_arch = "aarch64")]
            let grep_cmd = "grep -c ITS-MSI /proc/interrupts";

            let r = std::panic::catch_unwind(|| {
                assert_eq!(
                    guest
                        .ssh_command(grep_cmd)
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    12
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vmlinux_boot() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);

                assert_eq!(
                    guest
                        .ssh_command("grep -c PCI-MSI /proc/interrupts")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    12
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "aarch64")]
        fn test_aarch64_pe_boot() {
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

            vec![
                &mut bionic as &mut dyn DiskConfig,
                &mut focal as &mut dyn DiskConfig,
            ]
            .iter_mut()
            .for_each(|disk_config| {
                let guest = Guest::new(*disk_config);

                let mut workload_path = dirs::home_dir().unwrap();
                workload_path.push("workloads");

                let kernel_path = direct_kernel_boot_path().unwrap();

                let mut child = GuestCommand::new(&guest)
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", kernel_path.to_str().unwrap()])
                    .default_disks()
                    .default_net()
                    .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                    .args(&["--seccomp", "false"])
                    .capture_output()
                    .spawn()
                    .unwrap();

                let r = std::panic::catch_unwind(|| {
                    guest.wait_vm_boot(Some(120)).unwrap();

                    assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                    assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                    assert!(guest.get_entropy().unwrap_or_default() >= 900);
                });

                let _ = child.kill();
                let output = child.wait_with_output().unwrap();

                handle_child_output(r, &output);
            });
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_pvh_boot() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux.pvh");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);

                assert_eq!(
                    guest
                        .ssh_command("grep -c PCI-MSI /proc/interrupts")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    12
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_bzimage_boot() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);

                assert_eq!(
                    guest
                        .ssh_command("grep -c PCI-MSI /proc/interrupts")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    12
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_virtio_blk() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut blk_file_path = workload_path;
            blk_file_path.push("blk.img");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=512M,shared=on"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .args(&[
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
                    format!(
                        "path={},readonly=on,direct=on,num_queues=4",
                        blk_file_path.to_str().unwrap()
                    )
                    .as_str(),
                ])
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check both if /dev/vdc exists and if the block size is 16M.
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                // Check both if /dev/vdc exists and if this block is RO.
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | awk '{print $5}'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                // Check if the number of queues is 4.
                assert_eq!(
                    guest
                        .ssh_command("ls -ll /sys/block/vdc/mq | grep ^d | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    4
                );
            });

            let _ = cloud_child.kill();
            let output = cloud_child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_vhost_user_net_default() {
            test_vhost_user_net(None, 2, Some(&prepare_vhost_user_net_daemon), false, false)
        }

        #[test]
        fn test_vhost_user_net_named_tap() {
            test_vhost_user_net(
                Some("mytap0"),
                2,
                Some(&prepare_vhost_user_net_daemon),
                false,
                false,
            )
        }

        #[test]
        fn test_vhost_user_net_existing_tap() {
            test_vhost_user_net(
                Some("vunet-tap0"),
                2,
                Some(&prepare_vhost_user_net_daemon),
                false,
                false,
            )
        }

        #[test]
        fn test_vhost_user_net_multiple_queues() {
            test_vhost_user_net(None, 4, Some(&prepare_vhost_user_net_daemon), false, false)
        }

        #[test]
        fn test_vhost_user_net_tap_multiple_queues() {
            test_vhost_user_net(
                Some("vunet-tap1"),
                4,
                Some(&prepare_vhost_user_net_daemon),
                false,
                false,
            )
        }

        #[test]
        fn test_vhost_user_net_self_spawning() {
            test_vhost_user_net(None, 4, None, true, false)
        }

        #[test]
        fn test_vhost_user_net_self_spawning_host_mac() {
            test_vhost_user_net(None, 2, None, true, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vhost_user_net_host_mac() {
            test_vhost_user_net(None, 2, None, true, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vhost_user_blk_default() {
            test_vhost_user_blk(2, false, false, Some(&prepare_vubd), false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vhost_user_blk_self_spawning() {
            test_vhost_user_blk(1, false, false, None, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vhost_user_blk_readonly() {
            test_vhost_user_blk(1, true, false, Some(&prepare_vubd), false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vhost_user_blk_direct() {
            test_vhost_user_blk(1, false, true, Some(&prepare_vubd), false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_boot_from_vhost_user_blk_default() {
            test_boot_from_vhost_user_blk(1, false, false, Some(&prepare_vubd), false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_boot_from_vhost_user_blk_self_spawning() {
            test_boot_from_vhost_user_blk(1, false, false, None, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_split_irqchip() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(
                    guest
                        .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'timer'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );
                assert_eq!(
                    guest
                        .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'cascade'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_virtio_fs_dax_on_default_cache_size() {
            test_virtio_fs(true, None, "none", &prepare_virtiofsd, false)
        }

        #[test]
        fn test_virtio_fs_dax_on_cache_size_1_gib() {
            test_virtio_fs(true, Some(0x4000_0000), "none", &prepare_virtiofsd, false)
        }

        #[test]
        fn test_virtio_fs_dax_off() {
            test_virtio_fs(false, None, "none", &prepare_virtiofsd, false)
        }

        #[test]
        fn test_virtio_fs_dax_on_default_cache_size_w_vhost_user_fs_daemon() {
            test_virtio_fs(true, None, "none", &prepare_vhost_user_fs_daemon, false)
        }

        #[test]
        fn test_virtio_fs_dax_on_cache_size_1_gib_w_vhost_user_fs_daemon() {
            test_virtio_fs(
                true,
                Some(0x4000_0000),
                "none",
                &prepare_vhost_user_fs_daemon,
                false,
            )
        }

        #[test]
        fn test_virtio_fs_dax_off_w_vhost_user_fs_daemon() {
            test_virtio_fs(false, None, "none", &prepare_vhost_user_fs_daemon, false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_fs_hotplug_dax_on() {
            test_virtio_fs(true, None, "none", &prepare_virtiofsd, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_fs_hotplug_dax_off() {
            test_virtio_fs(false, None, "none", &prepare_virtiofsd, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_fs_hotplug_dax_on_w_vhost_user_fs_daemon() {
            test_virtio_fs(true, None, "none", &prepare_vhost_user_fs_daemon, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_fs_hotplug_dax_off_w_vhost_user_fs_daemon() {
            test_virtio_fs(false, None, "none", &prepare_vhost_user_fs_daemon, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_pmem_persist_writes() {
            test_virtio_pmem(false, false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_pmem_discard_writes() {
            test_virtio_pmem(true, false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_pmem_with_size() {
            test_virtio_pmem(true, true)
        }

        #[test]
        fn test_boot_from_virtio_pmem() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    format!(
                        "path={}",
                        guest.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str(),
                ])
                .default_net()
                .args(&[
                    "--pmem",
                    format!(
                        "file={},size={}",
                        guest
                            .disk_config
                            .disk(DiskType::RawOperatingSystem)
                            .unwrap(),
                        fs::metadata(
                            &guest
                                .disk_config
                                .disk(DiskType::RawOperatingSystem)
                                .unwrap()
                        )
                        .unwrap()
                        .len()
                    )
                    .as_str(),
                ])
                .args(&[
                    "--cmdline",
                    DIRECT_KERNEL_BOOT_CMDLINE
                        .replace("vda1", "pmem0p1")
                        .as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Simple checks to validate the VM booted properly
                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_multiple_network_interfaces() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&[
                    "--net",
                    guest.default_net_string().as_str(),
                    "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.0",
                    "tap=mytap1,mac=fe:1f:9e:e1:60:f2,ip=192.168.4.1,mask=255.255.255.0",
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                let tap_count = std::process::Command::new("bash")
                    .arg("-c")
                    .arg("ip link | grep -c mytap1")
                    .output()
                    .expect("Expected checking of tap count to succeed");
                assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");

                // 3 network interfaces + default localhost ==> 4 interfaces
                assert_eq!(
                    guest
                        .ssh_command("ip -o link | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    4
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_serial_off() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&[
                    "--cmdline",
                    DIRECT_KERNEL_BOOT_CMDLINE
                        .replace("console=ttyS0 ", "")
                        .as_str(),
                ])
                .args(&["--serial", "off"])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Test that there is no ttyS0
                assert_eq!(
                    guest
                        .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_serial_null() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&["--serial", "null"])
                .args(&["--console", "off"])
                .capture_output();

            // Now AArch64 can only boot from direct kernel, command-line is needed.
            #[cfg(target_arch = "aarch64")]
            cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

            let mut child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                #[cfg(target_arch = "x86_64")]
                // Test that there is a ttyS0
                assert_eq!(
                    guest
                        .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                assert!(!String::from_utf8_lossy(&output.stdout).contains("cloud login:"));
            });

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_serial_tty() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Test that there is a ttyS0
                assert_eq!(
                    guest
                        .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );
            });

            // This sleep is needed to wait for the login prompt
            thread::sleep(std::time::Duration::new(2, 0));

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                assert!(String::from_utf8_lossy(&output.stdout).contains("cloud login:"));
            });

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_serial_file() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let serial_path = guest.tmp_dir.path().join("/tmp/serial-output");
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&[
                    "--serial",
                    format!("file={}", serial_path.to_str().unwrap()).as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Test that there is a ttyS0
                assert_eq!(
                    guest
                        .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                guest.ssh_command("sudo shutdown -h now").unwrap();
            });

            let _ = child.wait_timeout(std::time::Duration::from_secs(20));
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                // Check that the cloud-hypervisor binary actually terminated
                assert_eq!(output.status.success(), true);

                // Do this check after shutdown of the VM as an easy way to ensure
                // all writes are flushed to disk
                let mut f = std::fs::File::open(serial_path).unwrap();
                let mut buf = String::new();
                f.read_to_string(&mut buf).unwrap();
                assert!(buf.contains("cloud login:"));
            });

            handle_child_output(r, &output);
        }

        #[test]
        fn test_virtio_console() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--console", "tty"])
                .args(&["--serial", "null"])
                .capture_output()
                .spawn()
                .unwrap();

            let text = String::from("On a branch floating down river a cricket, singing.");
            let cmd = format!("echo {} | sudo tee /dev/hvc0", text);

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                #[cfg(feature = "acpi")]
                assert!(guest
                    .does_device_vendor_pair_match("0x1043", "0x1af4")
                    .unwrap_or_default());

                guest.ssh_command(&cmd).unwrap();
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                assert!(String::from_utf8_lossy(&output.stdout).contains(&text));
            });

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_console_file() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let console_path = guest.tmp_dir.path().join("/tmp/console-output");
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&[
                    "--console",
                    format!("file={}", console_path.to_str().unwrap()).as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            guest.wait_vm_boot(None).unwrap();

            guest.ssh_command("sudo shutdown -h now").unwrap();

            let _ = child.wait_timeout(std::time::Duration::from_secs(20));
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            let r = std::panic::catch_unwind(|| {
                // Check that the cloud-hypervisor binary actually terminated
                assert_eq!(output.status.success(), true);

                // Do this check after shutdown of the VM as an easy way to ensure
                // all writes are flushed to disk
                let mut f = std::fs::File::open(console_path).unwrap();
                let mut buf = String::new();
                f.read_to_string(&mut buf).unwrap();
                assert!(buf.contains("cloud login:"));
            });

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        // The VFIO integration test starts cloud-hypervisor guest with 3 TAP
        // backed networking interfaces, bound through a simple bridge on the host.
        // So if the nested cloud-hypervisor succeeds in getting a directly
        // assigned interface from its cloud-hypervisor host, we should be able to
        // ssh into it, and verify that it's running with the right kernel command
        // line (We tag the command line from cloud-hypervisor for that purpose).
        // The third device is added to validate that hotplug works correctly since
        // it is being added to the L2 VM through hotplugging mechanism.
        fn test_vfio() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new_from_ip_range(&mut focal, "172.17", 0);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path.clone();
            kernel_path.push("bzImage");

            let mut vfio_path = workload_path.clone();
            vfio_path.push("vfio");

            let mut cloud_init_vfio_base_path = vfio_path.clone();
            cloud_init_vfio_base_path.push("cloudinit.img");

            // We copy our cloudinit into the vfio mount point, for the nested
            // cloud-hypervisor guest to use.
            rate_limited_copy(
                &guest.disk_config.disk(DiskType::CloudInit).unwrap(),
                &cloud_init_vfio_base_path,
            )
            .expect("copying of cloud-init disk failed");

            let mut vfio_disk_path = workload_path;
            vfio_disk_path.push("vfio.img");

            // Create the vfio disk image
            let output = Command::new("mkfs.ext4")
                .arg("-d")
                .arg(vfio_path.to_str().unwrap())
                .arg(vfio_disk_path.to_str().unwrap())
                .arg("2g")
                .output()
                .unwrap();
            if !output.status.success() {
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
                panic!("mkfs.ext4 command generated an error");
            }

            let vfio_tap0 = "vfio-tap0";
            let vfio_tap1 = "vfio-tap1";
            let vfio_tap2 = "vfio-tap2";
            let vfio_tap3 = "vfio-tap3";

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=2G,hugepages=on,shared=on"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
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
                    format!("path={}", vfio_disk_path.to_str().unwrap()).as_str(),
                ])
                .args(&[
                    "--cmdline",
                    format!(
                        "{} kvm-intel.nested=1 vfio_iommu_type1.allow_unsafe_interrupts",
                        DIRECT_KERNEL_BOOT_CMDLINE
                    )
                    .as_str(),
                ])
                .args(&[
                    "--net",
                    format!("tap={},mac={}", vfio_tap0, guest.network.guest_mac).as_str(),
                    format!(
                        "tap={},mac={},iommu=on",
                        vfio_tap1, guest.network.l2_guest_mac1
                    )
                    .as_str(),
                    format!(
                        "tap={},mac={},iommu=on",
                        vfio_tap2, guest.network.l2_guest_mac2
                    )
                    .as_str(),
                    format!(
                        "tap={},mac={},iommu=on",
                        vfio_tap3, guest.network.l2_guest_mac3
                    )
                    .as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(30, 0));

            let r = std::panic::catch_unwind(|| {
                guest.ssh_command_l1("sudo systemctl start vfio").unwrap();
                thread::sleep(std::time::Duration::new(120, 0));

                // We booted our cloud hypervisor L2 guest with a "VFIOTAG" tag
                // added to its kernel command line.
                // Let's ssh into it and verify that it's there. If it is it means
                // we're in the right guest (The L2 one) because the QEMU L1 guest
                // does not have this command line tag.
                assert_eq!(
                    guest
                        .ssh_command_l2_1("grep -c VFIOTAG /proc/cmdline")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                // Let's also verify from the second virtio-net device passed to
                // the L2 VM.
                assert_eq!(
                    guest
                        .ssh_command_l2_2("grep -c VFIOTAG /proc/cmdline")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                // Check the amount of PCI devices appearing in L2 VM.
                assert_eq!(
                    guest
                        .ssh_command_l2_1("ls /sys/bus/pci/devices | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    7,
                );

                // Hotplug an extra virtio-net device through L2 VM.
                guest.ssh_command_l1(
                    "echo 0000:00:08.0 | sudo tee /sys/bus/pci/devices/0000:00:08.0/driver/unbind",
                ).unwrap();
                guest
                    .ssh_command_l1(
                        "echo 1af4 1041 | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id",
                    )
                    .unwrap();
                let vfio_hotplug_output = guest
                    .ssh_command_l1(
                        "sudo /mnt/ch-remote \
                 --api-socket=/tmp/ch_api.sock \
                 add-device path=/sys/bus/pci/devices/0000:00:08.0,id=vfio123",
                    )
                    .unwrap();
                assert!(
                    vfio_hotplug_output.contains("{\"id\":\"vfio123\",\"bdf\":\"0000:00:07.0\"}")
                );

                thread::sleep(std::time::Duration::new(10, 0));

                // Let's also verify from the third virtio-net device passed to
                // the L2 VM. This third device has been hotplugged through the L2
                // VM, so this is our way to validate hotplug works for VFIO PCI.
                assert_eq!(
                    guest
                        .ssh_command_l2_3("grep -c VFIOTAG /proc/cmdline")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                // Check the amount of PCI devices appearing in L2 VM.
                // There should be one more device than before, raising the count
                // up to 8 PCI devices.
                assert_eq!(
                    guest
                        .ssh_command_l2_1("ls /sys/bus/pci/devices | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    8,
                );

                // Let's now verify that we can correctly remove the virtio-net
                // device through the "remove-device" command responsible for
                // unplugging VFIO devices.
                guest
                    .ssh_command_l1(
                        "sudo /mnt/ch-remote \
                 --api-socket=/tmp/ch_api.sock \
                 remove-device vfio123",
                    )
                    .unwrap();
                thread::sleep(std::time::Duration::new(10, 0));

                // Check the amount of PCI devices appearing in L2 VM is back down
                // to 7 devices.
                assert_eq!(
                    guest
                        .ssh_command_l2_1("ls /sys/bus/pci/devices | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    7,
                );

                // Perform memory hotplug in L2 and validate the memory is showing
                // up as expected. In order to check, we will use the virtio-net
                // device already passed through L2 as a VFIO device, this will
                // verify that VFIO devices are functional with memory hotplug.
                assert!(guest.get_total_memory_l2().unwrap_or_default() > 480_000);
                guest.ssh_command_l2_1(
                    "sudo bash -c 'echo online > /sys/devices/system/memory/auto_online_blocks'",
                ).unwrap();
                guest
                    .ssh_command_l1(
                        "sudo /mnt/ch-remote \
                 --api-socket=/tmp/ch_api.sock \
                 resize --memory=1073741824",
                    )
                    .unwrap();
                assert!(guest.get_total_memory_l2().unwrap_or_default() > 960_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_vmlinux_boot_noacpi() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&[
                    "--cmdline",
                    format!("{} acpi=off", DIRECT_KERNEL_BOOT_CMDLINE).as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_reboot() {
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

            vec![
                &mut bionic as &mut dyn DiskConfig,
                &mut focal as &mut dyn DiskConfig,
            ]
            .iter_mut()
            .for_each(|disk_config| {
                let guest = Guest::new(*disk_config);

                let mut cmd = GuestCommand::new(&guest);
                cmd.args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", guest.fw_path.as_str()])
                    .default_raw_disks()
                    .default_net()
                    .capture_output();

                #[cfg(target_arch = "aarch64")]
                cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

                let mut child = cmd.spawn().unwrap();

                let r = std::panic::catch_unwind(|| {
                    guest.wait_vm_boot(Some(120)).unwrap();

                    let reboot_count = guest
                        .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1);
                    let fd_count_1 = get_fd_count(child.id());

                    assert_eq!(reboot_count, 0);
                    guest.ssh_command("sudo reboot").unwrap_or_default();

                    guest.wait_vm_boot(Some(120)).unwrap();

                    let reboot_count = guest
                        .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default();
                    let fd_count_2 = get_fd_count(child.id());
                    assert_eq!(reboot_count, 1);
                    assert_eq!(fd_count_1, fd_count_2);

                    guest
                        .ssh_command("sudo shutdown -h now")
                        .unwrap_or_default();
                });

                let _ = child.wait_timeout(std::time::Duration::from_secs(40));
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                handle_child_output(r, &output);

                let r = std::panic::catch_unwind(|| {
                    // Check that the cloud-hypervisor binary actually terminated
                    assert_eq!(output.status.success(), true);
                });

                handle_child_output(r, &output);
            });
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_bzimage_reboot() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1);
                let fd_count_1 = get_fd_count(child.id());

                assert_eq!(reboot_count, 0);
                guest.ssh_command("sudo reboot").unwrap();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                let fd_count_2 = get_fd_count(child.id());
                assert_eq!(reboot_count, 1);
                assert_eq!(fd_count_1, fd_count_2);

                guest.ssh_command("sudo shutdown -h now").unwrap();
            });

            let _ = child.wait_timeout(std::time::Duration::from_secs(20));
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                // Check that the cloud-hypervisor binary actually terminated
                assert_eq!(output.status.success(), true);
            });

            handle_child_output(r, &output);
        }

        #[test]
        fn test_virtio_vsock() {
            _test_virtio_vsock(false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_vsock_hotplug() {
            _test_virtio_vsock(true);
        }

        #[test]
        // Start cloud-hypervisor with no VM parameters, only the API server running.
        // From the API: Create a VM, boot it and check that it looks as expected.
        fn test_api_create_boot() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(1, 0));

            // Verify API server is running
            curl_command(&api_socket, "GET", "http://localhost/api/v1/vmm.ping", None);

            // Create the VM first
            let cpu_count: u8 = 4;
            let http_body = guest.api_create_body(cpu_count);
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.create",
                Some(&http_body),
            );

            // Then boot it
            curl_command(&api_socket, "PUT", "http://localhost/api/v1/vm.boot", None);
            thread::sleep(std::time::Duration::new(20, 0));

            let r = std::panic::catch_unwind(|| {
                // Check that the VM booted as expected
                assert_eq!(guest.get_cpu_count().unwrap_or_default() as u8, cpu_count);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        // Start cloud-hypervisor with no VM parameters, only the API server running.
        // From the API: Create a VM, boot it and check that it looks as expected.
        // Then we pause the VM, check that it's no longer available.
        // Finally we resume the VM and check that it's available.
        fn test_api_pause_resume() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(1, 0));

            // Verify API server is running
            curl_command(&api_socket, "GET", "http://localhost/api/v1/vmm.ping", None);

            // Create the VM first
            let cpu_count: u8 = 4;
            let http_body = guest.api_create_body(cpu_count);
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.create",
                Some(&http_body),
            );

            // Then boot it
            curl_command(&api_socket, "PUT", "http://localhost/api/v1/vm.boot", None);
            thread::sleep(std::time::Duration::new(20, 0));

            let r = std::panic::catch_unwind(|| {
                // Check that the VM booted as expected
                assert_eq!(guest.get_cpu_count().unwrap_or_default() as u8, cpu_count);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);

                // We now pause the VM
                assert!(remote_command(&api_socket, "pause", None));

                // Check pausing again fails
                assert!(!remote_command(&api_socket, "pause", None));

                thread::sleep(std::time::Duration::new(2, 0));

                // SSH into the VM should fail
                assert!(ssh_command_ip(
                    "grep -c processor /proc/cpuinfo",
                    &guest.network.guest_ip,
                    2,
                    5
                )
                .is_err());

                // Resume the VM
                assert!(remote_command(&api_socket, "resume", None));

                // Check resuming again fails
                assert!(!remote_command(&api_socket, "resume", None));

                thread::sleep(std::time::Duration::new(2, 0));

                // Now we should be able to SSH back in and get the right number of CPUs
                assert_eq!(guest.get_cpu_count().unwrap_or_default() as u8, cpu_count);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        // This test validates that it can find the virtio-iommu device at first.
        // It also verifies that both disks and the network card are attached to
        // the virtual IOMMU by looking at /sys/kernel/iommu_groups directory.
        // The last interesting part of this test is that it exercises the network
        // interface attached to the virtual IOMMU since this is the one used to
        // send all commands through SSH.
        fn test_virtio_iommu() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
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
                .args(&["--net", guest.default_net_string_w_iommu().as_str()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Verify the virtio-iommu device is present.
                assert!(guest
                    .does_device_vendor_pair_match("0x1057", "0x1af4")
                    .unwrap_or_default());

                // Verify the first disk is located under IOMMU group 0.
                assert_eq!(
                    guest
                        .ssh_command("ls /sys/kernel/iommu_groups/0/devices")
                        .unwrap()
                        .trim(),
                    "0000:00:02.0"
                );

                // Verify the second disk is located under IOMMU group 1.
                assert_eq!(
                    guest
                        .ssh_command("ls /sys/kernel/iommu_groups/1/devices")
                        .unwrap()
                        .trim(),
                    "0000:00:03.0"
                );

                // Verify the network card is located under IOMMU group 2.
                assert_eq!(
                    guest
                        .ssh_command("ls /sys/kernel/iommu_groups/2/devices")
                        .unwrap()
                        .trim(),
                    "0000:00:04.0"
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        // We cannot force the software running in the guest to reprogram the BAR
        // with some different addresses, but we have a reliable way of testing it
        // with a standard Linux kernel.
        // By removing a device from the PCI tree, and then rescanning the tree,
        // Linux consistently chooses to reorganize the PCI device BARs to other
        // locations in the guest address space.
        // This test creates a dedicated PCI network device to be checked as being
        // properly probed first, then removing it, and adding it again by doing a
        // rescan.
        fn test_pci_bar_reprogramming() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .args(&[
                    "--net",
                    guest.default_net_string().as_str(),
                    "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.0",
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r =
                std::panic::catch_unwind(|| {
                    guest.wait_vm_boot(None).unwrap();

                    // 2 network interfaces + default localhost ==> 3 interfaces
                    assert_eq!(
                        guest
                            .ssh_command("ip -o link | wc -l")
                            .unwrap_or_default()
                            .trim()
                            .parse::<u32>()
                            .unwrap_or_default(),
                        3
                    );

                    let init_bar_addr = guest.ssh_command(
                    "sudo awk '{print $1; exit}' /sys/bus/pci/devices/0000:00:05.0/resource",
                ).unwrap();

                    // Remove the PCI device
                    guest
                        .ssh_command("echo 1 | sudo tee /sys/bus/pci/devices/0000:00:05.0/remove")
                        .unwrap();

                    // Only 1 network interface left + default localhost ==> 2 interfaces
                    assert_eq!(
                        guest
                            .ssh_command("ip -o link | wc -l")
                            .unwrap_or_default()
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
                            .unwrap_or_default()
                            .trim()
                            .parse::<u32>()
                            .unwrap_or_default(),
                        3
                    );

                    let new_bar_addr = guest.ssh_command(
                    "sudo awk '{print $1; exit}' /sys/bus/pci/devices/0000:00:05.0/resource",
                ).unwrap();

                    // Let's compare the BAR addresses for our virtio-net device.
                    // They should be different as we expect the BAR reprogramming
                    // to have happened.
                    assert_ne!(init_bar_addr, new_bar_addr);
                });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_memory_mergeable_off() {
            test_memory_mergeable(false)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_cpu_hotplug() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);

                // Resize the VM
                let desired_vcpus = 4;
                resize_command(&api_socket, Some(desired_vcpus), None, None);

                guest
                    .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")
                    .unwrap();
                guest
                    .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")
                    .unwrap();
                thread::sleep(std::time::Duration::new(10, 0));
                assert_eq!(
                    guest.get_cpu_count().unwrap_or_default(),
                    u32::from(desired_vcpus)
                );

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1);

                assert_eq!(reboot_count, 0);
                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                assert_eq!(
                    guest.get_cpu_count().unwrap_or_default(),
                    u32::from(desired_vcpus)
                );

                // Resize the VM
                let desired_vcpus = 2;
                resize_command(&api_socket, Some(desired_vcpus), None, None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert_eq!(
                    guest.get_cpu_count().unwrap_or_default(),
                    u32::from(desired_vcpus)
                );

                // Resize the VM back up to 4
                let desired_vcpus = 4;
                resize_command(&api_socket, Some(desired_vcpus), None, None);

                guest
                    .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")
                    .unwrap();
                guest
                    .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")
                    .unwrap();
                thread::sleep(std::time::Duration::new(10, 0));
                assert_eq!(
                    guest.get_cpu_count().unwrap_or_default(),
                    u32::from(desired_vcpus)
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_memory_hotplug() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M,hotplug_size=8192M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--balloon", "size=0"])
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

                // Use balloon to remove RAM from the VM
                let desired_balloon = 512 << 20;
                resize_command(&api_socket, None, None, Some(desired_balloon));

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_total_memory().unwrap_or_default() < 960_000);

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1);

                assert_eq!(reboot_count, 0);
                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                assert!(guest.get_total_memory().unwrap_or_default() < 960_000);

                // Use balloon add RAM to the VM
                let desired_balloon = 0;
                resize_command(&api_socket, None, None, Some(desired_balloon));

                thread::sleep(std::time::Duration::new(10, 0));

                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Add RAM to the VM
                let desired_ram = 2048 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 1_920_000);

                // Remove RAM to the VM (only applies after reboot)
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 2);

                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
                assert!(guest.get_total_memory().unwrap_or_default() < 1_920_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_mem() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&[
                    "--memory",
                    "size=512M,hotplug_method=virtio-mem,hotplug_size=8192M",
                ])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

                // Add RAM to the VM
                let desired_ram = 2048 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 1_920_000);

                // Remove RAM from the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
                assert!(guest.get_total_memory().unwrap_or_default() < 1_920_000);

                guest.ssh_command("sudo reboot").unwrap();
                guest.wait_vm_boot(None).unwrap();
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                // Check the amount of memory after reboot is 1GiB
                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
                assert!(guest.get_total_memory().unwrap_or_default() < 1_920_000);

                // Check we can still resize to 512MiB
                let desired_ram = 512 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);
                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_total_memory().unwrap_or_default() < 960_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        // Test both vCPU and memory resizing together
        fn test_resize() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M,hotplug_size=8192M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 2);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);

                guest
                    .ssh_command(
                        "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
                    )
                    .unwrap_or_default();

                // Resize the VM
                let desired_vcpus = 4;
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, Some(desired_vcpus), Some(desired_ram), None);

                guest
                    .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")
                    .unwrap();
                guest
                    .ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")
                    .unwrap();
                thread::sleep(std::time::Duration::new(10, 0));
                assert_eq!(
                    guest.get_cpu_count().unwrap_or_default(),
                    u32::from(desired_vcpus)
                );

                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_memory_overhead() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let guest_memory_size_kb = 512 * 1024;

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&[
                    "--memory",
                    format!("size={}K", guest_memory_size_kb).as_str(),
                ])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            let r = std::panic::catch_unwind(|| {
                let overhead = get_vmm_overhead(child.id(), guest_memory_size_kb);
                eprintln!(
                    "Guest memory overhead: {} vs {}",
                    overhead, MAXIMUM_VMM_OVERHEAD_KB
                );
                assert!(overhead <= MAXIMUM_VMM_OVERHEAD_KB);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_disk_hotplug() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check /dev/vdc is not there
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                // Now let's add the extra disk.
                let mut blk_file_path = dirs::home_dir().unwrap();
                blk_file_path.push("workloads");
                blk_file_path.push("blk.img");
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-disk",
                    Some(format!("path={},id=test0", blk_file_path.to_str().unwrap()).as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}"));

                thread::sleep(std::time::Duration::new(10, 0));

                // Check that /dev/vdc exists and the block size is 16M.
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );
                // And check the block device can be read.
                assert!(guest
                    .ssh_command("dd if=/dev/vdc of=/dev/null bs=1M iflag=direct count=16")
                    .is_ok());

                // Let's remove it the extra disk.
                assert!(remote_command(&api_socket, "remove-device", Some("test0")));
                thread::sleep(std::time::Duration::new(5, 0));
                // And check /dev/vdc is not there
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                // And add it back to validate unplug did work correctly.
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-disk",
                    Some(format!("path={},id=test0", blk_file_path.to_str().unwrap()).as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}"));

                thread::sleep(std::time::Duration::new(10, 0));

                // Check that /dev/vdc exists and the block size is 16M.
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );
                // And check the block device can be read.
                assert!(guest
                    .ssh_command("dd if=/dev/vdc of=/dev/null bs=1M iflag=direct count=16")
                    .is_ok());

                // Reboot the VM.
                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                // Check still there after reboot
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
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
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 2);

                // Check device still absent
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep vdc | grep -c 16M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_pmem_hotplug() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check /dev/pmem0 is not there
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep -c pmem0")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                let mut pmem_temp_file = NamedTempFile::new().unwrap();
                pmem_temp_file.as_file_mut().set_len(128 << 20).unwrap();
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-pmem",
                    Some(&format!(
                        "file={},id=test0",
                        pmem_temp_file.path().to_str().unwrap()
                    )),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}"));

                // Check that /dev/pmem0 exists and the block size is 128M
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                // Check still there after reboot
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                        .unwrap_or_default()
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
                        .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 2);

                // Check still absent after reboot
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_net_hotplug() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path().unwrap();

            let api_socket = temp_api_path(&guest.tmp_dir);

            // Boot without network
            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            let r = std::panic::catch_unwind(|| {
                // Add network
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-net",
                    Some(guest.default_net_string().as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"_net2\",\"bdf\":\"0000:00:05.0\"}"));

                thread::sleep(std::time::Duration::new(5, 0));

                // 1 network interfaces + default localhost ==> 2 interfaces
                assert_eq!(
                    guest
                        .ssh_command("ip -o link | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );

                // Remove network
                assert!(remote_command(&api_socket, "remove-device", Some("_net2")));
                thread::sleep(std::time::Duration::new(5, 0));

                // Add network again
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-net",
                    Some(guest.default_net_string().as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"_net3\",\"bdf\":\"0000:00:05.0\"}"));

                thread::sleep(std::time::Duration::new(5, 0));

                // 1 network interfaces + default localhost ==> 2 interfaces
                assert_eq!(
                    guest
                        .ssh_command("ip -o link | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );

                guest.ssh_command("sudo reboot").unwrap_or_default();

                guest.wait_vm_boot(None).unwrap();

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(reboot_count, 1);

                // Check still there after reboot
                // 1 network interfaces + default localhost ==> 2 interfaces
                assert_eq!(
                    guest
                        .ssh_command("ip -o link | wc -l")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_initramfs() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernels = vec![];
            kernels.push(direct_kernel_boot_path().unwrap());

            #[cfg(target_arch = "x86_64")]
            {
                let mut pvh_kernel_path = workload_path.clone();
                pvh_kernel_path.push("vmlinux.pvh");
                kernels.push(pvh_kernel_path);
            }

            let mut initramfs_path = workload_path;
            initramfs_path.push("alpine_initramfs.img");

            let test_string = String::from("axz34i9rylotd8n50wbv6kcj7f2qushme1pg");
            let cmdline = format!("console=hvc0 quiet TEST_STRING={}", test_string);

            kernels.iter().for_each(|k_path| {
                let mut child = GuestCommand::new(&guest)
                    .args(&["--kernel", k_path.to_str().unwrap()])
                    .args(&["--initramfs", initramfs_path.to_str().unwrap()])
                    .args(&["--cmdline", &cmdline])
                    .capture_output()
                    .spawn()
                    .unwrap();

                thread::sleep(std::time::Duration::new(20, 0));

                let _ = child.kill();
                let output = child.wait_with_output().unwrap();

                let r = std::panic::catch_unwind(|| {
                    let s = String::from_utf8_lossy(&output.stdout);

                    assert_ne!(s.lines().position(|line| line == test_string), None);
                });

                handle_child_output(r, &output);
            });
        }

        // One thing to note about this test. The virtio-net device is heavily used
        // through each ssh command. There's no need to perform a dedicated test to
        // verify the migration went well for virtio-net.
        #[test]
        fn test_snapshot_restore() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            #[cfg(target_arch = "x86_64")]
            kernel_path.push("bzImage");
            #[cfg(target_arch = "aarch64")]
            kernel_path.push("Image");

            let api_socket = temp_api_path(&guest.tmp_dir);

            let net_id = "net123";
            let net_params = format!(
                "id={},tap=,mac={},ip={},mask=255.255.255.0",
                net_id, guest.network.guest_mac, guest.network.host_ip
            );

            let cloudinit_params = format!(
                "path={},iommu=on",
                guest.disk_config.disk(DiskType::CloudInit).unwrap()
            );

            let socket = temp_vsock_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    format!(
                        "path={}",
                        guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                    )
                    .as_str(),
                    cloudinit_params.as_str(),
                ])
                .args(&["--net", net_params.as_str()])
                .args(&["--vsock", format!("cid=3,socket={}", socket).as_str()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .spawn()
                .unwrap();

            let console_text = String::from("On a branch floating down river a cricket, singing.");
            let console_cmd = format!("echo {} | sudo tee /dev/hvc0", console_text);
            // Create the snapshot directory
            let snapshot_dir = temp_snapshot_dir_path(&guest.tmp_dir);

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check the number of vCPUs
                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 4);
                // Check the guest RAM
                assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);
                // Check block devices are readable
                assert!(guest
                    .ssh_command("dd if=/dev/vda of=/dev/null bs=1M iflag=direct count=1024")
                    .is_ok());
                assert!(guest
                    .ssh_command("dd if=/dev/vdb of=/dev/null bs=1M iflag=direct count=8")
                    .is_ok());
                // Check if the rng device is readable
                assert!(guest
                    .ssh_command("head -c 1000 /dev/hwrng > /dev/null")
                    .is_ok());
                // Check vsock
                guest.check_vsock(socket.as_str());
                // Check if the console is usable

                assert!(guest.ssh_command(&console_cmd).is_ok());

                // We check that removing and adding back the virtio-net device
                // does not break the snapshot/restore support for virtio-pci.
                // This is an important thing to test as the hotplug will
                // trigger a PCI BAR reprogramming, which is a good way of
                // checking if the stored resources are correctly restored.
                // Unplug the virtio-net device
                assert!(remote_command(&api_socket, "remove-device", Some(net_id),));
                thread::sleep(std::time::Duration::new(10, 0));

                // Plug the virtio-net device again
                assert!(remote_command(
                    &api_socket,
                    "add-net",
                    Some(net_params.as_str()),
                ));
                thread::sleep(std::time::Duration::new(10, 0));

                // Pause the VM
                assert!(remote_command(&api_socket, "pause", None));

                // Take a snapshot from the VM
                assert!(remote_command(
                    &api_socket,
                    "snapshot",
                    Some(format!("file://{}", snapshot_dir).as_str()),
                ));

                // Wait to make sure the snapshot is completed
                thread::sleep(std::time::Duration::new(10, 0));
            });

            // Shutdown the source VM and check console output
            let _ = child.kill();
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

            // Restore the VM from the snapshot
            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .args(&[
                    "--restore",
                    format!("source_url=file://{}", snapshot_dir).as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            // Wait for the VM to be restored
            thread::sleep(std::time::Duration::new(10, 0));

            let r = std::panic::catch_unwind(|| {
                // Resume the VM
                assert!(remote_command(&api_socket, "resume", None));

                // Perform same checks to validate VM has been properly restored
                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 4);
                assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);
                assert!(guest
                    .ssh_command("dd if=/dev/vda of=/dev/null bs=1M iflag=direct count=1024")
                    .is_ok());
                assert!(guest
                    .ssh_command("dd if=/dev/vdb of=/dev/null bs=1M iflag=direct count=8")
                    .is_ok());
                assert!(guest
                    .ssh_command("head -c 1000 /dev/hwrng > /dev/null")
                    .is_ok());
                guest.check_vsock(socket.as_str());
                assert!(guest.ssh_command(&console_cmd).is_ok());
                // Shutdown the target VM and check console output
            });
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                assert!(String::from_utf8_lossy(&output.stdout).contains(&console_text));
            });

            handle_child_output(r, &output);
        }

        #[test]
        fn test_counters() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--api-socket", &api_socket])
                .capture_output();

            #[cfg(target_arch = "aarch64")]
            cmd.args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE]);

            let mut child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                let orig_counters = get_counters(&api_socket);
                assert!(guest
                    .ssh_command("dd if=/dev/zero of=test count=8 bs=1M")
                    .is_ok());

                let new_counters = get_counters(&api_socket);

                // Check that all the counters have increased
                assert!(new_counters > orig_counters);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_watchdog() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path().unwrap();

            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--watchdog"])
                .args(&["--api-socket", &api_socket])
                .capture_output();

            let mut child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check for PCI device
                assert!(guest
                    .does_device_vendor_pair_match("0x1063", "0x1af4")
                    .unwrap_or_default());

                // Enable systemd watchdog
                guest
                    .ssh_command(
                        "echo RuntimeWatchdogSec=15s | sudo tee -a /etc/systemd/system.conf",
                    )
                    .unwrap();

                guest.ssh_command("sudo reboot").unwrap();

                guest.wait_vm_boot(None).unwrap();

                // Check that systemd has activated the watchdog
                assert_eq!(
                    guest
                        .ssh_command("sudo journalctl | grep -c -- \"Watchdog started\"")
                        .unwrap_or_default()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );

                // Ensure that the current boot journal is written so reboot counts are valid
                guest.ssh_command("sudo journalctl --sync").unwrap();

                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 2);
                // Allow some normal time to elapse to check we don't get spurious reboots
                thread::sleep(std::time::Duration::new(40, 0));

                // Check no reboot
                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 2);

                // Ensure that the current boot journal is written so reboot counts are valid
                guest.ssh_command("sudo journalctl --sync").unwrap();

                // Trigger a panic (sync first). We need to do this inside a screen with a delay so the SSH command returns.
                guest.ssh_command("screen -dmS reboot sh -c \"sleep 5; echo s | tee /proc/sysrq-trigger; echo c | sudo tee /proc/sysrq-trigger\"").unwrap();

                // Allow some time for the watchdog to trigger (max 30s) and reboot to happen
                thread::sleep(std::time::Duration::new(50, 0));

                // Check that watchdog triggered reboot
                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 3);

                // Now pause the VM and remain offline for 30s
                assert!(remote_command(&api_socket, "pause", None));
                thread::sleep(std::time::Duration::new(30, 0));
                assert!(remote_command(&api_socket, "resume", None));

                // Check no reboot
                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 3);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }
    }

    mod sequential {
        use crate::tests::*;

        #[test]
        fn test_memory_mergeable_on() {
            test_memory_mergeable(true)
        }
    }

    mod windows {
        use crate::tests::*;

        #[cfg(target_arch = "x86_64")]
        fn windows_auth() -> PasswordAuth {
            PasswordAuth {
                username: String::from("administrator"),
                password: String::from("Admin123"),
            }
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_windows_guest() {
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut ovmf_path = workload_path.clone();
            ovmf_path.push("OVMF.fd");

            let mut osdisk_path = workload_path;
            osdisk_path.push("windows-server-2019.raw");

            let mut child = Command::new(clh_command("cloud-hypervisor"))
                .args(&["--cpus", "boot=2,kvm_hyperv=on,max_phys_bits=39"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--disk", &format!("path={}", osdisk_path.to_str().unwrap())])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .args(&["--net", "tap="])
                .stderr(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            let fd = child.stdout.as_ref().unwrap().as_raw_fd();
            let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
            let fd = child.stderr.as_ref().unwrap().as_raw_fd();
            let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

            assert!(pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE);

            thread::sleep(std::time::Duration::new(40, 0));
            let auth = windows_auth();
            let r = std::panic::catch_unwind(|| {
                ssh_command_ip_with_auth(
                    "shutdown /s",
                    &auth,
                    "192.168.249.2",
                    DEFAULT_SSH_RETRIES,
                    DEFAULT_SSH_TIMEOUT,
                )
                .unwrap();
            });

            let _ = child.wait_timeout(std::time::Duration::from_secs(40));
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_windows_guest_snapshot_restore() {
            let tmp_dir = TempDir::new("ch").unwrap();
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut ovmf_path = workload_path.clone();
            ovmf_path.push("OVMF.fd");

            let mut osdisk_path = workload_path;
            osdisk_path.push("windows-server-2019.raw");

            let api_socket = temp_api_path(&tmp_dir);

            let mut child = Command::new(clh_command("cloud-hypervisor"))
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,kvm_hyperv=on,max_phys_bits=39"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--disk", &format!("path={}", osdisk_path.to_str().unwrap())])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .args(&["--net", "tap="])
                .stderr(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            let fd = child.stdout.as_ref().unwrap().as_raw_fd();
            let pipesize = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };
            let fd = child.stderr.as_ref().unwrap().as_raw_fd();
            let pipesize1 = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_SIZE) };

            assert!(pipesize >= PIPE_SIZE && pipesize1 >= PIPE_SIZE);

            // Wait to make sure Windows boots up
            thread::sleep(std::time::Duration::new(20, 0));

            let snapshot_dir = temp_snapshot_dir_path(&tmp_dir);

            // Pause the VM
            assert!(remote_command(&api_socket, "pause", None));

            // Take a snapshot from the VM
            assert!(remote_command(
                &api_socket,
                "snapshot",
                Some(format!("file://{}", snapshot_dir).as_str()),
            ));

            // Wait to make sure the snapshot is completed
            thread::sleep(std::time::Duration::new(20, 0));

            let _ = child.kill();
            child.wait().unwrap();

            // Restore the VM from the snapshot
            let mut child = Command::new(clh_command("cloud-hypervisor"))
                .args(&["--api-socket", &api_socket])
                .args(&[
                    "--restore",
                    format!("source_url=file://{}", snapshot_dir).as_str(),
                ])
                .stderr(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            // Wait for the VM to be restored
            thread::sleep(std::time::Duration::new(10, 0));

            let r = std::panic::catch_unwind(|| {
                // Resume the VM
                assert!(remote_command(&api_socket, "resume", None));

                let auth = windows_auth();

                ssh_command_ip_with_auth(
                    "shutdown /s",
                    &auth,
                    "192.168.249.2",
                    DEFAULT_SSH_RETRIES,
                    DEFAULT_SSH_TIMEOUT,
                )
                .unwrap();
            });

            let _ = child.wait_timeout(std::time::Duration::from_secs(20));
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }
    }

    mod sgx {
        use crate::tests::*;

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_sgx() {
            let mut focal = UbuntuDiskConfig::new(FOCAL_SGX_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut focal);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage_w_sgx");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .args(&["--sgx-epc", "size=64M"])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check if SGX is correctly detected in the guest.
                assert!(guest.check_sgx_support().unwrap());

                // Validate the SGX EPC section is 64MiB.
                assert_eq!(
                    guest
                        .ssh_command("cpuid -l 0x12 -s 2 | grep 'section size' | cut -d '=' -f 2")
                        .unwrap_or_default()
                        .trim(),
                    "0x0000000004000000"
                );

                // Run a test relying on SGX enclaves and check if it runs
                // successfully.
                assert!(guest
                    .ssh_command("cd /linux-sgx/SampleCode/LocalAttestation/bin/ && sudo ./app")
                    .unwrap_or_default()
                    .trim()
                    .contains(
                        "succeed to load enclaves.\nsucceed to \
                        establish secure channel.\nSucceed to exchange \
                        secure message...\nSucceed to close Session..."
                    ));
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }
    }
}
