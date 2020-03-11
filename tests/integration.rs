// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate credibility;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod tests {
    #![allow(dead_code)]
    use ssh2::Session;
    use std::ffi::OsStr;
    use std::fs;
    use std::io;
    use std::io::BufRead;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::string::String;
    use std::sync::Mutex;
    use std::thread;
    use tempdir::TempDir;

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
    }

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

    #[derive(Clone)]
    struct ClearDiskConfig {
        osdisk_path: String,
        osdisk_raw_path: String,
        cloudinit_path: String,
    }

    impl ClearDiskConfig {
        fn new() -> Self {
            ClearDiskConfig {
                osdisk_path: String::new(),
                osdisk_raw_path: String::new(),
                cloudinit_path: String::new(),
            }
        }
    }

    struct UbuntuDiskConfig {
        osdisk_raw_path: String,
        cloudinit_path: String,
        image_name: String,
    }

    const BIONIC_IMAGE_NAME: &str = "bionic-server-cloudimg-amd64-raw.img";
    const EOAN_IMAGE_NAME: &str = "eoan-server-cloudimg-amd64-raw.img";

    impl UbuntuDiskConfig {
        fn new(image_name: String) -> Self {
            UbuntuDiskConfig {
                image_name,
                osdisk_raw_path: String::new(),
                cloudinit_path: String::new(),
            }
        }
    }

    fn rate_limited_copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
        for _ in 0..10 {
            match fs::copy(&from, &to) {
                Err(e) => {
                    if let Some(errno) = e.raw_os_error() {
                        if errno == libc::ENOSPC {
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

    impl DiskConfig for ClearDiskConfig {
        fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String {
            let cloudinit_file_path =
                String::from(tmp_dir.path().join("cloudinit").to_str().unwrap());

            let cloud_init_directory = tmp_dir
                .path()
                .join("cloud-init")
                .join("clear")
                .join("openstack");

            fs::create_dir_all(&cloud_init_directory.join("latest"))
                .expect("Expect creating cloud-init directory to succeed");

            let source_file_dir = std::env::current_dir()
                .unwrap()
                .join("test_data")
                .join("cloud-init")
                .join("clear")
                .join("openstack")
                .join("latest");

            rate_limited_copy(
                source_file_dir.join("meta_data.json"),
                cloud_init_directory.join("latest").join("meta_data.json"),
            )
            .expect("Expect copying cloud-init meta_data.json to succeed");

            let mut user_data_string = String::new();

            fs::File::open(source_file_dir.join("user_data"))
                .unwrap()
                .read_to_string(&mut user_data_string)
                .expect("Expected reading user_data file in to succeed");

            user_data_string = user_data_string.replace("192.168.2.1", &network.host_ip);
            user_data_string = user_data_string.replace("192.168.2.2", &network.guest_ip);
            user_data_string = user_data_string.replace("192.168.2.3", &network.l2_guest_ip1);
            user_data_string = user_data_string.replace("192.168.2.4", &network.l2_guest_ip2);
            user_data_string = user_data_string.replace("192.168.2.5", &network.l2_guest_ip3);
            user_data_string = user_data_string.replace("12:34:56:78:90:ab", &network.guest_mac);
            user_data_string =
                user_data_string.replace("de:ad:be:ef:12:34", &network.l2_guest_mac1);
            user_data_string =
                user_data_string.replace("de:ad:be:ef:34:56", &network.l2_guest_mac2);
            user_data_string =
                user_data_string.replace("de:ad:be:ef:56:78", &network.l2_guest_mac3);

            fs::File::create(cloud_init_directory.join("latest").join("user_data"))
                .unwrap()
                .write_all(&user_data_string.as_bytes())
                .expect("Expected writing out user_data to succeed");

            std::process::Command::new("mkdosfs")
                .args(&["-n", "config-2"])
                .args(&["-C", cloudinit_file_path.as_str()])
                .arg("8192")
                .output()
                .expect("Expect creating disk image to succeed");

            std::process::Command::new("mcopy")
                .arg("-o")
                .args(&["-i", cloudinit_file_path.as_str()])
                .args(&["-s", cloud_init_directory.to_str().unwrap(), "::"])
                .output()
                .expect("Expect copying files to disk image to succeed");

            cloudinit_file_path
        }

        fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig) {
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut osdisk_base_path = workload_path.clone();
            osdisk_base_path.push("clear-31311-cloudguest.img");

            let mut osdisk_raw_base_path = workload_path;
            osdisk_raw_base_path.push("clear-31311-cloudguest-raw.img");

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

            vec!["meta-data", "user-data"].iter().for_each(|x| {
                rate_limited_copy(source_file_dir.join(x), cloud_init_directory.join(x))
                    .expect("Expect copying cloud-init meta-data to succeed");
            });

            let mut network_config_string = String::new();

            fs::File::open(source_file_dir.join("network-config"))
                .unwrap()
                .read_to_string(&mut network_config_string)
                .expect("Expected reading network-config file in to succeed");

            network_config_string = network_config_string.replace("192.168.2.1", &network.host_ip);
            network_config_string = network_config_string.replace("192.168.2.2", &network.guest_ip);
            network_config_string =
                network_config_string.replace("12:34:56:78:90:ab", &network.guest_mac);

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

            let mut osdisk_raw_base_path = workload_path;
            osdisk_raw_base_path.push(&self.image_name);

            let osdisk_raw_path =
                String::from(tmp_dir.path().join("osdisk_raw.img").to_str().unwrap());
            let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

            rate_limited_copy(osdisk_raw_base_path, &osdisk_raw_path)
                .expect("copying of OS source disk raw image failed");

            self.cloudinit_path = cloudinit_path;
            self.osdisk_raw_path = osdisk_raw_path;
        }

        fn disk(&self, disk_type: DiskType) -> Option<String> {
            match disk_type {
                DiskType::OperatingSystem | DiskType::RawOperatingSystem => {
                    Some(self.osdisk_raw_path.clone())
                }
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
        let child = Command::new("target/release/vhost_user_fs")
            .args(&["--shared-dir", shared_dir])
            .args(&["--sock", virtiofsd_socket_path.as_str()])
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
        let child = Command::new("target/release/cloud-hypervisor")
            .args(&[
                "--block-backend",
                format!(
                    "image={},sock={},num_queues={},readonly={},direct={}",
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
                "tap={},ip={},mask=255.255.255.0,sock={},num_queues={},queue_size=1024",
                tap_str, ip, vunet_socket_path, num_queues
            )
        } else {
            format!(
                "ip={},mask=255.255.255.0,sock={},num_queues={},queue_size=1024",
                ip, vunet_socket_path, num_queues
            )
        };

        let child = Command::new("target/release/cloud-hypervisor")
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
        let mut cmd = Command::new("target/release/ch-remote");
        cmd.args(&[&format!("--api-socket={}", api_socket), command]);

        if let Some(arg) = arg {
            cmd.arg(arg);
        }

        cmd.status().expect("Failed to launch ch-remote").success()
    }

    fn resize_command(
        api_socket: &str,
        desired_vcpus: Option<u8>,
        desired_ram: Option<usize>,
    ) -> bool {
        let mut cmd = Command::new("target/release/ch-remote");
        cmd.args(&[&format!("--api-socket={}", api_socket), "resize"]);

        if let Some(desired_vcpus) = desired_vcpus {
            cmd.arg(format!("--cpus={}", desired_vcpus));
        }

        if let Some(desired_ram) = desired_ram {
            cmd.arg(format!("--memory={}", desired_ram));
        }

        cmd.status().expect("Failed to launch ch-remote").success()
    }

    const DEFAULT_SSH_RETRIES: u8 = 6;
    const DEFAULT_SSH_TIMEOUT: u8 = 10;
    fn ssh_command_ip(command: &str, ip: &str, retries: u8, timeout: u8) -> Result<String, Error> {
        let mut s = String::new();

        let mut counter = 0;
        loop {
            match (|| -> Result<(), Error> {
                let tcp = TcpStream::connect(format!("{}:22", ip)).map_err(Error::Connection)?;
                let mut sess = Session::new().unwrap();
                sess.set_tcp_stream(tcp);
                sess.handshake().map_err(Error::Handshake)?;

                sess.userauth_password("cloud", "cloud123")
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
                        return Err(e);
                    }
                }
            };
            thread::sleep(std::time::Duration::new((timeout * counter).into(), 0));
        }
        Ok(s)
    }

    #[derive(Debug)]
    enum Error {
        Connection(std::io::Error),
        Handshake(ssh2::Error),
        Authentication(ssh2::Error),
        ChannelSession(ssh2::Error),
        Command(ssh2::Error),
        Parsing(std::num::ParseIntError),
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
            format! {"{{\"cpus\":{{\"boot_vcpus\":{},\"max_vcpus\":{}}},\"kernel\":{{\"path\":\"{}\"}},\"cmdline\":{{\"args\": \"\"}},\"net\":[{{\"ip\":\"{}\", \"mask\":\"255.255.255.0\", \"mac\":\"{}\"}}], \"disks\":[{{\"path\":\"{}\"}}, {{\"path\":\"{}\"}}]}}",
                     cpu_count,
                     cpu_count,
                     self.fw_path.as_str(),
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
    }

    struct GuestCommand<'a> {
        command: Command,
        guest: &'a Guest<'a>,
        capture_output: bool,
    }

    impl<'a> GuestCommand<'a> {
        fn new(guest: &'a Guest) -> Self {
            Self {
                command: Command::new("target/release/cloud-hypervisor"),
                guest,
                capture_output: false,
            }
        }

        fn capture_output(&mut self) -> &mut Self {
            self.capture_output = true;
            self
        }

        fn spawn(&mut self) -> io::Result<Child> {
            if self.capture_output {
                self.command
                    .stderr(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
            } else {
                self.command.spawn()
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

        fn default_net(&mut self) -> &mut Self {
            self.args(&["--net", self.guest.default_net_string().as_str()])
        }
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_simple_launch() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let mut eoan = UbuntuDiskConfig::new(EOAN_IMAGE_NAME.to_string());

            vec![
                &mut clear as &mut dyn DiskConfig,
                &mut bionic as &mut dyn DiskConfig,
                &mut eoan as &mut dyn DiskConfig,
            ]
            .iter_mut()
            .for_each(|disk_config| {
                let guest = Guest::new(*disk_config);

                let mut child = GuestCommand::new(&guest)
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", guest.fw_path.as_str()])
                    .default_disks()
                    .default_net()
                    .args(&["--serial", "tty", "--console", "off"])
                    .spawn()
                    .unwrap();

                thread::sleep(std::time::Duration::new(20, 0));

                aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
                aver_eq!(tb, guest.get_initial_apicid().unwrap_or(1), 0);
                aver!(tb, guest.get_total_memory().unwrap_or_default() > 488_000);
                aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);
                aver_eq!(
                    tb,
                    guest.get_pci_bridge_class().unwrap_or_default(),
                    "0x060000"
                );

                let _ = child.kill();
                let _ = child.wait();
            });
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_multi_cpu() {
        test_block!(tb, "", {
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut bionic);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 2);

            aver_eq!(
                tb,
                guest
                    .ssh_command(r#"dmesg | grep "smpboot: Allowing" | sed "s/\[\ *[0-9.]*\] //""#)
                    .unwrap_or_default()
                    .trim(),
                "smpboot: Allowing 4 CPUs, 2 hotplug CPUs"
            );
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_large_memory() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=5120M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 5_000_000);

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_huge_memory() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=128G"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver!(
                tb,
                guest.get_total_memory().unwrap_or_default() > 128_000_000
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_pci_msi() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(
                tb,
                guest
                    .ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                12
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_vmlinux_boot() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 496_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            #[cfg(not(feature = "mmio"))]
            aver_eq!(
                tb,
                guest
                    .ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                12
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_bzimage_boot() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 496_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            #[cfg(not(feature = "mmio"))]
            aver_eq!(
                tb,
                guest
                    .ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                12
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_blk() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut blk_file_path = dirs::home_dir().unwrap();
            blk_file_path.push("workloads");
            blk_file_path.push("blk.img");

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
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
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Check both if /dev/vdc exists and if the block size is 16M.
            aver_eq!(
                tb,
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Check both if /dev/vdc exists and if this block is RO.
            aver_eq!(
                tb,
                guest
                    .ssh_command("lsblk | grep vdc | awk '{print $5}'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Check if the number of queues is 4.
            aver_eq!(
                tb,
                guest
                    .ssh_command("ls -ll /sys/block/vdc/mq | grep ^d | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4
            );
            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            Ok(())
        });
    }

    fn test_vhost_user_net(
        tap: Option<&str>,
        num_queues: usize,
        prepare_vhost_user_net_daemon: &dyn Fn(
            &TempDir,
            &str,
            Option<&str>,
            usize,
        ) -> (std::process::Child, String),
    ) {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            // Start the daemon
            let (mut daemon_child, vunet_socket_path) = prepare_vhost_user_net_daemon(
                &guest.tmp_dir,
                &guest.network.host_ip,
                tap,
                num_queues,
            );

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", format!("boot={}", num_queues / 2).as_str()])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .args(&[
                    "--net",
                    format!(
                        "vhost_user=true,mac={},socket={},num_queues={},queue_size=1024",
                        guest.network.guest_mac, vunet_socket_path, num_queues,
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));
            // 1 network interface + default localhost ==> 2 interfaces
            // It's important to note that this test is fully exercising the
            // vhost-user-net implementation and the associated backend since
            // it does not define any --net network interface. That means all
            // the ssh communication in that test happens through the network
            // interface backed by vhost-user-net.
            aver_eq!(
                tb,
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
            aver_eq!(
                tb,
                guest
                    .ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                10 + (num_queues as u32)
            );

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net_default() {
        test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net_tap() {
        test_vhost_user_net(Some("vunet-tap0"), 2, &prepare_vhost_user_net_daemon)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net_multiple_queues() {
        test_vhost_user_net(None, 4, &prepare_vhost_user_net_daemon)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net_tap_multiple_queues() {
        test_vhost_user_net(Some("vunet-tap1"), 4, &prepare_vhost_user_net_daemon)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net_self_spawning() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .args(&[
                    "--net",
                    format!(
                        "vhost_user=true,mac={},ip={},mask=255.255.255.0,num_queues=4,queue_size=1024",
                        guest.network.guest_mac,
                        guest.network.host_ip
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));
            // 1 network interface + default localhost ==> 2 interfaces
            aver_eq!(
                tb,
                guest
                    .ssh_command("ip -o link | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                2
            );

            thread::sleep(std::time::Duration::new(10, 0));

            // The following pci devices will appear on guest with PCI-MSI
            // interrupt vectors assigned.
            // 1 virtio-console with 3 vectors: config, Rx, Tx
            // 1 virtio-blk     with 2 vectors: config, Request
            // 1 virtio-blk     with 2 vectors: config, Request
            // 1 virtio-rng     with 2 vectors: config, Request
            // Since virtio-net has 2 queue pairs, its vectors is as follows:
            // 1 virtio-net     with 5 vectors: config, Rx (2), Tx (2)
            // Based on the above, the total vectors should 14.
            aver_eq!(
                tb,
                guest
                    .ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                14
            );

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_blk() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) =
                prepare_vubd(&guest.tmp_dir, "blk.img", 2, false, false);

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
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
                        "vhost_user=true,socket={},num_queues=2,queue_size=128,wce=true",
                        vubd_socket_path
                    )
                    .as_str(),
                ])
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Check both if /dev/vdc exists and if the block size is 16M.
            aver_eq!(
                tb,
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            thread::sleep(std::time::Duration::new(20, 0));
            // Check if the queue number in /sys/block/vdc/mq is same to 2.
            aver_eq!(
                tb,
                guest
                    .ssh_command("ls -ll /sys/block/vdc/mq | grep ^d | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                2
            );

            // Mount the device
            guest.ssh_command("mkdir mount_image")?;
            guest.ssh_command("sudo mount -t ext4 /dev/vdc mount_image/")?;

            // Check the content of the block device. The file "foo" should
            // contain "bar".
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat mount_image/foo")
                    .unwrap_or_default()
                    .trim(),
                "bar"
            );

            // Unmount the device
            guest.ssh_command("sudo umount /dev/vdc")?;
            guest.ssh_command("rm -r mount_image")?;

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_blk_self_spawning() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    format!(
                        "path={},vhost_user=true",
                        guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
                    )
                    .as_str(),
                    format!(
                        "path={},vhost_user=true",
                        guest.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str(),
                ])
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or(1);

            aver_eq!(tb, reboot_count, 0);
            guest.ssh_command("sudo reboot").unwrap_or_default();

            thread::sleep(std::time::Duration::new(20, 0));
            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            aver_eq!(tb, reboot_count, 1);

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_blk_readonly() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) =
                prepare_vubd(&guest.tmp_dir, "blk.img", 1, true, false);

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
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
                        "vhost_user=true,socket={},num_queues=1,queue_size=128,wce=true",
                        vubd_socket_path
                    )
                    .as_str(),
                ])
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Check both if /dev/vdc exists and if the block size is 16M.
            aver_eq!(
                tb,
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Check both if /dev/vdc exists and if this block is RO.
            aver_eq!(
                tb,
                guest
                    .ssh_command("lsblk | grep vdc | awk '{print $5}'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_blk_direct() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) =
                prepare_vubd(&guest.tmp_dir, "blk.img", 1, false, true);

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
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
                        "vhost_user=true,socket={},num_queues=1,queue_size=128,wce=true",
                        vubd_socket_path
                    )
                    .as_str(),
                ])
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Check both if /dev/vdc exists and if the block size is 16M.
            aver_eq!(
                tb,
                guest
                    .ssh_command("lsblk | grep vdc | grep -c 16M")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_boot_from_vhost_user_blk() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) = prepare_vubd(
                &guest.tmp_dir,
                guest
                    .disk_config
                    .disk(DiskType::RawOperatingSystem)
                    .unwrap()
                    .as_str(),
                1,
                false,
                false,
            );

            let mut cloud_child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    format!(
                        "path={}",
                        guest.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str(),
                    format!(
                        "vhost_user=true,socket={},num_queues=1,queue_size=128,wce=true",
                        vubd_socket_path
                    )
                    .as_str(),
                ])
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Just check the VM booted correctly.
            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);

            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_split_irqchip() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'timer'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1),
                0
            );
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'cascade'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1),
                0
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    fn test_virtio_fs(
        dax: bool,
        cache_size: Option<u64>,
        virtiofsd_cache: &str,
        prepare_daemon: &dyn Fn(&TempDir, &str, &str) -> (std::process::Child, String),
    ) {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut shared_dir = workload_path.clone();
            shared_dir.push("shared_dir");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

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

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&[
                    "--fs",
                    format!(
                        "tag=myfs,sock={},num_queues=1,queue_size=1024,dax={}{}",
                        virtiofsd_socket_path, dax_vmm_param, cache_size_vmm_param
                    )
                    .as_str(),
                ])
                .args(&[
                    "--cmdline",
                    "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c \
                     console=tty0 console=ttyS0,115200n8 console=hvc0 quiet \
                     init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable \
                     no_timer_check noreplace-smp cryptomgr.notests \
                     rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw",
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Mount shared directory through virtio_fs filesystem
            let mount_cmd = format!(
                "mkdir -p mount_dir && \
                 sudo mount -t virtiofs {} myfs mount_dir/ && \
                 echo ok",
                dax_mount_param
            );
            aver_eq!(
                tb,
                guest.ssh_command(&mount_cmd).unwrap_or_default().trim(),
                "ok"
            );

            // Check the cache size is the expected one.
            // With virtio-mmio the cache doesn't appear in /proc/iomem
            #[cfg(not(feature = "mmio"))]
            aver_eq!(
                tb,
                guest
                    .valid_virtio_fs_cache_size(dax, cache_size)
                    .unwrap_or_default(),
                true
            );
            // Check file1 exists and its content is "foo"
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat mount_dir/file1")
                    .unwrap_or_default()
                    .trim(),
                "foo"
            );
            // Check file2 does not exist
            aver_ne!(
                tb,
                guest
                    .ssh_command("ls mount_dir/file2")
                    .unwrap_or_default()
                    .trim(),
                "mount_dir/file2"
            );
            // Check file3 exists and its content is "bar"
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat mount_dir/file3")
                    .unwrap_or_default()
                    .trim(),
                "bar"
            );

            let _ = child.kill();
            let _ = daemon_child.kill();
            let _ = child.wait();
            let _ = daemon_child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_virtio_fs_dax_on_default_cache_size() {
        test_virtio_fs(true, None, "none", &prepare_virtiofsd)
    }

    #[test]
    fn test_virtio_fs_dax_on_cache_size_1_gib() {
        test_virtio_fs(true, Some(0x4000_0000), "none", &prepare_virtiofsd)
    }

    #[test]
    fn test_virtio_fs_dax_off() {
        test_virtio_fs(false, None, "none", &prepare_virtiofsd)
    }

    #[test]
    fn test_virtio_fs_dax_on_default_cache_size_w_vhost_user_fs_daemon() {
        test_virtio_fs(true, None, "none", &prepare_vhost_user_fs_daemon)
    }

    #[test]
    fn test_virtio_fs_dax_on_cache_size_1_gib_w_vhost_user_fs_daemon() {
        test_virtio_fs(
            true,
            Some(0x4000_0000),
            "none",
            &prepare_vhost_user_fs_daemon,
        )
    }

    #[test]
    fn test_virtio_fs_dax_off_w_vhost_user_fs_daemon() {
        test_virtio_fs(false, None, "none", &prepare_vhost_user_fs_daemon)
    }

    #[test]
    fn test_virtio_pmem() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&[
                    "--pmem",
                    format!(
                        "file={},size={}",
                        guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap(),
                        fs::metadata(&guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap()).unwrap().len()
                    )
                    .as_str(),
                ])
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Check for the presence of /dev/pmem0
            aver_eq!(
                tb,
                guest
                    .ssh_command("ls /dev/pmem0")
                    .unwrap_or_default()
                    .trim(),
                "/dev/pmem0"
            );

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[test]
    fn test_boot_from_virtio_pmem() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--disk",
                    format!(
                        "path={}",
                        guest.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str()])
                .default_net()
                .args(&[
                    "--pmem",
                    format!(
                        "file={},size={}",
                        guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap(),
                        fs::metadata(&guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap()).unwrap().len()
                    )
                    .as_str(),
                ])
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Simple checks to validate the VM booted properly
            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 496_000);

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_multiple_network_interfaces() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .args(&[
                    "--net",
                    guest.default_net_string().as_str(),
                    "tap=,mac=8a:6b:6f:5a:de:ac,ip=192.168.3.1,mask=255.255.255.0",
                    "tap=,mac=fe:1f:9e:e1:60:f2,ip=192.168.4.1,mask=255.255.255.0",
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // 3 network interfaces + default localhost ==> 4 interfaces
            aver_eq!(
                tb,
                guest
                    .ssh_command("ip -o link | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                4
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_serial_off() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&["--serial", "off"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Test that there is no ttyS0
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1),
                0
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_serial_null() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&["--serial", "null"])
                .args(&["--console", "off"])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Test that there is a ttyS0
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            let _ = child.kill();
            match child.wait_with_output() {
                Ok(out) => {
                    aver!(
                        tb,
                        !String::from_utf8_lossy(&out.stdout).contains("cloud login:")
                    );
                }
                Err(_) => aver!(tb, false),
            }
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_serial_tty() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Test that there is a ttyS0
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            let _ = child.kill();
            match child.wait_with_output() {
                Ok(out) => {
                    aver!(
                        tb,
                        String::from_utf8_lossy(&out.stdout).contains("cloud login:")
                    );
                }
                Err(_) => aver!(tb, false),
            }
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_serial_file() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

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
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Test that there is a ttyS0
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep 'IO-APIC' | grep -c 'ttyS0'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            guest.ssh_command("sudo shutdown -h now")?;

            // Check that the cloud-hypervisor binary actually terminated
            if let Ok(status) = child.wait() {
                aver_eq!(tb, status.success(), true);
            }
            // Do this check after shutdown of the VM as an easy way to ensure
            // all writes are flushed to disk
            let mut f = std::fs::File::open(serial_path)?;
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            aver!(tb, buf.contains("cloud login:"));

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_console() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&["--console", "tty"])
                .capture_output()
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            #[cfg(not(feature = "mmio"))]
            aver!(
                tb,
                guest
                    .does_device_vendor_pair_match("0x1043", "0x1af4")
                    .unwrap_or_default()
            );

            let text = String::from("On a branch floating down river a cricket, singing.");
            let cmd = format!("echo {} | sudo tee /dev/hvc0", text);
            guest.ssh_command(&cmd)?;

            let _ = child.kill();

            match child.wait_with_output() {
                Ok(out) => {
                    aver!(tb, String::from_utf8_lossy(&out.stdout).contains(&text));
                }
                Err(_) => aver!(tb, false),
            }

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_console_file() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

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
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            guest.ssh_command("sudo shutdown -h now")?;

            // Check that the cloud-hypervisor binary actually terminated
            if let Ok(status) = child.wait() {
                aver_eq!(tb, status.success(), true);
            }
            // Do this check after shutdown of the VM as an easy way to ensure
            // all writes are flushed to disk
            let mut f = std::fs::File::open(console_path)?;
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            aver!(tb, buf.contains("cloud login:"));

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    // The VFIO integration test starts cloud-hypervisor guest with 3 TAP
    // backed networking interfaces, bound through a simple bridge on the host.
    // So if the nested cloud-hypervisor succeeds in getting a directly
    // assigned interface from its cloud-hypervisor host, we should be able to
    // ssh into it, and verify that it's running with the right kernel command
    // line (We tag the command line from cloud-hypervisor for that purpose).
    // The third device is added to validate that hotplug works correctly since
    // it is being added to the L2 VM through hotplugging mechanism.
    fn test_vfio() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new_from_ip_range(&mut clear, "172.17", 0);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path.clone();
            kernel_path.push("bzImage");

            let mut vfio_path = workload_path;
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

            let vfio_tap0 = "vfio-tap0";
            let vfio_tap1 = "vfio-tap1";
            let vfio_tap2 = "vfio-tap2";
            let vfio_tap3 = "vfio-tap3";

            let (mut daemon_child, virtiofsd_socket_path) =
                prepare_virtiofsd(&guest.tmp_dir, vfio_path.to_str().unwrap(), "none");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=1G,file=/dev/hugepages"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 vfio_iommu_type1.allow_unsafe_interrupts rw"])
                .args(&[
                    "--net",
                    format!(
                        "tap={},mac={}", vfio_tap0, guest.network.guest_mac
                    )
                    .as_str(),
                    format!(
                        "tap={},mac={},iommu=on", vfio_tap1, guest.network.l2_guest_mac1
                    )
                    .as_str(),
                    format!(
                        "tap={},mac={},iommu=on", vfio_tap2, guest.network.l2_guest_mac2
                    )
                    .as_str(),
                    format!(
                        "tap={},mac={},iommu=on", vfio_tap3, guest.network.l2_guest_mac3
                    )
                    .as_str(),
                ])
                .args(&[
                    "--fs",
                    format!(
                        "tag=myfs,sock={},num_queues=1,queue_size=1024,dax=on",
                        virtiofsd_socket_path,
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(30, 0));

            guest.ssh_command_l1("sudo systemctl start vfio")?;
            thread::sleep(std::time::Duration::new(60, 0));

            // We booted our cloud hypervisor L2 guest with a "VFIOTAG" tag
            // added to its kernel command line.
            // Let's ssh into it and verify that it's there. If it is it means
            // we're in the right guest (The L2 one) because the QEMU L1 guest
            // does not have this command line tag.
            aver_eq!(
                tb,
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
            aver_eq!(
                tb,
                guest
                    .ssh_command_l2_2("grep -c VFIOTAG /proc/cmdline")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            // Check the amount of PCI devices appearing in L2 VM.
            aver_eq!(
                tb,
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
                "echo 0000:00:07.0 | sudo tee /sys/bus/pci/devices/0000:00:07.0/driver/unbind",
            )?;
            guest
                .ssh_command_l1("echo 1af4 1041 | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id")?;
            guest.ssh_command_l1(
                "sudo curl \
                 --unix-socket /tmp/ch_api.sock \
                 -i \
                 -X PUT http://localhost/api/v1/vm.add-device \
                 -H 'Accept: application/json' -H 'Content-Type: application/json' \
                 -d '{\"path\":\"/sys/bus/pci/devices/0000:00:07.0\",\"id\":\"vfio123\"}'",
            )?;
            thread::sleep(std::time::Duration::new(10, 0));

            // Let's also verify from the third virtio-net device passed to
            // the L2 VM. This third device has been hotplugged through the L2
            // VM, so this is our way to validate hotplug works for VFIO PCI.
            aver_eq!(
                tb,
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
            aver_eq!(
                tb,
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
            guest.ssh_command_l1(
                "sudo curl \
                 --unix-socket /tmp/ch_api.sock \
                 -i \
                 -X PUT http://localhost/api/v1/vm.remove-device \
                 -H 'Accept: application/json' -H 'Content-Type: application/json' \
                 -d '{\"id\":\"vfio123\"}'",
            )?;
            thread::sleep(std::time::Duration::new(10, 0));

            // Check the amount of PCI devices appearing in L2 VM is back down
            // to 7 devices.
            aver_eq!(
                tb,
                guest
                    .ssh_command_l2_1("ls /sys/bus/pci/devices | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                7,
            );

            let _ = child.kill();
            let _ = daemon_child.kill();
            let _ = child.wait();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vmlinux_boot_noacpi() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw acpi=off"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 496_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);
            aver_eq!(
                tb,
                guest
                    .ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                12
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_reboot() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let mut eoan = UbuntuDiskConfig::new(EOAN_IMAGE_NAME.to_string());

            vec![
                &mut clear as &mut dyn DiskConfig,
                &mut bionic as &mut dyn DiskConfig,
                &mut eoan as &mut dyn DiskConfig,
            ]
            .iter_mut()
            .for_each(|disk_config| {
                let guest = Guest::new(*disk_config);

                let mut child = GuestCommand::new(&guest)
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", guest.fw_path.as_str()])
                    .default_disks()
                    .default_net()
                    .args(&["--serial", "tty", "--console", "off"])
                    .spawn()
                    .unwrap();

                thread::sleep(std::time::Duration::new(20, 0));

                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1);

                aver_eq!(tb, reboot_count, 0);
                guest.ssh_command("sudo reboot").unwrap_or_default();

                thread::sleep(std::time::Duration::new(20, 0));
                let reboot_count = guest
                    .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                aver_eq!(tb, reboot_count, 1);

                guest
                    .ssh_command("sudo shutdown -h now")
                    .unwrap_or_default();

                // Check that the cloud-hypervisor binary actually terminated
                if let Ok(status) = child.wait() {
                    aver_eq!(tb, status.success(), true);
                }
                let _ = child.wait();
            });
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_bzimage_reboot() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            let reboot_count = guest
                .ssh_command("journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or(1);

            aver_eq!(tb, reboot_count, 0);
            guest.ssh_command("sudo reboot")?;

            thread::sleep(std::time::Duration::new(20, 0));
            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            aver_eq!(tb, reboot_count, 1);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(20, 0));

            // Check that the cloud-hypervisor binary actually terminated
            if let Ok(status) = child.wait() {
                aver_eq!(tb, status.success(), true);
            }
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_vsock() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let sock = temp_vsock_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .default_disks()
                .default_net()
                .args(&["--vsock", format!("cid=3,sock={}", sock).as_str()])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Listen from guest on vsock CID=3 PORT=16
            // SOCKET-LISTEN:<domain>:<protocol>:<local-address>
            let guest_ip = guest.network.guest_ip.clone();
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
                        sock
                    )
                    .as_str(),
                )
                .output()
                .unwrap();

            // Wait for the thread to terminate.
            listen_socat.join().unwrap();

            assert_eq!(
                guest.ssh_command("cat vsock_log").unwrap().trim(),
                "HelloWorld!"
            );

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    // Start cloud-hypervisor with no VM parameters, only the API server running.
    // From the API: Create a VM, boot it and check that it looks as expected.
    fn test_api_create_boot() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
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

            // Check that the VM booted as expected
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    // Start cloud-hypervisor with no VM parameters, only the API server running.
    // From the API: Create a VM, boot it and check that it looks as expected.
    // Then we pause the VM, check that it's no longer available.
    // Finally we resume the VM and check that it's available.
    fn test_api_pause_resume() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
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

            // Check that the VM booted as expected
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            // We now pause the VM
            aver!(tb, remote_command(&api_socket, "pause", None));

            // Check pausing again fails
            aver!(tb, !remote_command(&api_socket, "pause", None));

            thread::sleep(std::time::Duration::new(2, 0));

            // SSH into the VM should fail
            aver!(
                tb,
                ssh_command_ip(
                    "grep -c processor /proc/cpuinfo",
                    &guest.network.guest_ip,
                    2,
                    5
                )
                .is_err()
            );

            // Resume the VM
            aver!(tb, remote_command(&api_socket, "resume", None));

            // Check resuming again fails
            aver!(tb, !remote_command(&api_socket, "resume", None));

            thread::sleep(std::time::Duration::new(2, 0));

            // Now we should be able to SSH back in and get the right number of CPUs
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    // This test validates that it can find the virtio-iommu device at first.
    // It also verifies that both disks and the network card are attached to
    // the virtual IOMMU by looking at /sys/kernel/iommu_groups directory.
    // The last interesting part of this test is that it exercises the network
    // interface attached to the virtual IOMMU since this is the one used to
    // send all commands through SSH.
    fn test_virtio_iommu() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
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
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Verify the virtio-iommu device is present.
            #[cfg(not(feature = "mmio"))]
            aver!(
                tb,
                guest
                    .does_device_vendor_pair_match("0x1057", "0x1af4")
                    .unwrap_or_default()
            );

            // Verify the first disk is located under IOMMU group 0.
            aver_eq!(
                tb,
                guest
                    .ssh_command("ls /sys/kernel/iommu_groups/0/devices")
                    .unwrap()
                    .trim(),
                "0000:00:02.0"
            );

            // Verify the second disk is located under IOMMU group 1.
            aver_eq!(
                tb,
                guest
                    .ssh_command("ls /sys/kernel/iommu_groups/1/devices")
                    .unwrap()
                    .trim(),
                "0000:00:03.0"
            );

            // Verify the network card is located under IOMMU group 2.
            aver_eq!(
                tb,
                guest
                    .ssh_command("ls /sys/kernel/iommu_groups/2/devices")
                    .unwrap()
                    .trim(),
                "0000:00:04.0"
            );

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    // We cannot force the software running in the guest to reprogram the BAR
    // with some different addresses, but we have a reliable way of testing it
    // with a standard Linux kernel.
    // By removing a device from the PCI tree, and then rescanning the tree,
    // Linux consistently chooses to reorganize the PCI device BARs to other
    // locations in the guest address space.
    // This test creates a dedicated PCI network device to be checked as being
    // properly probed first, then removing it, and adding it again by doing a
    // rescan.
    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_pci_bar_reprogramming() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
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
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // 2 network interfaces + default localhost ==> 3 interfaces
            aver_eq!(
                tb,
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
            )?;

            // Remove the PCI device
            guest.ssh_command("echo 1 | sudo tee /sys/bus/pci/devices/0000:00:05.0/remove")?;

            // Only 1 network interface left + default localhost ==> 2 interfaces
            aver_eq!(
                tb,
                guest
                    .ssh_command("ip -o link | wc -l")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                2
            );

            // Remove the PCI device
            guest.ssh_command("echo 1 | sudo tee /sys/bus/pci/rescan")?;

            // Back to 2 network interface + default localhost ==> 3 interfaces
            aver_eq!(
                tb,
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
            )?;

            // Let's compare the BAR addresses for our virtio-net device.
            // They should be different as we expect the BAR reprogramming
            // to have happened.
            aver_ne!(tb, init_bar_addr, new_bar_addr);

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
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
        test_block!(tb, "", {
            let memory_param = if mergeable {
                "mergeable=on"
            } else {
                "mergeable=off"
            };

            let mut clear1 = ClearDiskConfig::new();
            let mut clear2 = ClearDiskConfig::new();

            let guest1 = Guest::new(&mut clear1 as &mut dyn DiskConfig);

            let mut child1 = GuestCommand::new(&guest1)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
                .args(&["--kernel", guest1.fw_path.as_str()])
                .default_disks()
                .args(&["--net", guest1.default_net_string().as_str()])
                .args(&["--serial", "tty", "--console", "off"])
                .spawn()
                .unwrap();

            // Let enough time for the first VM to be spawned, and to make
            // sure the PSS measurement is accurate.
            thread::sleep(std::time::Duration::new(60, 0));

            // Get initial PSS
            let old_pss = get_pss(child1.id());

            let guest2 = Guest::new(&mut clear2 as &mut dyn DiskConfig);

            let mut child2 = GuestCommand::new(&guest2)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
                .args(&["--kernel", guest2.fw_path.as_str()])
                .default_disks()
                .args(&["--net", guest2.default_net_string().as_str()])
                .args(&["--serial", "tty", "--console", "off"])
                .spawn()
                .unwrap();

            // Let enough time for the second VM to be spawned, and to make
            // sure KSM has enough time to merge identical pages between the
            // 2 VMs.
            thread::sleep(std::time::Duration::new(60, 0));

            // Get new PSS
            let new_pss = get_pss(child1.id());

            // Convert PSS from u32 into float.
            let old_pss = old_pss as f32;
            let new_pss = new_pss as f32;

            if mergeable {
                aver!(tb, new_pss < (old_pss * 0.95));
            } else {
                aver!(tb, (old_pss * 0.95) < new_pss && new_pss < (old_pss * 1.05));
            }

            let _ = child1.kill();
            let _ = child2.kill();
            let _ = child1.wait();
            let _ = child2.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_memory_mergeable_on() {
        test_memory_mergeable(true)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_memory_mergeable_off() {
        test_memory_mergeable(false)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_cpu_hotplug() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");
            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 2);

            // Resize the VM
            let desired_vcpus = 4;
            resize_command(&api_socket, Some(desired_vcpus), None);

            guest.ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")?;
            guest.ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")?;
            thread::sleep(std::time::Duration::new(10, 0));
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or(1);

            aver_eq!(tb, reboot_count, 0);
            guest.ssh_command("sudo reboot").unwrap_or_default();

            thread::sleep(std::time::Duration::new(30, 0));
            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            aver_eq!(tb, reboot_count, 1);

            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            // Resize the VM
            let desired_vcpus = 2;
            resize_command(&api_socket, Some(desired_vcpus), None);

            thread::sleep(std::time::Duration::new(10, 0));
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_memory_hotplug() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");
            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M,hotplug_size=8192M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);

            guest
                .ssh_command("echo online | sudo tee /sys/devices/system/memory/auto_online_blocks")
                .unwrap_or_default();

            // Add RAM to the VM
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram));

            thread::sleep(std::time::Duration::new(10, 0));
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 982_000);

            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or(1);

            aver_eq!(tb, reboot_count, 0);
            guest.ssh_command("sudo reboot").unwrap_or_default();

            thread::sleep(std::time::Duration::new(30, 0));
            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            aver_eq!(tb, reboot_count, 1);

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 982_000);

            guest
                .ssh_command("echo online | sudo tee /sys/devices/system/memory/auto_online_blocks")
                .unwrap_or_default();

            // Add RAM to the VM
            let desired_ram = 2048 << 20;
            resize_command(&api_socket, None, Some(desired_ram));

            thread::sleep(std::time::Duration::new(10, 0));
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 1_964_000);

            // Remove RAM to the VM (only applies after reboot)
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, None, Some(desired_ram));

            guest.ssh_command("sudo reboot").unwrap_or_default();

            thread::sleep(std::time::Duration::new(30, 0));
            let reboot_count = guest
                .ssh_command("sudo journalctl | grep -c -- \"-- Reboot --\"")
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            aver_eq!(tb, reboot_count, 2);

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 982_000);
            aver!(tb, guest.get_total_memory().unwrap_or_default() < 1_964_000);

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    // Test both vCPU and memory resizing together
    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_resize() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let api_socket = temp_api_path(&guest.tmp_dir);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");
            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M,hotplug_size=8192M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 2);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);

            guest
                .ssh_command("echo online | sudo tee /sys/devices/system/memory/auto_online_blocks")
                .unwrap_or_default();

            // Resize the VM
            let desired_vcpus = 4;
            let desired_ram = 1024 << 20;
            resize_command(&api_socket, Some(desired_vcpus), Some(desired_ram));

            guest.ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")?;
            guest.ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")?;
            thread::sleep(std::time::Duration::new(10, 0));
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 982_000);

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    fn get_vmm_overhead(pid: u32, guest_memory_size: u32) -> u32 {
        let smaps = fs::File::open(format!("/proc/{}/smaps", pid)).unwrap();
        let reader = io::BufReader::new(smaps);

        let mut total = 0;
        let mut skip_map: bool = false;
        for line in reader.lines() {
            let l = line.unwrap();

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
            if !skip_map && l.starts_with("Rss") {
                let values: Vec<&str> = l.split_whitespace().collect();
                total += values[1].trim().parse::<u32>().unwrap();
            }
        }
        total
    }

    // 10MB is our maximum accepted overhead.
    const MAXIMUM_VMM_OVERHEAD_KB: u32 = 10 * 1024;

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_memory_overhead() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let guest_memory_size_kb = 512 * 1024;

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus","boot=1"])
                .args(&["--memory", format!("size={}K", guest_memory_size_kb).as_str()])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .default_disks()
                .default_net()
                .args(&["--cmdline", "root=PARTUUID=6fb4d1a8-6c8c-4dd7-9f7c-1fe0b9f2574c console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver!(
                tb,
                get_vmm_overhead(child.id(), guest_memory_size_kb) <= MAXIMUM_VMM_OVERHEAD_KB
            );

            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }
}
