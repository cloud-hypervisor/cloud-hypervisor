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
extern crate test_infra;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod tests {
    use net_util::MacAddr;
    use std::collections::HashMap;
    use std::env;
    use std::ffi::OsStr;
    use std::fs;
    use std::io;
    use std::io::BufRead;
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::string::String;
    use std::sync::mpsc::Receiver;
    use std::sync::{mpsc, Mutex};
    use std::thread;
    use test_infra::*;
    use vmm_sys_util::{tempdir::TempDir, tempfile::TempFile};
    #[cfg_attr(target_arch = "aarch64", allow(unused_imports))]
    use wait_timeout::ChildExt;

    lazy_static! {
        static ref NEXT_VM_ID: Mutex<u8> = Mutex::new(1);
    }

    struct Guest {
        tmp_dir: TempDir,
        disk_config: Box<dyn DiskConfig>,
        fw_path: String,
        network: GuestNetworkConfig,
    }

    // Safe to implement as we know we have no interior mutability
    impl std::panic::RefUnwindSafe for Guest {}

    #[cfg(target_arch = "x86_64")]
    const BIONIC_IMAGE_NAME: &str = "bionic-server-cloudimg-amd64.raw";
    #[cfg(target_arch = "x86_64")]
    const FOCAL_IMAGE_NAME: &str = "focal-server-cloudimg-amd64-custom-20210609-0.raw";
    #[cfg(target_arch = "x86_64")]
    const FOCAL_SGX_IMAGE_NAME: &str = "focal-server-cloudimg-amd64-sgx.raw";
    #[cfg(target_arch = "x86_64")]
    const HIRSUTE_NVIDIA_IMAGE_NAME: &str = "hirsute-server-cloudimg-amd64-nvidia.raw";
    #[cfg(target_arch = "aarch64")]
    const BIONIC_IMAGE_NAME: &str = "bionic-server-cloudimg-arm64.raw";
    #[cfg(target_arch = "aarch64")]
    const FOCAL_IMAGE_NAME: &str = "focal-server-cloudimg-arm64-custom.raw";
    #[cfg(target_arch = "aarch64")]
    const FOCAL_IMAGE_NAME_QCOW2: &str = "focal-server-cloudimg-arm64-custom.qcow2";
    #[cfg(target_arch = "x86_64")]
    const FOCAL_IMAGE_NAME_QCOW2: &str = "focal-server-cloudimg-amd64-custom-20210609-0.qcow2";
    #[cfg(target_arch = "aarch64")]
    const FOCAL_IMAGE_NAME_VHD: &str = "focal-server-cloudimg-arm64-custom.vhd";
    #[cfg(target_arch = "x86_64")]
    const FOCAL_IMAGE_NAME_VHD: &str = "focal-server-cloudimg-amd64-custom-20210609-0.vhd";
    #[cfg(target_arch = "x86_64")]
    const WINDOWS_IMAGE_NAME: &str = "windows-server-2019.raw";
    #[cfg(target_arch = "x86_64")]
    const OVMF_NAME: &str = "OVMF-4b47d0c6c8.fd";

    const DIRECT_KERNEL_BOOT_CMDLINE: &str =
        "root=/dev/vda1 console=hvc0 rw systemd.journald.forward_to_console=1";

    #[cfg(target_arch = "x86_64")]
    const GREP_SERIAL_IRQ_CMD: &str = "grep -c 'IO-APIC.*ttyS0' /proc/interrupts || true";
    #[cfg(target_arch = "aarch64")]
    const GREP_SERIAL_IRQ_CMD: &str = "grep -c 'GICv3.*uart-pl011' /proc/interrupts || true";

    const PIPE_SIZE: i32 = 32 << 20;

    fn clh_command(cmd: &str) -> String {
        env::var("BUILD_TARGET").map_or(
            format!("target/x86_64-unknown-linux-gnu/release/{}", cmd),
            |target| format!("target/{}/release/{}", target, cmd),
        )
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
            String::from(tmp_dir.as_path().join("virtiofs.sock").to_str().unwrap());

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

    fn prepare_virtofsd_rs_daemon(
        tmp_dir: &TempDir,
        shared_dir: &str,
        _cache: &str,
    ) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut virtiofsd_path = workload_path;
        virtiofsd_path.push("virtiofsd-rs");
        let virtiofsd_path = String::from(virtiofsd_path.to_str().unwrap());

        let virtiofsd_socket_path =
            String::from(tmp_dir.as_path().join("virtiofs.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(virtiofsd_path.as_str())
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

        let vubd_socket_path = String::from(tmp_dir.as_path().join("vub.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(clh_command("vhost_user_block"))
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
        String::from(tmp_dir.as_path().join("vsock").to_str().unwrap())
    }

    fn temp_api_path(tmp_dir: &TempDir) -> String {
        String::from(
            tmp_dir
                .as_path()
                .join("cloud-hypervisor.sock")
                .to_str()
                .unwrap(),
        )
    }

    // Creates the directory and returns the path.
    fn temp_snapshot_dir_path(tmp_dir: &TempDir) -> String {
        let snapshot_dir = String::from(tmp_dir.as_path().join("snapshot").to_str().unwrap());
        std::fs::create_dir(&snapshot_dir).unwrap();
        snapshot_dir
    }

    // Creates the path for direct kernel boot and return the path.
    // For x86_64, this function returns the vmlinux kernel path.
    // For AArch64, this function returns the PE kernel path.
    fn direct_kernel_boot_path() -> PathBuf {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut kernel_path = workload_path;
        #[cfg(target_arch = "x86_64")]
        kernel_path.push("vmlinux");
        #[cfg(target_arch = "aarch64")]
        kernel_path.push("Image");

        kernel_path
    }

    fn prepare_vhost_user_net_daemon(
        tmp_dir: &TempDir,
        ip: &str,
        tap: Option<&str>,
        num_queues: usize,
        client_mode: bool,
    ) -> (std::process::Command, String) {
        let vunet_socket_path =
            String::from(tmp_dir.as_path().join("vunet.sock").to_str().unwrap());

        // Start the daemon
        let net_params = if let Some(tap_str) = tap {
            format!(
                "tap={},ip={},mask=255.255.255.0,socket={},num_queues={},queue_size=1024,client={}",
                tap_str, ip, vunet_socket_path, num_queues, client_mode
            )
        } else {
            format!(
                "ip={},mask=255.255.255.0,socket={},num_queues={},queue_size=1024,client={}",
                ip, vunet_socket_path, num_queues, client_mode
            )
        };

        let mut command = Command::new(clh_command("vhost_user_net"));
        command.args(&["--net-backend", net_params.as_str()]);

        (command, vunet_socket_path)
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
    enum Error {
        Parsing(std::num::ParseIntError),
        SshCommand(SshCommandError),
        WaitForBoot(WaitForBootError),
    }

    impl From<SshCommandError> for Error {
        fn from(e: SshCommandError) -> Self {
            Self::SshCommand(e)
        }
    }

    impl Guest {
        fn new_from_ip_range(mut disk_config: Box<dyn DiskConfig>, class: &str, id: u8) -> Self {
            let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();

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

        fn new(disk_config: Box<dyn DiskConfig>) -> Self {
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

        fn ssh_command(&self, command: &str) -> Result<String, SshCommandError> {
            ssh_command_ip(
                command,
                &self.network.guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l1(&self, command: &str) -> Result<String, SshCommandError> {
            ssh_command_ip(
                command,
                &self.network.guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2_1(&self, command: &str) -> Result<String, SshCommandError> {
            ssh_command_ip(
                command,
                &self.network.l2_guest_ip1,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2_2(&self, command: &str) -> Result<String, SshCommandError> {
            ssh_command_ip(
                command,
                &self.network.l2_guest_ip2,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2_3(&self, command: &str) -> Result<String, SshCommandError> {
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
                     direct_kernel_boot_path().to_str().unwrap(),
                     DIRECT_KERNEL_BOOT_CMDLINE,
                     self.network.host_ip,
                     self.network.guest_mac,
                     self.disk_config.disk(DiskType::OperatingSystem).unwrap().as_str(),
                     self.disk_config.disk(DiskType::CloudInit).unwrap().as_str(),
            }
        }

        fn get_cpu_count(&self) -> Result<u32, Error> {
            self.ssh_command("grep -c processor /proc/cpuinfo")?
                .trim()
                .parse()
                .map_err(Error::Parsing)
        }

        fn get_initial_apicid(&self) -> Result<u32, Error> {
            self.ssh_command("grep \"initial apicid\" /proc/cpuinfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(Error::Parsing)
        }

        fn get_total_memory(&self) -> Result<u32, Error> {
            self.ssh_command("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(Error::Parsing)
        }

        fn get_total_memory_l2(&self) -> Result<u32, Error> {
            self.ssh_command_l2_1("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(Error::Parsing)
        }

        fn get_numa_node_memory(&self, node_id: usize) -> Result<u32, Error> {
            self.ssh_command(
                format!(
                    "grep MemTotal /sys/devices/system/node/node{}/meminfo \
                        | cut -d \":\" -f 2 | grep -o \"[0-9]*\"",
                    node_id
                )
                .as_str(),
            )?
            .trim()
            .parse()
            .map_err(Error::Parsing)
        }

        fn wait_vm_boot(&self, custom_timeout: Option<i32>) -> Result<(), Error> {
            self.network
                .wait_vm_boot(custom_timeout)
                .map_err(Error::WaitForBoot)
        }

        fn check_numa_node_cpus(&self, node_id: usize, cpus: Vec<usize>) -> Result<(), Error> {
            for cpu in cpus.iter() {
                let cmd = format!(
                    "[ -d \"/sys/devices/system/node/node{}/cpu{}\" ]",
                    node_id, cpu
                );
                self.ssh_command(cmd.as_str())?;
            }

            Ok(())
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

        fn check_sgx_support(&self) -> Result<(), Error> {
            self.ssh_command(
                "cpuid -l 0x7 -s 0 | tr -s [:space:] | grep -q 'SGX: \
                    Software Guard Extensions supported = true'",
            )?;
            self.ssh_command(
                "cpuid -l 0x7 -s 0 | tr -s [:space:] | grep -q 'SGX_LC: \
                    SGX launch config supported = true'",
            )?;
            self.ssh_command(
                "cpuid -l 0x12 -s 0 | tr -s [:space:] | grep -q 'SGX1 \
                    supported = true'",
            )?;

            Ok(())
        }

        fn get_entropy(&self) -> Result<u32, Error> {
            self.ssh_command("cat /proc/sys/kernel/random/entropy_avail")?
                .trim()
                .parse()
                .map_err(Error::Parsing)
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
            // SHM region is called different things depending on kernel
            let shm_region = self
                .ssh_command("sudo grep 'virtio[0-9]\\|virtio-pci-shm' /proc/iomem || true")?
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
            assert!(exec_host_command_status(&format!(
                "echo -e \"CONNECT 16\\nHelloWorld!\" | socat - UNIX-CONNECT:{}",
                socket
            ))
            .success());

            // Wait for the thread to terminate.
            listen_socat.join().unwrap();

            assert_eq!(
                self.ssh_command("cat vsock_log").unwrap().trim(),
                "HelloWorld!"
            );
        }

        fn check_nvidia_gpu(&self) {
            // Run CUDA sample to validate it can find the device
            let device_query_result = self
                .ssh_command(
                    "sudo /root/NVIDIA_CUDA-11.3_Samples/bin/x86_64/linux/release/deviceQuery",
                )
                .unwrap();
            assert!(device_query_result.contains("Detected 1 CUDA Capable device"));
            assert!(device_query_result.contains("Device 0: \"NVIDIA Tesla T4\""));
            assert!(device_query_result.contains("Result = PASS"));

            // Run NVIDIA DCGM Diagnostics to validate the device is functional
            self.ssh_command("sudo nv-hostengine").unwrap();

            assert!(self
                .ssh_command("sudo dcgmi discovery -l")
                .unwrap()
                .contains("Name: NVIDIA Tesla T4"));
            assert_eq!(
                self.ssh_command("sudo dcgmi diag -r 'diagnostic' | grep Pass | wc -l")
                    .unwrap()
                    .trim(),
                "10"
            );
        }

        fn reboot_linux(&self, current_reboot_count: u32, custom_timeout: Option<i32>) {
            let list_boots_cmd = "sudo journalctl --list-boots | wc -l";
            let boot_count = self
                .ssh_command(list_boots_cmd)
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();

            assert_eq!(boot_count, current_reboot_count + 1);
            self.ssh_command("sudo reboot").unwrap();

            self.wait_vm_boot(custom_timeout).unwrap();
            let boot_count = self
                .ssh_command(list_boots_cmd)
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap_or_default();
            assert_eq!(boot_count, current_reboot_count + 2);
        }

        fn enable_memory_hotplug(&self) {
            self.ssh_command(
                "echo online | sudo tee /sys/devices/system/memory/auto_online_blocks",
            )
            .unwrap();
        }
    }

    struct GuestCommand<'a> {
        command: Command,
        guest: &'a Guest,
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
            if self.guest.disk_config.disk(DiskType::CloudInit).is_some() {
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
            } else {
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
                ])
            }
        }

        fn default_net(&mut self) -> &mut Self {
            self.args(&["--net", self.guest.default_net_string().as_str()])
        }
    }

    fn test_cpu_topology(threads_per_core: u8, cores_per_package: u8, packages: u8) {
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));
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
            .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
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
        });

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        handle_child_output(r, &output);
    }

    type PrepareNetDaemon =
        dyn Fn(&TempDir, &str, Option<&str>, usize, bool) -> (std::process::Command, String);

    fn test_vhost_user_net(
        tap: Option<&str>,
        num_queues: usize,
        prepare_daemon: &PrepareNetDaemon,
        generate_host_mac: bool,
        client_mode_daemon: bool,
    ) {
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();

        let host_mac = if generate_host_mac {
            Some(MacAddr::local_random())
        } else {
            None
        };

        let (mut daemon_command, vunet_socket_path) = prepare_daemon(
            &guest.tmp_dir,
            &guest.network.host_ip,
            tap,
            num_queues,
            client_mode_daemon,
        );

        let net_params = format!(
            "vhost_user=true,mac={},socket={},num_queues={},queue_size=1024{},vhost_mode={}",
            guest.network.guest_mac,
            vunet_socket_path,
            num_queues,
            if let Some(host_mac) = host_mac {
                format!(",host_mac={}", host_mac)
            } else {
                "".to_owned()
            },
            if client_mode_daemon {
                "server"
            } else {
                "client"
            },
        );

        let mut ch_command = GuestCommand::new(&guest);
        ch_command
            .args(&["--cpus", format!("boot={}", num_queues / 2).as_str()])
            .args(&["--memory", "size=512M,hotplug_size=2048M,shared=on"])
            .args(&["--kernel", kernel_path.to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(&["--net", net_params.as_str()])
            .args(&["--api-socket", &api_socket])
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
            guest.wait_vm_boot(None).unwrap();

            if let Some(tap_name) = tap {
                let tap_count =
                    exec_host_command_output(&format!("ip link | grep -c {}", tap_name));
                assert_eq!(String::from_utf8_lossy(&tap_count.stdout).trim(), "1");
            }

            if let Some(host_mac) = tap {
                let mac_count =
                    exec_host_command_output(&format!("ip link | grep -c {}", host_mac));
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
            #[cfg(target_arch = "x86_64")]
            let grep_cmd = "grep -c PCI-MSI /proc/interrupts";
            #[cfg(target_arch = "aarch64")]
            let grep_cmd = "grep -c ITS-MSI /proc/interrupts";
            assert_eq!(
                guest
                    .ssh_command(grep_cmd)
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                10 + (num_queues as u32)
            );

            // ACPI feature is needed.
            #[cfg(feature = "acpi")]
            {
                guest.enable_memory_hotplug();

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

        thread::sleep(std::time::Duration::new(5, 0));
        let _ = daemon_child.kill();
        let _ = daemon_child.wait();

        handle_child_output(r, &output);
    }

    type PrepareBlkDaemon =
        dyn Fn(&TempDir, &str, usize, bool, bool) -> (std::process::Child, String);

    fn test_vhost_user_blk(
        num_queues: usize,
        readonly: bool,
        direct: bool,
        prepare_vhost_user_blk_daemon: Option<&PrepareBlkDaemon>,
    ) {
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let kernel_path = direct_kernel_boot_path();

        let (blk_params, daemon_child) = {
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
                guest.ssh_command("cat mount_image/foo").unwrap().trim(),
                "bar"
            );

            // ACPI feature is needed.
            #[cfg(feature = "acpi")]
            {
                guest.enable_memory_hotplug();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

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
    ) {
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));

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
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));
        let api_socket = temp_api_path(&guest.tmp_dir);

        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut shared_dir = workload_path;
        shared_dir.push("shared_dir");

        let kernel_path = direct_kernel_boot_path();

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
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .default_net()
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
                 sudo mount -t virtiofs {} myfs mount_dir/",
                dax_mount_param
            );
            guest.ssh_command(&mount_cmd).unwrap();

            assert!(guest
                .valid_virtio_fs_cache_size(dax, cache_size)
                .unwrap_or_default());

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
            #[cfg(feature = "acpi")]
            {
                guest.enable_memory_hotplug();

                // Add RAM to the VM
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

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
                     sudo mount -t virtiofs {} myfs mount_dir/",
                    dax_mount_param
                );
                guest.ssh_command(&mount_cmd).unwrap();
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
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));

        let kernel_path = direct_kernel_boot_path();

        let pmem_temp_file = TempFile::new().unwrap();
        pmem_temp_file.as_file().set_len(128 << 20).unwrap();

        std::process::Command::new("mkfs.ext4")
            .arg(pmem_temp_file.as_path())
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
            guest.wait_vm_boot(None).unwrap();

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

            guest.reboot_linux(0, None);
            assert_eq!(guest.ssh_command("sudo mount /dev/pmem0 /mnt").unwrap(), "");
            assert_eq!(
                guest
                    .ssh_command("sudo cat /mnt/test || true")
                    .unwrap()
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
        let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest = Guest::new(Box::new(focal));

        let kernel_path = direct_kernel_boot_path();

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
                guest.reboot_linux(0, None);

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

    fn get_ksm_pages_shared() -> u32 {
        fs::read_to_string("/sys/kernel/mm/ksm/pages_shared")
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    }

    fn test_memory_mergeable(mergeable: bool) {
        let memory_param = if mergeable {
            "mergeable=on"
        } else {
            "mergeable=off"
        };

        // We are assuming the rest of the system in our CI is not using mergeable memeory
        let ksm_ps_init = get_ksm_pages_shared();
        assert!(ksm_ps_init == 0);

        let focal1 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest1 = Guest::new(Box::new(focal1));
        let mut child1 = GuestCommand::new(&guest1)
            .args(&["--cpus", "boot=1"])
            .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
            .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(&["--net", guest1.default_net_string().as_str()])
            .args(&["--serial", "tty", "--console", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest1.wait_vm_boot(None).unwrap();
        });
        if r.is_err() {
            let _ = child1.kill();
            let output = child1.wait_with_output().unwrap();
            handle_child_output(r, &output);
            panic!("Test should already be failed/panicked"); // To explicitly mark this block never return
        }

        let ksm_ps_guest1 = get_ksm_pages_shared();

        let focal2 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest2 = Guest::new(Box::new(focal2));
        let mut child2 = GuestCommand::new(&guest2)
            .args(&["--cpus", "boot=1"])
            .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
            .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
            .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
            .default_disks()
            .args(&["--net", guest2.default_net_string().as_str()])
            .args(&["--serial", "tty", "--console", "off"])
            .capture_output()
            .spawn()
            .unwrap();

        let r = std::panic::catch_unwind(|| {
            guest2.wait_vm_boot(None).unwrap();
            let ksm_ps_guest2 = get_ksm_pages_shared();

            if mergeable {
                println!(
                    "ksm pages_shared after vm1 booted '{}', ksm pages_shared after vm2 booted '{}'",
                    ksm_ps_guest1, ksm_ps_guest2
                );
                // We are expecting the number of shared pages to increase as the number of VM increases
                assert!(ksm_ps_guest1 < ksm_ps_guest2);
            } else {
                assert!(ksm_ps_guest1 == 0);
                assert!(ksm_ps_guest2 == 0);
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
        let (cmd_success, cmd_output) = remote_command_w_output(api_socket, "counters", None);
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
            write_bytes,
            read_ops,
            write_ops,
        }
    }

    fn pty_read(mut pty: std::fs::File) -> Receiver<String> {
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::new(1, 0));
            let mut buf = [0; 512];
            match pty.read(&mut buf) {
                Ok(_) => {
                    let output = std::str::from_utf8(&buf).unwrap().to_string();
                    match tx.send(output) {
                        Ok(_) => (),
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        });
        rx
    }

    fn get_pty_path(api_socket: &str, pty_type: &str) -> PathBuf {
        let (cmd_success, cmd_output) = remote_command_w_output(api_socket, "info", None);
        assert!(cmd_success);
        let info: serde_json::Value = serde_json::from_slice(&cmd_output).unwrap_or_default();
        assert_eq!("Pty", info["config"][pty_type]["mode"]);
        PathBuf::from(
            info["config"][pty_type]["file"]
                .as_str()
                .expect("Missing pty path"),
        )
    }

    // VFIO test network setup.
    // We reserve a different IP class for it: 172.18.0.0/24.
    fn setup_vfio_network_interfaces() {
        // 'vfio-br0'
        assert!(exec_host_command_status("sudo ip link add name vfio-br0 type bridge").success());
        assert!(exec_host_command_status("sudo ip link set vfio-br0 up").success());
        assert!(exec_host_command_status("sudo ip addr add 172.18.0.1/24 dev vfio-br0").success());
        // 'vfio-tap0'
        assert!(exec_host_command_status("sudo ip tuntap add vfio-tap0 mode tap").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap0 master vfio-br0").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap0 up").success());
        // 'vfio-tap1'
        assert!(exec_host_command_status("sudo ip tuntap add vfio-tap1 mode tap").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap1 master vfio-br0").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap1 up").success());
        // 'vfio-tap2'
        assert!(exec_host_command_status("sudo ip tuntap add vfio-tap2 mode tap").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap2 master vfio-br0").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap2 up").success());
        // 'vfio-tap3'
        assert!(exec_host_command_status("sudo ip tuntap add vfio-tap3 mode tap").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap3 master vfio-br0").success());
        assert!(exec_host_command_status("sudo ip link set vfio-tap3 up").success());
    }

    // Tear VFIO test network down
    fn cleanup_vfio_network_interfaces() {
        assert!(exec_host_command_status("sudo ip link del vfio-br0").success());
        assert!(exec_host_command_status("sudo ip link del vfio-tap0").success());
        assert!(exec_host_command_status("sudo ip link del vfio-tap1").success());
        assert!(exec_host_command_status("sudo ip link del vfio-tap2").success());
        assert!(exec_host_command_status("sudo ip link del vfio-tap3").success());
    }

    fn balloon_size(api_socket: &str) -> u64 {
        let (cmd_success, cmd_output) = remote_command_w_output(api_socket, "info", None);
        assert!(cmd_success);

        let info: serde_json::Value = serde_json::from_slice(&cmd_output).unwrap_or_default();
        let total_mem = &info["config"]["memory"]["size"]
            .to_string()
            .parse::<u64>()
            .unwrap();
        let actual_mem = &info["memory_actual_size"]
            .to_string()
            .parse::<u64>()
            .unwrap();
        total_mem - actual_mem
    }

    mod parallel {
        use crate::tests::*;

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_simple_launch() {
            let bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

            vec![Box::new(bionic), Box::new(focal)]
                .drain(..)
                .for_each(|disk_config| {
                    let guest = Guest::new(disk_config);

                    let mut child = GuestCommand::new(&guest)
                        .args(&["--cpus", "boot=1"])
                        .args(&["--memory", "size=512M"])
                        .args(&["--kernel", guest.fw_path.as_str()])
                        .default_disks()
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
        #[cfg(all(target_arch = "aarch64", feature = "acpi"))]
        fn test_edk2_acpi_launch() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");
            let mut edk2_path = workload_path;
            edk2_path.push("CLOUDHV_EFI.fd");

            vec![Box::new(focal)].drain(..).for_each(|disk_config| {
                let guest = Guest::new(disk_config);

                let mut child = GuestCommand::new(&guest)
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", edk2_path.to_str().unwrap()])
                    .default_disks()
                    .default_net()
                    .args(&["--serial", "tty", "--console", "off"])
                    .capture_output()
                    .spawn()
                    .unwrap();

                let r = std::panic::catch_unwind(|| {
                    guest.wait_vm_boot(Some(120)).unwrap();

                    assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                    assert!(guest.get_total_memory().unwrap_or_default() > 400_000);
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
            let bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(bionic));
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .default_disks()
                .default_net();

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
                        .unwrap()
                        .trim(),
                    "smpboot: Allowing 4 CPUs, 2 hotplug CPUs"
                );
                #[cfg(target_arch = "aarch64")]
                assert_eq!(
                    guest
                        .ssh_command(
                            r#"dmesg | grep "smp: Brought up" | sed "s/\[\ *[0-9.]*\] //""#
                        )
                        .unwrap()
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let max_phys_bits: u8 = 36;
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", &format!("max_phys_bits={}", max_phys_bits)])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
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
                        .unwrap()
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=48"])
                .args(&["--memory", "size=5120M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .capture_output()
                .default_disks()
                .default_net();

            let mut child = cmd.spawn().unwrap();

            guest.wait_vm_boot(None).unwrap();

            let r = std::panic::catch_unwind(|| {
                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 48);
                assert_eq!(
                    guest
                        .ssh_command(
                            "lscpu | grep \"On-line\" | cut -f 2 -d \":\" | sed \"s# *##\""
                        )
                        .unwrap()
                        .trim(),
                    "0-47"
                );

                assert!(guest.get_total_memory().unwrap_or_default() > 5_000_000);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_huge_memory() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=128G"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .default_disks()
                .default_net();

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
        fn test_power_button() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut cmd = GuestCommand::new(&guest);
            let api_socket = temp_api_path(&guest.tmp_dir);

            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .default_disks()
                .default_net()
                .args(&["--api-socket", &api_socket]);

            let child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();
                assert!(remote_command(&api_socket, "power-button", None));
            });

            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_user_defined_memory_regions() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

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

                guest.enable_memory_hotplug();

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

                guest.reboot_linux(0, None);

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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=6,max=12"])
                .args(&["--memory", "size=0,hotplug_method=virtio-mem"])
                .args(&[
                    "--memory-zone",
                    "id=mem0,size=1G,hotplug_size=3G",
                    "id=mem1,size=2G,hotplug_size=3G",
                    "id=mem2,size=3G,hotplug_size=3G",
                ])
                .args(&[
                    "--numa",
                    "guest_numa_id=0,cpus=0-2:9,distances=1@15:2@20,memory_zones=mem0",
                    "guest_numa_id=1,cpus=3-4:6-8,distances=0@20:2@25,memory_zones=mem1",
                    "guest_numa_id=2,cpus=5:10-11,distances=0@25:1@30,memory_zones=mem2",
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
                guest.check_numa_node_cpus(0, vec![0, 1, 2]).unwrap();
                guest.check_numa_node_cpus(1, vec![3, 4]).unwrap();
                guest.check_numa_node_cpus(2, vec![5]).unwrap();

                // Check each NUMA node has been assigned the right distances.
                assert!(guest.check_numa_node_distances(0, "10 15 20").unwrap());
                assert!(guest.check_numa_node_distances(1, "20 10 25").unwrap());
                assert!(guest.check_numa_node_distances(2, "25 30 10").unwrap());

                guest.enable_memory_hotplug();

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

                // Resize to the maximum amount of CPUs and check each NUMA
                // node has been assigned the right CPUs set.
                resize_command(&api_socket, Some(12), None, None);
                guest.check_numa_node_cpus(0, vec![0, 1, 2, 9]).unwrap();
                guest.check_numa_node_cpus(1, vec![3, 4, 6, 7, 8]).unwrap();
                guest.check_numa_node_cpus(2, vec![5, 10, 11]).unwrap();
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_pci_msi() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .capture_output()
                .default_disks()
                .default_net();

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
                        .unwrap()
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
        fn test_direct_kernel_boot() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

            let mut child = GuestCommand::new(&guest)
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

                assert_eq!(guest.get_cpu_count().unwrap_or_default(), 1);
                assert!(guest.get_total_memory().unwrap_or_default() > 480_000);
                assert!(guest.get_entropy().unwrap_or_default() >= 900);

                let grep_cmd = if cfg!(target_arch = "x86_64") {
                    "grep -c PCI-MSI /proc/interrupts"
                } else {
                    "grep -c ITS-MSI /proc/interrupts"
                };
                assert_eq!(
                    guest
                        .ssh_command(grep_cmd)
                        .unwrap()
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

        fn _test_virtio_block(image_name: &str, disable_io_uring: bool) {
            let focal = UbuntuDiskConfig::new(image_name.to_string());
            let guest = Guest::new(Box::new(focal));

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut blk_file_path = workload_path;
            blk_file_path.push("blk.img");

            let kernel_path = direct_kernel_boot_path();

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
                        "path={},readonly=on,direct=on,num_queues=4,_disable_io_uring={}",
                        blk_file_path.to_str().unwrap(),
                        disable_io_uring
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

            let _ = cloud_child.kill();
            let output = cloud_child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_virtio_block() {
            _test_virtio_block(FOCAL_IMAGE_NAME, false)
        }

        #[test]
        fn test_virtio_block_disable_io_uring() {
            _test_virtio_block(FOCAL_IMAGE_NAME, true)
        }

        #[test]
        fn test_virtio_block_qcow2() {
            _test_virtio_block(FOCAL_IMAGE_NAME_QCOW2, false)
        }

        #[test]
        fn test_virtio_block_vhd() {
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut raw_file_path = workload_path.clone();
            let mut vhd_file_path = workload_path;
            raw_file_path.push(FOCAL_IMAGE_NAME);
            vhd_file_path.push(FOCAL_IMAGE_NAME_VHD);

            // Generate VHD file from RAW file
            std::process::Command::new("qemu-img")
                .arg("convert")
                .arg("-p")
                .args(&["-f", "raw"])
                .args(&["-O", "vpc"])
                .args(&["-o", "subformat=fixed"])
                .arg(raw_file_path.to_str().unwrap())
                .arg(vhd_file_path.to_str().unwrap())
                .output()
                .expect("Expect generating VHD image from RAW image");

            _test_virtio_block(FOCAL_IMAGE_NAME_VHD, false)
        }

        #[test]
        fn test_vhost_user_net_default() {
            test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon, false, false)
        }

        #[test]
        fn test_vhost_user_net_named_tap() {
            test_vhost_user_net(
                Some("mytap0"),
                2,
                &prepare_vhost_user_net_daemon,
                false,
                false,
            )
        }

        #[test]
        fn test_vhost_user_net_existing_tap() {
            test_vhost_user_net(
                Some("vunet-tap0"),
                2,
                &prepare_vhost_user_net_daemon,
                false,
                false,
            )
        }

        #[test]
        fn test_vhost_user_net_multiple_queues() {
            test_vhost_user_net(None, 4, &prepare_vhost_user_net_daemon, false, false)
        }

        #[test]
        fn test_vhost_user_net_tap_multiple_queues() {
            test_vhost_user_net(
                Some("vunet-tap1"),
                4,
                &prepare_vhost_user_net_daemon,
                false,
                false,
            )
        }

        #[test]
        fn test_vhost_user_net_host_mac() {
            test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon, true, false)
        }

        #[test]
        fn test_vhost_user_net_client_mode() {
            test_vhost_user_net(None, 2, &prepare_vhost_user_net_daemon, false, true)
        }

        #[test]
        fn test_vhost_user_blk_default() {
            test_vhost_user_blk(2, false, false, Some(&prepare_vubd))
        }

        #[test]
        fn test_vhost_user_blk_readonly() {
            test_vhost_user_blk(1, true, false, Some(&prepare_vubd))
        }

        #[test]
        fn test_vhost_user_blk_direct() {
            test_vhost_user_blk(1, false, true, Some(&prepare_vubd))
        }

        #[test]
        fn test_boot_from_vhost_user_blk_default() {
            test_boot_from_vhost_user_blk(1, false, false, Some(&prepare_vubd))
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_split_irqchip() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

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
        fn test_virtio_fs_dax_on_default_cache_size_w_virtiofsd_rs_daemon() {
            test_virtio_fs(true, None, "none", &prepare_virtofsd_rs_daemon, false)
        }

        #[test]
        fn test_virtio_fs_dax_on_cache_size_1_gib_w_virtiofsd_rs_daemon() {
            test_virtio_fs(
                true,
                Some(0x4000_0000),
                "none",
                &prepare_virtofsd_rs_daemon,
                false,
            )
        }

        #[test]
        fn test_virtio_fs_dax_off_w_virtiofsd_rs_daemon() {
            test_virtio_fs(false, None, "none", &prepare_virtofsd_rs_daemon, false)
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
        fn test_virtio_fs_hotplug_dax_on_w_virtiofsd_rs_daemon() {
            test_virtio_fs(true, None, "none", &prepare_virtofsd_rs_daemon, true)
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_fs_hotplug_dax_off_w_virtiofsd_rs_daemon() {
            test_virtio_fs(false, None, "none", &prepare_virtofsd_rs_daemon, true)
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

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
                        guest.disk_config.disk(DiskType::OperatingSystem).unwrap(),
                        fs::metadata(&guest.disk_config.disk(DiskType::OperatingSystem).unwrap())
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

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

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_serial_off() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--serial", "off"])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

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

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_serial_null() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut cmd = GuestCommand::new(&guest);
            #[cfg(target_arch = "x86_64")]
            let console_str: &str = "console=ttyS0";
            #[cfg(target_arch = "aarch64")]
            let console_str: &str = "console=ttyAMA0";

            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&[
                    "--cmdline",
                    DIRECT_KERNEL_BOOT_CMDLINE
                        .replace("console=hvc0 ", console_str)
                        .as_str(),
                ])
                .default_disks()
                .default_net()
                .args(&["--serial", "null"])
                .args(&["--console", "off"])
                .capture_output();

            let mut child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Test that there is a ttyS0
                assert_eq!(
                    guest
                        .ssh_command(GREP_SERIAL_IRQ_CMD)
                        .unwrap()
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
        fn test_serial_tty() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

            #[cfg(target_arch = "x86_64")]
            let console_str: &str = "console=ttyS0";
            #[cfg(target_arch = "aarch64")]
            let console_str: &str = "console=ttyAMA0";

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--cmdline",
                    DIRECT_KERNEL_BOOT_CMDLINE
                        .replace("console=hvc0 ", console_str)
                        .as_str(),
                ])
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
                        .ssh_command(GREP_SERIAL_IRQ_CMD)
                        .unwrap()
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
        fn test_serial_file() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let serial_path = guest.tmp_dir.as_path().join("/tmp/serial-output");
            #[cfg(target_arch = "x86_64")]
            let console_str: &str = "console=ttyS0";
            #[cfg(target_arch = "aarch64")]
            let console_str: &str = "console=ttyAMA0";

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&[
                    "--cmdline",
                    DIRECT_KERNEL_BOOT_CMDLINE
                        .replace("console=hvc0 ", console_str)
                        .as_str(),
                ])
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
                        .ssh_command(GREP_SERIAL_IRQ_CMD)
                        .unwrap()
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
                assert!(output.status.success());

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
        fn test_pty_interaction() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);
            let serial_option = if cfg!(target_arch = "x86_64") {
                " console=ttyS0"
            } else {
                " console=ttyAMA0"
            };
            let cmdline = DIRECT_KERNEL_BOOT_CMDLINE.to_owned() + serial_option;

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", &cmdline])
                .default_disks()
                .default_net()
                .args(&["--serial", "null"])
                .args(&["--console", "pty"])
                .args(&["--api-socket", &api_socket])
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();
                // Get pty fd for console
                let console_path = get_pty_path(&api_socket, "console");
                // TODO: Get serial pty test working
                let mut cf = std::fs::OpenOptions::new()
                    .write(true)
                    .read(true)
                    .open(console_path)
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
                            if empty > 5 {
                                panic!("No login on pty");
                            }
                        }
                        _ => panic!("No login on pty"),
                    }
                }

                guest.ssh_command("sudo shutdown -h now").unwrap();
            });

            let _ = child.wait_timeout(std::time::Duration::from_secs(20));
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            handle_child_output(r, &output);

            let r = std::panic::catch_unwind(|| {
                // Check that the cloud-hypervisor binary actually terminated
                assert!(output.status.success())
            });
            handle_child_output(r, &output);
        }

        #[test]
        fn test_virtio_console() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

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
        fn test_console_file() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let console_path = guest.tmp_dir.as_path().join("/tmp/console-output");
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
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
                assert!(output.status.success());

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
            setup_vfio_network_interfaces();

            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new_from_ip_range(Box::new(focal), "172.18", 0);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let kernel_path = direct_kernel_boot_path();

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
                        .unwrap()
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
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                // Check the amount of PCI devices appearing in L2 VM.
                assert_eq!(
                    guest
                        .ssh_command_l2_1("ls /sys/bus/pci/devices | wc -l")
                        .unwrap()
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
                        "echo 0000:00:08.0 | sudo tee /sys/bus/pci/drivers/vfio-pci/bind",
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
                        .unwrap()
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
                        .unwrap()
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
                        .unwrap()
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

            cleanup_vfio_network_interfaces();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_direct_kernel_boot_noacpi() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--cmdline",
                    format!("{} acpi=off", DIRECT_KERNEL_BOOT_CMDLINE).as_str(),
                ])
                .default_disks()
                .default_net()
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
            let bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());

            vec![Box::new(bionic), Box::new(focal)]
                .drain(..)
                .for_each(|disk_config| {
                    let guest = Guest::new(disk_config);

                    let mut cmd = GuestCommand::new(&guest);
                    cmd.args(&["--cpus", "boot=1"])
                        .args(&["--memory", "size=512M"])
                        .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                        .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                        .default_disks()
                        .default_net()
                        .capture_output();

                    let mut child = cmd.spawn().unwrap();

                    let r = std::panic::catch_unwind(|| {
                        guest.wait_vm_boot(Some(120)).unwrap();

                        let fd_count_1 = get_fd_count(child.id());
                        guest.reboot_linux(0, Some(120));
                        let fd_count_2 = get_fd_count(child.id());
                        assert_eq!(fd_count_1, fd_count_2);

                        guest.ssh_command("sudo shutdown -h now").unwrap();
                    });

                    let _ = child.wait_timeout(std::time::Duration::from_secs(40));
                    let _ = child.kill();
                    let output = child.wait_with_output().unwrap();
                    handle_child_output(r, &output);

                    let r = std::panic::catch_unwind(|| {
                        // Check that the cloud-hypervisor binary actually terminated
                        assert!(output.status.success());
                    });

                    handle_child_output(r, &output);
                });
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

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
        // Start cloud-hypervisor with no VM parameters, only the API server running.
        // From the API: Create a VM, boot it and check that it looks as expected.
        // Then we pause the VM, check that it's no longer available.
        // Finally we resume the VM and check that it's available.
        fn test_api_pause_resume() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
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
                            .unwrap()
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

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

                guest.reboot_linux(0, None);

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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

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

                guest.enable_memory_hotplug();

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

                guest.reboot_linux(0, None);

                assert!(guest.get_total_memory().unwrap_or_default() < 960_000);

                // Use balloon add RAM to the VM
                let desired_balloon = 0;
                resize_command(&api_socket, None, None, Some(desired_balloon));

                thread::sleep(std::time::Duration::new(10, 0));

                assert!(guest.get_total_memory().unwrap_or_default() > 960_000);

                guest.enable_memory_hotplug();

                // Add RAM to the VM
                let desired_ram = 2048 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                thread::sleep(std::time::Duration::new(10, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 1_920_000);

                // Remove RAM to the VM (only applies after reboot)
                let desired_ram = 1024 << 20;
                resize_command(&api_socket, None, Some(desired_ram), None);

                guest.reboot_linux(1, None);

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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

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

                guest.enable_memory_hotplug();

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

                guest.reboot_linux(0, None);

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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

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

                guest.enable_memory_hotplug();

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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

            let guest_memory_size_kb = 512 * 1024;

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&[
                    "--memory",
                    format!("size={}K", guest_memory_size_kb).as_str(),
                ])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

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
                guest.reboot_linux(0, None);

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

                guest.reboot_linux(1, None);

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

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_virtio_balloon() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

            let api_socket = temp_api_path(&guest.tmp_dir);

            //Let's start a 4G guest with balloon occupied 2G memory
            let mut child = GuestCommand::new(&guest)
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .args(&["--balloon", "size=2G,deflate_on_oom=on"])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Wait for balloon memory's initialization and check its size.
                // The virtio-balloon driver might take a few seconds to report the
                // balloon effective size back to the VMM.
                thread::sleep(std::time::Duration::new(20, 0));

                let orig_balloon = balloon_size(&api_socket);
                println!("The original balloon memory size is {} bytes", orig_balloon);
                assert!(orig_balloon == 2147483648);

                // Two steps to verify if the 'deflate_on_oom' parameter works.
                // 1st: run a command in guest to eat up memory heavily, which
                // will consume much more memory than $(total_mem - balloon_size)
                // to trigger an oom.
                guest
                    .ssh_command("sudo stress --vm 25 --vm-keep --vm-bytes 1G --timeout 20")
                    .unwrap();

                // 2nd: check balloon_mem's value to verify balloon has been automatically deflated
                let deflated_balloon = balloon_size(&api_socket);
                println!(
                    "After deflating, balloon memory size is {} bytes",
                    deflated_balloon
                );
                // Verify the balloon size deflated
                assert!(deflated_balloon < 2147483648);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_pmem_hotplug() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

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
                        .ssh_command("lsblk | grep -c pmem0 || true")
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                let pmem_temp_file = TempFile::new().unwrap();
                pmem_temp_file.as_file().set_len(128 << 20).unwrap();
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-pmem",
                    Some(&format!(
                        "file={},id=test0",
                        pmem_temp_file.as_path().to_str().unwrap()
                    )),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"test0\",\"bdf\":\"0000:00:06.0\"}"));

                // Check that /dev/pmem0 exists and the block size is 128M
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep pmem0 | grep -c 128M")
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    1
                );

                guest.reboot_linux(0, None);

                // Check still there after reboot
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep pmem0 | grep -c 128M")
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
                        .ssh_command("lsblk | grep -c pmem0.*128M || true")
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1),
                    0
                );

                guest.reboot_linux(1, None);

                // Check still absent after reboot
                assert_eq!(
                    guest
                        .ssh_command("lsblk | grep -c pmem0.*128M || true")
                        .unwrap()
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));

            let kernel_path = direct_kernel_boot_path();

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
                        .unwrap()
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
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );

                guest.reboot_linux(0, None);

                // Check still there after reboot
                // 1 network interfaces + default localhost ==> 2 interfaces
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

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_initramfs() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernels = vec![direct_kernel_boot_path()];

            #[cfg(target_arch = "x86_64")]
            {
                let mut pvh_kernel_path = workload_path.clone();
                pvh_kernel_path.push("vmlinux");
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
        #[cfg(target_arch = "x86_64")]
        fn test_snapshot_restore() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let kernel_path = direct_kernel_boot_path();

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
                guest
                    .ssh_command("sudo dd if=/dev/vda of=/dev/null bs=1M iflag=direct count=1024")
                    .unwrap();
                guest
                    .ssh_command("sudo dd if=/dev/vdb of=/dev/null bs=1M iflag=direct count=8")
                    .unwrap();
                // Check if the rng device is readable
                guest
                    .ssh_command("sudo head -c 1000 /dev/hwrng > /dev/null")
                    .unwrap();
                // Check vsock
                guest.check_vsock(socket.as_str());
                // Check if the console is usable

                guest.ssh_command(&console_cmd).unwrap();

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
                guest
                    .ssh_command("sudo dd if=/dev/vda of=/dev/null bs=1M iflag=direct count=1024")
                    .unwrap();
                guest
                    .ssh_command("sudo dd if=/dev/vdb of=/dev/null bs=1M iflag=direct count=8")
                    .unwrap();
                guest
                    .ssh_command("sudo head -c 1000 /dev/hwrng > /dev/null")
                    .unwrap();
                guest.check_vsock(socket.as_str());
                guest.ssh_command(&console_cmd).unwrap();
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
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut cmd = GuestCommand::new(&guest);
            cmd.args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--api-socket", &api_socket])
                .capture_output();

            let mut child = cmd.spawn().unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                let orig_counters = get_counters(&api_socket);
                guest
                    .ssh_command("dd if=/dev/zero of=test count=8 bs=1M")
                    .unwrap();

                let new_counters = get_counters(&api_socket);

                // Check that all the counters have increased
                assert!(new_counters > orig_counters);
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_watchdog() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let kernel_path = direct_kernel_boot_path();

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
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );

                // Ensure that the current boot journal is written so reboot counts are valid
                guest.ssh_command("sudo journalctl --sync").unwrap();

                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 2);
                // Allow some normal time to elapse to check we don't get spurious reboots
                thread::sleep(std::time::Duration::new(40, 0));

                // Check no reboot
                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 2);

                // Ensure that the current boot journal is written so reboot counts are valid
                guest.ssh_command("sudo journalctl --sync").unwrap();

                // Trigger a panic (sync first). We need to do this inside a screen with a delay so the SSH command returns.
                guest.ssh_command("screen -dmS reboot sh -c \"sleep 5; echo s | tee /proc/sysrq-trigger; echo c | sudo tee /proc/sysrq-trigger\"").unwrap();

                // Allow some time for the watchdog to trigger (max 30s) and reboot to happen
                guest.wait_vm_boot(Some(50)).unwrap();

                // Check that watchdog triggered reboot
                let boot_count = guest
                    .ssh_command("sudo journalctl --list-boots | wc -l")
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default();
                assert_eq!(boot_count, 3);

                #[cfg(target_arch = "x86_64")]
                {
                    // Now pause the VM and remain offline for 30s
                    assert!(remote_command(&api_socket, "pause", None));
                    thread::sleep(std::time::Duration::new(30, 0));
                    assert!(remote_command(&api_socket, "resume", None));

                    // Check no reboot
                    let boot_count = guest
                        .ssh_command("sudo journalctl --list-boots | wc -l")
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default();
                    assert_eq!(boot_count, 3);
                }
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_tap_from_fd() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let kernel_path = direct_kernel_boot_path();

            // Create a TAP interface with multi-queue enabled
            let num_queue_pairs: usize = 2;

            use std::str::FromStr;
            let taps = net_util::open_tap(
                Some("chtap0"),
                Some(std::net::Ipv4Addr::from_str(&guest.network.host_ip).unwrap()),
                None,
                &mut None,
                num_queue_pairs,
                Some(libc::O_RDWR | libc::O_NONBLOCK),
            )
            .unwrap();

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", &format!("boot={}", num_queue_pairs)])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&[
                    "--net",
                    &format!(
                        "fd={}:{},mac={},num_queues={}",
                        taps[0].as_raw_fd(),
                        taps[1].as_raw_fd(),
                        guest.network.guest_mac,
                        num_queue_pairs * 2
                    ),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert_eq!(
                    guest
                        .ssh_command("ip -o link | wc -l")
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap_or_default(),
                    2
                );

                guest.reboot_linux(0, None);

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

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        // By design, a guest VM won't be able to connect to the host
        // machine when using a macvtap network interface (while it can
        // communicate externally). As a workaround, this integration
        // test creates two macvtap interfaces in 'bridge' mode on the
        // same physical net interface, one for the guest and one for
        // the host. With additional setup on the IP address and the
        // routing table, it enables the communications between the
        // guest VM and the host machine.
        // Details: https://wiki.libvirt.org/page/TroubleshootMacvtapHostFail
        fn test_macvtap() {
            let focal = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let kernel_path = direct_kernel_boot_path();
            let phy_net = "eth0";

            // Create a macvtap interface for the guest VM to use
            let guest_macvtap_name = "guestmacvtap0";
            std::process::Command::new("bash")
                .args(&[
                    "-c",
                    &format!(
                        "sudo ip link add link {} name {} type macvtap mod bridge",
                        phy_net, guest_macvtap_name
                    ),
                ])
                .status()
                .expect("Expected 'ip link add' to work");
            std::process::Command::new("bash")
                .args(&[
                    "-c",
                    &format!(
                        "sudo ip link set {} address {} up",
                        guest_macvtap_name, guest.network.guest_mac
                    ),
                ])
                .status()
                .expect("Expected 'ip link set' to work");
            std::process::Command::new("bash")
                .args(&["-c", &format!("sudo ip link show {}", guest_macvtap_name)])
                .status()
                .expect("Expected 'ip link show' to work");

            let tap_index =
                fs::read_to_string(&format!("/sys/class/net/{}/ifindex", guest_macvtap_name))
                    .unwrap();
            let tap_device = format!("/dev/tap{}", tap_index.trim());

            std::process::Command::new("bash")
                .args(&["-c", &format!("sudo chown $UID.$UID {}", tap_device)])
                .status()
                .expect("Expected 'chown' to work");

            let cstr_tap_device = std::ffi::CString::new(tap_device).unwrap();
            let tap_fd = unsafe { libc::open(cstr_tap_device.as_ptr(), libc::O_RDWR) };
            assert!(tap_fd > 0);

            // Create a macvtap on the same physical net interface for
            // the host machine to use
            let host_macvtap_name = "hostmacvtap0";
            std::process::Command::new("bash")
                .args(&[
                    "-c",
                    &format!(
                        "sudo ip link add link {} name {} type macvtap mod bridge",
                        phy_net, host_macvtap_name
                    ),
                ])
                .status()
                .expect("Expected 'ip link add' to work");
            // Use default mask "255.255.255.0"
            std::process::Command::new("bash")
                .args(&[
                    "-c",
                    &format!(
                        "sudo ip address add {}/24 dev {}",
                        guest.network.host_ip, host_macvtap_name
                    ),
                ])
                .status()
                .expect("Expected 'ip address add' to work");
            std::process::Command::new("bash")
                .args(&[
                    "-c",
                    &format!("sudo ip link set dev {} up", host_macvtap_name),
                ])
                .status()
                .expect("Expected 'ip link set dev up' to work");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&[
                    "--net",
                    &format!("fd={},mac={}", tap_fd, guest.network.guest_mac),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

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

            let _ = child.kill();

            std::process::Command::new("bash")
                .args(&["-c", &format!("sudo ip link del {}", guest_macvtap_name)])
                .status()
                .expect("Expected 'ip link del' to work");
            std::process::Command::new("bash")
                .args(&["-c", &format!("sudo ip link del {}", host_macvtap_name)])
                .status()
                .expect("Expected 'ip link del' to work");

            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_ovs_dpdk() {
            // Create OVS-DPDK bridge and ports
            assert!(exec_host_command_status(
                "ovs-vsctl add-br ovsbr0 -- set bridge ovsbr0 datapath_type=netdev",
            )
            .success());
            assert!(exec_host_command_status("ovs-vsctl add-port ovsbr0 vhost-user1 -- set Interface vhost-user1 type=dpdkvhostuserclient options:vhost-server-path=/tmp/dpdkvhostclient1").success());
            assert!(exec_host_command_status("ovs-vsctl add-port ovsbr0 vhost-user2 -- set Interface vhost-user2 type=dpdkvhostuserclient options:vhost-server-path=/tmp/dpdkvhostclient2").success());
            assert!(exec_host_command_status("ip link set up dev ovsbr0").success());
            assert!(exec_host_command_status("service openvswitch-switch restart").success());

            let focal1 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest1 = Guest::new(Box::new(focal1));
            let mut child1 = GuestCommand::new(&guest1)
                .args(&["--cpus", "boot=2"])
                .args(&["--memory", "size=0,shared=on"])
                .args(&["--memory-zone", "id=mem0,size=1G,shared=on,host_numa_node=0"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&["--net", guest1.default_net_string().as_str(), "vhost_user=true,socket=/tmp/dpdkvhostclient1,num_queues=2,queue_size=256,vhost_mode=server"])
                .capture_output()
                .spawn()
                .unwrap();

            #[cfg(target_arch = "x86_64")]
            let guest_net_iface = "ens5";
            #[cfg(target_arch = "aarch64")]
            let guest_net_iface = "enp0s5";

            let r = std::panic::catch_unwind(|| {
                guest1.wait_vm_boot(None).unwrap();

                guest1
                    .ssh_command(&format!(
                        "sudo ip addr add 172.100.0.1/24 dev {}",
                        guest_net_iface
                    ))
                    .unwrap();
                guest1
                    .ssh_command(&format!("sudo ip link set up dev {}", guest_net_iface))
                    .unwrap();

                let guest_ip = guest1.network.guest_ip.clone();
                thread::spawn(move || {
                    ssh_command_ip(
                        "nc -l 12345",
                        &guest_ip,
                        DEFAULT_SSH_RETRIES,
                        DEFAULT_SSH_TIMEOUT,
                    )
                    .unwrap();
                });
            });
            if r.is_err() {
                let _ = child1.kill();
                let output = child1.wait_with_output().unwrap();
                handle_child_output(r, &output);
                panic!("Test should already be failed/panicked"); // To explicitly mark this block never return
            }

            let focal2 = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
            let guest2 = Guest::new(Box::new(focal2));
            let mut child2 = GuestCommand::new(&guest2)
                .args(&["--cpus", "boot=2"])
                .args(&["--memory", "size=0,shared=on"])
                .args(&["--memory-zone", "id=mem0,size=1G,shared=on,host_numa_node=0"])
                .args(&["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .args(&["--net", guest2.default_net_string().as_str(), "vhost_user=true,socket=/tmp/dpdkvhostclient2,num_queues=2,queue_size=256,vhost_mode=server"])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest2.wait_vm_boot(None).unwrap();

                guest2
                    .ssh_command(&format!(
                        "sudo ip addr add 172.100.0.2/24 dev {}",
                        guest_net_iface
                    ))
                    .unwrap();
                guest2
                    .ssh_command(&format!("sudo ip link set up dev {}", guest_net_iface))
                    .unwrap();

                // Check the connection works properly between the two VMs
                guest2.ssh_command("nc -vz 172.100.0.1 12345").unwrap();

                // Remove one of the two ports from the OVS bridge
                assert!(exec_host_command_status("ovs-vsctl del-port vhost-user1").success());

                // Spawn a new netcat listener in the first VM
                let guest_ip = guest1.network.guest_ip.clone();
                thread::spawn(move || {
                    ssh_command_ip(
                        "nc -l 12345",
                        &guest_ip,
                        DEFAULT_SSH_RETRIES,
                        DEFAULT_SSH_TIMEOUT,
                    )
                    .unwrap();
                });

                // Check the connection fails this time
                assert!(guest2.ssh_command("nc -vz 172.100.0.1 12345").is_err());

                // Add the OVS port back
                assert!(exec_host_command_status("ovs-vsctl add-port ovsbr0 vhost-user1 -- set Interface vhost-user1 type=dpdkvhostuserclient options:vhost-server-path=/tmp/dpdkvhostclient1").success());

                // And finally check the connection is functional again
                guest2.ssh_command("nc -vz 172.100.0.1 12345").unwrap();
            });

            let _ = child1.kill();
            let _ = child2.kill();

            let output = child1.wait_with_output().unwrap();
            child2.wait().unwrap();

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

    #[cfg(target_arch = "x86_64")]
    mod windows {
        use crate::tests::*;

        lazy_static! {
            static ref NEXT_DISK_ID: Mutex<u8> = Mutex::new(1);
        }

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
                ssh_command_ip_with_auth(
                    cmd,
                    &self.auth,
                    &self.guest.network.guest_ip,
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
                self.ssh_cmd("powershell -Command \"(Get-CimInstance win32_computersystem).TotalPhysicalMemory\"")
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
                let listen_address = format!("--listen-address={}", self.guest.network.host_ip);
                let dhcp_host = format!(
                    "--dhcp-host={},{}",
                    self.guest.network.guest_mac, self.guest.network.guest_ip
                );
                let dhcp_range = format!(
                    "--dhcp-range=eth,{},{}",
                    self.guest.network.guest_ip, self.guest.network.guest_ip
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

                let img = PathBuf::from(format!("/tmp/test-hotplug-{}.raw", id));
                let _ = fs::remove_file(&img);

                // Create an image file
                let out = Command::new("qemu-img")
                    .args(&[
                        "create",
                        "-f",
                        "raw",
                        img.to_str().unwrap(),
                        format!("{}m", sz).as_str(),
                    ])
                    .output()
                    .expect("qemu-img command failed")
                    .stdout;
                println!("{:?}", out);

                // Associate image to a loop device
                let out = Command::new("losetup")
                    .args(&["--show", "-f", img.to_str().unwrap()])
                    .output()
                    .expect("failed to create loop device")
                    .stdout;
                let _tmp = String::from_utf8_lossy(&out);
                let loop_dev = _tmp.trim();
                println!("{:?}", out);

                // Create a partition table
                // echo 'type=7' | sudo sfdisk "${LOOP}"
                let mut child = Command::new("sfdisk")
                    .args(&[loop_dev])
                    .stdin(Stdio::piped())
                    .spawn()
                    .unwrap();
                let stdin = child.stdin.as_mut().expect("failed to open stdin");
                let _ = stdin
                    .write_all("type=7".as_bytes())
                    .expect("failed to write stdin");
                let out = child.wait_with_output().expect("sfdisk failed").stdout;
                println!("{:?}", out);

                // Disengage the loop device
                let out = Command::new("losetup")
                    .args(&["-d", loop_dev])
                    .output()
                    .expect("loop device not found")
                    .stdout;
                println!("{:?}", out);

                // Re-associate loop device pointing to the partition only
                let out = Command::new("losetup")
                    .args(&[
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
                println!("{:?}", out);

                // Create filesystem.
                let fs_cmd = match fs {
                    WindowsGuest::FS_FAT => "mkfs.msdos",
                    WindowsGuest::FS_NTFS => "mkfs.ntfs",
                    _ => panic!("Unknown filesystem type '{}'", fs),
                };
                let out = Command::new(fs_cmd)
                    .args(&[&loop_dev])
                    .output()
                    .unwrap_or_else(|_| panic!("{} failed", fs_cmd))
                    .stdout;
                println!("{:?}", out);

                // Disengage the loop device
                let out = Command::new("losetup")
                    .args(&["-d", loop_dev])
                    .output()
                    .unwrap_or_else(|_| panic!("loop device '{}' not found", loop_dev))
                    .stdout;
                println!("{:?}", out);

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
                    "powershell -Command \"'{}' | Set-Content -Path {}\"",
                    data, fname
                ));
            }

            fn disk_file_read(&self, fname: &str) -> String {
                self.ssh_cmd(&format!(
                    "powershell -Command \"Get-Content -Path {}\"",
                    fname
                ))
            }

            fn wait_for_boot(&self) -> bool {
                let cmd = "dir /b c:\\ | find \"Windows\"";
                let tmo_max = 180;
                // The timeout increase by n*1+n*2+n*3+..., therefore the initial
                // interval must be small.
                let tmo_int = 2;
                let out = ssh_command_ip_with_auth(
                    cmd,
                    &self.auth,
                    &self.guest.network.guest_ip,
                    {
                        let mut ret = 1;
                        let mut tmo_acc = 0;
                        loop {
                            tmo_acc += tmo_int * ret;
                            if tmo_acc >= tmo_max {
                                break;
                            }
                            ret += 1;
                        }
                        ret
                    },
                    tmo_int,
                )
                .unwrap();

                if "Windows" == out.trim() {
                    return true;
                }

                false
            }
        }

        fn vcpu_threads_count(pid: u32) -> u8 {
            // ps -T -p 12345 | grep vcpu | wc -l
            let out = Command::new("ps")
                .args(&["-T", "-p", format!("{}", pid).as_str()])
                .output()
                .expect("ps command failed")
                .stdout;
            return String::from_utf8_lossy(&out).matches("vcpu").count() as u8;
        }

        fn netdev_ctrl_threads_count(pid: u32) -> u8 {
            // ps -T -p 12345 | grep "_net[0-9]*_ctrl" | wc -l
            let out = Command::new("ps")
                .args(&["-T", "-p", format!("{}", pid).as_str()])
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
                .args(&["-T", "-p", format!("{}", pid).as_str()])
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

            let mut ovmf_path = dirs::home_dir().unwrap();
            ovmf_path.push("workloads");
            ovmf_path.push(OVMF_NAME);

            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--cpus", "boot=2,kvm_hyperv=on"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
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
                assert!(windows_guest.wait_for_boot());

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
                .args(&["--cpus", "boot=4,kvm_hyperv=on"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .args(&[
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
                .args(&[
                    "--net",
                    format!(
                        "tap=,mac={},ip={},mask=255.255.255.0,num_queues=8",
                        windows_guest.guest().network.guest_mac,
                        windows_guest.guest().network.host_ip
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
                assert!(windows_guest.wait_for_boot());

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
        fn test_windows_guest_snapshot_restore() {
            let windows_guest = WindowsGuest::new();

            let mut ovmf_path = dirs::home_dir().unwrap();
            ovmf_path.push("workloads");
            ovmf_path.push(OVMF_NAME);

            let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
            let api_socket = temp_api_path(&tmp_dir);

            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,kvm_hyperv=on"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
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
            assert!(windows_guest.wait_for_boot());

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
            thread::sleep(std::time::Duration::new(30, 0));

            let _ = child.kill();
            child.wait().unwrap();

            // Restore the VM from the snapshot
            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--api-socket", &api_socket])
                .args(&[
                    "--restore",
                    format!("source_url=file://{}", snapshot_dir).as_str(),
                ])
                .capture_output()
                .spawn()
                .unwrap();

            // Wait for the VM to be restored
            thread::sleep(std::time::Duration::new(20, 0));

            let r = std::panic::catch_unwind(|| {
                // Resume the VM
                assert!(remote_command(&api_socket, "resume", None));

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
        fn test_windows_guest_cpu_hotplug() {
            let windows_guest = WindowsGuest::new();

            let mut ovmf_path = dirs::home_dir().unwrap();
            ovmf_path.push("workloads");
            ovmf_path.push(OVMF_NAME);

            let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
            let api_socket = temp_api_path(&tmp_dir);

            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,max=8,kvm_hyperv=on"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let mut child_dnsmasq = windows_guest.run_dnsmasq();

            let r = std::panic::catch_unwind(|| {
                // Wait to make sure Windows boots up
                assert!(windows_guest.wait_for_boot());

                let vcpu_num = 2;
                // Check the initial number of CPUs the guest sees
                assert_eq!(windows_guest.cpu_count(), vcpu_num);
                // Check the initial number of vcpu threads in the CH process
                assert_eq!(vcpu_threads_count(child.id()), vcpu_num);

                let vcpu_num = 6;
                // Hotplug some CPUs
                resize_command(&api_socket, Some(vcpu_num), None, None);
                // Wait to make sure CPUs are added
                thread::sleep(std::time::Duration::new(10, 0));
                // Check the guest sees the correct number
                assert_eq!(windows_guest.cpu_count(), vcpu_num);
                // Check the CH process has the correct number of vcpu threads
                assert_eq!(vcpu_threads_count(child.id()), vcpu_num);

                let vcpu_num = 4;
                // Remove some CPUs. Note that Windows doesn't support hot-remove.
                resize_command(&api_socket, Some(vcpu_num), None, None);
                // Wait to make sure CPUs are removed
                thread::sleep(std::time::Duration::new(10, 0));
                // Reboot to let Windows catch up
                windows_guest.reboot();
                // Wait to make sure Windows completely rebooted
                thread::sleep(std::time::Duration::new(60, 0));
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
        fn test_windows_guest_ram_hotplug() {
            let windows_guest = WindowsGuest::new();

            let mut ovmf_path = dirs::home_dir().unwrap();
            ovmf_path.push("workloads");
            ovmf_path.push(OVMF_NAME);

            let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
            let api_socket = temp_api_path(&tmp_dir);

            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,kvm_hyperv=on"])
                .args(&["--memory", "size=2G,hotplug_size=5G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let mut child_dnsmasq = windows_guest.run_dnsmasq();

            let r = std::panic::catch_unwind(|| {
                // Wait to make sure Windows boots up
                assert!(windows_guest.wait_for_boot());

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
                resize_command(&api_socket, None, Some(ram_size), None);
                // Wait to make sure RAM has been added
                thread::sleep(std::time::Duration::new(10, 0));
                // Check the guest sees the correct number
                assert_eq!(windows_guest.ram_size(), ram_size - reserved_ram_size);

                let ram_size = 3 * 1024 * 1024 * 1024;
                // Unplug some RAM. Note that hot-remove most likely won't work.
                resize_command(&api_socket, None, Some(ram_size), None);
                // Wait to make sure RAM has been added
                thread::sleep(std::time::Duration::new(10, 0));
                // Reboot to let Windows catch up
                windows_guest.reboot();
                // Wait to make sure guest completely rebooted
                thread::sleep(std::time::Duration::new(60, 0));
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
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,kvm_hyperv=on"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let mut child_dnsmasq = windows_guest.run_dnsmasq();

            let r = std::panic::catch_unwind(|| {
                // Wait to make sure Windows boots up
                assert!(windows_guest.wait_for_boot());

                // Initially present network device
                let netdev_num = 1;
                assert_eq!(windows_guest.netdev_count(), netdev_num);
                assert_eq!(netdev_ctrl_threads_count(child.id()), netdev_num);

                // Hotplug network device
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-net",
                    Some(windows_guest.guest().default_net_string().as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output).contains("\"id\":\"_net2\""));
                thread::sleep(std::time::Duration::new(5, 0));
                // Verify the device  is on the system
                let netdev_num = 2;
                assert_eq!(windows_guest.netdev_count(), netdev_num);
                assert_eq!(netdev_ctrl_threads_count(child.id()), netdev_num);

                // Remove network device
                let cmd_success = remote_command(&api_socket, "remove-device", Some("_net2"));
                assert!(cmd_success);
                thread::sleep(std::time::Duration::new(5, 0));
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
        #[cfg(not(feature = "mshv"))]
        fn test_windows_guest_disk_hotplug() {
            let windows_guest = WindowsGuest::new();

            let mut ovmf_path = dirs::home_dir().unwrap();
            ovmf_path.push("workloads");
            ovmf_path.push(OVMF_NAME);

            let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
            let api_socket = temp_api_path(&tmp_dir);

            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,kvm_hyperv=on"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let mut child_dnsmasq = windows_guest.run_dnsmasq();

            let disk = windows_guest.disk_new(WindowsGuest::FS_FAT, 100);

            let r = std::panic::catch_unwind(|| {
                // Wait to make sure Windows boots up
                assert!(windows_guest.wait_for_boot());

                // Initially present disk device
                let disk_num = 1;
                assert_eq!(windows_guest.disk_count(), disk_num);
                assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

                // Hotplug disk device
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-disk",
                    Some(format!("path={},readonly=off", disk).as_str()),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output).contains("\"id\":\"_disk2\""));
                thread::sleep(std::time::Duration::new(5, 0));
                // Online disk device
                windows_guest.disks_set_rw();
                windows_guest.disks_online();
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
                thread::sleep(std::time::Duration::new(5, 0));
                // Verify the device has been removed
                let disk_num = 1;
                assert_eq!(windows_guest.disk_count(), disk_num);
                assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

                // Remount and check the file exists with the expected contents
                let (cmd_success, _cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-disk",
                    Some(format!("path={},readonly=off", disk).as_str()),
                );
                assert!(cmd_success);
                thread::sleep(std::time::Duration::new(5, 0));
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
        #[cfg(not(feature = "mshv"))]
        fn test_windows_guest_disk_hotplug_multi() {
            let windows_guest = WindowsGuest::new();

            let mut ovmf_path = dirs::home_dir().unwrap();
            ovmf_path.push("workloads");
            ovmf_path.push(OVMF_NAME);

            let tmp_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
            let api_socket = temp_api_path(&tmp_dir);

            let mut child = GuestCommand::new(windows_guest.guest())
                .args(&["--api-socket", &api_socket])
                .args(&["--cpus", "boot=2,kvm_hyperv=on"])
                .args(&["--memory", "size=2G"])
                .args(&["--kernel", ovmf_path.to_str().unwrap()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
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
                assert!(windows_guest.wait_for_boot());

                // Initially present disk device
                let disk_num = 1;
                assert_eq!(windows_guest.disk_count(), disk_num);
                assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

                for it in &disk_test_data {
                    let disk_id = it[0].as_str();
                    let disk = it[1].as_str();
                    // Hotplug disk device
                    let (cmd_success, cmd_output) = remote_command_w_output(
                        &api_socket,
                        "add-disk",
                        Some(format!("path={},readonly=off", disk).as_str()),
                    );
                    assert!(cmd_success);
                    assert!(String::from_utf8_lossy(&cmd_output)
                        .contains(format!("\"id\":\"{}\"", disk_id).as_str()));
                    thread::sleep(std::time::Duration::new(5, 0));
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
                    thread::sleep(std::time::Duration::new(5, 0));
                }

                // Verify the devices have been removed
                let disk_num = 1;
                assert_eq!(windows_guest.disk_count(), disk_num);
                assert_eq!(disk_ctrl_threads_count(child.id()), disk_num);

                // Remount
                for it in &disk_test_data {
                    let disk = it[1].as_str();
                    let (cmd_success, _cmd_output) = remote_command_w_output(
                        &api_socket,
                        "add-disk",
                        Some(format!("path={},readonly=off", disk).as_str()),
                    );
                    assert!(cmd_success);
                    thread::sleep(std::time::Duration::new(5, 0));
                }

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
    }

    #[cfg(target_arch = "x86_64")]
    mod sgx {
        use crate::tests::*;

        #[test]
        fn test_sgx() {
            let focal = UbuntuDiskConfig::new(FOCAL_SGX_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(focal));
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux_w_sgx");

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                .default_disks()
                .default_net()
                .args(&["--sgx-epc", "size=64M"])
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check if SGX is correctly detected in the guest.
                guest.check_sgx_support().unwrap();

                // Validate the SGX EPC section is 64MiB.
                assert_eq!(
                    guest
                        .ssh_command("cpuid -l 0x12 -s 2 | grep 'section size' | cut -d '=' -f 2")
                        .unwrap()
                        .trim(),
                    "0x0000000004000000"
                );

                // Run a test relying on SGX enclaves and check if it runs
                // successfully.
                assert!(guest
                    .ssh_command("cd /linux-sgx/SampleCode/LocalAttestation/bin/ && sudo ./app")
                    .unwrap()
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

    #[cfg(target_arch = "x86_64")]
    mod vfio {
        use crate::tests::*;

        fn test_nvidia_card_memory_hotplug(hotplug_method: &str) {
            let hirsute = UbuntuDiskConfig::new(HIRSUTE_NVIDIA_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(hirsute));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&[
                    "--memory",
                    format!("size=4G,hotplug_size=4G,hotplug_method={}", hotplug_method).as_str(),
                ])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&["--device", "path=/sys/bus/pci/devices/0000:31:00.0/"])
                .args(&["--api-socket", &api_socket])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                assert!(guest.get_total_memory().unwrap_or_default() > 3_840_000);

                guest.enable_memory_hotplug();

                // Add RAM to the VM
                let desired_ram = 6 << 30;
                resize_command(&api_socket, None, Some(desired_ram), None);
                thread::sleep(std::time::Duration::new(30, 0));
                assert!(guest.get_total_memory().unwrap_or_default() > 5_760_000);

                // Check the VFIO device works when RAM is increased to 6GiB
                guest.check_nvidia_gpu();
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_nvidia_card_memory_hotplug_acpi() {
            test_nvidia_card_memory_hotplug("acpi")
        }

        #[test]
        fn test_nvidia_card_memory_hotplug_virtio_mem() {
            test_nvidia_card_memory_hotplug("virtio-mem")
        }

        #[test]
        fn test_nvidia_card_pci_hotplug() {
            let hirsute = UbuntuDiskConfig::new(HIRSUTE_NVIDIA_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(hirsute));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&["--api-socket", &api_socket])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Hotplug the card to the VM
                let (cmd_success, cmd_output) = remote_command_w_output(
                    &api_socket,
                    "add-device",
                    Some("id=vfio0,path=/sys/bus/pci/devices/0000:31:00.0/"),
                );
                assert!(cmd_success);
                assert!(String::from_utf8_lossy(&cmd_output)
                    .contains("{\"id\":\"vfio0\",\"bdf\":\"0000:00:06.0\"}"));

                thread::sleep(std::time::Duration::new(10, 0));

                // Check the VFIO device works after hotplug
                guest.check_nvidia_gpu();
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }

        #[test]
        fn test_nvidia_card_reboot() {
            let hirsute = UbuntuDiskConfig::new(HIRSUTE_NVIDIA_IMAGE_NAME.to_string());
            let guest = Guest::new(Box::new(hirsute));
            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = GuestCommand::new(&guest)
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=4G"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&["--device", "path=/sys/bus/pci/devices/0000:31:00.0/"])
                .args(&["--api-socket", &api_socket])
                .default_disks()
                .default_net()
                .capture_output()
                .spawn()
                .unwrap();

            let r = std::panic::catch_unwind(|| {
                guest.wait_vm_boot(None).unwrap();

                // Check the VFIO device works after boot
                guest.check_nvidia_gpu();

                guest.reboot_linux(0, None);

                // Check the VFIO device works after reboot
                guest.check_nvidia_gpu();
            });

            let _ = child.kill();
            let output = child.wait_with_output().unwrap();

            handle_child_output(r, &output);
        }
    }
}
