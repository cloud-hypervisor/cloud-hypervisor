// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;
extern crate vmm_sys_util;

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg, ArgGroup};
use libc::EFD_NONBLOCK;
use log::LevelFilter;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::{env, process};
use vmm::config;
use vmm_sys_util::eventfd::EventFd;

struct Logger {
    output: Mutex<Box<dyn std::io::Write + Send>>,
    start: std::time::Instant,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = std::time::Instant::now();
        let duration = now.duration_since(self.start);

        if record.file().is_some() && record.line().is_some() {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:?}: {}:{}:{} -- {}",
                duration,
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            )
            .expect("Failed to write to log file");
        } else {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:?}: {}:{} -- {}",
                duration,
                record.level(),
                record.target(),
                record.args()
            )
            .expect("Failed to write to log file");
        }
    }
    fn flush(&self) {}
}

fn main() {
    let pid = unsafe { libc::getpid() };
    let uid = unsafe { libc::getuid() };

    let mut api_server_path = format! {"/run/user/{}/cloud-hypervisor.{}", uid, pid};
    if uid == 0 {
        // If we're running as root, we try to get the real user ID if we've been sudo'ed
        // or else create our socket directly under /run.
        let key = "SUDO_UID";
        match env::var(key) {
            Ok(sudo_uid) => {
                api_server_path = format! {"/run/user/{}/cloud-hypervisor.{}", sudo_uid, pid}
            }
            Err(_) => api_server_path = format! {"/run/cloud-hypervisor.{}", pid},
        }
    }

    let default_vcpus = format! {"{}", config::DEFAULT_VCPUS};
    let default_memory = &format! {"size={}M", config::DEFAULT_MEMORY_MB};

    let cmd_arguments = App::new("cloud-hypervisor")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a cloud-hypervisor VMM.")
        .group(ArgGroup::with_name("vm-config").multiple(true))
        .group(ArgGroup::with_name("vmm-config").multiple(true))
        .arg(
            Arg::with_name("cpus")
                .long("cpus")
                .help("Number of virtual CPUs")
                .default_value(&default_vcpus)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("memory")
                .long("memory")
                .help(
                    "Memory parameters \"size=<guest_memory_size>,\
                     file=<backing_file_path>\"",
                )
                .default_value(&default_memory)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("kernel")
                .long("kernel")
                .help("Path to kernel image (vmlinux)")
                .takes_value(true)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("cmdline")
                .long("cmdline")
                .help("Kernel command line")
                .takes_value(true)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("disk")
                .long("disk")
                .help("Path to VM disk image")
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("net")
                .long("net")
                .help(
                    "Network parameters \"tap=<if_name>,\
                     ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("rng")
                .long("rng")
                .help("Path to entropy source")
                .default_value(config::DEFAULT_RNG_SOURCE)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("fs")
                .long("fs")
                .help(
                    "virtio-fs parameters \"tag=<tag_name>,\
                     sock=<socket_path>,num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>,dax=on|off,\
                     cache_size=<DAX cache size: default 8Gib>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("pmem")
                .long("pmem")
                .help(
                    "Persistent memory parameters \"file=<backing_file_path>,\
                     size=<persistent_memory_size>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("serial")
                .long("serial")
                .help("Control serial port: off|null|tty|file=/path/to/a/file")
                .default_value("null")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("console")
                .long("console")
                .help("Control (virtio) console: off|null|tty|file=/path/to/a/file")
                .default_value("tty")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("device")
                .long("device")
                .help("Direct device assignment parameter")
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vhost-user-net")
                .long("vhost-user-net")
                .help(
                    "Network parameters \"mac=<mac_addr>,\
                     sock=<socket_path>, num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vsock")
                .long("vsock")
                .help(
                    "Virtio VSOCK parameters \"cid=<context_id>,\
                     sock=<socket_path>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vhost-user-blk")
                .long("vhost-user-blk")
                .help(
                    "Vhost user Block parameters \"sock=<socket_path>,\
                     num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>, \
                     wce=<true|false, default true>\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of debugging output")
                .group("vmm-config"),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .help("Log file. Standard error is used if not specified")
                .takes_value(true)
                .min_values(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::with_name("api-socket")
                .long("api-socket")
                .help("HTTP API socket path (UNIX domain socket).")
                .takes_value(true)
                .min_values(1)
                .default_value(&api_server_path)
                .group("vmm-config"),
        )
        .get_matches();

    // These .unwrap()s cannot fail as there is a default value defined
    let cpus = cmd_arguments.value_of("cpus").unwrap();
    let memory = cmd_arguments.value_of("memory").unwrap();
    let rng = cmd_arguments.value_of("rng").unwrap();
    let serial = cmd_arguments.value_of("serial").unwrap();

    let kernel = cmd_arguments.value_of("kernel");
    let cmdline = cmd_arguments.value_of("cmdline");

    let disks: Option<Vec<&str>> = cmd_arguments.values_of("disk").map(|x| x.collect());
    let net: Option<Vec<&str>> = cmd_arguments.values_of("net").map(|x| x.collect());
    let console = cmd_arguments.value_of("console").unwrap();
    let fs: Option<Vec<&str>> = cmd_arguments.values_of("fs").map(|x| x.collect());
    let pmem: Option<Vec<&str>> = cmd_arguments.values_of("pmem").map(|x| x.collect());
    let devices: Option<Vec<&str>> = cmd_arguments.values_of("device").map(|x| x.collect());
    let vhost_user_net: Option<Vec<&str>> = cmd_arguments
        .values_of("vhost-user-net")
        .map(|x| x.collect());
    let vhost_user_blk: Option<Vec<&str>> = cmd_arguments
        .values_of("vhost-user-blk")
        .map(|x| x.collect());
    let vsock: Option<Vec<&str>> = cmd_arguments.values_of("vsock").map(|x| x.collect());

    let log_level = match cmd_arguments.occurrences_of("v") {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn std::io::Write + Send> =
        if let Some(file) = cmd_arguments.value_of("log-file") {
            Box::new(
                std::fs::File::create(std::path::Path::new(file)).expect("Error creating log file"),
            )
        } else {
            Box::new(std::io::stderr())
        };

    log::set_boxed_logger(Box::new(Logger {
        output: Mutex::new(log_file),
        start: std::time::Instant::now(),
    }))
    .map(|()| log::set_max_level(log_level))
    .expect("Expected to be able to setup logger");

    let vm_config = match config::VmConfig::parse(config::VmParams {
        cpus,
        memory,
        kernel,
        cmdline,
        disks,
        net,
        rng,
        fs,
        pmem,
        serial,
        console,
        devices,
        vhost_user_net,
        vhost_user_blk,
        vsock,
    }) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let api_socket_path = cmd_arguments
        .value_of("api-socket")
        .expect("Missing argument: api-socket");

    println!(
        "Cloud Hypervisor Guest\n\tAPI server: {}\n\tvCPUs: {}\n\tMemory: {} MB\
         \n\tKernel: {:?}\n\tKernel cmdline: {}\n\tDisk(s): {:?}",
        api_socket_path,
        u8::from(&vm_config.cpus),
        vm_config.memory.size >> 20,
        vm_config.kernel,
        vm_config.cmdline.args.as_str(),
        vm_config.disks,
    );

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).expect("Cannot create API EventFd");

    let http_sender = api_request_sender.clone();
    let vmm_thread = match vmm::start_vmm_thread(
        api_socket_path,
        api_evt.try_clone().unwrap(),
        http_sender,
        api_request_receiver,
    ) {
        Ok(t) => t,
        Err(e) => {
            println!("Failed spawning the VMM thread {:?}", e);
            process::exit(1);
        }
    };

    if cmd_arguments.is_present("vm-config") && vm_config.valid() {
        // Create and boot the VM based off the VM config we just built.
        let sender = api_request_sender.clone();
        vmm::api::vm_create(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(vm_config),
        )
        .expect("Could not create the VM");
        vmm::api::vm_boot(api_evt.try_clone().unwrap(), sender).expect("Could not boot the VM");
    }

    match vmm_thread.join() {
        Ok(res) => match res {
            Ok(_) => (),
            Err(e) => {
                println!("VMM thread failed {:?}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            println!("Could not joing VMM thread {:?}", e);
            process::exit(1);
        }
    }
}

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
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};
    use std::string::String;
    use std::sync::Mutex;
    use std::thread;
    use tempdir::TempDir;

    lazy_static! {
        static ref NEXT_VM_ID: Mutex<u8> = Mutex::new(1);
    }

    struct GuestNetworkConfig {
        guest_ip: String,
        l2_guest_ip: String,
        host_ip: String,
        guest_mac: String,
        l2_guest_mac: String,
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

            fs::copy(
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
            user_data_string = user_data_string.replace("192.168.2.3", &network.l2_guest_ip);
            user_data_string = user_data_string.replace("12:34:56:78:90:ab", &network.guest_mac);
            user_data_string = user_data_string.replace("de:ad:be:ef:12:34", &network.l2_guest_mac);

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
            osdisk_base_path.push("clear-cloudguest.img");

            let mut osdisk_raw_base_path = workload_path.clone();
            osdisk_raw_base_path.push("clear-cloudguest-raw.img");

            let osdisk_path = String::from(tmp_dir.path().join("osdisk.img").to_str().unwrap());
            let osdisk_raw_path =
                String::from(tmp_dir.path().join("osdisk_raw.img").to_str().unwrap());
            let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

            fs::copy(osdisk_base_path, &osdisk_path)
                .expect("copying of OS source disk image failed");
            fs::copy(osdisk_raw_base_path, &osdisk_raw_path)
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
                fs::copy(source_file_dir.join(x), cloud_init_directory.join(x))
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

            let mut osdisk_raw_base_path = workload_path.clone();
            osdisk_raw_base_path.push(&self.image_name);

            let osdisk_raw_path =
                String::from(tmp_dir.path().join("osdisk_raw.img").to_str().unwrap());
            let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

            fs::copy(osdisk_raw_base_path, &osdisk_raw_path)
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

    fn prepare_virtiofsd(tmp_dir: &TempDir, cache: &str) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut virtiofsd_path = workload_path.clone();
        virtiofsd_path.push("virtiofsd");
        let virtiofsd_path = String::from(virtiofsd_path.to_str().unwrap());

        let mut shared_dir_path = workload_path.clone();
        shared_dir_path.push("shared_dir");
        let shared_dir_path = String::from(shared_dir_path.to_str().unwrap());

        let virtiofsd_socket_path =
            String::from(tmp_dir.path().join("virtiofs.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(virtiofsd_path.as_str())
            .args(&[
                "-o",
                format!("vhost_user_socket={}", virtiofsd_socket_path).as_str(),
            ])
            .args(&["-o", format!("source={}", shared_dir_path).as_str()])
            .args(&["-o", format!("cache={}", cache).as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, virtiofsd_socket_path)
    }

    fn prepare_vubd(tmp_dir: &TempDir, blk_img: &str) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut vubd_path = workload_path.clone();
        vubd_path.push("vubd");
        let vubd_path = String::from(vubd_path.to_str().unwrap());

        let mut blk_file_path = workload_path.clone();
        blk_file_path.push(blk_img);
        let blk_file_path = String::from(blk_file_path.to_str().unwrap());

        let vubd_socket_path = String::from(tmp_dir.path().join("vub.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(vubd_path.as_str())
            .args(&["-b", blk_file_path.as_str()])
            .args(&["-s", vubd_socket_path.as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, vubd_socket_path)
    }

    fn temp_vsock_path(tmp_dir: &TempDir) -> String {
        String::from(tmp_dir.path().join("vsock").to_str().unwrap())
    }

    fn ssh_command_ip(command: &str, ip: &str) -> Result<String, Error> {
        let mut s = String::new();

        let mut counter = 0;
        loop {
            match (|| -> Result<(), Error> {
                let tcp =
                    TcpStream::connect(format!("{}:22", ip)).map_err(|_| Error::Connection)?;
                let mut sess = Session::new().unwrap();
                sess.set_tcp_stream(tcp);
                sess.handshake().map_err(|_| Error::Connection)?;

                sess.userauth_password("cloud", "cloud123")
                    .map_err(|_| Error::Authentication)?;
                assert!(sess.authenticated());

                let mut channel = sess.channel_session().map_err(|_| Error::Command)?;
                channel.exec(command).map_err(|_| Error::Command)?;

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
                    if counter >= 6 {
                        return Err(e);
                    }
                }
            };
            thread::sleep(std::time::Duration::new(10 * counter, 0));
        }
        Ok(s)
    }

    #[derive(Debug)]
    enum Error {
        Connection,
        Authentication,
        Command,
        Parsing,
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

            let mut fw_path = workload_path.clone();
            fw_path.push("hypervisor-fw");
            let fw_path = String::from(fw_path.to_str().unwrap());
            let network = GuestNetworkConfig {
                guest_ip: format!("{}.{}.2", class, id),
                l2_guest_ip: format!("{}.{}.3", class, id),
                host_ip: format!("{}.{}.1", class, id),
                guest_mac: format!("12:34:56:78:90:{:02x}", id),
                l2_guest_mac: format!("de:ad:be:ef:12:{:02x}", id),
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

        fn ssh_command(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(command, &self.network.guest_ip)
        }

        fn ssh_command_l1(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(command, &self.network.guest_ip)
        }

        fn ssh_command_l2(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(command, &self.network.l2_guest_ip)
        }

        fn get_cpu_count(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep -c processor /proc/cpuinfo")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_initial_apicid(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep \"initial apicid\" /proc/cpuinfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_total_memory(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_entropy(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("cat /proc/sys/kernel/random/entropy_avail")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
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
                .ssh_command("sudo -E bash -c 'cat /proc/iomem' | grep virtio-pci-shm")?
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

            let start_addr = u64::from_str_radix(args[0], 16).map_err(|_| Error::Parsing)?;
            let end_addr = u64::from_str_radix(args[1], 16).map_err(|_| Error::Parsing)?;

            Ok(cache == (end_addr - start_addr + 1))
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

                let mut child = Command::new("target/debug/cloud-hypervisor")
                    .args(&["--cpus", "1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", guest.fw_path.as_str()])
                    .args(&[
                        "--disk",
                        guest
                            .disk_config
                            .disk(DiskType::OperatingSystem)
                            .unwrap()
                            .as_str(),
                        guest
                            .disk_config
                            .disk(DiskType::CloudInit)
                            .unwrap()
                            .as_str(),
                    ])
                    .args(&["--net", guest.default_net_string().as_str()])
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

                guest
                    .ssh_command("sudo shutdown -h now")
                    .unwrap_or_default();
                thread::sleep(std::time::Duration::new(10, 0));
                let _ = child.kill();
                let _ = child.wait();
            });
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_multi_cpu() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "2"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 2);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=5120M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 5_000_000);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=128G"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver!(
                tb,
                guest.get_total_memory().unwrap_or_default() > 128_000_000
            );

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut kernel_path = workload_path.clone();
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut kernel_path = workload_path.clone();
            kernel_path.push("bzImage");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            // Start the daemon
            let mut daemon_child = Command::new("target/debug/vhost_user_net")
                .args(&[
                    "--backend",
                    format!(
                        "ip={},mask=255.255.255.0,sock=/tmp/vunet.sock",
                        guest.network.host_ip
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();

            let mut cloud_child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&[
                    "--vhost-user-net",
                    format!("mac={},sock=/tmp/vunet.sock", guest.network.guest_mac).as_str(),
                ])
                .spawn()
                .unwrap();

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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(5, 0));
            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            thread::sleep(std::time::Duration::new(5, 0));
            let _ = daemon_child.kill();
            let _ = daemon_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_blk() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) = prepare_vubd(&guest.tmp_dir, "blk.img");

            let mut cloud_child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&[
                    "--vhost-user-blk",
                    format!(
                        "sock={},num_queues=1,queue_size=128,wce=true",
                        vubd_socket_path
                    )
                    .as_str(),
                ])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(5, 0));
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
            );

            let mut cloud_child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&[
                    "--vhost-user-blk",
                    format!(
                        "sock={},num_queues=1,queue_size=128,wce=true",
                        vubd_socket_path
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Just check the VM booted correctly.
            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 492_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(5, 0));
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

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    fn test_virtio_fs(dax: bool, cache_size: Option<u64>, virtiofsd_cache: &str) {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let (mut daemon_child, virtiofsd_socket_path) =
                prepare_virtiofsd(&guest.tmp_dir, virtiofsd_cache);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path.clone();
            kernel_path.push("vmlinux");

            let (dax_vmm_param, dax_mount_param) = if dax { ("on", ",dax") } else { ("off", "") };
            let cache_size_vmm_param = if let Some(cache) = cache_size {
                format!(",cache_size={}", cache)
            } else {
                "".to_string()
            };

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&[
                    "--fs",
                    format!(
                        "tag=virtiofs,sock={},num_queues=1,queue_size=1024,dax={}{}",
                        virtiofsd_socket_path, dax_vmm_param, cache_size_vmm_param
                    )
                    .as_str(),
                ])
                .args(&[
                    "--cmdline",
                    "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b \
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
                 sudo mount -t virtio_fs virtiofs mount_dir/ -o \
                 rootmode=040000,user_id=1001,group_id=1001{} && \
                 echo ok",
                dax_mount_param
            );
            aver_eq!(
                tb,
                guest.ssh_command(&mount_cmd).unwrap_or_default().trim(),
                "ok"
            );
            // Check the cache size is the expected one
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = daemon_child.kill();
            let _ = child.wait();
            let _ = daemon_child.wait();
            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_fs_dax_on_default_cache_size() {
        test_virtio_fs(true, None, "always")
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_fs_dax_on_cache_size_1_gib() {
        test_virtio_fs(true, Some(0x4000_0000), "always")
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_fs_dax_off() {
        test_virtio_fs(false, None, "none")
    }

    #[test]
    fn test_virtio_pmem() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path.clone();
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&[
                    "--pmem",
                    format!(
                        "file={},size={}",
                        guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap(),
                        fs::metadata(&guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap()).unwrap().len()
                    )
                    .as_str(),
                ])
                .args(&["--cmdline", "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut kernel_path = workload_path.clone();
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--disk", guest.disk_config.disk(DiskType::CloudInit).unwrap().as_str()])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&[
                    "--pmem",
                    format!(
                        "file={},size={}",
                        guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap(),
                        fs::metadata(&guest.disk_config.disk(DiskType::RawOperatingSystem).unwrap()).unwrap().len()
                    )
                    .as_str(),
                ])
                .args(&["--cmdline", "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Simple checks to validate the VM booted properly
            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 1);
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 496_000);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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

            // Further test that we're MSI only now
            aver_eq!(
                tb,
                guest
                    .ssh_command("cat /proc/interrupts | grep -c 'IO-APIC'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(1),
                0
            );

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--serial", "null"])
                .args(&["--console", "off"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
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

            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--serial", "tty"])
                .args(&["--console", "off"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
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

            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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

            thread::sleep(std::time::Duration::new(10, 0));

            // Do this check after shutdown of the VM as an easy way to ensure
            // all writes are flushed to disk
            let mut f = std::fs::File::open(serial_path)?;
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            aver!(tb, buf.contains("cloud login:"));

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_console() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--console", "tty"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
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
            let cmd = format!("sudo -E bash -c 'echo {} > /dev/hvc0'", text);
            guest.ssh_command(&cmd)?;

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&[
                    "--console",
                    format!("file={}", console_path.to_str().unwrap()).as_str(),
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));

            // Do this check after shutdown of the VM as an easy way to ensure
            // all writes are flushed to disk
            let mut f = std::fs::File::open(console_path)?;
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            aver!(tb, buf.contains("cloud login:"));

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    // The VFIO integration test starts a qemu guest and then direct assigns
    // one of the virtio-PCI device to a cloud-hypervisor nested guest. The
    // test assigns one of the 2 virtio-pci networking interface, and thus
    // the cloud-hypervisor guest will get a networking interface through that
    // direct assignment.
    // The test starts the QEMU guest with 2 TAP backed networking interfaces,
    // bound through a simple bridge on the host. So if the nested
    // cloud-hypervisor succeeds in getting a directly assigned interface from
    // its QEMU host, we should be able to ssh into it, and verify that it's
    // running with the right kernel command line (We tag the cloud-hypervisor
    // command line for that puspose).
    fn test_vfio() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new_from_ip_range(&mut clear, "172.16", 0);

            let home = dirs::home_dir().unwrap();
            let mut cloud_init_vfio_base_path = home.clone();
            cloud_init_vfio_base_path.push("workloads");
            cloud_init_vfio_base_path.push("vfio");
            cloud_init_vfio_base_path.push("cloudinit.img");

            // We copy our cloudinit into the vfio mount point, for the nested
            // cloud-hypervisor guest to use.
            fs::copy(
                &guest.disk_config.disk(DiskType::CloudInit).unwrap(),
                &cloud_init_vfio_base_path,
            )
            .expect("copying of cloud-init disk failed");

            let vfio_9p_path = format!(
                "local,id=shared,path={}/workloads/vfio/,security_model=none",
                home.to_str().unwrap()
            );

            let ovmf_path = format!("{}/workloads/OVMF.fd", home.to_str().unwrap());
            let os_disk = format!(
                "file={},format=qcow2",
                guest
                    .disk_config
                    .disk(DiskType::OperatingSystem)
                    .unwrap()
                    .as_str()
            );
            let cloud_init_disk = format!(
                "file={},format=raw",
                guest
                    .disk_config
                    .disk(DiskType::CloudInit)
                    .unwrap()
                    .as_str()
            );

            let vfio_tap0 = "vfio-tap0";
            let vfio_tap1 = "vfio-tap1";

            let ssh_net = "ssh-net";
            let vfio_net = "vfio-net";

            let netdev_ssh = format!(
                "tap,ifname={},id={},script=no,downscript=no",
                vfio_tap0, ssh_net
            );
            let netdev_ssh_device = format!(
                "virtio-net-pci,netdev={},disable-legacy=on,iommu_platform=on,ats=on,mac={}",
                ssh_net, guest.network.guest_mac
            );

            let netdev_vfio = format!(
                "tap,ifname={},id={},script=no,downscript=no",
                vfio_tap1, vfio_net
            );
            let netdev_vfio_device = format!(
                "virtio-net-pci,netdev={},disable-legacy=on,iommu_platform=on,ats=on,mac={}",
                vfio_net, guest.network.l2_guest_mac
            );

            let mut qemu_child = Command::new("qemu-system-x86_64")
                .args(&["-machine", "q35,accel=kvm,kernel_irqchip=split"])
                .args(&["-bios", &ovmf_path])
                .args(&["-smp", "sockets=1,cpus=4,cores=2"])
                .args(&["-cpu", "host"])
                .args(&["-m", "1024"])
                .args(&["-vga", "none"])
                .args(&["-nographic"])
                .args(&["-drive", &os_disk])
                .args(&["-drive", &cloud_init_disk])
                .args(&["-device", "virtio-rng-pci"])
                .args(&["-netdev", &netdev_ssh])
                .args(&["-device", &netdev_ssh_device])
                .args(&["-netdev", &netdev_vfio])
                .args(&["-device", &netdev_vfio_device])
                .args(&[
                    "-device",
                    "intel-iommu,intremap=on,caching-mode=on,device-iotlb=on",
                ])
                .args(&["-fsdev", &vfio_9p_path])
                .args(&[
                    "-device",
                    "virtio-9p-pci,fsdev=shared,mount_tag=cloud_hypervisor",
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(30, 0));

            guest.ssh_command_l1("sudo systemctl start vfio")?;
            thread::sleep(std::time::Duration::new(30, 0));

            // We booted our cloud hypervisor L2 guest with a "VFIOTAG" tag
            // added to its kernel command line.
            // Let's ssh into it and verify that it's there. If it is it means
            // we're in the right guest (The L2 one) because the QEMU L1 guest
            // does not have this command line tag.
            aver_eq!(
                tb,
                guest
                    .ssh_command_l2("cat /proc/cmdline | grep -c 'VFIOTAG'")
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_default(),
                1
            );

            guest.ssh_command_l2("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));

            guest.ssh_command_l1("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));

            let _ = qemu_child.kill();
            let _ = qemu_child.wait();

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

            let mut kernel_path = workload_path.clone();
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw acpi=off"])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

                let mut child = Command::new("target/debug/cloud-hypervisor")
                    .args(&["--cpus", "1"])
                    .args(&["--memory", "size=512M"])
                    .args(&["--kernel", guest.fw_path.as_str()])
                    .args(&[
                        "--disk",
                        guest
                            .disk_config
                            .disk(DiskType::OperatingSystem)
                            .unwrap()
                            .as_str(),
                        guest
                            .disk_config
                            .disk(DiskType::CloudInit)
                            .unwrap()
                            .as_str(),
                    ])
                    .args(&["--net", guest.default_net_string().as_str()])
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

                thread::sleep(std::time::Duration::new(20, 0));

                // Check that the cloud-hypervisor binary actually terminated
                if let Ok(status) = child.wait() {
                    aver_eq!(tb, status.success(), true);
                }
                let _ = child.kill();
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

            let mut kernel_path = workload_path.clone();
            kernel_path.push("bzImage");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=19866ecd-ecc4-4ef8-b313-09a92260ef9b console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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
            let _ = child.kill();
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

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", guest.fw_path.as_str()])
                .args(&[
                    "--disk",
                    guest
                        .disk_config
                        .disk(DiskType::OperatingSystem)
                        .unwrap()
                        .as_str(),
                    guest
                        .disk_config
                        .disk(DiskType::CloudInit)
                        .unwrap()
                        .as_str(),
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--vsock", format!("cid=3,sock={}", sock).as_str()])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Listen from guest on vsock CID=3 PORT=16
            // SOCKET-LISTEN:<domain>:<protocol>:<local-address>
            let guest_ip = guest.network.guest_ip.clone();
            let listen_socat = thread::spawn(move || {
                ssh_command_ip("sudo socat - SOCKET-LISTEN:40:0:x00x00x10x00x00x00x03x00x00x00x00x00x00x00 > vsock_log", &guest_ip).unwrap();
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }
}
