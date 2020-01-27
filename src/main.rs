// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;
extern crate vmm_sys_util;

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg, ArgGroup, ArgMatches};
use libc::EFD_NONBLOCK;
use log::LevelFilter;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::{env, process};
use vhost_user_block::start_block_backend;
use vhost_user_net::start_net_backend;
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

fn prepare_default_values() -> (String, String, String) {
    let default_vcpus = format! {"boot={}", config::DEFAULT_VCPUS};
    let default_memory = format! {"size={}M", config::DEFAULT_MEMORY_MB};
    let default_rng = format! {"src={}", config::DEFAULT_RNG_SOURCE};

    (default_vcpus, default_memory, default_rng)
}

fn create_app<'a, 'b>(
    default_vcpus: &'a str,
    default_memory: &'a str,
    default_rng: &'a str,
    api_server_path: &'a str,
) -> App<'a, 'b> {
    App::new("cloud-hypervisor")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a cloud-hypervisor VMM.")
        .group(ArgGroup::with_name("vm-config").multiple(true))
        .group(ArgGroup::with_name("vmm-config").multiple(true))
        .group(ArgGroup::with_name("logging").multiple(true))
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
                     file=<backing_file_path>,mergeable=on|off,\
                     hotplug_size=<hotpluggable_memory_size>\"",
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
                .help(
                    "Disk parameters \"path=<disk_image_path>,\
                     readonly=on|off,iommu=on|off,\
                     num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("net")
                .long("net")
                .help(
                    "Network parameters \"tap=<if_name>,\
                     ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,\
                     iommu=on|off,num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>,\
                     vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("rng")
                .long("rng")
                .help(
                    "Random number generator parameters \
                     \"src=<entropy_source_path>,iommu=on|off\"",
                )
                .default_value(&default_rng)
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
                     size=<persistent_memory_size>,iommu=on|off,mergeable=on|off\"",
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
                .help(
                    "Control (virtio) console: \"off|null|tty|file=/path/to/a/file,\
                     iommu=on|off\"",
                )
                .default_value("tty")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("device")
                .long("device")
                .help("Direct device assignment parameter")
                .help(
                    "Direct device assignment parameters \
                     \"path=<device_path>,iommu=on|off\"",
                )
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
                     sock=<socket_path>,iommu=on|off\"",
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
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of debugging output")
                .group("logging"),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .help("Log file. Standard error is used if not specified")
                .takes_value(true)
                .min_values(1)
                .group("logging"),
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
        .arg(
            Arg::with_name("net-backend")
                .long("net-backend")
                .help(
                    "vhost-user-net backend parameters \"ip=<ip_addr>,\
                     mask=<net_mask>,sock=<socket_path>,\
                     num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>\"",
                )
                .takes_value(true)
                .conflicts_with_all(&["block-backend", "kernel"])
                .min_values(1),
        )
        .arg(
            Arg::with_name("block-backend")
                .long("block-backend")
                .help(
                    "vhost-user-block backend parameters \"image=<image_path>,\
                     sock=<socket_path>,readonly=true|false,\
                     direct=true|false\"",
                )
                .takes_value(true)
                .conflicts_with_all(&["net-backend", "kernel"])
                .min_values(1),
        )
}

fn start_vmm(cmd_arguments: ArgMatches) {
    let vm_params = config::VmParams::from_arg_matches(&cmd_arguments);
    let vm_config = match config::VmConfig::parse(vm_params) {
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
        vm_config.cpus.boot_vcpus,
        vm_config.memory.size >> 20,
        vm_config.kernel,
        vm_config.cmdline.args.as_str(),
        vm_config.disks,
    );

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).expect("Cannot create API EventFd");

    let http_sender = api_request_sender.clone();
    let vmm_thread = match vmm::start_vmm_thread(
        env!("CARGO_PKG_VERSION").to_string(),
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
            Arc::new(Mutex::new(vm_config)),
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

    let (default_vcpus, default_memory, default_rng) = prepare_default_values();

    let cmd_arguments = create_app(
        &default_vcpus,
        &default_memory,
        &default_rng,
        &api_server_path,
    )
    .get_matches();

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

    if let Some(backend_command) = cmd_arguments.value_of("net-backend") {
        start_net_backend(backend_command);
    } else if let Some(backend_command) = cmd_arguments.value_of("block-backend") {
        start_block_backend(backend_command);
    } else {
        start_vmm(cmd_arguments);
    }
}

#[cfg(test)]
#[macro_use]
extern crate credibility;

#[cfg(test)]
mod unit_tests {
    use crate::{create_app, prepare_default_values};
    use std::path::PathBuf;
    use vmm::config::{
        CmdlineConfig, ConsoleConfig, ConsoleOutputMode, CpusConfig, MemoryConfig, RngConfig,
        VmConfig, VmParams,
    };

    fn get_vm_config_from_vec(args: &[&str]) -> VmConfig {
        let (default_vcpus, default_memory, default_rng) = prepare_default_values();
        let api_server_path = "";

        let cmd_arguments = create_app(
            &default_vcpus,
            &default_memory,
            &default_rng,
            &api_server_path,
        )
        .get_matches_from(args);

        let vm_params = VmParams::from_arg_matches(&cmd_arguments);

        VmConfig::parse(vm_params).unwrap()
    }

    fn compare_vm_config_cli_vs_json(
        cli: &[&str],
        openapi: &str,
        equal: bool,
    ) -> (VmConfig, VmConfig) {
        let cli_vm_config = get_vm_config_from_vec(cli);
        let openapi_vm_config: VmConfig = serde_json::from_str(openapi).unwrap();

        test_block!(tb, "", {
            if equal {
                aver_eq!(tb, cli_vm_config, openapi_vm_config);
            } else {
                aver_ne!(tb, cli_vm_config, openapi_vm_config);
            }

            Ok(())
        });

        (cli_vm_config, openapi_vm_config)
    }

    #[test]
    fn test_valid_vm_config_default() {
        let cli = vec!["cloud-hypervisor"];
        let openapi = r#"{}"#;

        // First we check we get identical VmConfig structures.
        let (result_vm_config, _) = compare_vm_config_cli_vs_json(&cli, openapi, true);

        // As a second step, we validate all the default values.
        test_block!(tb, "", {
            let expected_vm_config = VmConfig {
                cpus: CpusConfig {
                    boot_vcpus: 1,
                    max_vcpus: 1,
                },
                memory: MemoryConfig {
                    size: 536_870_912,
                    file: None,
                    mergeable: false,
                    hotplug_size: None,
                },
                kernel: None,
                cmdline: CmdlineConfig {
                    args: String::from(""),
                },
                disks: None,
                net: None,
                rng: RngConfig {
                    src: PathBuf::from("/dev/urandom"),
                    iommu: false,
                },
                fs: None,
                pmem: None,
                serial: ConsoleConfig {
                    file: None,
                    mode: ConsoleOutputMode::Null,
                    iommu: false,
                },
                console: ConsoleConfig {
                    file: None,
                    mode: ConsoleOutputMode::Tty,
                    iommu: false,
                },
                devices: None,
                vhost_user_net: None,
                vhost_user_blk: None,
                vsock: None,
                iommu: false,
            };

            aver_eq!(tb, expected_vm_config, result_vm_config);
            Ok(())
        })
    }

    #[test]
    fn test_valid_vm_config_cpus() {
        vec![
            (
                vec!["cloud-hypervisor", "--cpus", "boot=1"],
                r#"{
                    "cpus": {"boot_vcpus": 1, "max_vcpus": 1}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--cpus", "boot=1,max=3"],
                r#"{
                    "cpus": {"boot_vcpus": 1, "max_vcpus": 3}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--cpus", "boot=2,max=4"],
                r#"{
                    "cpus": {"boot_vcpus": 1, "max_vcpus": 3}
                }"#,
                false,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_memory() {
        vec![
            (
                vec!["cloud-hypervisor", "--memory", "size=1073741824"],
                r#"{
                    "memory": {"size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--memory", "size=1G"],
                r#"{
                    "memory": {"size": 1073741824}
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--memory",
                    "size=1G,file=/path/to/shared/file",
                ],
                r#"{
                    "memory": {"size": 1073741824, "file": "/path/to/shared/file"}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--memory", "size=1G,mergeable=on"],
                r#"{
                    "memory": {"size": 1073741824, "mergeable": true}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--memory", "size=1G,mergeable=off"],
                r#"{
                    "memory": {"size": 1073741824, "mergeable": false}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--memory", "size=1G,mergeable=on"],
                r#"{
                    "memory": {"size": 1073741824, "mergeable": false}
                }"#,
                false,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_kernel() {
        vec![(
            vec!["cloud-hypervisor", "--kernel", "/path/to/kernel"],
            r#"{
                "kernel": {"path": "/path/to/kernel"}
            }"#,
            true,
        )]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_cmdline() {
        vec![(
            vec!["cloud-hypervisor", "--cmdline", "arg1=foo arg2=bar"],
            r#"{
                "cmdline": {"args": "arg1=foo arg2=bar"}
            }"#,
            true,
        )]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_disks() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--disk",
                    "path=/path/to/disk/1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "disks": [
                        {"path": "/path/to/disk/1"},
                        {"path": "/path/to/disk/2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--disk",
                    "path=/path/to/disk/1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "disks": [
                        {"path": "/path/to/disk/1"}
                    ]
                }"#,
                false,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_net() {
        vec![
            // This test is expected to fail because the default MAC address is
            // randomly generated. There's no way we can have twice the same
            // default value.
            (
                vec!["cloud-hypervisor", "--net", "mac="],
                r#"{
                    "net": []
                }"#,
                false,
            ),
            (
                vec!["cloud-hypervisor", "--net", "mac=12:34:56:78:90:ab"],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=4",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=4,queue_size=128",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256,iommu=on",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": true}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256,iommu=on",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": true}
                    ],
                    "iommu": true
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--net",
                    "mac=12:34:56:78:90:ab,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256,iommu=off",
                ],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": false}
                    ]
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_rng() {
        vec![(
            vec!["cloud-hypervisor", "--rng", "src=/path/to/entropy/source"],
            r#"{
                "rng": {"src": "/path/to/entropy/source"}
            }"#,
            true,
        )]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_fs() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1",
                    "tag=virtiofs2,sock=/path/to/sock2",
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1"},
                        {"tag": "virtiofs2", "sock": "/path/to/sock2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1",
                    "tag=virtiofs2,sock=/path/to/sock2",
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4",
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128,dax=on"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128,dax=on"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "dax": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "dax": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128,cache_size=8589934592"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "cache_size": 8589934592}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128,cache_size=4294967296"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "cache_size": 4294967296}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--fs",
                    "tag=virtiofs1,sock=/path/to/sock1,num_queues=4,queue_size=128,cache_size=4294967296"
                ],
                r#"{
                    "fs": [
                        {"tag": "virtiofs1", "sock": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                false,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_pmem() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--pmem",
                    "file=/path/to/img/1,size=1G",
                    "file=/path/to/img/2,size=2G",
                ],
                r#"{
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824},
                        {"file": "/path/to/img/2", "size": 2147483648}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,iommu=on",
                ],
                r#"{
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "iommu": true}
                    ],
                    "iommu": true
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,iommu=on",
                ],
                r#"{
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "iommu": true}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,mergeable=on",
                ],
                r#"{
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "mergeable": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,mergeable=off",
                ],
                r#"{
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "mergeable": false}
                    ]
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_serial_console() {
        vec![
            (
                vec!["cloud-hypervisor"],
                r#"{
                    "serial": {"mode": "Null"},
                    "console": {"mode": "Tty"}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--serial", "null", "--console", "tty"],
                r#"{}"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--serial", "tty", "--console", "off"],
                r#"{
                    "serial": {"mode": "Tty"},
                    "console": {"mode": "Off"}
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_devices() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--device",
                    "path=/path/to/device/1",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "devices": [
                        {"path": "/path/to/device/1"},
                        {"path": "/path/to/device/2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--device",
                    "path=/path/to/device/1",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "devices": [
                        {"path": "/path/to/device/1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--device",
                    "path=/path/to/device,iommu=on",
                ],
                r#"{
                    "devices": [
                        {"path": "/path/to/device", "iommu": true}
                    ],
                    "iommu": true
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--device",
                    "path=/path/to/device,iommu=on",
                ],
                r#"{
                    "devices": [
                        {"path": "/path/to/device", "iommu": true}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--device",
                    "path=/path/to/device,iommu=off",
                ],
                r#"{
                    "devices": [
                        {"path": "/path/to/device", "iommu": false}
                    ]
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_vunet() {
        vec![
            // This test is expected to fail because the default MAC address is
            // randomly generated. There's no way we can have twice the same
            // default value.
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-net",
                    "sock=/path/to/sock/1",
                    "sock=/path/to/sock/2",
                ],
                r#"{
                    "vhost_user_net": [
                        {"sock": "/path/to/sock/1"},
                        {"sock": "/path/to/sock/2"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-net",
                    "sock=/path/to/sock/1,mac=12:34:56:78:90:ab",
                    "sock=/path/to/sock/2,mac=12:34:56:78:90:cd",
                ],
                r#"{
                    "vhost_user_net": [
                        {"sock": "/path/to/sock/1", "mac": "12:34:56:78:90:ab"},
                        {"sock": "/path/to/sock/2", "mac": "12:34:56:78:90:cd"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-net",
                    "sock=/path/to/sock,mac=12:34:56:78:90:ab,num_queues=4",
                ],
                r#"{
                    "vhost_user_net": [
                        {"sock": "/path/to/sock", "mac": "12:34:56:78:90:ab", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-net",
                    "sock=/path/to/sock,mac=12:34:56:78:90:ab,num_queues=4,queue_size=128",
                ],
                r#"{
                    "vhost_user_net": [
                        {"sock": "/path/to/sock", "mac": "12:34:56:78:90:ab", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-net",
                    "sock=/path/to/sock,mac=12:34:56:78:90:ab,num_queues=2,queue_size=256",
                ],
                r#"{
                    "vhost_user_net": [
                        {"sock": "/path/to/sock", "mac": "12:34:56:78:90:ab"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-net",
                    "sock=/path/to/sock,mac=12:34:56:78:90:ab",
                ],
                r#"{
                    "vhost_user_net": [
                        {"sock": "/path/to/sock", "mac": "12:34:56:78:90:ab", "num_queues": 2, "queue_size": 256}
                    ]
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_vublk() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1",
                    "sock=/path/to/sock/2",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1"},
                        {"sock": "/path/to/sock/2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1",
                    "sock=/path/to/sock/2",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1,num_queues=4",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1,num_queues=4,queue_size=1024",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1", "num_queues": 4, "queue_size": 1024}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1,num_queues=4,queue_size=1024,wce=true",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1", "num_queues": 4, "queue_size": 1024, "wce": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1,num_queues=1,queue_size=128,wce=true",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vhost-user-blk",
                    "sock=/path/to/sock/1",
                ],
                r#"{
                    "vhost_user_blk": [
                        {"sock": "/path/to/sock/1", "num_queues": 1, "queue_size": 128, "wce": true}
                    ]
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_vsock() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--vsock",
                    "cid=123,sock=/path/to/sock/1",
                    "cid=456,sock=/path/to/sock/2",
                ],
                r#"{
                    "vsock": [
                        {"cid": 123, "sock": "/path/to/sock/1"},
                        {"cid": 456, "sock": "/path/to/sock/2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vsock",
                    "cid=123,sock=/path/to/sock/1",
                    "cid=456,sock=/path/to/sock/2",
                ],
                r#"{
                    "vsock": [
                        {"cid": 123, "sock": "/path/to/sock/1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vsock",
                    "cid=124,sock=/path/to/sock/1",
                ],
                r#"{
                    "vsock": [
                        {"cid": 123, "sock": "/path/to/sock/1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vsock",
                    "cid=123,sock=/path/to/sock/1,iommu=on",
                ],
                r#"{
                    "vsock": [
                        {"cid": 123, "sock": "/path/to/sock/1", "iommu": true}
                    ],
                    "iommu": true
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vsock",
                    "cid=123,sock=/path/to/sock/1,iommu=on",
                ],
                r#"{
                    "vsock": [
                        {"cid": 123, "sock": "/path/to/sock/1", "iommu": true}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--vsock",
                    "cid=123,sock=/path/to/sock/1,iommu=off",
                ],
                r#"{
                    "vsock": [
                        {"cid": 123, "sock": "/path/to/sock/1", "iommu": false}
                    ]
                }"#,
                true,
            ),
        ]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }
}

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
    use std::io;
    use std::io::BufRead;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::Path;
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
        l2_guest_ip1: String,
        l2_guest_ip2: String,
        host_ip: String,
        guest_mac: String,
        l2_guest_mac1: String,
        l2_guest_mac2: String,
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
            user_data_string = user_data_string.replace("12:34:56:78:90:ab", &network.guest_mac);
            user_data_string =
                user_data_string.replace("de:ad:be:ef:12:34", &network.l2_guest_mac1);
            user_data_string =
                user_data_string.replace("de:ad:be:ef:34:56", &network.l2_guest_mac2);

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
            osdisk_base_path.push("clear-31310-cloudguest.img");

            let mut osdisk_raw_base_path = workload_path;
            osdisk_raw_base_path.push("clear-31310-cloudguest-raw.img");

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
                    "image={},sock={},readonly={},direct={}",
                    blk_file_path, vubd_socket_path, rdonly, direct
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
                host_ip: format!("{}.{}.1", class, id),
                guest_mac: format!("12:34:56:78:90:{:02x}", id),
                l2_guest_mac1: format!("de:ad:be:ef:12:{:02x}", id),
                l2_guest_mac2: format!("de:ad:be:ef:34:{:02x}", id),
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

        fn api_resize_body(&self, desired_vcpus: Option<u8>, desired_ram: Option<u64>) -> String {
            let resize = vmm::api::VmResizeData {
                desired_vcpus,
                desired_ram,
            };
            serde_json::to_string(&resize).unwrap()
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

            let start_addr = u64::from_str_radix(args[0], 16).map_err(Error::Parsing)?;
            let end_addr = u64::from_str_radix(args[1], 16).map_err(Error::Parsing)?;

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

                let mut child = Command::new("target/release/cloud-hypervisor")
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
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
            let mut bionic = UbuntuDiskConfig::new(BIONIC_IMAGE_NAME.to_string());
            let guest = Guest::new(&mut bionic);
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=5120M"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=128G"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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
    fn test_virtio_blk() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut blk_file_path = dirs::home_dir().unwrap();
            blk_file_path.push("workloads");
            blk_file_path.push("blk.img");

            let mut cloud_child = Command::new("target/release/cloud-hypervisor")
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
                .args(&["--net", guest.default_net_string().as_str()])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(5, 0));
            let _ = cloud_child.kill();
            let _ = cloud_child.wait();

            Ok(())
        });
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_vhost_user_net() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            // Start the daemon
            let mut daemon_child = Command::new("target/release/cloud-hypervisor")
                .args(&[
                    "--net-backend",
                    format!(
                        "ip={},mask=255.255.255.0,sock=/tmp/vunet.sock,num_queues=4,queue_size=1024",
                        guest.network.host_ip
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();
            thread::sleep(std::time::Duration::new(10, 0));

            let mut cloud_child = Command::new("target/release/cloud-hypervisor")
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
                ])
                .args(&[
                    "--net",
                    format!(
                        "vhost_user=true,mac={},socket=/tmp/vunet.sock,num_queues=4,queue_size=1024",
                        guest.network.guest_mac
                    )
                    .as_str(),
                ])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));
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

            thread::sleep(std::time::Duration::new(10, 0));
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

            let (mut daemon_child, vubd_socket_path) =
                prepare_vubd(&guest.tmp_dir, "blk.img", false, false);

            let mut cloud_child = Command::new("target/release/cloud-hypervisor")
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
    fn test_vhost_user_blk_readonly() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) =
                prepare_vubd(&guest.tmp_dir, "blk.img", true, false);

            let mut cloud_child = Command::new("target/release/cloud-hypervisor")
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
    fn test_vhost_user_blk_direct() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);

            let (mut daemon_child, vubd_socket_path) =
                prepare_vubd(&guest.tmp_dir, "blk.img", false, true);

            let mut cloud_child = Command::new("target/release/cloud-hypervisor")
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
                false,
                false,
            );

            let mut cloud_child = Command::new("target/release/cloud-hypervisor")
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M,file=/dev/shm"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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
                    "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 \
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
        test_virtio_fs(true, None, "none", &prepare_virtiofsd)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_fs_dax_on_cache_size_1_gib() {
        test_virtio_fs(true, Some(0x4000_0000), "none", &prepare_virtiofsd)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    fn test_virtio_fs_dax_off() {
        test_virtio_fs(false, None, "none", &prepare_virtiofsd)
    }

    #[cfg_attr(not(feature = "mmio"), test)]
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
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
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            let mut kernel_path = workload_path;
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--disk",
                    format!(
                        "path={}",
                        guest.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str()])
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
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
    // The VFIO integration test starts a cloud-hypervisor guest and then
    // direct assigns one of the virtio-pci device to a cloud-hypervisor
    // nested guest. The test assigns one of the 2 virtio-pci networking
    // interface, and thus the cloud-hypervisor guest will get a networking
    // interface through that direct assignment.
    // The test starts cloud-hypervisor guest with 2 TAP backed networking
    // interfaces, bound through a simple bridge on the host. So if the nested
    // cloud-hypervisor succeeds in getting a directly assigned interface from
    // its cloud-hypervisor host, we should be able to ssh into it, and verify
    // that it's running with the right kernel command line (We tag the command
    // line from cloud-hypervisor for that purpose).
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

            let (mut daemon_child, virtiofsd_socket_path) =
                prepare_virtiofsd(&guest.tmp_dir, vfio_path.to_str().unwrap(), "none");

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=4"])
                .args(&["--memory", "size=1G,file=/dev/shm"])
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
                ])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 vfio_iommu_type1.allow_unsafe_interrupts rw"])
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

            guest.ssh_command_l2_1("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));

            guest.ssh_command_l1("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));

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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw acpi=off"])
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

                let mut child = Command::new("target/release/cloud-hypervisor")
                    .args(&["--cpus", "boot=1"])
                    .args(&["--memory", "size=512M"])
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

            let mut kernel_path = workload_path;
            kernel_path.push("bzImage");

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus","boot=1"])
                .args(&["--memory", "size=512M"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut child = Command::new("target/release/cloud-hypervisor")
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
            thread::sleep(std::time::Duration::new(5, 0));

            // Check that the VM booted as expected
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            guest
                .ssh_command("sudo shutdown -h now")
                .unwrap_or_default();
            thread::sleep(std::time::Duration::new(10, 0));

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

            let mut child = Command::new("target/release/cloud-hypervisor")
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
            thread::sleep(std::time::Duration::new(5, 0));

            // Check that the VM booted as expected
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            // We now pause the VM
            curl_command(&api_socket, "PUT", "http://localhost/api/v1/vm.pause", None);
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
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resume",
                None,
            );
            thread::sleep(std::time::Duration::new(2, 0));

            // Now we should be able to SSH back in and get the right number of CPUs
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );

            guest
                .ssh_command("sudo shutdown -h now")
                .unwrap_or_default();
            thread::sleep(std::time::Duration::new(10, 0));

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

            let mut child = Command::new("target/release/cloud-hypervisor")
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
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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
            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", "size=512M"])
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
                ])
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

            let init_bar_addr = guest
                .ssh_command("sudo bash -c \"cat /sys/bus/pci/devices/0000:00:05.0/resource | awk '{print $1; exit}'\"")?;

            // Remove the PCI device
            guest
                .ssh_command("sudo bash -c 'echo 1 > /sys/bus/pci/devices/0000:00:05.0/remove'")?;

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
            guest.ssh_command("sudo bash -c 'echo 1 > /sys/bus/pci/rescan'")?;

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

            let new_bar_addr = guest
                .ssh_command("sudo bash -c \"cat /sys/bus/pci/devices/0000:00:05.0/resource | awk '{print $1; exit}'\"")?;

            // Let's compare the BAR addresses for our virtio-net device.
            // They should be different as we expect the BAR reprogramming
            // to have happened.
            aver_ne!(tb, init_bar_addr, new_bar_addr);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut child1 = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
                .args(&["--kernel", guest1.fw_path.as_str()])
                .args(&[
                    "--disk",
                    format!(
                        "path={}",
                        guest1.disk_config.disk(DiskType::OperatingSystem).unwrap()
                    )
                    .as_str(),
                    format!(
                        "path={}",
                        guest1.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str(),
                ])
                .args(&["--net", guest1.default_net_string().as_str()])
                .args(&["--serial", "tty", "--console", "off"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            // Get initial PSS
            let old_pss = get_pss(child1.id());

            let guest2 = Guest::new(&mut clear2 as &mut dyn DiskConfig);

            let mut child2 = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=1"])
                .args(&["--memory", format!("size=512M,{}", memory_param).as_str()])
                .args(&["--kernel", guest2.fw_path.as_str()])
                .args(&[
                    "--disk",
                    format!(
                        "path={}",
                        guest2.disk_config.disk(DiskType::OperatingSystem).unwrap()
                    )
                    .as_str(),
                    format!(
                        "path={}",
                        guest2.disk_config.disk(DiskType::CloudInit).unwrap()
                    )
                    .as_str(),
                ])
                .args(&["--net", guest2.default_net_string().as_str()])
                .args(&["--serial", "tty", "--console", "off"])
                .spawn()
                .unwrap();

            // Let enough time for the second VM to be spawned, and to make
            // sure KVM has enough time to merge identical pages between the
            // 2 VMs.
            thread::sleep(std::time::Duration::new(30, 0));

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

            guest1
                .ssh_command("sudo shutdown -h now")
                .unwrap_or_default();
            guest2
                .ssh_command("sudo shutdown -h now")
                .unwrap_or_default();
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
                .args(&["--api-socket", &api_socket])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(20, 0));

            aver_eq!(tb, guest.get_cpu_count().unwrap_or_default(), 2);

            // Resize the VM
            let desired_vcpus = 4;
            let http_body = guest.api_resize_body(Some(desired_vcpus), None);
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resize",
                Some(&http_body),
            );

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
            let http_body = guest.api_resize_body(Some(desired_vcpus), None);
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resize",
                Some(&http_body),
            );
            thread::sleep(std::time::Duration::new(10, 0));
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M,hotplug_size=8192M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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
            let http_body = guest.api_resize_body(None, Some(desired_ram));
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resize",
                Some(&http_body),
            );

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
            let http_body = guest.api_resize_body(None, Some(desired_ram));
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resize",
                Some(&http_body),
            );

            thread::sleep(std::time::Duration::new(10, 0));
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 1_964_000);

            // Remove RAM to the VM (only applies after reboot)
            let desired_ram = 1024 << 20;
            let http_body = guest.api_resize_body(None, Some(desired_ram));
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resize",
                Some(&http_body),
            );

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

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
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

            let mut child = Command::new("target/release/cloud-hypervisor")
                .args(&["--cpus", "boot=2,max=4"])
                .args(&["--memory", "size=512M,hotplug_size=8192M"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--cmdline", "root=PARTUUID=8d93774b-e12c-4ac5-aa35-77bfa7168767 console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
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
                ])
                .args(&["--net", guest.default_net_string().as_str()])
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
            let http_body = guest.api_resize_body(Some(desired_vcpus), Some(desired_ram));
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.resize",
                Some(&http_body),
            );

            guest.ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu2/online")?;
            guest.ssh_command("echo 1 | sudo tee /sys/bus/cpu/devices/cpu3/online")?;
            thread::sleep(std::time::Duration::new(10, 0));
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default(),
                u32::from(desired_vcpus)
            );

            aver!(tb, guest.get_total_memory().unwrap_or_default() > 982_000);

            guest.ssh_command("sudo shutdown -h now")?;
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }
}
