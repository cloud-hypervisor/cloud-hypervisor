// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;
extern crate vmm_sys_util;

#[macro_use(crate_authors)]
extern crate clap;

use clap::{App, Arg, ArgGroup, ArgMatches};
use libc::EFD_NONBLOCK;
use log::LevelFilter;
use seccomp::SeccompLevel;
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
        } else {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:?}: {}:{} -- {}",
                duration,
                record.level(),
                record.target(),
                record.args()
            )
        }
        .ok();
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
        // 'BUILT_VERSION' is set by the build script 'build.rs' at
        // compile time
        .version(env!("BUILT_VERSION"))
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
                    "Memory parameters \
                     \"size=<guest_memory_size>,file=<backing_file_path>,mergeable=on|off,\
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
                .help(config::DiskConfig::SYNTAX)
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("net")
                .long("net")
                .help(
                    "Network parameters \
                     \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,iommu=on|off,\
                     num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\
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
                    "Random number generator parameters \"src=<entropy_source_path>,iommu=on|off\"",
                )
                .default_value(&default_rng)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("fs")
                .long("fs")
                .help(
                    "virtio-fs parameters \
                     \"tag=<tag_name>,sock=<socket_path>,num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>,dax=on|off,cache_size=<DAX cache size: \
                     default 8Gib>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("pmem")
                .long("pmem")
                .help(config::PmemConfig::SYNTAX)
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
                    "Control (virtio) console: \"off|null|tty|file=/path/to/a/file,iommu=on|off\"",
                )
                .default_value("tty")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("device")
                .long("device")
                .help(config::DeviceConfig::SYNTAX)
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vsock")
                .long("vsock")
                .help(
                    "Virtio VSOCK parameters \"cid=<context_id>,sock=<socket_path>,iommu=on|off\"",
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
                    "vhost-user-net backend parameters \
                     \"ip=<ip_addr>,mask=<net_mask>,sock=<socket_path>,\
                     num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,tap=<if_name>\"",
                )
                .takes_value(true)
                .conflicts_with_all(&["block-backend", "kernel"])
                .min_values(1),
        )
        .arg(
            Arg::with_name("block-backend")
                .long("block-backend")
                .help(
                    "vhost-user-block backend parameters \
                     \"image=<image_path>,sock=<socket_path>,num_queues=<number_of_queues>,\
                     readonly=true|false,direct=true|false,poll_queue=true|false\"",
                )
                .takes_value(true)
                .conflicts_with_all(&["net-backend", "kernel"])
                .min_values(1),
        )
        .arg(
            Arg::with_name("seccomp")
                .long("seccomp")
                .takes_value(true)
                .possible_values(&["true", "false"])
                .default_value("true"),
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
        "Cloud Hypervisor Guest\n\tAPI server: {}\n\tvCPUs: {}\n\tMemory: {} MB\n\tKernel: \
         {:?}\n\tKernel cmdline: {}\n\tDisk(s): {:?}",
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

    let seccomp_level = if let Some(seccomp_value) = cmd_arguments.value_of("seccomp") {
        match seccomp_value {
            "true" => SeccompLevel::Advanced,
            "false" => SeccompLevel::None,
            _ => {
                eprintln!("Invalid parameter {} for \"--seccomp\" flag", seccomp_value);
                process::exit(1);
            }
        }
    } else {
        SeccompLevel::Advanced
    };

    let vmm_thread = match vmm::start_vmm_thread(
        env!("CARGO_PKG_VERSION").to_string(),
        api_socket_path,
        api_evt.try_clone().unwrap(),
        http_sender,
        api_request_receiver,
        &seccomp_level,
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
            (
                vec![
                    "cloud-hypervisor",
                    "--disk",
                    "vhost_user=true,socket=/tmp/socket1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "disks": [
                        {"vhost_user":true, "vhost_socket":"/tmp/socket1"},
                        {"path": "/path/to/disk/2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--disk",
                    "vhost_user=true,socket=/tmp/socket1,wce=true",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "disks": [
                        {"vhost_user":true, "vhost_socket":"/tmp/socket1", "wce":true},
                        {"path": "/path/to/disk/2"}
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
            (
                vec!["cloud-hypervisor", "--net", "mac=12:34:56:78:90:ab,vhost_user=true,socket=/tmp/socket"],
                r#"{
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "vhost_user": true, "vhost_socket": "/tmp/socket"}
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
