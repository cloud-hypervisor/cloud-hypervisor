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
use seccomp::SeccompAction;
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
    #[cfg(target_arch = "x86_64")]
    let mut app: App;
    #[cfg(target_arch = "aarch64")]
    let app: App;

    app = App::new("cloud-hypervisor")
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
                .help(
                    "boot=<boot_vcpus>,max=<max_vcpus>,\
                    topology=<threads_per_core>:<cores_per_die>:<dies_per_package>:<packages>",
                )
                .default_value(&default_vcpus)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("memory")
                .long("memory")
                .help(
                    "Memory parameters \
                     \"size=<guest_memory_size>,mergeable=on|off,shared=on|off,hugepages=on|off,\
                     hotplug_method=acpi|virtio-mem,\
                     hotplug_size=<hotpluggable_memory_size>\"",
                )
                .default_value(&default_memory)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("memory-zone")
                .long("memory-zone")
                .help(
                    "User defined memory zone parameters \
                     \"size=<guest_memory_region_size>,file=<backing_file>,\
                     shared=on|off,hugepages=on|off\"",
                )
                .takes_value(true)
                .min_values(1)
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
            Arg::with_name("initramfs")
                .long("initramfs")
                .help("Path to initramfs image")
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
                .help(config::NetConfig::SYNTAX)
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
                .help(config::FsConfig::SYNTAX)
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
                .help(config::VsockConfig::SYNTAX)
                .takes_value(true)
                .number_of_values(1)
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
            Arg::with_name("restore")
                .long("restore")
                .help(config::RestoreConfig::SYNTAX)
                .takes_value(true)
                .min_values(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::with_name("net-backend")
                .long("net-backend")
                .help(vhost_user_net::SYNTAX)
                .takes_value(true)
                .conflicts_with_all(&["block-backend", "kernel"])
                .min_values(1),
        )
        .arg(
            Arg::with_name("block-backend")
                .long("block-backend")
                .help(vhost_user_block::SYNTAX)
                .takes_value(true)
                .conflicts_with_all(&["net-backend", "kernel"])
                .min_values(1),
        )
        .arg(
            Arg::with_name("seccomp")
                .long("seccomp")
                .takes_value(true)
                .possible_values(&["true", "false", "log"])
                .default_value("true"),
        );

    #[cfg(target_arch = "x86_64")]
    {
        app = app.arg(
            Arg::with_name("sgx-epc")
                .long("sgx-epc")
                .help(config::SgxEpcConfig::SYNTAX)
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        );
    }

    app
}

fn start_vmm(cmd_arguments: ArgMatches) {
    let api_socket_path = cmd_arguments
        .value_of("api-socket")
        .expect("Missing argument: api-socket");

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).expect("Cannot create API EventFd");

    let http_sender = api_request_sender.clone();
    let seccomp_action = if let Some(seccomp_value) = cmd_arguments.value_of("seccomp") {
        match seccomp_value {
            "true" => SeccompAction::Trap,
            "false" => SeccompAction::Allow,
            "log" => SeccompAction::Log,
            _ => {
                eprintln!("Invalid parameter {} for \"--seccomp\" flag", seccomp_value);
                process::exit(1);
            }
        }
    } else {
        SeccompAction::Trap
    };
    let hypervisor = hypervisor::new().unwrap();
    let vmm_thread = match vmm::start_vmm_thread(
        env!("CARGO_PKG_VERSION").to_string(),
        api_socket_path,
        api_evt.try_clone().unwrap(),
        http_sender,
        api_request_receiver,
        &seccomp_action,
        hypervisor,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed spawning the VMM thread {:?}", e);
            process::exit(1);
        }
    };

    // Can't test for "vm-config" group as some have default values. The kernel
    // is the only required option for booting the VM.
    if cmd_arguments.is_present("kernel") {
        let vm_params = config::VmParams::from_arg_matches(&cmd_arguments);
        let vm_config = match config::VmConfig::parse(vm_params) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };

        println!(
            "Cloud Hypervisor Guest\n\tAPI server: {}\n\tvCPUs: {}\n\tMemory: {} MB\n\tKernel: \
             {:?}\n\tInitramfs: {:?}\n\tKernel cmdline: {}\n\tDisk(s): {:?}",
            api_socket_path,
            vm_config.cpus.boot_vcpus,
            vm_config.memory.size >> 20,
            vm_config.kernel,
            vm_config.initramfs,
            vm_config.cmdline.args.as_str(),
            vm_config.disks,
        );

        // Create and boot the VM based off the VM config we just built.
        let sender = api_request_sender.clone();
        vmm::api::vm_create(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(Mutex::new(vm_config)),
        )
        .expect("Could not create the VM");
        vmm::api::vm_boot(api_evt.try_clone().unwrap(), sender).expect("Could not boot the VM");
    } else if let Some(restore_params) = cmd_arguments.value_of("restore") {
        vmm::api::vm_restore(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(match config::RestoreConfig::parse(restore_params) {
                Ok(config) => config,
                Err(e) => {
                    println!("{}", e);
                    process::exit(1);
                }
            }),
        )
        .expect("Could not restore the VM");
    }

    match vmm_thread.join() {
        Ok(res) => match res {
            Ok(_) => (),
            Err(e) => {
                eprintln!("VMM thread failed {:?}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Could not join VMM thread {:?}", e);
            process::exit(1);
        }
    }
}

fn main() {
    // Ensure all created files (.e.g sockets) are only accessible by this user
    let _ = unsafe { libc::umask(0o077) };

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
    use crate::config::HotplugMethod;
    use crate::{create_app, prepare_default_values};
    use std::path::PathBuf;
    use vmm::config::{
        CmdlineConfig, ConsoleConfig, ConsoleOutputMode, CpusConfig, KernelConfig, MemoryConfig,
        RngConfig, VmConfig, VmParams,
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
        let cli = vec!["cloud-hypervisor", "--kernel", "/path/to/kernel"];
        let openapi = r#"{ "kernel": {"path": "/path/to/kernel"} }"#;

        // First we check we get identical VmConfig structures.
        let (result_vm_config, _) = compare_vm_config_cli_vs_json(&cli, openapi, true);

        // As a second step, we validate all the default values.
        test_block!(tb, "", {
            let expected_vm_config = VmConfig {
                cpus: CpusConfig {
                    boot_vcpus: 1,
                    max_vcpus: 1,
                    topology: None,
                },
                memory: MemoryConfig {
                    size: 536_870_912,
                    mergeable: false,
                    hotplug_method: HotplugMethod::Acpi,
                    hotplug_size: None,
                    shared: false,
                    hugepages: false,
                    balloon: false,
                    balloon_size: 0,
                    zones: None,
                },
                kernel: Some(KernelConfig {
                    path: PathBuf::from("/path/to/kernel"),
                }),
                initramfs: None,
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
                #[cfg(target_arch = "x86_64")]
                sgx_epc: None,
            };

            aver_eq!(tb, expected_vm_config, result_vm_config);
            Ok(())
        })
    }

    #[test]
    fn test_valid_vm_config_cpus() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--cpus",
                    "boot=1",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "cpus": {"boot_vcpus": 1, "max_vcpus": 1}
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--cpus",
                    "boot=1,max=3",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "cpus": {"boot_vcpus": 1, "max_vcpus": 3}
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--cpus",
                    "boot=2,max=4",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1073741824"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,mergeable=on"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "mergeable": true}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,mergeable=off"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "mergeable": false}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,mergeable=on"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "mergeable": false}
                }"#,
                false,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,hotplug_size=1G"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "hotplug_method": "Acpi", "hotplug_size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,hotplug_method=virtio-mem,hotplug_size=1G"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "hotplug_method": "VirtioMem", "hotplug_size": 1073741824}
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
            vec![
                "cloud-hypervisor",
                "--kernel",
                "/path/to/kernel",
                "--cmdline",
                "arg1=foo arg2=bar",
            ],
            r#"{
                "kernel": {"path": "/path/to/kernel"},
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
                    "--kernel",
                    "/path/to/kernel",
                    "--disk",
                    "path=/path/to/disk/1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
                    "--kernel",
                    "/path/to/kernel",
                    "--disk",
                    "path=/path/to/disk/1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "disks": [
                        {"path": "/path/to/disk/1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--memory",
                    "shared=true",
                    "--disk",
                    "vhost_user=true,socket=/tmp/sock1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "disks": [
                        {"vhost_user":true, "vhost_socket":"/tmp/sock1"},
                        {"path": "/path/to/disk/2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--memory",
                    "shared=true",
                    "--disk",
                    "vhost_user=true,socket=/tmp/sock1",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "disks": [
                        {"vhost_user":true, "vhost_socket":"/tmp/sock1"},
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
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--net", "mac="],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": []
                }"#,
                false,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--net", "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=4",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=4,queue_size=128",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256}
                    ]
                }"#,
                true,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": true}
                    ]
                }"#,
                false,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": true}
                    ],
                    "iommu": true
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=2,queue_size=256,iommu=off",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": false}
                    ]
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "shared=true", "--net", "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,vhost_user=true,socket=/tmp/sock"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "vhost_user": true, "vhost_socket": "/tmp/sock"}
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
            vec![
                "cloud-hypervisor",
                "--kernel",
                "/path/to/kernel",
                "--rng",
                "src=/path/to/entropy/source",
            ],
            r#"{
                "kernel": {"path": "/path/to/kernel"},
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
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1",
                    "tag=virtiofs2,socket=/path/to/sock2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1"},
                        {"tag": "virtiofs2", "socket": "/path/to/sock2"}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1",
                    "tag=virtiofs2,socket=/path/to/sock2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,dax=on"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,dax=on"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "dax": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "dax": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,cache_size=8589934592"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "cache_size": 8589934592}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,cache_size=4294967296"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "cache_size": 4294967296}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,cache_size=4294967296"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
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
                    "--kernel",
                    "/path/to/kernel",
                    "--pmem",
                    "file=/path/to/img/1,size=1G",
                    "file=/path/to/img/2,size=2G",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824},
                        {"file": "/path/to/img/2", "size": 2147483648}
                    ]
                }"#,
                true,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "iommu": true}
                    ],
                    "iommu": true
                }"#,
                true,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "iommu": true}
                    ]
                }"#,
                false,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,mergeable=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "mergeable": true}
                    ]
                }"#,
                true,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--pmem",
                    "file=/path/to/img/1,size=1G,mergeable=off",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel"],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "serial": {"mode": "Null"},
                    "console": {"mode": "Tty"}
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--serial",
                    "null",
                    "--console",
                    "tty",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"}
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--serial",
                    "tty",
                    "--console",
                    "off",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
    #[cfg(target_arch = "x86_64")]
    fn test_valid_vm_config_devices() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--device",
                    "path=/path/to/device/1",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
                    "--kernel",
                    "/path/to/kernel",
                    "--device",
                    "path=/path/to/device/1",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "devices": [
                        {"path": "/path/to/device/1"}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--device",
                    "path=/path/to/device,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
                    "--kernel",
                    "/path/to/kernel",
                    "--device",
                    "path=/path/to/device,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "devices": [
                        {"path": "/path/to/device", "iommu": true}
                    ]
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--device",
                    "path=/path/to/device,iommu=off",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
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
                    "--kernel",
                    "/path/to/kernel",
                    "--vsock",
                    "cid=123,socket=/path/to/sock/1",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "vsock": {"cid": 123, "socket": "/path/to/sock/1"}
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vsock",
                    "cid=124,socket=/path/to/sock/1",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "vsock": {"cid": 123, "socket": "/path/to/sock/1"}
                }"#,
                false,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vsock",
                    "cid=123,socket=/path/to/sock/1,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "vsock": {"cid": 123, "socket": "/path/to/sock/1", "iommu": true},
                    "iommu": true
                }"#,
                true,
            ),
            #[cfg(target_arch = "x86_64")]
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vsock",
                    "cid=123,socket=/path/to/sock/1,iommu=on",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "vsock": {"cid": 123, "socket": "/path/to/sock/1", "iommu": true}
                }"#,
                false,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vsock",
                    "cid=123,socket=/path/to/sock/1,iommu=off",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "vsock": {"cid": 123, "socket": "/path/to/sock/1", "iommu": false}
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
