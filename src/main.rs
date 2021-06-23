// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use(crate_authors)]
extern crate clap;
#[macro_use]
extern crate event_monitor;

use clap::{App, Arg, ArgGroup, ArgMatches};
use libc::EFD_NONBLOCK;
use log::LevelFilter;
use option_parser::OptionParser;
use seccomp::SeccompAction;
use signal_hook::{
    consts::SIGSYS,
    iterator::{exfiltrator::WithRawSiginfo, SignalsInfo},
};
use std::env;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use thiserror::Error;
use vmm::config;
use vmm_sys_util::eventfd::EventFd;

#[derive(Error, Debug)]
enum Error {
    #[error("Failed to create API EventFd: {0}")]
    CreateApiEventFd(#[source] std::io::Error),
    #[cfg_attr(
        feature = "kvm",
        error("Failed to open hypervisor interface (is /dev/kvm available?): {0}")
    )]
    #[cfg_attr(
        feature = "mshv",
        error("Failed to open hypervisor interface (is /dev/mshv available?): {0}")
    )]
    CreateHypervisor(#[source] hypervisor::HypervisorError),
    #[error("Failed to start the VMM thread: {0}")]
    StartVmmThread(#[source] vmm::Error),
    #[error("Error parsing config: {0}")]
    ParsingConfig(vmm::config::Error),
    #[error("Error creating VM: {0:?}")]
    VmCreate(vmm::api::ApiError),
    #[error("Error booting VM: {0:?}")]
    VmBoot(vmm::api::ApiError),
    #[error("Error restoring VM: {0:?}")]
    VmRestore(vmm::api::ApiError),
    #[error("Error parsing restore: {0}")]
    ParsingRestore(vmm::config::Error),
    #[error("Failed to join on VMM thread: {0:?}")]
    ThreadJoin(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    #[error("VMM thread exited with error: {0}")]
    VmmThread(#[source] vmm::Error),
    #[error("Error parsing --api-socket: {0}")]
    ParsingApiSocket(std::num::ParseIntError),
    #[error("Error parsing --event-monitor: {0}")]
    ParsingEventMonitor(option_parser::OptionParserError),
    #[error("Error parsing --event-monitor: path or fd required")]
    BareEventMonitor,
    #[error("Error doing event monitor I/O: {0}")]
    EventMonitorIo(std::io::Error),
    #[error("Error creating log file: {0}")]
    LogFileCreation(std::io::Error),
    #[error("Error setting up logger: {0}")]
    LoggerSetup(log::SetLoggerError),
}

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
                "cloud-hypervisor: {:?}: <{}> {}:{}:{} -- {}",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            )
        } else {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:?}: <{}> {}:{} -- {}",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
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
                    topology=<threads_per_core>:<cores_per_die>:<dies_per_package>:<packages>,\
                    kvm_hyperv=on|off,max_phys_bits=<maximum_number_of_physical_bits>",
                )
                .default_value(default_vcpus)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("memory")
                .long("memory")
                .help(
                    "Memory parameters \
                     \"size=<guest_memory_size>,mergeable=on|off,shared=on|off,\
                     hugepages=on|off,hugepage_size=<hugepage_size>\
                     hotplug_method=acpi|virtio-mem,\
                     hotplug_size=<hotpluggable_memory_size>,\
                     hotplugged_size=<hotplugged_memory_size>\"",
                )
                .default_value(default_memory)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("memory-zone")
                .long("memory-zone")
                .help(
                    "User defined memory zone parameters \
                     \"size=<guest_memory_region_size>,file=<backing_file>,\
                     shared=on|off,\
                     hugepages=on|off,hugepage_size=<hugepage_size>\
                     host_numa_node=<node_id>,\
                     id=<zone_identifier>,hotplug_size=<hotpluggable_memory_size>,\
                     hotplugged_size=<hotplugged_memory_size>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("kernel")
                .long("kernel")
                .help(
                    "Path to loaded kernel. This may be a kernel or firmware that supports a PVH \
                entry point (e.g. vmlinux) or architecture equivalent",
                )
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
                .default_value(default_rng)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("balloon")
                .long("balloon")
                .help(config::BalloonConfig::SYNTAX)
                .takes_value(true)
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
                .help("Control serial port: off|null|pty|tty|file=/path/to/a/file")
                .default_value("null")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("console")
                .long("console")
                .help(
                    "Control (virtio) console: \"off|null|pty|tty|file=/path/to/a/file,iommu=on|off\"",
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
            Arg::with_name("numa")
                .long("numa")
                .help(config::NumaConfig::SYNTAX)
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("watchdog")
                .long("watchdog")
                .help("Enable virtio-watchdog")
                .takes_value(false)
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
                .help("HTTP API socket (UNIX domain socket): path=</path/to/a/file> or fd=<fd>.")
                .takes_value(true)
                .min_values(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::with_name("event-monitor")
                .long("event-monitor")
                .help("File to report events on: path=</path/to/a/file> or fd=<fd>")
                .takes_value(true)
                .min_values(1)
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

    #[cfg(feature = "tdx")]
    {
        app = app.arg(
            Arg::with_name("tdx")
                .long("tdx")
                .help("TDX Support: firmware=<tdvf path>")
                .takes_value(true)
                .group("vm-config"),
        );
    }

    app
}

fn start_vmm(cmd_arguments: ArgMatches) -> Result<Option<String>, Error> {
    let log_level = match cmd_arguments.occurrences_of("v") {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn std::io::Write + Send> = if let Some(file) =
        cmd_arguments.value_of("log-file")
    {
        Box::new(std::fs::File::create(std::path::Path::new(file)).map_err(Error::LogFileCreation)?)
    } else {
        Box::new(std::io::stderr())
    };

    log::set_boxed_logger(Box::new(Logger {
        output: Mutex::new(log_file),
        start: std::time::Instant::now(),
    }))
    .map(|()| log::set_max_level(log_level))
    .map_err(Error::LoggerSetup)?;

    let (api_socket_path, api_socket_fd) =
        if let Some(socket_config) = cmd_arguments.value_of("api-socket") {
            let mut parser = OptionParser::new();
            parser.add("path").add("fd");
            parser.parse(socket_config).unwrap_or_default();

            if let Some(fd) = parser.get("fd") {
                (
                    None,
                    Some(fd.parse::<RawFd>().map_err(Error::ParsingApiSocket)?),
                )
            } else if let Some(path) = parser.get("path") {
                (Some(path), None)
            } else {
                (
                    cmd_arguments.value_of("api-socket").map(|s| s.to_string()),
                    None,
                )
            }
        } else {
            (None, None)
        };

    if let Some(monitor_config) = cmd_arguments.value_of("event-monitor") {
        let mut parser = OptionParser::new();
        parser.add("path").add("fd");
        parser
            .parse(monitor_config)
            .map_err(Error::ParsingEventMonitor)?;

        let file = if parser.is_set("fd") {
            let fd = parser
                .convert("fd")
                .map_err(Error::ParsingEventMonitor)?
                .unwrap();
            unsafe { File::from_raw_fd(fd) }
        } else if parser.is_set("path") {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(parser.get("path").unwrap())
                .map_err(Error::EventMonitorIo)?
        } else {
            return Err(Error::BareEventMonitor);
        };
        event_monitor::set_monitor(file).map_err(Error::EventMonitorIo)?;
    }

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateApiEventFd)?;

    let http_sender = api_request_sender.clone();
    let seccomp_action = if let Some(seccomp_value) = cmd_arguments.value_of("seccomp") {
        match seccomp_value {
            "true" => SeccompAction::Trap,
            "false" => SeccompAction::Allow,
            "log" => SeccompAction::Log,
            _ => {
                // The user providing an invalid value will be rejected by clap
                panic!("Invalid parameter {} for \"--seccomp\" flag", seccomp_value);
            }
        }
    } else {
        SeccompAction::Trap
    };

    // See https://github.com/rust-lang/libc/issues/716 why we can't get the details from siginfo_t
    if seccomp_action == SeccompAction::Trap {
        thread::Builder::new()
            .name("seccomp_signal_handler".to_string())
            .spawn(move || {
                for si in SignalsInfo::<WithRawSiginfo>::new(&[SIGSYS])
                    .unwrap()
                    .forever()
                {
                    /* SYS_SECCOMP */
                    if si.si_code == 1 {
                        eprint!(
                            "\n==== seccomp violation ====\n\
                            Try running with `strace -ff` to identify the cause and open an issue: \
                            https://github.com/cloud-hypervisor/cloud-hypervisor/issues/new\n"
                        );

                        signal_hook::low_level::emulate_default_handler(SIGSYS).unwrap();
                    }
                }
            })
            .unwrap();
    }

    event!("vmm", "starting");

    let hypervisor = hypervisor::new().map_err(Error::CreateHypervisor)?;
    let vmm_thread = vmm::start_vmm_thread(
        env!("CARGO_PKG_VERSION").to_string(),
        &api_socket_path,
        api_socket_fd,
        api_evt.try_clone().unwrap(),
        http_sender,
        api_request_receiver,
        &seccomp_action,
        hypervisor,
    )
    .map_err(Error::StartVmmThread)?;

    // Can't test for "vm-config" group as some have default values. The kernel
    // is the only required option for booting the VM.
    if cmd_arguments.is_present("kernel") || cmd_arguments.is_present("tdx") {
        let vm_params = config::VmParams::from_arg_matches(&cmd_arguments);
        let vm_config = config::VmConfig::parse(vm_params).map_err(Error::ParsingConfig)?;

        // Create and boot the VM based off the VM config we just built.
        let sender = api_request_sender.clone();
        vmm::api::vm_create(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(Mutex::new(vm_config)),
        )
        .map_err(Error::VmCreate)?;
        vmm::api::vm_boot(api_evt.try_clone().unwrap(), sender).map_err(Error::VmBoot)?;
    } else if let Some(restore_params) = cmd_arguments.value_of("restore") {
        vmm::api::vm_restore(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(config::RestoreConfig::parse(restore_params).map_err(Error::ParsingRestore)?),
        )
        .map_err(Error::VmRestore)?;
    }

    vmm_thread
        .join()
        .map_err(Error::ThreadJoin)?
        .map_err(Error::VmmThread)?;

    Ok(api_socket_path)
}

fn main() {
    // Ensure all created files (.e.g sockets) are only accessible by this user
    let _ = unsafe { libc::umask(0o077) };

    let (default_vcpus, default_memory, default_rng) = prepare_default_values();
    let cmd_arguments = create_app(&default_vcpus, &default_memory, &default_rng).get_matches();
    let exit_code = match start_vmm(cmd_arguments) {
        Ok(path) => {
            path.map(|s| std::fs::remove_file(s).ok());
            0
        }
        Err(e) => {
            eprintln!("{}", e);
            1
        }
    };

    std::process::exit(exit_code);
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
        let cmd_arguments =
            create_app(&default_vcpus, &default_memory, &default_rng).get_matches_from(args);

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
                    kvm_hyperv: false,
                    max_phys_bits: None,
                },
                memory: MemoryConfig {
                    size: 536_870_912,
                    mergeable: false,
                    hotplug_method: HotplugMethod::Acpi,
                    hotplug_size: None,
                    hotplugged_size: None,
                    shared: false,
                    hugepages: false,
                    zones: None,
                    hugepage_size: None,
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
                balloon: None,
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
                numa: None,
                watchdog: false,
                #[cfg(feature = "tdx")]
                tdx: None,
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
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "disks": [
                        {"vhost_user":true, "vhost_socket":"/tmp/sock1"}
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
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "disks": [
                        {"vhost_user":true, "vhost_socket":"/tmp/sock1"}
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
                    "--cpus", "boot=2",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=4",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "cpus": {"boot_vcpus": 2, "max_vcpus": 2},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--cpus", "boot=2",
                    "--net",
                    "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,tap=tap0,ip=1.2.3.4,mask=5.6.7.8,num_queues=4,queue_size=128",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "cpus": {"boot_vcpus": 2, "max_vcpus": 2},
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
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,dax=on"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,dax=on"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "dax": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "dax": true}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,cache_size=8589934592"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true", "--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "cache_size": 8589934592}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true","--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,cache_size=4294967296"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128, "cache_size": 4294967296}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true","--cpus", "boot=4",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1,num_queues=4,queue_size=128,cache_size=4294967296"
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
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
    fn test_valid_vm_config_serial_pty_console_pty() {
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
                    "pty",
                    "--console",
                    "pty",
                ],
                r#"{
                    "kernel": {"path": "/path/to/kernel"},
                    "serial": {"mode": "Pty"},
                    "console": {"mode": "Pty"}
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
