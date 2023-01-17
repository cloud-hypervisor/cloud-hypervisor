// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate event_monitor;

use argh::FromArgs;
use libc::EFD_NONBLOCK;
use log::LevelFilter;
use option_parser::OptionParser;
use seccompiler::SeccompAction;
use signal_hook::consts::SIGSYS;
use std::env;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use vmm::config;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::block_signal;
use vmm_sys_util::terminal::Terminal;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Error, Debug)]
enum Error {
    #[error("Failed to create API EventFd: {0}")]
    CreateApiEventFd(#[source] std::io::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Failed to create Debug EventFd: {0}")]
    CreateDebugEventFd(#[source] std::io::Error),
    #[error("Failed to open hypervisor interface (is hypervisor interface available?): {0}")]
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
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb: {0}")]
    ParsingGdb(option_parser::OptionParserError),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb: path required")]
    BareGdb,
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
                "cloud-hypervisor: {:.6?}: <{}> {}:{}:{} -- {}",
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
                "cloud-hypervisor: {:.6?}: <{}> {}:{} -- {}",
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

fn default_vcpus() -> String {
    format!(
        "boot={},max_phys_bits={}",
        config::DEFAULT_VCPUS,
        config::DEFAULT_MAX_PHYS_BITS
    )
}

fn default_memory() -> String {
    format!("size={}M", config::DEFAULT_MEMORY_MB)
}

fn default_rng() -> String {
    format!("src={}", config::DEFAULT_RNG_SOURCE)
}

#[derive(FromArgs)]
/// Launch a cloud-hypervisor VMM.
pub struct TopLevel {
    #[argh(option, long = "cpus", default = "default_vcpus()")]
    /// boot=<boot_vcpus>,max=<max_vcpus>,topology=<threads_per_core>:<cores_per_die>:<dies_per_package>:<packages>,kvm_hyperv=on|off,max_phys_bits=<maximum_number_of_physical_bits>,affinity=<list_of_vcpus_with_their_associated_cpuset>,features=<list_of_features_to_enable>
    cpus: String,

    #[argh(option, long = "platform")]
    /// num_pci_segments=<num_pci_segments>,iommu_segments=<list_of_segments>,serial_number=<dmi_device_serial_number>,uuid=<dmi_device_uuid>,oem_strings=<list_of_strings>
    platform: Option<String>,

    #[argh(option, long = "memory", default = "default_memory()")]
    /// size=<guest_memory_size>,mergeable=on|off,shared=on|off,hugepages=on|off,hugepage_size=<hugepage_size>,hotplug_method=acpi|virtio-mem,hotplug_size=<hotpluggable_memory_size>,hotplugged_size=<hotplugged_memory_size>,prefault=on|off,thp=on|off
    memory: String,

    #[argh(option, long = "memory-zone")]
    /// size=<guest_memory_region_size>,file=<backing_file>,shared=on|off,hugepages=on|off,hugepage_size=<hugepage_size>,host_numa_node=<node_id>,id=<zone_identifier>,hotplug_size=<hotpluggable_memory_size>,hotplugged_size=<hotplugged_memory_size>,prefault=on|off
    memory_zone: Vec<String>,

    #[argh(option, long = "firmware")]
    /// path to firmware that is loaded in an architectural specific way
    firmware: Option<String>,

    #[argh(option, long = "kernel")]
    /// path to kernel or firmware that supports a PVH entry point or architecture equivalent
    kernel: Option<String>,

    #[argh(option, long = "initramfs")]
    /// path to initramfs image
    initramfs: Option<String>,

    #[argh(option, long = "cmdline")]
    /// kernel command line
    cmdline: Option<String>,

    #[argh(option, long = "disk")]
    /// path=<disk_image_path>,readonly=on|off,direct=on|off,iommu=on|off,num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,vhost_user=on|off,socket=<vhost_user_socket_path>,bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,id=<device_id>,pci_segment=<segment_id>
    disk: Vec<String>,

    #[argh(option, long = "net")]
    /// tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,fd=<fd1,fd2...>,iommu=on|off,num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,id=<device_id>,vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>,vhost_mode=client|server,bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,pci_segment=<segment_id>offload_tso=on|off,offload_ufo=on|off,offload_csum=on|off
    net: Vec<String>,

    #[argh(option, long = "rng", default = "default_rng()")]
    /// src=<entropy_source_path>,iommu=on|off
    rng: String,

    #[argh(option, long = "balloon")]
    /// size=<balloon_size>,deflate_on_oom=on|off,free_page_reporting=on|off
    balloon: Option<String>,

    #[argh(option, long = "fs")]
    /// tag=<tag_name>,socket=<socket_path>,num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,id=<device_id>,pci_segment=<segment_id>
    fs: Vec<String>,

    #[argh(option, long = "pmem")]
    /// file=<backing_file_path>,size=<persistent_memory_size>,iommu=on|off,discard_writes=on|off,id=<device_id>,pci_segment=<segment_id>
    pmem: Vec<String>,

    #[argh(option, long = "serial", default = "String::from(\"null\")")]
    /// off|null|pty|tty|file=/path/to/a/file
    serial: String,

    #[argh(option, long = "console", default = "String::from(\"tty\")")]
    /// off|null|pty|tty|file=/path/to/a/file,iommu=on|off
    console: String,

    #[argh(option, long = "device")]
    /// path=<device_path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>
    device: Vec<String>,

    #[argh(option, long = "user-device")]
    /// socket=<socket_path>,id=<device_id>,pci_segment=<segment_id>
    user_device: Vec<String>,

    #[argh(option, long = "vdpa")]
    /// path=<device_path>,num_queues=<number_of_queues>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>
    vdpa: Vec<String>,

    #[argh(option, long = "vsock")]
    /// cid=<context_id>,socket=<socket_path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>
    vsock: Option<String>,

    #[argh(option, long = "numa")]
    /// guest_numa_id=<node_id>,cpus=<cpus_id>,distances=<list_of_distances_to_destination_nodes>,memory_zones=<list_of_memory_zones>,sgx_epc_sections=<list_of_sgx_epc_sections>
    numa: Vec<String>,

    #[argh(switch, long = "watchdog")]
    /// enable virtio-watchdog
    watchdog: bool,

    #[argh(switch, short = 'v')]
    /// set the level of debugging output
    verbosity: u8,

    #[argh(option, long = "log-file")]
    /// path to log file
    log_file: Option<String>,

    #[argh(option, long = "api-socket")]
    /// path=<path/to/a/file>|fd=<fd>
    api_socket: Option<String>,

    #[argh(option, long = "event-monitor")]
    /// path=<path/to/a/file>|fd=<fd>
    event_monitor: Option<String>,

    #[argh(option, long = "restore")]
    /// source_url=<source_url>,prefault=on|off
    restore: Option<String>,

    #[argh(option, long = "seccomp", default = "String::from(\"true\")")]
    /// seccomp configuration (true, false or log)
    seccomp: String,

    #[argh(option, long = "tpm")]
    /// socket=<path/to/a/socket>
    tpm: Option<String>,

    #[cfg(target_arch = "x86_64")]
    #[argh(option, long = "sgx-epc")]
    /// id=<epc_section_identifier>,size=<epc_section_size>,prefault=on|off
    sgx_epc: Vec<String>,

    #[cfg(feature = "guest_debug")]
    #[argh(option, long = "gdb")]
    /// path=<path/to/a/file>
    gdb: Option<String>,

    #[argh(switch, short = 'V', long = "version")]
    /// print version information
    version: bool,
}

impl TopLevel {
    fn to_vm_params(&self) -> config::VmParams<'_> {
        let cpus = &self.cpus;
        let memory = &self.memory;
        let memory_zones = if !self.memory_zone.is_empty() {
            Some(self.memory_zone.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };
        let rng = &self.rng;
        let serial = &self.serial;
        let firmware = self.firmware.as_deref();
        let kernel = self.kernel.as_deref();
        let initramfs = self.initramfs.as_deref();
        let cmdline = self.cmdline.as_deref();

        let disks = if !self.disk.is_empty() {
            Some(self.disk.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };

        let net = if !self.net.is_empty() {
            Some(self.net.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };

        let console = &self.console;
        let balloon = self.balloon.as_deref();
        let fs = if !self.fs.is_empty() {
            Some(self.fs.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };

        let pmem = if !self.pmem.is_empty() {
            Some(self.pmem.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };
        let devices = if !self.device.is_empty() {
            Some(self.device.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };
        let user_devices = if !self.user_device.is_empty() {
            Some(self.user_device.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };
        let vdpa = if !self.vdpa.is_empty() {
            Some(self.vdpa.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };

        let vsock = self.vsock.as_deref();
        #[cfg(target_arch = "x86_64")]
        let sgx_epc = if !self.sgx_epc.is_empty() {
            Some(self.sgx_epc.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };

        let numa = if !self.numa.is_empty() {
            Some(self.numa.iter().map(|x| x.as_str()).collect())
        } else {
            None
        };
        let watchdog = self.watchdog;
        let platform = self.platform.as_deref();
        #[cfg(feature = "guest_debug")]
        let gdb = self.gdb.is_some();
        let tpm = self.tpm.as_deref();

        config::VmParams {
            cpus,
            memory,
            memory_zones,
            firmware,
            kernel,
            initramfs,
            cmdline,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            devices,
            user_devices,
            vdpa,
            vsock,
            #[cfg(target_arch = "x86_64")]
            sgx_epc,
            numa,
            watchdog,
            #[cfg(feature = "guest_debug")]
            gdb,
            platform,
            tpm,
        }
    }
}

fn start_vmm(toplevel: TopLevel) -> Result<Option<String>, Error> {
    let log_level = match toplevel.verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn std::io::Write + Send> = if let Some(ref file) = toplevel.log_file {
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

    let (api_socket_path, api_socket_fd) = if let Some(ref socket_config) = toplevel.api_socket {
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
            (toplevel.api_socket.as_ref().map(|s| s.to_string()), None)
        }
    } else {
        (None, None)
    };

    if let Some(ref monitor_config) = toplevel.event_monitor {
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
            // SAFETY: fd is valid
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
    let seccomp_action = match &toplevel.seccomp as &str {
        "true" => SeccompAction::Trap,
        "false" => SeccompAction::Allow,
        "log" => SeccompAction::Log,
        val => {
            // The user providing an invalid value will be rejected
            panic!("Invalid parameter {val} for \"--seccomp\" flag");
        }
    };

    if seccomp_action == SeccompAction::Trap {
        // SAFETY: We only using signal_hook for managing signals and only execute signal
        // handler safe functions (writing to stderr) and manipulating signals.
        unsafe {
            signal_hook::low_level::register(signal_hook::consts::SIGSYS, || {
                eprint!(
                    "\n==== Possible seccomp violation ====\n\
                Try running with `strace -ff` to identify the cause and open an issue: \
                https://github.com/cloud-hypervisor/cloud-hypervisor/issues/new\n"
                );
                signal_hook::low_level::emulate_default_handler(SIGSYS).unwrap();
            })
        }
        .map_err(|e| eprintln!("Error adding SIGSYS signal handler: {e}"))
        .ok();
    }

    // Before we start any threads, mask the signals we'll be
    // installing handlers for, to make sure they only ever run on the
    // dedicated signal handling thread we'll start in a bit.
    for sig in &vmm::vm::Vm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            eprintln!("Error blocking signals: {e}");
        }
    }

    for sig in &vmm::Vmm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            eprintln!("Error blocking signals: {e}");
        }
    }

    event!("vmm", "starting");

    let hypervisor = hypervisor::new().map_err(Error::CreateHypervisor)?;

    #[cfg(feature = "guest_debug")]
    let gdb_socket_path = if let Some(ref gdb_config) = toplevel.gdb {
        let mut parser = OptionParser::new();
        parser.add("path");
        parser.parse(gdb_config).map_err(Error::ParsingGdb)?;

        if parser.is_set("path") {
            Some(std::path::PathBuf::from(parser.get("path").unwrap()))
        } else {
            return Err(Error::BareGdb);
        }
    } else {
        None
    };
    #[cfg(feature = "guest_debug")]
    let debug_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateDebugEventFd)?;
    #[cfg(feature = "guest_debug")]
    let vm_debug_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateDebugEventFd)?;

    let vmm_thread = vmm::start_vmm_thread(
        env!("CARGO_PKG_VERSION").to_string(),
        &api_socket_path,
        api_socket_fd,
        api_evt.try_clone().unwrap(),
        http_sender,
        api_request_receiver,
        #[cfg(feature = "guest_debug")]
        gdb_socket_path,
        #[cfg(feature = "guest_debug")]
        debug_evt.try_clone().unwrap(),
        #[cfg(feature = "guest_debug")]
        vm_debug_evt.try_clone().unwrap(),
        &seccomp_action,
        hypervisor,
    )
    .map_err(Error::StartVmmThread)?;

    let payload_present = toplevel.kernel.is_some() || toplevel.firmware.is_some();

    if payload_present {
        let vm_params = toplevel.to_vm_params();
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
    } else if let Some(restore_params) = toplevel.restore {
        vmm::api::vm_restore(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(config::RestoreConfig::parse(&restore_params).map_err(Error::ParsingRestore)?),
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
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Ensure all created files (.e.g sockets) are only accessible by this user
    // SAFETY: trivially safe
    let _ = unsafe { libc::umask(0o077) };

    let toplevel: TopLevel = argh::from_env();

    if toplevel.version {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("BUILT_VERSION"));
        return;
    }

    let exit_code = match start_vmm(toplevel) {
        Ok(path) => {
            path.map(|s| std::fs::remove_file(s).ok());
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    };

    // SAFETY: trivially safe
    let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } != 0;
    if on_tty {
        // Don't forget to set the terminal in canonical mode
        // before to exit.
        std::io::stdin().lock().set_canon_mode().unwrap();
    }

    #[cfg(feature = "dhat-heap")]
    drop(_profiler);

    std::process::exit(exit_code);
}

#[cfg(test)]
mod unit_tests {
    use crate::config::HotplugMethod;
    use crate::TopLevel;
    use std::path::PathBuf;
    use vmm::config::{
        ConsoleConfig, ConsoleOutputMode, CpuFeatures, CpusConfig, MemoryConfig, PayloadConfig,
        RngConfig, VmConfig,
    };

    // Taken from argh
    fn cmd<'a>(default: &'a str, path: &'a str) -> &'a str {
        std::path::Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(default)
    }

    // Some code taken from argh since it does not provide a helper to parse arbitrary strings
    fn get_vm_config_from_vec(args: &[&str]) -> VmConfig {
        let strings: Vec<String> = args.iter().map(|x| x.to_string()).collect();
        let cmd = cmd(&strings[0], &strings[0]);
        let strs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let toplevel = <TopLevel as argh::FromArgs>::from_args(&[cmd], &strs[1..]).unwrap_or_else(
            |early_exit| {
                std::process::exit(match early_exit.status {
                    Ok(()) => {
                        println!("{}", early_exit.output);
                        0
                    }
                    Err(()) => {
                        eprintln!(
                            "{}\nRun {} --help for more information.",
                            early_exit.output, cmd
                        );
                        1
                    }
                })
            },
        );

        let vm_params = toplevel.to_vm_params();

        VmConfig::parse(vm_params).unwrap()
    }

    fn compare_vm_config_cli_vs_json(
        cli: &[&str],
        openapi: &str,
        equal: bool,
    ) -> (VmConfig, VmConfig) {
        let cli_vm_config = get_vm_config_from_vec(cli);
        let openapi_vm_config: VmConfig = serde_json::from_str(openapi).unwrap();

        if equal {
            assert_eq!(cli_vm_config, openapi_vm_config);
        } else {
            assert_ne!(cli_vm_config, openapi_vm_config);
        }

        (cli_vm_config, openapi_vm_config)
    }

    #[test]
    fn test_valid_vm_config_default() {
        let cli = vec!["cloud-hypervisor", "--kernel", "/path/to/kernel"];
        let openapi = r#"{ "payload": {"kernel": "/path/to/kernel"} }"#;

        // First we check we get identical VmConfig structures.
        let (result_vm_config, _) = compare_vm_config_cli_vs_json(&cli, openapi, true);

        // As a second step, we validate all the default values.
        let expected_vm_config = VmConfig {
            cpus: CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                topology: None,
                kvm_hyperv: false,
                max_phys_bits: 46,
                affinity: None,
                features: CpuFeatures::default(),
            },
            memory: MemoryConfig {
                size: 536_870_912,
                mergeable: false,
                hotplug_method: HotplugMethod::Acpi,
                hotplug_size: None,
                hotplugged_size: None,
                shared: false,
                hugepages: false,
                hugepage_size: None,
                prefault: false,
                zones: None,
                thp: true,
            },
            payload: Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                ..Default::default()
            }),
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
            user_devices: None,
            vdpa: None,
            vsock: None,
            iommu: false,
            #[cfg(target_arch = "x86_64")]
            sgx_epc: None,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            platform: None,
            tpm: None,
        };

        assert_eq!(expected_vm_config, result_vm_config);
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory": {"size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory": {"size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,mergeable=on"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "mergeable": true}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,mergeable=off"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "mergeable": false}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,mergeable=on"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "mergeable": false}
                }"#,
                false,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,hotplug_size=1G"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory": {"size": 1073741824, "hotplug_method": "Acpi", "hotplug_size": 1073741824}
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "size=1G,hotplug_method=virtio-mem,hotplug_size=1G"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                "payload": {"kernel": "/path/to/kernel"}
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
                "payload": {"kernel": "/path/to/kernel", "cmdline": "arg1=foo arg2=bar"}
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
                    "--disk",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "--disk",
                    "path=/path/to/disk/2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
                    "net": []
                }"#,
                false,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--net", "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
                    "net": [
                        {"mac": "12:34:56:78:90:ab", "host_mac": "34:56:78:90:ab:cd", "tap": "tap0", "ip": "1.2.3.4", "mask": "5.6.7.8", "num_queues": 2, "queue_size": 256, "iommu": false}
                    ]
                }"#,
                true,
            ),
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel", "--memory", "shared=true", "--net", "mac=12:34:56:78:90:ab,host_mac=34:56:78:90:ab:cd,vhost_user=true,socket=/tmp/sock"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                "payload": {"kernel": "/path/to/kernel"},
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
                    "--fs",
                    "tag=virtiofs2,socket=/path/to/sock2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "--fs",
                    "tag=virtiofs2,socket=/path/to/sock2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
                    "memory" : { "shared": true, "size": 536870912 },
                    "cpus": {"boot_vcpus": 4, "max_vcpus": 4},
                    "fs": [
                        {"tag": "virtiofs1", "socket": "/path/to/sock1", "num_queues": 4, "queue_size": 128}
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
    fn test_valid_vm_config_pmem() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--pmem",
                    "file=/path/to/img/1,size=1G",
                    "--pmem",
                    "file=/path/to/img/2,size=2G",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
                    "pmem": [
                        {"file": "/path/to/img/1", "size": 1073741824, "iommu": true}
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
    fn test_valid_vm_config_serial_console() {
        vec![
            (
                vec!["cloud-hypervisor", "--kernel", "/path/to/kernel"],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"}
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"}
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "--device",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "--device",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
    fn test_valid_vm_config_vdpa() {
        vec![
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vdpa",
                    "path=/path/to/device/1",
                    "--vdpa",
                    "path=/path/to/device/2,num_queues=2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "vdpa": [
                        {"path": "/path/to/device/1", "num_queues": 1},
                        {"path": "/path/to/device/2", "num_queues": 2}
                    ]
                }"#,
                true,
            ),
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vdpa",
                    "path=/path/to/device/1",
                    "--vdpa",
                    "path=/path/to/device/2",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "vdpa": [
                        {"path": "/path/to/device/1"}
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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
                    "payload": {"kernel": "/path/to/kernel"},
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

    #[test]
    fn test_valid_vm_config_tpm_socket() {
        vec![(
            vec![
                "cloud-hypervisor",
                "--kernel",
                "/path/to/kernel",
                "--tpm",
                "socket=/path/to/tpm/sock",
            ],
            r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "tpm": {"socket": "/path/to/tpm/sock"}
                }"#,
            true,
        )]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }
}
