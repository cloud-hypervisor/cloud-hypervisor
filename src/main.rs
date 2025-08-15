// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
mod test_util;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::mpsc::channel;
use std::sync::Mutex;
use std::{env, io};

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use event_monitor::event;
use libc::EFD_NONBLOCK;
use log::{error, warn, LevelFilter};
use option_parser::OptionParser;
use seccompiler::SeccompAction;
use signal_hook::consts::SIGSYS;
use thiserror::Error;
#[cfg(feature = "dbus_api")]
use vmm::api::dbus::{dbus_api_graceful_shutdown, DBusApiOptions};
use vmm::api::http::http_api_graceful_shutdown;
use vmm::api::ApiAction;
use vmm::config::{RestoreConfig, VmParams};
use vmm::landlock::{Landlock, LandlockError};
use vmm::vm_config;
#[cfg(feature = "fw_cfg")]
use vmm::vm_config::FwCfgConfig;
#[cfg(feature = "ivshmem")]
use vmm::vm_config::IvshmemConfig;
use vmm::vm_config::{
    BalloonConfig, DeviceConfig, DiskConfig, FsConfig, LandlockConfig, NetConfig, NumaConfig,
    PciSegmentConfig, PmemConfig, RateLimiterGroupConfig, TpmConfig, UserDeviceConfig, VdpaConfig,
    VmConfig, VsockConfig,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::block_signal;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Error, Debug)]
enum Error {
    #[error("Failed to create API EventFd")]
    CreateApiEventFd(#[source] std::io::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Failed to create Debug EventFd")]
    CreateDebugEventFd(#[source] std::io::Error),
    #[error("Failed to create exit EventFd")]
    CreateExitEventFd(#[source] std::io::Error),
    #[error("Failed to open hypervisor interface (is hypervisor interface available?)")]
    CreateHypervisor(#[source] hypervisor::HypervisorError),
    #[error("Failed to start the VMM thread")]
    StartVmmThread(#[source] vmm::Error),
    #[error("Error parsing config")]
    ParsingConfig(#[source] vmm::config::Error),
    #[error("Error creating VM")]
    VmCreate(#[source] vmm::api::ApiError),
    #[error("Error booting VM")]
    VmBoot(#[source] vmm::api::ApiError),
    #[error("Error restoring VM")]
    VmRestore(#[source] vmm::api::ApiError),
    #[error("Error parsing restore")]
    ParsingRestore(#[source] vmm::config::Error),
    #[error("Failed to join on VMM thread: {0:?}")]
    ThreadJoin(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    #[error("VMM thread exited with error")]
    VmmThread(#[source] vmm::Error),
    #[error("Error parsing --api-socket")]
    ParsingApiSocket(#[source] std::num::ParseIntError),
    #[error("Error parsing --event-monitor")]
    ParsingEventMonitor(#[source] option_parser::OptionParserError),
    #[cfg(feature = "dbus_api")]
    #[error("`--dbus-object-path` option isn't provided")]
    MissingDBusObjectPath,
    #[cfg(feature = "dbus_api")]
    #[error("`--dbus-service-name` option isn't provided")]
    MissingDBusServiceName,
    #[error("Error parsing --event-monitor: path or fd required")]
    BareEventMonitor,
    #[error("Error doing event monitor I/O")]
    EventMonitorIo(#[source] std::io::Error),
    #[error("Event monitor thread failed")]
    EventMonitorThread(#[source] vmm::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb")]
    ParsingGdb(#[source] option_parser::OptionParserError),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb: path required")]
    BareGdb,
    #[error("Error creating log file")]
    LogFileCreation(#[source] std::io::Error),
    #[error("Error setting up logger")]
    LoggerSetup(#[source] log::SetLoggerError),
    #[error("Failed to gracefully shutdown http api")]
    HttpApiShutdown(#[source] vmm::Error),
    #[error("Failed to create Landlock object")]
    CreateLandlock(#[source] LandlockError),
    #[error("Failed to apply Landlock")]
    ApplyLandlock(#[source] LandlockError),
}

#[derive(Error, Debug)]
enum FdTableError {
    #[error("Failed to create event fd")]
    CreateEventFd(#[source] std::io::Error),
    #[error("Failed to obtain file limit")]
    GetRLimit(#[source] std::io::Error),
    #[error("Error calling fcntl with F_GETFD")]
    GetFd(#[source] std::io::Error),
    #[error("Failed to duplicate file handle")]
    Dup2(#[source] std::io::Error),
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
            write!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:.6?}: <{}> {}:{}:{} -- {}\r\n",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            )
        } else {
            write!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:.6?}: <{}> {}:{} -- {}\r\n",
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
    (default_vcpus(), default_memory(), default_rng())
}

fn default_vcpus() -> String {
    format!(
        "boot={},max_phys_bits={}",
        vm_config::DEFAULT_VCPUS,
        vm_config::DEFAULT_MAX_PHYS_BITS
    )
}

fn default_memory() -> String {
    format!("size={}M", vm_config::DEFAULT_MEMORY_MB)
}

fn default_rng() -> String {
    format!("src={}", vm_config::DEFAULT_RNG_SOURCE)
}

/// Returns all [`Arg`]s in alphabetical order. This is the order used in the
/// `--help` output.
fn get_cli_options_sorted(
    default_vcpus: String,
    default_memory: String,
    default_rng: String,
) -> Box<[Arg]> {
    [
        Arg::new("api-socket")
            .long("api-socket")
            .help("HTTP API socket (UNIX domain socket): path=</path/to/a/file> or fd=<fd>.")
            .num_args(1)
            .group("vmm-config"),
        Arg::new("balloon")
            .long("balloon")
            .help(BalloonConfig::SYNTAX)
            .num_args(1)
            .group("vm-config"),
        Arg::new("cmdline")
            .long("cmdline")
            .help("Kernel command line")
            .num_args(1)
            .group("vm-config"), Arg::new("console")
            .long("console")
            .help(
                "Control (virtio) console: \"off|null|pty|tty|file=</path/to/a/file>,iommu=on|off\"",
            )
            .default_value("tty")
            .group("vm-config"),
        Arg::new("cpus")
            .long("cpus")
            .help(
                "boot=<boot_vcpus>,max=<max_vcpus>,\
                    topology=<threads_per_core>:<cores_per_die>:<dies_per_package>:<packages>,\
                    kvm_hyperv=on|off,max_phys_bits=<maximum_number_of_physical_bits>,\
                    affinity=<list_of_vcpus_with_their_associated_cpuset>,\
                    features=<list_of_features_to_enable>",
            )
            .default_value(default_vcpus)
            .group("vm-config"),
        #[cfg(target_arch = "x86_64")]
        Arg::new("debug-console")
            .long("debug-console")
            .help("Debug console: off|pty|tty|file=</path/to/a/file>,iobase=<port in hex>")
            .default_value("off,iobase=0xe9")
            .group("vm-config"),
        #[cfg(feature = "dbus_api")]
        Arg::new("dbus-service-name")
            .long("dbus-service-name")
            .help("Well known name of the device")
            .num_args(1)
            .group("vmm-config"),
        #[cfg(feature = "dbus_api")]
        Arg::new("dbus-object-path")
            .long("dbus-object-path")
            .help("Object path to serve the dbus interface")
            .num_args(1)
            .group("vmm-config"),
        #[cfg(feature = "dbus_api")]
        Arg::new("dbus-system-bus")
            .long("dbus-system-bus")
            .action(ArgAction::SetTrue)
            .help("Use the system bus instead of a session bus")
            .num_args(0)
            .group("vmm-config"),
        Arg::new("device")
            .long("device")
            .help(DeviceConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("disk")
            .long("disk")
            .help(DiskConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("event-monitor")
            .long("event-monitor")
            .help("File to report events on: path=</path/to/a/file> or fd=<fd>")
            .num_args(1)
            .group("vmm-config"),
        Arg::new("firmware")
            .long("firmware")
            .help("Path to firmware that is loaded in an architectural specific way")
            .num_args(1)
            .group("vm-payload"),
        Arg::new("fs")
            .long("fs")
            .help(FsConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        #[cfg(feature = "fw_cfg")]
        Arg::new("fw-cfg-config")
            .long("fw-cfg-config")
            .help(FwCfgConfig::SYNTAX)
            .num_args(1)
            .group("vm-payload"),
        #[cfg(feature = "guest_debug")]
        Arg::new("gdb")
            .long("gdb")
            .help("GDB socket (UNIX domain socket): path=</path/to/a/file>")
            .num_args(1)
            .group("vmm-config"),
        #[cfg(feature = "igvm")]
        Arg::new("igvm")
            .long("igvm")
            .help("Path to IGVM file to load.")
            .num_args(1)
            .group("vm-payload"),
        #[cfg(feature = "sev_snp")]
        Arg::new("host-data")
            .long("host-data")
            .help("Host specific data to SEV SNP guest")
            .num_args(1)
            .group("vm-config"),
        Arg::new("initramfs")
            .long("initramfs")
            .help("Path to initramfs image")
            .num_args(1)
            .group("vm-config"),
        #[cfg(feature = "ivshmem")]
        Arg::new("ivshmem")
            .long("ivshmem")
            .help(IvshmemConfig::SYNTAX)
            .num_args(1)
            .group("vm-config"),
        Arg::new("kernel")
            .long("kernel")
            .help(
                "Path to kernel to load. This may be a kernel or firmware that supports a PVH \
                entry point (e.g. vmlinux) or architecture equivalent",
            )
            .num_args(1)
            .group("vm-payload"),
        Arg::new("landlock")
            .long("landlock")
            .num_args(0)
            .help(
                "enable/disable Landlock.",
            )
            .action(ArgAction::SetTrue)
            .default_value("false")
            .group("vm-config"),
        Arg::new("landlock-rules")
            .long("landlock-rules")
            .help(LandlockConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("log-file")
            .long("log-file")
            .help("Log file. Standard error is used if not specified")
            .num_args(1)
            .group("logging"),
        Arg::new("memory")
            .long("memory")
            .help(
                "Memory parameters \
                     \"size=<guest_memory_size>,mergeable=on|off,shared=on|off,\
                     hugepages=on|off,hugepage_size=<hugepage_size>,\
                     hotplug_method=acpi|virtio-mem,\
                     hotplug_size=<hotpluggable_memory_size>,\
                     hotplugged_size=<hotplugged_memory_size>,\
                     prefault=on|off,thp=on|off\"",
            )
            .default_value(default_memory)
            .group("vm-config"),
        Arg::new("memory-zone")
            .long("memory-zone")
            .help(
                "User defined memory zone parameters \
                     \"size=<guest_memory_region_size>,file=<backing_file>,\
                     shared=on|off,\
                     hugepages=on|off,hugepage_size=<hugepage_size>,\
                     host_numa_node=<node_id>,\
                     id=<zone_identifier>,hotplug_size=<hotpluggable_memory_size>,\
                     hotplugged_size=<hotplugged_memory_size>,\
                     prefault=on|off\"",
            )
            .num_args(1..)
            .group("vm-config"),
        Arg::new("net")
            .long("net")
            .help(NetConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("numa")
            .long("numa")
            .help(NumaConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("pci-segment")
            .long("pci-segment")
            .help(PciSegmentConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("platform")
            .long("platform")
            .help(
                "num_pci_segments=<num_pci_segments>,iommu_segments=<list_of_segments>,iommu_address_width=<bits>,serial_number=<dmi_device_serial_number>,uuid=<dmi_device_uuid>,oem_strings=<list_of_strings>"
            )
            .num_args(1)
            .group("vm-config"),
        Arg::new("pmem")
            .long("pmem")
            .help(PmemConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        #[cfg(feature = "pvmemcontrol")]
        Arg::new("pvmemcontrol")
            .long("pvmemcontrol")
            .help("Pvmemcontrol device")
            .num_args(0)
            .action(ArgAction::SetTrue)
            .group("vm-config"),
        Arg::new("pvpanic")
            .long("pvpanic")
            .help("Enable pvpanic device")
            .num_args(0)
            .action(ArgAction::SetTrue)
            .group("vm-config"),
        Arg::new("rate-limit-group")
            .long("rate-limit-group")
            .help(RateLimiterGroupConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("restore")
            .long("restore")
            .help(RestoreConfig::SYNTAX)
            .num_args(1)
            .group("vmm-config"),
        Arg::new("rng")
            .long("rng")
            .help(
                "Random number generator parameters \"src=<entropy_source_path>,iommu=on|off\"",
            )
            .default_value(default_rng)
            .group("vm-config"),
        Arg::new("seccomp")
            .long("seccomp")
            .num_args(1)
            .value_parser(["true", "false", "log"])
            .default_value("true"),
        Arg::new("serial")
            .long("serial")
            .help("Control serial port: off|null|pty|tty|file=</path/to/a/file>|socket=</path/to/a/file>")
            .default_value("null")
            .group("vm-config"),
        Arg::new("tpm")
            .long("tpm")
            .num_args(1)
            .help(TpmConfig::SYNTAX)
            .group("vm-config"),
        Arg::new("user-device")
            .long("user-device")
            .help(UserDeviceConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("v")
            .short('v')
            .action(ArgAction::Count)
            .help("Sets the level of debugging output")
            .group("logging"),
        Arg::new("vdpa")
            .long("vdpa")
            .help(VdpaConfig::SYNTAX)
            .num_args(1..)
            .group("vm-config"),
        Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::SetTrue)
            .help("Print version")
            .num_args(0),
        Arg::new("vsock")
            .long("vsock")
            .help(VsockConfig::SYNTAX)
            .num_args(1)
            .group("vm-config"),
        Arg::new("watchdog")
            .long("watchdog")
            .help("Enable virtio-watchdog")
            .num_args(0)
            .action(ArgAction::SetTrue)
            .group("vm-config"),
    ].to_vec().into_boxed_slice()
}

/// Creates the CLI definition of Cloud Hypervisor.
fn create_app(default_vcpus: String, default_memory: String, default_rng: String) -> Command {
    let groups = [
        ArgGroup::new("vm-config")
            .multiple(true)
            .requires("vm-payload"),
        ArgGroup::new("vmm-config").multiple(true),
        ArgGroup::new("logging").multiple(true),
        ArgGroup::new("vm-payload").multiple(true),
    ];

    let args = get_cli_options_sorted(default_vcpus, default_memory, default_rng);

    Command::new("cloud-hypervisor")
        // 'BUILD_VERSION' is set by the build script 'build.rs' at
        // compile time
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Launch a cloud-hypervisor VMM.")
        .arg_required_else_help(true)
        .groups(groups)
        .args(args)
}

fn start_vmm(cmd_arguments: ArgMatches) -> Result<Option<String>, Error> {
    let log_level = match cmd_arguments.get_count("v") {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn std::io::Write + Send> = if let Some(ref file) =
        cmd_arguments.get_one::<String>("log-file")
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
        if let Some(socket_config) = cmd_arguments.get_one::<String>("api-socket") {
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
                    cmd_arguments
                        .get_one::<String>("api-socket")
                        .map(|s| s.to_string()),
                    None,
                )
            }
        } else {
            (None, None)
        };

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateApiEventFd)?;

    let api_request_sender_clone = api_request_sender.clone();
    let seccomp_action = if let Some(seccomp_value) = cmd_arguments.get_one::<String>("seccomp") {
        match seccomp_value as &str {
            "true" => SeccompAction::Trap,
            "false" => SeccompAction::Allow,
            "log" => SeccompAction::Log,
            val => {
                // The user providing an invalid value will be rejected
                panic!("Invalid parameter {val} for \"--seccomp\" flag");
            }
        }
    } else {
        SeccompAction::Trap
    };

    if seccomp_action == SeccompAction::Trap {
        // SAFETY: We only using signal_hook for managing signals and only execute signal
        // handler safe functions (writing to stderr) and manipulating signals.
        unsafe {
            signal_hook::low_level::register(signal_hook::consts::SIGSYS, || {
                eprintln!(
                    "\n==== Possible seccomp violation ====\n\
                Try running with `strace -ff` to identify the cause and open an issue: \
                https://github.com/cloud-hypervisor/cloud-hypervisor/issues/new"
                );
                signal_hook::low_level::emulate_default_handler(SIGSYS).unwrap();
            })
        }
        .map_err(|e| error!("Error adding SIGSYS signal handler: {e}"))
        .ok();
    }

    // SAFETY: Trivially safe.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    // Before we start any threads, mask the signals we'll be
    // installing handlers for, to make sure they only ever run on the
    // dedicated signal handling thread we'll start in a bit.
    for sig in &vmm::vm::Vm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            error!("Error blocking signals: {e}");
        }
    }

    for sig in &vmm::Vmm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            error!("Error blocking signals: {e}");
        }
    }

    let hypervisor = hypervisor::new().map_err(Error::CreateHypervisor)?;

    #[cfg(feature = "guest_debug")]
    let gdb_socket_path = if let Some(gdb_config) = cmd_arguments.get_one::<String>("gdb") {
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

    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateExitEventFd)?;
    let landlock_enable = cmd_arguments.get_flag("landlock");

    #[allow(unused_mut)]
    let mut event_monitor = cmd_arguments
        .get_one::<String>("event-monitor")
        .as_ref()
        .map(|monitor_config| {
            let mut parser = OptionParser::new();
            parser.add("path").add("fd");
            parser
                .parse(monitor_config)
                .map_err(Error::ParsingEventMonitor)?;

            if parser.is_set("fd") {
                let fd = parser
                    .convert("fd")
                    .map_err(Error::ParsingEventMonitor)?
                    .unwrap();
                // SAFETY: fd is valid
                Ok(Some(unsafe { File::from_raw_fd(fd) }))
            } else if parser.is_set("path") {
                Ok(Some(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(parser.get("path").unwrap())
                        .map_err(Error::EventMonitorIo)?,
                ))
            } else {
                Err(Error::BareEventMonitor)
            }
        })
        .transpose()?
        .map(|event_monitor_file| {
            event_monitor::set_monitor(event_monitor_file).map_err(Error::EventMonitorIo)
        })
        .transpose()?;

    #[cfg(feature = "dbus_api")]
    let dbus_options = match (
        cmd_arguments.get_one::<String>("dbus-service-name"),
        cmd_arguments.get_one::<String>("dbus-object-path"),
    ) {
        (Some(name), Some(path)) => {
            // monitor is either set (file based) or not.
            // if it's not set, create one without file support.
            let mut monitor = match event_monitor.take() {
                Some(monitor) => monitor,
                None => event_monitor::set_monitor(None).map_err(Error::EventMonitorIo)?,
            };
            let options = DBusApiOptions {
                service_name: name.to_string(),
                object_path: path.to_string(),
                system_bus: cmd_arguments.get_flag("dbus-system-bus"),
                event_monitor_rx: monitor.subscribe(),
            };

            event_monitor = Some(monitor);
            Ok(Some(options))
        }
        (Some(_), None) => Err(Error::MissingDBusObjectPath),
        (None, Some(_)) => Err(Error::MissingDBusServiceName),
        (None, None) => Ok(None),
    }?;

    if let Some(monitor) = event_monitor {
        vmm::start_event_monitor_thread(
            monitor,
            &seccomp_action,
            landlock_enable,
            hypervisor.hypervisor_type(),
            exit_evt.try_clone().unwrap(),
        )
        .map_err(Error::EventMonitorThread)?;
    }

    event!("vmm", "starting");

    let vmm_thread_handle = vmm::start_vmm_thread(
        vmm::VmmVersionInfo::new(env!("BUILD_VERSION"), env!("CARGO_PKG_VERSION")),
        &api_socket_path,
        api_socket_fd,
        #[cfg(feature = "dbus_api")]
        dbus_options,
        api_evt.try_clone().unwrap(),
        api_request_sender_clone,
        api_request_receiver,
        #[cfg(feature = "guest_debug")]
        gdb_socket_path,
        #[cfg(feature = "guest_debug")]
        debug_evt.try_clone().unwrap(),
        #[cfg(feature = "guest_debug")]
        vm_debug_evt.try_clone().unwrap(),
        exit_evt.try_clone().unwrap(),
        &seccomp_action,
        hypervisor,
        landlock_enable,
    )
    .map_err(Error::StartVmmThread)?;

    let r: Result<(), Error> = (|| {
        #[cfg(feature = "igvm")]
        let payload_present = cmd_arguments.contains_id("kernel")
            || cmd_arguments.contains_id("firmware")
            || cmd_arguments.contains_id("igvm");
        #[cfg(not(feature = "igvm"))]
        let payload_present =
            cmd_arguments.contains_id("kernel") || cmd_arguments.contains_id("firmware");

        if payload_present {
            let vm_params = VmParams::from_arg_matches(&cmd_arguments);
            let vm_config = VmConfig::parse(vm_params).map_err(Error::ParsingConfig)?;

            // Create and boot the VM based off the VM config we just built.
            let sender = api_request_sender.clone();
            vmm::api::VmCreate
                .send(
                    api_evt.try_clone().unwrap(),
                    api_request_sender,
                    Box::new(vm_config),
                )
                .map_err(Error::VmCreate)?;
            vmm::api::VmBoot
                .send(api_evt.try_clone().unwrap(), sender, ())
                .map_err(Error::VmBoot)?;
        } else if let Some(restore_params) = cmd_arguments.get_one::<String>("restore") {
            vmm::api::VmRestore
                .send(
                    api_evt.try_clone().unwrap(),
                    api_request_sender,
                    RestoreConfig::parse(restore_params).map_err(Error::ParsingRestore)?,
                )
                .map_err(Error::VmRestore)?;
        }

        Ok(())
    })();

    if r.is_err() {
        if let Err(e) = exit_evt.write(1) {
            warn!("writing to exit EventFd: {e}");
        }
    }

    if landlock_enable {
        Landlock::new()
            .map_err(Error::CreateLandlock)?
            .restrict_self()
            .map_err(Error::ApplyLandlock)?;
    }

    vmm_thread_handle
        .thread_handle
        .join()
        .map_err(Error::ThreadJoin)?
        .map_err(Error::VmmThread)?;

    if let Some(api_handle) = vmm_thread_handle.http_api_handle {
        http_api_graceful_shutdown(api_handle).map_err(Error::HttpApiShutdown)?
    }

    #[cfg(feature = "dbus_api")]
    if let Some(chs) = vmm_thread_handle.dbus_shutdown_chs {
        dbus_api_graceful_shutdown(chs);
    }

    r.map(|_| api_socket_path)
}

// This is a best-effort solution to the latency induced by the RCU
// synchronization that happens in the kernel whenever the file descriptor table
// fills up.
// The table has initially 64 entries on amd64 and every time it fills up, a new
// table is created, double the size of the current one, and the entries are
// copied to the new table. The filesystem code that does this uses
// synchronize_rcu() to ensure all preexisting RCU read-side critical sections
// have completed:
//
//     https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/fs/file.c?h=v6.9.1#n162
//
// Rust programs that create lots of file handles or use
// {File,EventFd}::try_clone() to share them are impacted by this issue. This
// behavior is quite noticeable in the snapshot restore scenario, the latency is
// a big chunk of the total time required to start cloud-hypervisor and restore
// the snapshot.
//
// The kernel has an optimization in code, where it doesn't call
// synchronize_rcu() if there is only one thread in the process. We can take
// advantage of this optimization by expanding the descriptor table at
// application start, when it has only one thread.
//
// The code tries to resize the table to an adequate size for most use cases,
// 4096, this way we avoid any expansion that might take place later.
fn expand_fdtable() -> Result<(), FdTableError> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: FFI call with valid arguments
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } < 0 {
        return Err(FdTableError::GetRLimit(io::Error::last_os_error()));
    }

    let table_size = if limits.rlim_cur == libc::RLIM_INFINITY {
        4096
    } else {
        std::cmp::min(limits.rlim_cur, 4096) as libc::c_int
    };

    // The first 3 handles are stdin, stdout, stderr. We don't want to touch
    // any of them.
    if table_size <= 3 {
        return Ok(());
    }

    let dummy_evt = EventFd::new(0).map_err(FdTableError::CreateEventFd)?;

    // Test if the file descriptor is empty
    // SAFETY: FFI call with valid arguments
    let flags: i32 = unsafe { libc::fcntl(table_size - 1, libc::F_GETFD) };
    if flags >= 0 {
        // Nothing to do, the table is already big enough
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EBADF) {
        return Err(FdTableError::GetFd(err));
    }
    // SAFETY: FFI call with valid arguments
    if unsafe { libc::dup2(dummy_evt.as_raw_fd(), table_size - 1) } < 0 {
        return Err(FdTableError::Dup2(io::Error::last_os_error()));
    }
    // SAFETY: FFI call, trivially
    unsafe { libc::close(table_size - 1) };

    Ok(())
}

fn main() {
    #[cfg(all(feature = "tdx", feature = "sev_snp"))]
    compile_error!("Feature 'tdx' and 'sev_snp' are mutually exclusive.");
    #[cfg(all(feature = "sev_snp", not(target_arch = "x86_64")))]
    compile_error!("Feature 'sev_snp' needs target 'x86_64'");
    #[cfg(all(feature = "fw_cfg", target_arch = "riscv64"))]
    compile_error!("Feature 'fw_cfg' needs targets 'x86_64' or 'aarch64'");

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Ensure all created files (.e.g sockets) are only accessible by this user
    // SAFETY: trivially safe
    let _ = unsafe { libc::umask(0o077) };

    let (default_vcpus, default_memory, default_rng) = prepare_default_values();
    let cmd_arguments = create_app(default_vcpus, default_memory, default_rng).get_matches();

    if cmd_arguments.get_flag("version") {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("BUILD_VERSION"));

        if cmd_arguments.get_count("v") != 0 {
            println!("Enabled features: {:?}", vmm::feature_list());
        }

        return;
    }

    if let Err(e) = expand_fdtable() {
        warn!("Error expanding FD table: {e}");
    }

    let exit_code = match start_vmm(cmd_arguments) {
        Ok(path) => {
            path.map(|s| std::fs::remove_file(s).ok());
            0
        }
        Err(top_error) => {
            cloud_hypervisor::cli_print_error_chain(&top_error, "Cloud Hypervisor", |_, _, _| None);
            1
        }
    };

    #[cfg(feature = "dhat-heap")]
    drop(_profiler);

    std::process::exit(exit_code);
}

#[cfg(test)]
mod unit_tests {
    use std::path::PathBuf;

    use vmm::config::VmParams;
    #[cfg(target_arch = "x86_64")]
    use vmm::vm_config::DebugConsoleConfig;
    use vmm::vm_config::{
        ConsoleConfig, ConsoleOutputMode, CpuFeatures, CpusConfig, HotplugMethod, MemoryConfig,
        PayloadConfig, RngConfig, VmConfig,
    };

    use crate::test_util::assert_args_sorted;
    use crate::{create_app, get_cli_options_sorted, prepare_default_values};

    fn get_vm_config_from_vec(args: &[&str]) -> VmConfig {
        let (default_vcpus, default_memory, default_rng) = prepare_default_values();
        let cmd_arguments =
            create_app(default_vcpus, default_memory, default_rng).get_matches_from(args);
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
                firmware: None,
                cmdline: None,
                initramfs: None,
                #[cfg(feature = "igvm")]
                igvm: None,
                #[cfg(feature = "sev_snp")]
                host_data: None,
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config: None,
            }),
            rate_limit_groups: None,
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
                socket: None,
            },
            console: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                socket: None,
            },
            #[cfg(target_arch = "x86_64")]
            debug_console: DebugConsoleConfig::default(),
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            pvpanic: false,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: None,
            iommu: false,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            pci_segments: None,
            platform: None,
            tpm: None,
            preserved_fds: None,
            landlock_enable: false,
            landlock_rules: None,
            #[cfg(feature = "ivshmem")]
            ivshmem: None,
        };

        assert_eq!(expected_vm_config, result_vm_config);
    }

    #[test]
    fn test_valid_vm_config_cpus() {
        [
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
        [(
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
        [(
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
        [
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
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--disk",
                    "path=/path/to/disk/1,rate_limit_group=group0",
                    "path=/path/to/disk/2,rate_limit_group=group0",
                    "--rate-limit-group",
                    "id=group0,bw_size=1000,bw_refill_time=100",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "disks": [
                        {"path": "/path/to/disk/1", "rate_limit_group": "group0"},
                        {"path": "/path/to/disk/2", "rate_limit_group": "group0"}
                    ],
                    "rate_limit_groups": [
                        {"id": "group0", "rate_limiter_config": {"bandwidth": {"size": 1000, "one_time_burst": 0, "refill_time": 100}}}
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
        [(
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
        [(
                vec![
                    "cloud-hypervisor", "--kernel", "/path/to/kernel",
                    "--memory", "shared=true",
                    "--fs",
                    "tag=virtiofs1,socket=/path/to/sock1",
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
            )]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_pmem() {
        [
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_valid_vm_config_debug_console() {
        [(
            vec![
                "cloud-hypervisor",
                "--kernel",
                "/path/to/kernel",
                "--debug-console",
                "tty,iobase=0xe9",
            ],
            // 233 == 0xe9
            r#"{
                "payload": {"kernel": "/path/to/kernel" },
                "debug_console": {"mode": "Tty", "iobase": 233 }
            }"#,
            true,
        )]
        .iter()
        .for_each(|(cli, openapi, equal)| {
            compare_vm_config_cli_vs_json(cli, openapi, *equal);
        });
    }

    #[test]
    fn test_valid_vm_config_serial_console() {
        [
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
        [
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
        [
            (
                vec![
                    "cloud-hypervisor",
                    "--kernel",
                    "/path/to/kernel",
                    "--vdpa",
                    "path=/path/to/device/1",
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
        [
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
        [(
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

    // TODO the check for the option list being sorted could be moved into the
    // getter itself, when the getter becomes a const function. This however
    // needs more support by Rust (as of March 2025).
    #[test]
    fn test_cli_options_sorted() {
        let (default_vcpus, default_memory, default_rng) = prepare_default_values();
        let args = get_cli_options_sorted(default_vcpus, default_memory, default_rng);

        assert_args_sorted(|| args.iter())
    }
}
