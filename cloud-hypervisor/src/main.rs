// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

mod logger;
#[cfg(test)]
mod test_util;

use std::fs::{self, File};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
#[cfg(feature = "guest_debug")]
use std::path::PathBuf;
use std::ptr::from_ref;
use std::sync::mpsc::channel;
use std::{any, cmp, env, io, num, process};

use clap::{ArgAction, ArgGroup, Parser, ValueEnum};
use event_monitor::event;
use libc::EFD_NONBLOCK;
use log::{LevelFilter, error, info, warn};
use option_parser::OptionParser;
use seccompiler::SeccompAction;
use signal_hook::consts::SIGSYS;
use signal_hook::low_level;
use thiserror::Error;
#[cfg(feature = "dbus_api")]
use vmm::api::dbus::{DBusApiOptions, dbus_api_graceful_shutdown};
use vmm::api::http::http_api_graceful_shutdown;
use vmm::api::{self, ApiAction};
use vmm::config::{self, RestoreConfig, VmParams};
use vmm::landlock::{Landlock, LandlockError};
use vmm::seccomp_filters::{Thread, get_seccomp_filter};
use vmm::vm::Vm;
#[cfg(target_arch = "x86_64")]
use vmm::vm_config::DebugConsoleConfig;
#[cfg(feature = "fw_cfg")]
use vmm::vm_config::FwCfgConfig;
#[cfg(feature = "ivshmem")]
use vmm::vm_config::IvshmemConfig;
use vmm::vm_config::{
    BalloonConfig, ConsoleConfig, CpusConfig, DeviceConfig, DiskConfig, FsConfig,
    GenericVhostUserConfig, LandlockConfig, MemoryConfig, MemoryZoneConfig, NetConfig, NumaConfig,
    PciSegmentConfig, PlatformConfig, PmemConfig, RateLimiterGroupConfig, RngConfig, RtcConfig,
    SerialConfig, TpmConfig, UserDeviceConfig, VdpaConfig, VmConfig, VsockConfig,
};
use vmm::{GuestResetAction, GuestShutdownAction, vm_config};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::{block_signal, register_signal_handler};

use crate::logger::Logger;

// Linux exposes seccomp's SIGSYS payload via the siginfo_t layout; this struct mirrors the
// fields we need so the handler can read the syscall and arch.
#[repr(C)]
struct SeccompSiginfo {
    si_signo: libc::c_int,
    si_errno: libc::c_int,
    si_code: libc::c_int,
    _pad0: libc::c_int,
    si_call_addr: *mut libc::c_void,
    si_syscall: libc::c_int,
    si_arch: libc::c_uint,
}

impl SeccompSiginfo {
    const OUTPUT_LEN: usize = 128;

    // Only valid for a SIGSYS raised by seccomp, as that is what determines
    // which member of the siginfo_t union is populated.
    fn from_siginfo(info: &libc::siginfo_t) -> &Self {
        // SAFETY: SeccompSiginfo mirrors Linux's siginfo_t layout for SIGSYS.
        unsafe { &*from_ref(info).cast::<SeccompSiginfo>() }
    }

    // Inside a signal handler can't do any dynamic allocation
    fn format_into<'a>(&self, buf: &'a mut [u8; Self::OUTPUT_LEN]) -> &'a [u8] {
        fn append(buf: &mut [u8], len: &mut usize, bytes: &[u8]) {
            for byte in bytes {
                let Some(slot) = buf.get_mut(*len) else {
                    return;
                };
                *slot = *byte;
                *len = len.saturating_add(1);
            }
        }

        fn append_number(buf: &mut [u8], len: &mut usize, mut value: u64, radix: u64) {
            const DIGITS: &[u8] = b"0123456789abcdef";

            let mut digits = [0; 64];
            let mut start = digits.len();
            loop {
                start -= 1;
                digits[start] = DIGITS[(value % radix) as usize];
                value /= radix;
                if value == 0 {
                    break;
                }
            }

            append(buf, len, &digits[start..]);
        }

        let mut name = [0u8; 16];
        // SAFETY: prctl(PR_GET_NAME) writes at most 16 bytes into the buffer.
        unsafe { libc::prctl(libc::PR_GET_NAME, name.as_mut_ptr()) };
        let name_len = name.iter().position(|b| *b == 0).unwrap_or(name.len());

        let mut len = 0;
        append(buf, &mut len, b"Probable seccomp violation:");
        append(buf, &mut len, b" si_syscall=");
        append_number(buf, &mut len, self.si_syscall as u32 as u64, 10);
        append(buf, &mut len, b" si_arch=0x");
        append_number(buf, &mut len, self.si_arch as u64, 16);
        append(buf, &mut len, b" thread=");
        append(buf, &mut len, &name[..name_len]);
        append(buf, &mut len, b"\n");

        &buf[..len]
    }
}

extern "C" fn handle_sigsys(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: The handler is installed with SA_SIGINFO, so the kernel passes
    // a valid siginfo_t.
    let info = SeccompSiginfo::from_siginfo(unsafe { &*info });
    let mut buffer = [0; SeccompSiginfo::OUTPUT_LEN];
    let message = info.format_into(&mut buffer);
    // SAFETY: message points to initialized memory for message.len() bytes.
    unsafe {
        libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len());
    }

    // For SIGSYS this terminates or aborts and does not return.
    let _ = low_level::emulate_default_handler(SIGSYS);
}

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Error, Debug)]
enum Error {
    #[error("Failed to create API EventFd")]
    CreateApiEventFd(#[source] io::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Failed to create Debug EventFd")]
    CreateDebugEventFd(#[source] io::Error),
    #[error("Failed to create exit EventFd")]
    CreateExitEventFd(#[source] io::Error),
    #[error("Failed to open hypervisor interface (is hypervisor interface available?)")]
    CreateHypervisor(#[source] hypervisor::HypervisorError),
    #[error("Failed to create main thread seccomp filter")]
    CreateSeccompFilter(#[source] seccompiler::Error),
    #[error("Failed to apply main thread seccomp filter")]
    ApplySeccompFilter(#[source] seccompiler::Error),
    #[error("Failed to start the VMM thread")]
    StartVmmThread(#[source] vmm::Error),
    #[error("Error parsing config")]
    ParsingConfig(#[source] config::Error),
    #[error("Error creating VM")]
    VmCreate(#[source] api::ApiError),
    #[error("Error booting VM")]
    VmBoot(#[source] api::ApiError),
    #[error("Error restoring VM")]
    VmRestore(#[source] api::ApiError),
    #[error("Error parsing restore")]
    ParsingRestore(#[source] config::Error),
    #[error("Failed to join on VMM thread: {0:?}")]
    ThreadJoin(Box<dyn any::Any + Send>),
    #[error("VMM thread exited with error")]
    VmmThread(#[source] vmm::Error),
    #[error("Error parsing --api-socket")]
    ParsingApiSocket(#[source] num::ParseIntError),
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
    EventMonitorIo(#[source] io::Error),
    #[error("Event monitor thread failed")]
    EventMonitorThread(#[source] vmm::Error),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb")]
    ParsingGdb(#[source] option_parser::OptionParserError),
    #[cfg(feature = "guest_debug")]
    #[error("Error parsing --gdb: path required")]
    BareGdb,
    #[error("Error creating log file")]
    LogFileCreation(#[source] io::Error),
    #[error("Error parsing logger format")]
    LoggerFormat(#[source] logger::Error),
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
    CreateEventFd(#[source] io::Error),
    #[error("Failed to obtain file limit")]
    GetRLimit(#[source] io::Error),
    #[error("Error calling fcntl with F_GETFD")]
    GetFd(#[source] io::Error),
    #[error("Failed to duplicate file handle")]
    Dup2(#[source] io::Error),
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
    format!("src={}", RngConfig::DEFAULT_RNG_SOURCE)
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliGuestResetAction {
    /// Reset (reboot) the VM
    ResetVm,
    /// Exit Cloud Hypervisor
    ExitVmm,
    /// Shut down the VM and keep Cloud Hypervisor running
    ShutdownVm,
}

impl From<CliGuestResetAction> for GuestResetAction {
    fn from(action: CliGuestResetAction) -> Self {
        match action {
            CliGuestResetAction::ResetVm => Self::ResetVm,
            CliGuestResetAction::ExitVmm => Self::ExitVmm,
            CliGuestResetAction::ShutdownVm => Self::ShutdownVm,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliGuestShutdownAction {
    /// Exit Cloud Hypervisor
    ExitVmm,
    /// Shut down the VM and keep Cloud Hypervisor running
    ShutdownVm,
}

impl From<CliGuestShutdownAction> for GuestShutdownAction {
    fn from(action: CliGuestShutdownAction) -> Self {
        match action {
            CliGuestShutdownAction::ExitVmm => Self::ExitVmm,
            CliGuestShutdownAction::ShutdownVm => Self::ShutdownVm,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliSeccompAction {
    /// Terminate Cloud Hypervisor on prohibited system calls
    True,
    /// Disable system call filtering
    False,
    /// Allow prohibited system calls but log them
    Log,
    /// Fail prohibited system calls with EPERM
    Errno,
}

impl From<CliSeccompAction> for SeccompAction {
    fn from(action: CliSeccompAction) -> Self {
        match action {
            CliSeccompAction::True => Self::Trap,
            CliSeccompAction::False => Self::Allow,
            CliSeccompAction::Log => Self::Log,
            CliSeccompAction::Errno => Self::Errno(libc::EPERM as u32),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "cloud-hypervisor",
    about = "Launch a cloud-hypervisor VMM",
    arg_required_else_help = true
)]
#[command(group(ArgGroup::new("vm-config").multiple(true).requires("vm-payload")))]
#[command(group(ArgGroup::new("vmm-config").multiple(true)))]
#[command(group(ArgGroup::new("logging").multiple(true)))]
#[command(group(ArgGroup::new("vm-payload").multiple(true)))]
#[group(skip)]
struct Cli {
    #[arg(
        long,
        help = "HTTP API socket (UNIX domain socket): path=<path> or fd=<fd>",
        group = "vmm-config"
    )]
    api_socket: Option<String>,
    #[arg(
        long,
        help = BalloonConfig::SYNTAX,
        group = "vm-config",
    )]
    balloon: Option<String>,
    #[arg(long, help = "Kernel command line", group = "vm-config")]
    cmdline: Option<String>,
    #[arg(
        long,
        help = ConsoleConfig::SYNTAX,
        default_value = "tty",
        group = "vm-config",
    )]
    console: String,
    #[arg(
        long,
        help = CpusConfig::SYNTAX,
        default_value = default_vcpus(),
        group = "vm-config",
    )]
    cpus: String,
    #[cfg(feature = "dbus_api")]
    #[arg(
        long,
        help = "Object path to serve the dbus interface",
        group = "vmm-config"
    )]
    dbus_object_path: Option<String>,
    #[cfg(feature = "dbus_api")]
    #[arg(
        long,
        help = "Well known name of the dbus service",
        group = "vmm-config"
    )]
    dbus_service_name: Option<String>,
    #[cfg(feature = "dbus_api")]
    #[arg(
        long,
        help = "Use the system bus instead of a session bus",
        group = "vmm-config"
    )]
    dbus_system_bus: bool,
    #[cfg(target_arch = "x86_64")]
    #[arg(
        long,
        help = DebugConsoleConfig::SYNTAX,
        default_value = "off,iobase=0xe9",
        group = "vm-config"
    )]
    debug_console: String,
    #[arg(
        long,
        help = DeviceConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    device: Option<Vec<String>>,
    #[arg(
        long,
        help = DiskConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    disk: Option<Vec<String>>,
    #[arg(
        long,
        help = "Path to report events on: path=<path> or fd=<fd>",
        group = "vmm-config"
    )]
    event_monitor: Option<String>,
    #[arg(
        long,
        help = "Path to firmware that is loaded in an architecture-specific way",
        group = "vm-payload"
    )]
    firmware: Option<String>,
    #[arg(
        long,
        help = FsConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    fs: Option<Vec<String>>,
    #[cfg(feature = "fw_cfg")]
    #[arg(
        long,
        help = FwCfgConfig::SYNTAX,
        group = "vm-config",
    )]
    fw_cfg_config: Option<String>,
    #[cfg(feature = "guest_debug")]
    #[arg(
        long,
        help = "GDB socket (UNIX domain socket): path=<path>",
        group = "vmm-config"
    )]
    gdb: Option<String>,
    #[arg(
        long,
        help = GenericVhostUserConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    generic_vhost_user: Option<Vec<String>>,
    #[arg(
        long,
        help = "Action when the guest resets",
        default_value = "reset-vm",
        group = "vmm-config"
    )]
    guest_reset_action: CliGuestResetAction,
    #[arg(
        long,
        help = "Action when the guest shuts down",
        default_value = "exit-vmm",
        group = "vmm-config"
    )]
    guest_shutdown_action: CliGuestShutdownAction,
    #[cfg(feature = "sev_snp")]
    #[arg(
        long,
        help = "Host specific data to SEV SNP guest",
        group = "vm-config"
    )]
    host_data: Option<String>,
    #[cfg(feature = "igvm")]
    #[arg(long, help = "Path to IGVM file to load", group = "vm-payload")]
    igvm: Option<String>,
    #[arg(long, help = "Path to initramfs image", group = "vm-config")]
    initramfs: Option<String>,
    #[cfg(feature = "ivshmem")]
    #[arg(
        long,
        help = IvshmemConfig::SYNTAX,
        group = "vm-config",
    )]
    ivshmem: Option<String>,
    #[arg(
        long,
        help = "Path to kernel to load. This may be a kernel or firmware that supports a PVH \
                entry point (e.g. vmlinux) or architecture equivalent",
        group = "vm-payload"
    )]
    kernel: Option<String>,
    #[arg(long, help = "Enable Landlock", group = "vmm-config")]
    landlock: bool,
    #[arg(
        long,
        help = LandlockConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    landlock_rules: Option<Vec<String>>,
    #[arg(
        long,
        help = "Log file. Standard error is used if not specified",
        group = "logging"
    )]
    log_file: Option<String>,
    #[arg(
        long,
        help = "Log format. Common tokens: {boottime}, {wallclock}, {glog}, \
                 {localglog}, {thread}, {level}, {location}, {msg}. See \
                 docs/logging.md for the full list (per-field date/time tokens, \
                 local-time variants, glog level letter).",
        default_value = logger::DEFAULT_FORMAT,
        group = "logging",
    )]
    log_format: String,
    #[arg(
        long,
        help = MemoryConfig::SYNTAX,
        default_value = default_memory(),
        group = "vm-config",
    )]
    memory: String,
    #[arg(
        long,
        help = MemoryZoneConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    memory_zone: Option<Vec<String>>,
    #[arg(
        long,
        help = NetConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    net: Option<Vec<String>>,
    #[arg(
        long,
        help = "Do not exit Cloud Hypervisor when the guest shuts down \
                 [deprecated: use --guest-shutdown-action=shutdown-vm]",
        conflicts_with = "guest_shutdown_action",
        group = "vmm-config"
    )]
    no_shutdown: bool,
    #[arg(
        long,
        help = NumaConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    numa: Option<Vec<String>>,
    #[arg(
        long,
        help = PciSegmentConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    pci_segment: Option<Vec<String>>,
    #[arg(
        long,
        help = PlatformConfig::SYNTAX,
        group = "vm-config",
    )]
    platform: Option<String>,
    #[arg(
        long,
        help = PmemConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    pmem: Option<Vec<String>>,
    #[cfg(feature = "pvmemcontrol")]
    #[arg(long, help = "Enable pvmemcontrol device", group = "vm-config")]
    pvmemcontrol: bool,
    #[arg(long, help = "Enable pvpanic device", group = "vm-config")]
    pvpanic: bool,
    #[arg(
        long,
        help = RateLimiterGroupConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    rate_limit_group: Option<Vec<String>>,
    #[arg(
        long,
        help = RestoreConfig::SYNTAX,
        group = "vmm-config",
    )]
    restore: Option<String>,
    #[arg(
        long,
        help = RngConfig::SYNTAX,
        default_value = default_rng(),
        group = "vm-config",
    )]
    rng: String,
    #[arg(
        long,
        help = RtcConfig::SYNTAX,
        num_args = 0..=1,
        default_missing_value = "",
        group = "vm-config",
    )]
    rtc: Option<String>,
    #[arg(
        long,
        help = "Action on prohibited system calls",
        default_value = "true",
        group = "vmm-config"
    )]
    seccomp: CliSeccompAction,
    #[arg(
        long,
        help = SerialConfig::SYNTAX,
        default_value = "null",
        group = "vm-config",
    )]
    serial: String,
    #[arg(
        long,
        help = TpmConfig::SYNTAX,
        group = "vm-config",
    )]
    tpm: Option<String>,
    #[arg(
        long,
        help = UserDeviceConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    user_device: Option<Vec<String>>,
    #[arg(
        short = 'v',
        action = ArgAction::Count,
        help = "Increase log verbosity: -v for info, -vv for debug, -vvv for trace",
        group = "logging",
    )]
    v: u8,
    #[arg(
        long,
        help = VdpaConfig::SYNTAX,
        num_args = 1..,
        group = "vm-config",
    )]
    vdpa: Option<Vec<String>>,
    #[arg(short = 'V', long, help = "Print version")]
    version: bool,
    #[arg(
        long,
        help = VsockConfig::SYNTAX,
        group = "vm-config",
    )]
    vsock: Option<String>,
    #[arg(long, help = "Enable virtio-watchdog device", group = "vm-config")]
    watchdog: bool,
}

impl Cli {
    /// Combines --guest-shutdown-action with the deprecated --no-shutdown.
    fn guest_shutdown_action(&self) -> GuestShutdownAction {
        if self.no_shutdown {
            warn!("--no-shutdown is deprecated: use --guest-shutdown-action=shutdown-vm instead");
            return GuestShutdownAction::ShutdownVm;
        }

        self.guest_shutdown_action.into()
    }
}

impl<'a> From<&'a Cli> for VmParams<'a> {
    fn from(cli: &'a Cli) -> Self {
        Self {
            cpus: &cli.cpus,
            memory: &cli.memory,
            memory_zones: cli
                .memory_zone
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            firmware: cli.firmware.as_deref(),
            kernel: cli.kernel.as_deref(),
            initramfs: cli.initramfs.as_deref(),
            cmdline: cli.cmdline.as_deref(),
            rate_limit_groups: cli
                .rate_limit_group
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            disks: cli
                .disk
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            net: cli
                .net
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            rng: &cli.rng,
            balloon: cli.balloon.as_deref(),
            fs: cli
                .fs
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            generic_vhost_user: cli
                .generic_vhost_user
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            pmem: cli
                .pmem
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            serial: &cli.serial,
            console: &cli.console,
            #[cfg(target_arch = "x86_64")]
            debug_console: &cli.debug_console,
            devices: cli
                .device
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            user_devices: cli
                .user_device
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            vdpa: cli
                .vdpa
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            vsock: cli.vsock.as_deref(),
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol: cli.pvmemcontrol,
            pvpanic: cli.pvpanic,
            numa: cli
                .numa
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            watchdog: cli.watchdog,
            rtc: cli.rtc.as_deref(),
            #[cfg(feature = "guest_debug")]
            gdb: cli.gdb.is_some(),
            pci_segments: cli
                .pci_segment
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            platform: cli.platform.as_deref(),
            tpm: cli.tpm.as_deref(),
            #[cfg(feature = "igvm")]
            igvm: cli.igvm.as_deref(),
            #[cfg(feature = "sev_snp")]
            host_data: cli.host_data.as_deref(),
            landlock_enable: cli.landlock,
            landlock_rules: cli
                .landlock_rules
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            #[cfg(feature = "fw_cfg")]
            fw_cfg_config: cli.fw_cfg_config.as_deref(),
            #[cfg(feature = "ivshmem")]
            ivshmem: cli.ivshmem.as_deref(),
        }
    }
}

fn parse_api_socket(cmd_arguments: &Cli) -> Result<(Option<String>, Option<RawFd>), Error> {
    if let Some(socket_config) = cmd_arguments.api_socket.as_ref() {
        let mut parser = OptionParser::new();
        parser.add("path").add("fd");
        parser.parse(socket_config).unwrap_or_default();

        if let Some(fd) = parser.get("fd") {
            Ok((
                None,
                Some(fd.parse::<RawFd>().map_err(Error::ParsingApiSocket)?),
            ))
        } else if let Some(path) = parser.get("path") {
            Ok((Some(path), None))
        } else {
            Ok((
                cmd_arguments.api_socket.as_ref().map(|s| s.to_string()),
                None,
            ))
        }
    } else {
        Ok((None, None))
    }
}

fn start_vmm(
    cmd_arguments: &Cli,
    api_socket_path: &Option<String>,
    api_socket_fd: Option<RawFd>,
) -> Result<(), Error> {
    #[cfg(feature = "igvm")]
    let payload_present = cmd_arguments.kernel.is_some()
        || cmd_arguments.firmware.is_some()
        || cmd_arguments.igvm.is_some();
    #[cfg(not(feature = "igvm"))]
    let payload_present = cmd_arguments.kernel.is_some() || cmd_arguments.firmware.is_some();

    let vm_config = if payload_present {
        let vm_params = VmParams::from(cmd_arguments);
        // SAFETY: The CLI transfers inherited FDs before the VMM opens new FDs.
        Some(unsafe { VmConfig::parse(vm_params) }.map_err(Error::ParsingConfig)?)
    } else {
        None
    };
    let restore_config = if vm_config.is_none() {
        cmd_arguments
            .restore
            .as_ref()
            // SAFETY: The CLI transfers inherited FDs before the VMM opens new FDs.
            .map(|restore| unsafe { RestoreConfig::parse(restore) })
            .transpose()
            .map_err(Error::ParsingRestore)?
    } else {
        None
    };

    if let Err(e) = expand_fdtable() {
        warn!("Error expanding FD table: {e}");
    }

    let log_level = match cmd_arguments.v {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn io::Write + Send> =
        if let Some(ref file) = cmd_arguments.log_file.as_ref() {
            Box::new(File::create(Path::new(file)).map_err(Error::LogFileCreation)?)
        } else {
            Box::new(io::stderr())
        };

    let format = &cmd_arguments.log_format;
    let logger = Logger::new(log_file, format).map_err(Error::LoggerFormat)?;
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(log_level))
        .map_err(Error::LoggerSetup)?;

    let shutdown_action = cmd_arguments.guest_shutdown_action();
    let reset_action = GuestResetAction::from(cmd_arguments.guest_reset_action);
    let seccomp_action = SeccompAction::from(cmd_arguments.seccomp);

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateApiEventFd)?;

    let api_request_sender_clone = api_request_sender.clone();

    if seccomp_action == SeccompAction::Trap {
        // handle_sigsys only performs async signal safe operations.
        register_signal_handler(SIGSYS, handle_sigsys)
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
    for sig in &Vm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            error!("Error blocking signals: {e}");
        }
    }

    for sig in &vmm::Vmm::HANDLED_SIGNALS {
        if let Err(e) = block_signal(*sig) {
            error!("Error blocking signals: {e}");
        }
    }

    info!("{} starting", env!("BUILD_VERSION"));

    let hypervisor = hypervisor::new().map_err(Error::CreateHypervisor)?;
    let main_seccomp_filter = get_seccomp_filter(&seccomp_action, Thread::Main, None)
        .map_err(Error::CreateSeccompFilter)?;

    #[cfg(feature = "guest_debug")]
    let gdb_socket_path = if let Some(gdb_config) = cmd_arguments.gdb.as_ref() {
        let mut parser = OptionParser::new();
        parser.add("path");
        parser.parse(gdb_config).map_err(Error::ParsingGdb)?;

        if parser.is_set("path") {
            Some(PathBuf::from(parser.get("path").unwrap()))
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
    let landlock_enable = cmd_arguments.landlock;

    #[allow(unused_mut)]
    let mut event_monitor = cmd_arguments
        .event_monitor
        .as_ref()
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
                    fs::OpenOptions::new()
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
        cmd_arguments.dbus_service_name.as_ref(),
        cmd_arguments.dbus_object_path.as_ref(),
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
                system_bus: cmd_arguments.dbus_system_bus,
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
            exit_evt.try_clone().unwrap(),
        )
        .map_err(Error::EventMonitorThread)?;
    }

    event!("vmm", "starting");

    let vmm_thread_handle = vmm::start_vmm_thread(
        vmm::VmmVersionInfo::new(env!("BUILD_VERSION"), env!("CARGO_PKG_VERSION")),
        api_socket_path,
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
        shutdown_action,
        reset_action,
        landlock_enable,
    )
    .map_err(Error::StartVmmThread)?;

    // Spawn workers first so they do not inherit main's narrower filter.
    if !main_seccomp_filter.is_empty() {
        seccompiler::apply_filter(&main_seccomp_filter).map_err(Error::ApplySeccompFilter)?;
    }

    // API endpoints (HTTP, D-Bus) are set up at this point (if API socket is
    // configured)
    event!("vmm", "started");

    let r: Result<(), Error> = (|| {
        if let Some(vm_config) = vm_config {
            // Create and boot the VM based off the VM config we just built.
            let sender = api_request_sender.clone();
            api::VmCreate
                .send(
                    api_evt.try_clone().unwrap(),
                    api_request_sender,
                    Box::new(vm_config),
                )
                .map_err(Error::VmCreate)?;
            api::VmBoot
                .send(api_evt.try_clone().unwrap(), sender, ())
                .map_err(Error::VmBoot)?;
        } else if let Some(restore_config) = restore_config {
            api::VmRestore
                .send(
                    api_evt.try_clone().unwrap(),
                    api_request_sender,
                    restore_config,
                )
                .map_err(Error::VmRestore)?;
        }

        Ok(())
    })();

    if r.is_err()
        && let Err(e) = exit_evt.write(1)
    {
        warn!("writing to exit EventFd: {e}");
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
        http_api_graceful_shutdown(api_handle).map_err(Error::HttpApiShutdown)?;
    }

    #[cfg(feature = "dbus_api")]
    if let Some(chs) = vmm_thread_handle.dbus_shutdown_chs {
        dbus_api_graceful_shutdown(chs);
    }

    r
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
        cmp::min(limits.rlim_cur, 4096) as libc::c_int
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
    #[cfg(all(feature = "sev_snp", not(target_arch = "x86_64")))]
    compile_error!("Feature 'sev_snp' needs target 'x86_64'");
    #[cfg(all(feature = "fw_cfg", target_arch = "riscv64"))]
    compile_error!("Feature 'fw_cfg' needs targets 'x86_64' or 'aarch64'");
    #[cfg(all(feature = "igvm", not(any(feature = "kvm", feature = "mshv"))))]
    compile_error!("Feature 'igvm' needs feature 'kvm' or 'mshv'");
    #[cfg(all(feature = "sev_snp", not(any(feature = "kvm", feature = "mshv"))))]
    compile_error!("Feature 'sev_snp' needs feature 'kvm' or 'mshv'");

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Ensure all created files (.e.g sockets) are only accessible by this user
    // SAFETY: trivially safe
    let _ = unsafe { libc::umask(0o077) };
    let cmd_arguments = Cli::parse();

    if cmd_arguments.version {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("BUILD_VERSION"));
        if cmd_arguments.v != 0 {
            println!("Enabled features: {:?}", vmm::feature_list());
        }

        return;
    }

    let (api_socket_path, api_socket_fd) = match parse_api_socket(&cmd_arguments) {
        Ok(p) => p,
        Err(top_error) => {
            cloud_hypervisor::cli_print_error_chain(&top_error, "Cloud Hypervisor", |_, _, _| None);
            process::exit(1);
        }
    };

    let vmm_result = start_vmm(&cmd_arguments, &api_socket_path, api_socket_fd);

    let exit_code = match vmm_result {
        Ok(()) => {
            info!("Cloud Hypervisor exited successfully");
            0
        }
        Err(top_error) => {
            cloud_hypervisor::cli_print_error_chain(&top_error, "Cloud Hypervisor", |_, _, _| None);
            1
        }
    };

    #[cfg(feature = "dhat-heap")]
    drop(_profiler);

    process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use std::mem::zeroed;
    use std::path::PathBuf;
    use std::ptr::from_mut;
    use std::thread;

    use clap::{CommandFactory, Parser};
    use vmm::config::VmParams;
    #[cfg(target_arch = "x86_64")]
    use vmm::vm_config::DebugConsoleConfig;
    use vmm::vm_config::{
        ConsoleConfig, ConsoleOutput, CoreScheduling, CpuFeatures, CpusConfig, HotplugMethod,
        MemoryConfig, PayloadConfig, PciDeviceCommonConfig, RngConfig, SerialConfig, VmConfig,
    };

    use crate::test_util::assert_args_sorted;
    use crate::{Cli, GuestResetAction, GuestShutdownAction, SeccompSiginfo};

    #[test]
    fn clap_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_options_sorted() {
        let command = Cli::command();
        assert_args_sorted(|| command.get_arguments());
    }

    #[test]
    fn test_reset_action() {
        for (options, expected) in [
            (vec![], GuestResetAction::ResetVm),
            (
                vec!["--guest-reset-action", "reset-vm"],
                GuestResetAction::ResetVm,
            ),
            (
                vec!["--guest-reset-action", "exit-vmm"],
                GuestResetAction::ExitVmm,
            ),
            (
                vec!["--guest-reset-action=shutdown-vm"],
                GuestResetAction::ShutdownVm,
            ),
            (vec!["--no-shutdown"], GuestResetAction::ResetVm),
            (
                vec![
                    "--guest-shutdown-action=shutdown-vm",
                    "--guest-reset-action=exit-vmm",
                ],
                GuestResetAction::ExitVmm,
            ),
        ] {
            let mut args = vec!["cloud-hypervisor", "--api-socket", "/tmp/api.sock"];
            args.extend(options);
            let matches = Cli::try_parse_from(&args).unwrap();
            assert!(
                matches!(
                    (GuestResetAction::from(matches.guest_reset_action), expected),
                    (GuestResetAction::ResetVm, GuestResetAction::ResetVm)
                        | (GuestResetAction::ExitVmm, GuestResetAction::ExitVmm)
                        | (GuestResetAction::ShutdownVm, GuestResetAction::ShutdownVm)
                ),
                "args: {args:?}",
            );
        }
    }

    #[test]
    fn test_reset_action_invalid_arguments() {
        use clap::error::ErrorKind;

        for options in [
            vec!["--guest-reset-action", "invalid"],
            vec!["--guest-reset-action"],
        ] {
            let mut args = vec!["cloud-hypervisor", "--api-socket", "/tmp/api.sock"];
            args.extend(options);
            let error = Cli::try_parse_from(&args).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidValue);
        }
    }

    #[test]
    fn test_shutdown_action() {
        for (options, shutdown) in [
            (vec![], false),
            (vec!["--guest-shutdown-action", "exit-vmm"], false),
            (vec!["--guest-shutdown-action", "shutdown-vm"], true),
            (vec!["--guest-shutdown-action=shutdown-vm"], true),
            (vec!["--no-shutdown"], true),
        ] {
            let mut args = vec!["cloud-hypervisor", "--api-socket", "/tmp/api.sock"];
            args.extend(options);
            let matches = Cli::try_parse_from(&args).unwrap();
            assert_eq!(
                matches!(
                    matches.guest_shutdown_action(),
                    GuestShutdownAction::ShutdownVm
                ),
                shutdown,
                "args: {args:?}",
            );
        }
    }

    #[test]
    fn test_shutdown_action_invalid_arguments() {
        use clap::error::ErrorKind;

        for (options, expected_error) in [
            (
                vec!["--guest-shutdown-action", "reset-vm"],
                ErrorKind::InvalidValue,
            ),
            (vec!["--guest-shutdown-action"], ErrorKind::InvalidValue),
            (
                vec!["--no-shutdown", "--guest-shutdown-action", "exit-vmm"],
                ErrorKind::ArgumentConflict,
            ),
            (
                vec!["--guest-shutdown-action", "shutdown-vm", "--no-shutdown"],
                ErrorKind::ArgumentConflict,
            ),
        ] {
            let mut args = vec!["cloud-hypervisor", "--api-socket", "/tmp/api.sock"];
            args.extend(options);
            let error = Cli::try_parse_from(&args).unwrap_err();
            assert_eq!(error.kind(), expected_error, "args: {args:?}");
        }
    }

    #[test]
    fn test_seccomp_siginfo_output() {
        thread::Builder::new()
            .name("test-sigsys".to_string())
            .spawn(|| {
                // SAFETY: An all-zero libc::siginfo_t is valid on Linux.
                let mut siginfo = unsafe { zeroed::<libc::siginfo_t>() };
                // SAFETY: SeccompSiginfo mirrors the initial Linux siginfo_t layout.
                unsafe {
                    let seccomp = &mut *from_mut(&mut siginfo).cast::<SeccompSiginfo>();
                    seccomp.si_syscall = 47;
                    seccomp.si_arch = 0x3e;
                }

                let info = SeccompSiginfo::from_siginfo(&siginfo);
                let mut buffer = [0; SeccompSiginfo::OUTPUT_LEN];
                let expected = "Probable seccomp violation: si_syscall=47 \
                     si_arch=0x3e thread=test-sigsys\n";

                assert_eq!(info.format_into(&mut buffer), expected.as_bytes());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_landlock_without_payload() {
        // A VMM that receives its VM config later through vm.create can
        // still confine its own threads.
        let cmd_arguments =
            Cli::try_parse_from(["cloud-hypervisor", "--api-socket", "/tmp/api", "--landlock"])
                .unwrap();
        assert!(cmd_arguments.landlock);
    }

    fn get_vm_config_from_vec(args: &[&str]) -> VmConfig {
        let cmd_arguments = Cli::parse_from(args);
        let vm_params = VmParams::from(&cmd_arguments);

        // SAFETY: These CLI test cases supply no inherited descriptors.
        unsafe { VmConfig::parse(vm_params) }.unwrap()
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_valid_vm_config_cpuid_overrides() {
        let cli = vec![
            "cloud-hypervisor",
            "--kernel",
            "/path/to/kernel",
            "--cpus",
            "boot=2,x-cpuid-overrides=[[0x80000002,0x0,0x0,0x0,0x0,0x0]]",
        ];
        let openapi = r#"{
            "payload": {"kernel": "/path/to/kernel"},
            "cpus": {
                "boot_vcpus": 2,
                "max_vcpus": 2,
                "x-cpuid-overrides": [{
                    "leaf": "0x80000002", "subleaf": "0x0",
                    "eax": "0x0", "ebx": "0x0", "ecx": "0x0", "edx": "0x0"
                }]
            }
        }"#;
        compare_vm_config_cli_vs_json(&cli, openapi, true);
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
                #[cfg(target_arch = "x86_64")]
                kvm_hint_realtime: false,
                max_phys_bits: 46,
                affinity: None,
                features: CpuFeatures::default(),
                nested: false,
                core_scheduling: CoreScheduling::Vm,
                profile: Default::default(),
                #[cfg(target_arch = "x86_64")]
                cpuid_overrides: Vec::new(),
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
                reserve: None,
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
                pci_common: PciDeviceCommonConfig::default(),
            },
            balloon: None,
            fs: None,
            generic_vhost_user: None,
            pmem: None,
            serial: SerialConfig {
                output: ConsoleOutput::Null,
            },
            console: ConsoleConfig {
                output: ConsoleOutput::Tty,
                pci_common: PciDeviceCommonConfig::default(),
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
            rtc: None,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            pci_segments: None,
            platform: None,
            tpm: None,
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
        [(
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
                    "path=/path/to/disk/1,image_type=raw",
                    "path=/path/to/disk/2,image_type=raw",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "disks": [
                        {"path": "/path/to/disk/1", "image_type": "Raw"},
                        {"path": "/path/to/disk/2", "image_type": "Raw"}
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
                    "path=/path/to/disk/1,image_type=raw",
                    "path=/path/to/disk/2,image_type=qcow2",
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
                    "--disk",
                    "path=/path/to/disk/1,rate_limit_group=group0,image_type=raw",
                    "path=/path/to/disk/2,rate_limit_group=group0,image_type=raw",
                    "--rate-limit-group",
                    "id=group0,bw_size=1000,bw_refill_time=100",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "disks": [
                        {"path": "/path/to/disk/1", "rate_limit_group": "group0", "image_type": "Raw"},
                        {"path": "/path/to/disk/2", "rate_limit_group": "group0", "image_type": "Raw"}
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
        [
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
                    "tty,pci_segment=0,pci_device_id=7",
                ],
                r#"{
                    "payload": {"kernel": "/path/to/kernel"},
                    "serial": {"mode": "Null"},
                    "console": {"mode": "Tty", "iommu": false, "pci_segment": 0, "pci_device_id": 7}
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
        [
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
}
