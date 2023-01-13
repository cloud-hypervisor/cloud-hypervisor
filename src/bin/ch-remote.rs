// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use api_client::simple_api_command;
use api_client::simple_api_command_with_fds;
use api_client::simple_api_full_command;
use api_client::Error as ApiClientError;
use argh::FromArgs;
use option_parser::{ByteSized, ByteSizedParseError};
use std::fmt;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::process;

#[derive(Debug)]
enum Error {
    Connect(std::io::Error),
    ApiClient(ApiClientError),
    InvalidMemorySize(ByteSizedParseError),
    InvalidBalloonSize(ByteSizedParseError),
    AddDeviceConfig(vmm::config::Error),
    AddDiskConfig(vmm::config::Error),
    AddFsConfig(vmm::config::Error),
    AddPmemConfig(vmm::config::Error),
    AddNetConfig(vmm::config::Error),
    AddUserDeviceConfig(vmm::config::Error),
    AddVdpaConfig(vmm::config::Error),
    AddVsockConfig(vmm::config::Error),
    Restore(vmm::config::Error),
    ReadingStdin(std::io::Error),
    ReadingFile(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            ApiClient(e) => e.fmt(f),
            Connect(e) => write!(f, "Error opening HTTP socket: {e}"),
            InvalidMemorySize(e) => write!(f, "Error parsing memory size: {e:?}"),
            InvalidBalloonSize(e) => write!(f, "Error parsing balloon size: {e:?}"),
            AddDeviceConfig(e) => write!(f, "Error parsing device syntax: {e}"),
            AddDiskConfig(e) => write!(f, "Error parsing disk syntax: {e}"),
            AddFsConfig(e) => write!(f, "Error parsing filesystem syntax: {e}"),
            AddPmemConfig(e) => write!(f, "Error parsing persistent memory syntax: {e}"),
            AddNetConfig(e) => write!(f, "Error parsing network syntax: {e}"),
            AddUserDeviceConfig(e) => write!(f, "Error parsing user device syntax: {e}"),
            AddVdpaConfig(e) => write!(f, "Error parsing vDPA device syntax: {e}"),
            AddVsockConfig(e) => write!(f, "Error parsing vsock syntax: {e}"),
            Restore(e) => write!(f, "Error parsing restore syntax: {e}"),
            ReadingStdin(e) => write!(f, "Error reading from stdin: {e}"),
            ReadingFile(e) => write!(f, "Error reading from file: {e}"),
        }
    }
}

fn resize_api_command(
    socket: &mut UnixStream,
    desired_vcpus: Option<u8>,
    memory: &Option<String>,
    balloon: &Option<String>,
) -> Result<(), Error> {
    let desired_ram: Option<u64> = if let Some(memory) = memory {
        Some(
            memory
                .parse::<ByteSized>()
                .map_err(Error::InvalidMemorySize)?
                .0,
        )
    } else {
        None
    };

    let desired_balloon: Option<u64> = if let Some(balloon) = balloon {
        Some(
            balloon
                .parse::<ByteSized>()
                .map_err(Error::InvalidBalloonSize)?
                .0,
        )
    } else {
        None
    };

    let resize = vmm::api::VmResizeData {
        desired_vcpus,
        desired_ram,
        desired_balloon,
    };

    simple_api_command(
        socket,
        "PUT",
        "resize",
        Some(&serde_json::to_string(&resize).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn resize_zone_api_command(socket: &mut UnixStream, id: &str, size: &str) -> Result<(), Error> {
    let resize_zone = vmm::api::VmResizeZoneData {
        id: id.to_owned(),
        desired_ram: size
            .parse::<ByteSized>()
            .map_err(Error::InvalidMemorySize)?
            .0,
    };

    simple_api_command(
        socket,
        "PUT",
        "resize-zone",
        Some(&serde_json::to_string(&resize_zone).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_device_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let device_config = vmm::config::DeviceConfig::parse(config).map_err(Error::AddDeviceConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-device",
        Some(&serde_json::to_string(&device_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_user_device_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let device_config =
        vmm::config::UserDeviceConfig::parse(config).map_err(Error::AddUserDeviceConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-user-device",
        Some(&serde_json::to_string(&device_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn remove_device_api_command(socket: &mut UnixStream, id: &str) -> Result<(), Error> {
    let remove_device_data = vmm::api::VmRemoveDeviceData { id: id.to_owned() };

    simple_api_command(
        socket,
        "PUT",
        "remove-device",
        Some(&serde_json::to_string(&remove_device_data).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_disk_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let disk_config = vmm::config::DiskConfig::parse(config).map_err(Error::AddDiskConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-disk",
        Some(&serde_json::to_string(&disk_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_fs_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let fs_config = vmm::config::FsConfig::parse(config).map_err(Error::AddFsConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-fs",
        Some(&serde_json::to_string(&fs_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_pmem_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let pmem_config = vmm::config::PmemConfig::parse(config).map_err(Error::AddPmemConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-pmem",
        Some(&serde_json::to_string(&pmem_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_net_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let mut net_config = vmm::config::NetConfig::parse(config).map_err(Error::AddNetConfig)?;

    // NetConfig is modified on purpose here by taking the list of file
    // descriptors out. Keeping the list and send it to the server side
    // process would not make any sense since the file descriptor may be
    // represented with different values.
    let fds = net_config.fds.take().unwrap_or_default();

    simple_api_command_with_fds(
        socket,
        "PUT",
        "add-net",
        Some(&serde_json::to_string(&net_config).unwrap()),
        fds,
    )
    .map_err(Error::ApiClient)
}

fn add_vdpa_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let vdpa_config = vmm::config::VdpaConfig::parse(config).map_err(Error::AddVdpaConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-vdpa",
        Some(&serde_json::to_string(&vdpa_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn add_vsock_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let vsock_config = vmm::config::VsockConfig::parse(config).map_err(Error::AddVsockConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-vsock",
        Some(&serde_json::to_string(&vsock_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn snapshot_api_command(socket: &mut UnixStream, url: &str) -> Result<(), Error> {
    let snapshot_config = vmm::api::VmSnapshotConfig {
        destination_url: String::from(url),
    };

    simple_api_command(
        socket,
        "PUT",
        "snapshot",
        Some(&serde_json::to_string(&snapshot_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn restore_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let restore_config = vmm::config::RestoreConfig::parse(config).map_err(Error::Restore)?;

    simple_api_command(
        socket,
        "PUT",
        "restore",
        Some(&serde_json::to_string(&restore_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn coredump_api_command(socket: &mut UnixStream, destination_url: &str) -> Result<(), Error> {
    let coredump_config = vmm::api::VmCoredumpData {
        destination_url: String::from(destination_url),
    };

    simple_api_command(
        socket,
        "PUT",
        "coredump",
        Some(&serde_json::to_string(&coredump_config).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn receive_migration_api_command(socket: &mut UnixStream, url: &str) -> Result<(), Error> {
    let receive_migration_data = vmm::api::VmReceiveMigrationData {
        receiver_url: url.to_owned(),
    };
    simple_api_command(
        socket,
        "PUT",
        "receive-migration",
        Some(&serde_json::to_string(&receive_migration_data).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn send_migration_api_command(
    socket: &mut UnixStream,
    url: &str,
    local: bool,
) -> Result<(), Error> {
    let send_migration_data = vmm::api::VmSendMigrationData {
        destination_url: url.to_owned(),
        local,
    };
    simple_api_command(
        socket,
        "PUT",
        "send-migration",
        Some(&serde_json::to_string(&send_migration_data).unwrap()),
    )
    .map_err(Error::ApiClient)
}

fn create_api_command(socket: &mut UnixStream, path: &str) -> Result<(), Error> {
    let mut data = String::default();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut data)
            .map_err(Error::ReadingStdin)?;
    } else {
        data = std::fs::read_to_string(path).map_err(Error::ReadingFile)?;
    }

    simple_api_command(socket, "PUT", "create", Some(&data)).map_err(Error::ApiClient)
}

fn do_command(toplevel: &TopLevel) -> Result<(), Error> {
    let mut socket =
        UnixStream::connect(toplevel.api_socket.as_deref().unwrap()).map_err(Error::Connect)?;

    match toplevel.command {
        SubCommandEnum::Boot(_) => {
            simple_api_command(&mut socket, "PUT", "boot", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Delete(_) => {
            simple_api_command(&mut socket, "PUT", "delete", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::ShutdownVmm(_) => {
            simple_api_command(&mut socket, "PUT", "shutdown-vmm", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Resume(_) => {
            simple_api_command(&mut socket, "PUT", "resume", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::PowerButton(_) => {
            simple_api_command(&mut socket, "PUT", "power-button", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Reboot(_) => {
            simple_api_command(&mut socket, "PUT", "reboot", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Pause(_) => {
            simple_api_command(&mut socket, "PUT", "pause", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Info(_) => {
            simple_api_command(&mut socket, "GET", "info", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Counters(_) => {
            simple_api_command(&mut socket, "GET", "counters", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Ping(_) => {
            simple_api_full_command(&mut socket, "GET", "vmm.ping", None).map_err(Error::ApiClient)
        }
        SubCommandEnum::Shutdown(_) => {
            simple_api_full_command(&mut socket, "PUT", "vmm.shutdown", None)
                .map_err(Error::ApiClient)
        }
        SubCommandEnum::Resize(ref config) => {
            resize_api_command(&mut socket, config.cpus, &config.memory, &config.balloon)
        }
        SubCommandEnum::ResizeZone(ref config) => {
            resize_zone_api_command(&mut socket, &config.id, &config.size)
        }
        SubCommandEnum::AddDevice(ref config) => {
            add_device_api_command(&mut socket, &config.device_config)
        }
        SubCommandEnum::RemoveDevice(ref config) => {
            remove_device_api_command(&mut socket, &config.device_config)
        }
        SubCommandEnum::AddDisk(ref config) => {
            add_disk_api_command(&mut socket, &config.disk_config)
        }
        SubCommandEnum::AddFs(ref config) => add_fs_api_command(&mut socket, &config.fs_config),
        SubCommandEnum::AddPmem(ref config) => {
            add_pmem_api_command(&mut socket, &config.pmem_config)
        }
        SubCommandEnum::AddNet(ref config) => add_net_api_command(&mut socket, &config.net_config),
        SubCommandEnum::AddUserDevice(ref config) => {
            add_user_device_api_command(&mut socket, &config.device_config)
        }
        SubCommandEnum::AddVdpa(ref config) => {
            add_vdpa_api_command(&mut socket, &config.vdpa_config)
        }
        SubCommandEnum::AddVsock(ref config) => {
            add_vsock_api_command(&mut socket, &config.vsock_config)
        }
        SubCommandEnum::Snapshot(ref config) => {
            snapshot_api_command(&mut socket, &config.snapshot_config)
        }
        SubCommandEnum::Restore(ref config) => {
            restore_api_command(&mut socket, &config.restore_config)
        }
        SubCommandEnum::Coredump(ref config) => {
            coredump_api_command(&mut socket, &config.coredump_config)
        }
        SubCommandEnum::SendMigration(ref config) => send_migration_api_command(
            &mut socket,
            &config.send_migration_config,
            config.send_migration_local,
        ),
        SubCommandEnum::ReceiveMigration(ref config) => {
            receive_migration_api_command(&mut socket, &config.receive_migration_config)
        }
        SubCommandEnum::Create(ref config) => create_api_command(&mut socket, &config.vm_config),
        SubCommandEnum::Version(_) => {
            // Already handled outside of this function
            panic!()
        }
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[doc = "Remotely control a cloud-hypervisor VMM.\n\nPlease refer to cloud-hypervisor for configuration syntaxes."]
struct TopLevel {
    #[argh(subcommand)]
    command: SubCommandEnum,

    #[argh(option, long = "api-socket")]
    /// HTTP API socket path (UNIX domain socket)
    api_socket: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommandEnum {
    AddDevice(AddDeviceSubcommand),
    AddDisk(AddDiskSubcommand),
    AddFs(AddFsSubcommand),
    AddPmem(AddPmemSubcommand),
    AddNet(AddNetSubcommand),
    AddUserDevice(AddUserDeviceSubcommand),
    AddVdpa(AddVdpaSubcommand),
    AddVsock(AddVsockSubcommand),
    RemoveDevice(RemoveDeviceSubcommand),
    Info(InfoSubcommand),
    Counters(CountersSubcommand),
    Pause(PauseSubcommand),
    Reboot(RebootSubcommand),
    PowerButton(PowerButtonSubcommand),
    Resume(ResumeSubcommand),
    Boot(BootSubcommand),
    Delete(DeleteSubcommand),
    Shutdown(ShutdownSubcommand),
    Ping(PingSubcommand),
    ShutdownVmm(ShutdownVmmSubcommand),
    Resize(ResizeSubcommand),
    ResizeZone(ResizeZoneSubcommand),
    Snapshot(SnapshotSubcommand),
    Restore(RestoreSubcommand),
    Coredump(CoredumpSubcommand),
    SendMigration(SendMigrationSubcommand),
    ReceiveMigration(ReceiveMigrationSubcommand),
    Create(CreateSubcommand),
    Version(VersionSubcommand),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-device")]
/// Add VFIO device
struct AddDeviceSubcommand {
    #[argh(positional)]
    /// device config
    device_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-disk")]
/// Add block device
struct AddDiskSubcommand {
    #[argh(positional)]
    /// disk config
    disk_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-fs")]
/// Add virtio-fs backed fs device
struct AddFsSubcommand {
    #[argh(positional)]
    /// virtio-fs config
    fs_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-pmem")]
/// Add virtio-fs backed fs device
struct AddPmemSubcommand {
    #[argh(positional)]
    /// pmem config
    pmem_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-net")]
/// Add virtio-fs backed fs device
struct AddNetSubcommand {
    #[argh(positional)]
    /// net config
    net_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-user-device")]
/// Add userspace device
struct AddUserDeviceSubcommand {
    #[argh(positional)]
    /// device config
    device_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-vdpa")]
/// Add vdpa device
struct AddVdpaSubcommand {
    #[argh(positional)]
    /// vdpa config
    vdpa_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "add-vsock")]
/// Add vsock device
struct AddVsockSubcommand {
    #[argh(positional)]
    /// vsock config
    vsock_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "remove-device")]
/// Remove VFIO device
struct RemoveDeviceSubcommand {
    #[argh(positional)]
    /// device config
    device_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "info")]
/// Information on the VM
struct InfoSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "counters")]
/// Counters from the VM
struct CountersSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "pause")]
/// Pause the VM
struct PauseSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "reboot")]
/// Reboot the VM
struct RebootSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "power-button")]
/// Trigger a power button in the VM
struct PowerButtonSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "resume")]
/// Resume the VM
struct ResumeSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "boot")]
/// Boot a created VM
struct BootSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "delete")]
/// Delete a VM
struct DeleteSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "shutdown")]
/// Shutdown a VM
struct ShutdownSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "ping")]
/// Ping the VMM to check for API server availability
struct PingSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "shutdown-vmm")]
/// Shutdown the VMM
struct ShutdownVmmSubcommand {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "resize")]
/// Resize the VM
struct ResizeSubcommand {
    #[argh(option, long = "cpus")]
    /// new VCPUs count
    cpus: Option<u8>,

    #[argh(option, long = "memory")]
    /// new memory size in bytes (supports K/M/G suffix)"
    memory: Option<String>,

    #[argh(option, long = "balloon")]
    /// new balloon size in bytes (supports K/M/G suffix)"
    balloon: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "resize-zone")]
/// Resize a memory zone
struct ResizeZoneSubcommand {
    #[argh(option, long = "id")]
    /// memory zone identifier
    id: String,

    #[argh(option, long = "size")]
    /// new memory size in bytes (supports K/M/G suffix)"
    size: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "snapshot")]
/// Create a snapshot from VM
struct SnapshotSubcommand {
    #[argh(positional)]
    /// destination_url
    snapshot_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "restore")]
/// Restore VM from a snapshot
struct RestoreSubcommand {
    #[argh(positional)]
    /// restore config
    restore_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "coredump")]
/// Create a coredump from VM
struct CoredumpSubcommand {
    #[argh(positional)]
    /// coredump config
    coredump_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "send-migration")]
/// Initiate a VM migration
struct SendMigrationSubcommand {
    #[argh(switch, long = "local")]
    /// local migration
    send_migration_local: bool,

    #[argh(positional)]
    /// destination_url
    send_migration_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "receive-migration")]
/// Receive a VM migration
struct ReceiveMigrationSubcommand {
    #[argh(positional)]
    /// receiver url
    receive_migration_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "create")]
/// Create a VM from a JSON configuration
struct CreateSubcommand {
    #[argh(positional, default = "String::from(\"-\")")]
    /// vm config
    vm_config: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "version")]
/// Print version information
struct VersionSubcommand {}

fn main() {
    let toplevel: TopLevel = argh::from_env();

    if matches!(toplevel.command, SubCommandEnum::Version(_)) {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("BUILT_VERSION"));
        return;
    }

    if toplevel.api_socket.is_none() {
        println!("Please specify --api-socket");
        process::exit(1)
    }

    if let Err(e) = do_command(&toplevel) {
        eprintln!("Error running command: {e}");
        process::exit(1)
    };
}
