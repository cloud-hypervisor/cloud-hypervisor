// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use(crate_authors)]
extern crate clap;
extern crate api_client;
extern crate serde_json;
extern crate vmm;

use api_client::simple_api_command;
use api_client::Error as ApiClientError;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use option_parser::{ByteSized, ByteSizedParseError};
use std::fmt;
use std::os::unix::net::UnixStream;
use std::process;

#[derive(Debug)]
enum Error {
    Connect(std::io::Error),
    ApiClient(ApiClientError),
    InvalidCPUCount(std::num::ParseIntError),
    InvalidMemorySize(ByteSizedParseError),
    InvalidBalloonSize(ByteSizedParseError),
    AddDeviceConfig(vmm::config::Error),
    AddDiskConfig(vmm::config::Error),
    AddFsConfig(vmm::config::Error),
    AddPmemConfig(vmm::config::Error),
    AddNetConfig(vmm::config::Error),
    AddVsockConfig(vmm::config::Error),
    Restore(vmm::config::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            ApiClient(e) => e.fmt(f),
            Connect(e) => write!(f, "Error openning HTTP socket: {}", e),
            InvalidCPUCount(e) => write!(f, "Error parsing CPU count: {}", e),
            InvalidMemorySize(e) => write!(f, "Error parsing memory size: {:?}", e),
            InvalidBalloonSize(e) => write!(f, "Error parsing balloon size: {:?}", e),
            AddDeviceConfig(e) => write!(f, "Error parsing device syntax: {}", e),
            AddDiskConfig(e) => write!(f, "Error parsing disk syntax: {}", e),
            AddFsConfig(e) => write!(f, "Error parsing filesystem syntax: {}", e),
            AddPmemConfig(e) => write!(f, "Error parsing persistent memory syntax: {}", e),
            AddNetConfig(e) => write!(f, "Error parsing network syntax: {}", e),
            AddVsockConfig(e) => write!(f, "Error parsing vsock syntax: {}", e),
            Restore(e) => write!(f, "Error parsing restore syntax: {}", e),
        }
    }
}

fn resize_api_command(
    socket: &mut UnixStream,
    cpus: Option<&str>,
    memory: Option<&str>,
    balloon: Option<&str>,
) -> Result<(), Error> {
    let desired_vcpus: Option<u8> = if let Some(cpus) = cpus {
        Some(cpus.parse().map_err(Error::InvalidCPUCount)?)
    } else {
        None
    };

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
    let net_config = vmm::config::NetConfig::parse(config).map_err(Error::AddNetConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-net",
        Some(&serde_json::to_string(&net_config).unwrap()),
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

fn do_command(matches: &ArgMatches) -> Result<(), Error> {
    let mut socket =
        UnixStream::connect(matches.value_of("api-socket").unwrap()).map_err(Error::Connect)?;

    match matches.subcommand_name() {
        Some("info") => {
            simple_api_command(&mut socket, "GET", "info", None).map_err(Error::ApiClient)
        }
        Some("counters") => {
            simple_api_command(&mut socket, "GET", "counters", None).map_err(Error::ApiClient)
        }
        Some("resize") => resize_api_command(
            &mut socket,
            matches
                .subcommand_matches("resize")
                .unwrap()
                .value_of("cpus"),
            matches
                .subcommand_matches("resize")
                .unwrap()
                .value_of("memory"),
            matches
                .subcommand_matches("resize")
                .unwrap()
                .value_of("balloon"),
        ),
        Some("resize-zone") => resize_zone_api_command(
            &mut socket,
            matches
                .subcommand_matches("resize-zone")
                .unwrap()
                .value_of("id")
                .unwrap(),
            matches
                .subcommand_matches("resize-zone")
                .unwrap()
                .value_of("size")
                .unwrap(),
        ),
        Some("add-device") => add_device_api_command(
            &mut socket,
            matches
                .subcommand_matches("add-device")
                .unwrap()
                .value_of("device_config")
                .unwrap(),
        ),
        Some("remove-device") => remove_device_api_command(
            &mut socket,
            matches
                .subcommand_matches("remove-device")
                .unwrap()
                .value_of("id")
                .unwrap(),
        ),
        Some("add-disk") => add_disk_api_command(
            &mut socket,
            matches
                .subcommand_matches("add-disk")
                .unwrap()
                .value_of("disk_config")
                .unwrap(),
        ),
        Some("add-fs") => add_fs_api_command(
            &mut socket,
            matches
                .subcommand_matches("add-fs")
                .unwrap()
                .value_of("fs_config")
                .unwrap(),
        ),
        Some("add-pmem") => add_pmem_api_command(
            &mut socket,
            matches
                .subcommand_matches("add-pmem")
                .unwrap()
                .value_of("pmem_config")
                .unwrap(),
        ),
        Some("add-net") => add_net_api_command(
            &mut socket,
            matches
                .subcommand_matches("add-net")
                .unwrap()
                .value_of("net_config")
                .unwrap(),
        ),
        Some("add-vsock") => add_vsock_api_command(
            &mut socket,
            matches
                .subcommand_matches("add-vsock")
                .unwrap()
                .value_of("vsock_config")
                .unwrap(),
        ),
        Some("snapshot") => snapshot_api_command(
            &mut socket,
            matches
                .subcommand_matches("snapshot")
                .unwrap()
                .value_of("snapshot_config")
                .unwrap(),
        ),
        Some("restore") => restore_api_command(
            &mut socket,
            matches
                .subcommand_matches("restore")
                .unwrap()
                .value_of("restore_config")
                .unwrap(),
        ),
        Some(c) => simple_api_command(&mut socket, "PUT", c, None).map_err(Error::ApiClient),
        None => unreachable!(),
    }
}

fn main() {
    let app = App::new("ch-remote")
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequired)
        .about("Remotely control a cloud-hypervisor VMM.")
        .arg(
            Arg::with_name("api-socket")
                .long("api-socket")
                .help("HTTP API socket path (UNIX domain socket).")
                .takes_value(true)
                .number_of_values(1)
                .required(true),
        )
        .subcommand(
            SubCommand::with_name("add-device")
                .about("Add VFIO device")
                .arg(
                    Arg::with_name("device_config")
                        .index(1)
                        .help(vmm::config::DeviceConfig::SYNTAX),
                ),
        )
        .subcommand(
            SubCommand::with_name("add-disk")
                .about("Add block device")
                .arg(
                    Arg::with_name("disk_config")
                        .index(1)
                        .help(vmm::config::DiskConfig::SYNTAX),
                ),
        )
        .subcommand(
            SubCommand::with_name("add-fs")
                .about("Add virtio-fs backed fs device")
                .arg(
                    Arg::with_name("fs_config")
                        .index(1)
                        .help(vmm::config::FsConfig::SYNTAX),
                ),
        )
        .subcommand(
            SubCommand::with_name("add-pmem")
                .about("Add persistent memory device")
                .arg(
                    Arg::with_name("pmem_config")
                        .index(1)
                        .help(vmm::config::PmemConfig::SYNTAX),
                ),
        )
        .subcommand(
            SubCommand::with_name("add-net")
                .about("Add network device")
                .arg(
                    Arg::with_name("net_config")
                        .index(1)
                        .help(vmm::config::NetConfig::SYNTAX),
                ),
        )
        .subcommand(
            SubCommand::with_name("add-vsock")
                .about("Add vsock device")
                .arg(
                    Arg::with_name("vsock_config")
                        .index(1)
                        .help(vmm::config::VsockConfig::SYNTAX),
                ),
        )
        .subcommand(
            SubCommand::with_name("remove-device")
                .about("Remove VFIO device")
                .arg(Arg::with_name("id").index(1).help("<device_id>")),
        )
        .subcommand(SubCommand::with_name("info").about("Info on the VM"))
        .subcommand(SubCommand::with_name("counters").about("Counters from the VM"))
        .subcommand(SubCommand::with_name("pause").about("Pause the VM"))
        .subcommand(SubCommand::with_name("reboot").about("Reboot the VM"))
        .subcommand(
            SubCommand::with_name("resize")
                .about("Resize the VM")
                .arg(
                    Arg::with_name("cpus")
                        .long("cpus")
                        .help("New vCPUs count")
                        .takes_value(true)
                        .number_of_values(1),
                )
                .arg(
                    Arg::with_name("memory")
                        .long("memory")
                        .help("New memory size in bytes (supports K/M/G suffix)")
                        .takes_value(true)
                        .number_of_values(1),
                )
                .arg(
                    Arg::with_name("balloon")
                        .long("balloon")
                        .help("New balloon size in bytes (supports K/M/G suffix)")
                        .takes_value(true)
                        .number_of_values(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("resize-zone")
                .about("Resize a memory zone")
                .arg(
                    Arg::with_name("id")
                        .long("id")
                        .help("Memory zone identifier")
                        .takes_value(true)
                        .number_of_values(1),
                )
                .arg(
                    Arg::with_name("size")
                        .long("size")
                        .help("New memory zone size in bytes (supports K/M/G suffix)")
                        .takes_value(true)
                        .number_of_values(1),
                ),
        )
        .subcommand(SubCommand::with_name("resume").about("Resume the VM"))
        .subcommand(SubCommand::with_name("shutdown").about("Shutdown the VM"))
        .subcommand(
            SubCommand::with_name("snapshot")
                .about("Create a snapshot from VM")
                .arg(
                    Arg::with_name("snapshot_config")
                        .index(1)
                        .help("<destination_url>"),
                ),
        )
        .subcommand(
            SubCommand::with_name("restore")
                .about("Restore VM from a snapshot")
                .arg(
                    Arg::with_name("restore_config")
                        .index(1)
                        .help(vmm::config::RestoreConfig::SYNTAX),
                ),
        );

    let matches = app.get_matches();

    if let Err(e) = do_command(&matches) {
        eprintln!("Error running command: {}", e);
        process::exit(1)
    };
}
