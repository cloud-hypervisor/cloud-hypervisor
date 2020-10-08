// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use(crate_authors)]
extern crate clap;
extern crate serde_json;
extern crate vmm;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use option_parser::{ByteSized, ByteSizedParseError};
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process;

#[derive(Debug)]
enum Error {
    Socket(std::io::Error),
    StatusCodeParsing(std::num::ParseIntError),
    MissingProtocol,
    ContentLengthParsing(std::num::ParseIntError),
    ServerResponse(StatusCode, Option<String>),
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
            Socket(e) => write!(f, "Error writing to HTTP socket: {}", e),
            StatusCodeParsing(e) => write!(f, "Error parsing HTTP status code: {}", e),
            MissingProtocol => write!(f, "HTTP output is missing protocol statement"),
            ContentLengthParsing(e) => write!(f, "Error parsing HTTP Content-Length field: {}", e),
            ServerResponse(s, o) => {
                if let Some(o) = o {
                    write!(f, "Server responded with an error: {:?}: {}", s, o)
                } else {
                    write!(f, "Server responded with an error: {:?}", s)
                }
            }
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

#[derive(Clone, Copy, Debug)]
pub enum StatusCode {
    Continue,
    OK,
    NoContent,
    BadRequest,
    NotFound,
    InternalServerError,
    NotImplemented,
    Unknown,
}

impl StatusCode {
    fn from_raw(code: usize) -> StatusCode {
        match code {
            100 => StatusCode::Continue,
            200 => StatusCode::OK,
            204 => StatusCode::NoContent,
            400 => StatusCode::BadRequest,
            404 => StatusCode::NotFound,
            500 => StatusCode::InternalServerError,
            501 => StatusCode::NotImplemented,
            _ => StatusCode::Unknown,
        }
    }

    fn parse(code: &str) -> Result<StatusCode, Error> {
        Ok(StatusCode::from_raw(
            code.trim().parse().map_err(Error::StatusCodeParsing)?,
        ))
    }

    fn is_server_error(self) -> bool {
        !matches!(
            self,
            StatusCode::OK | StatusCode::Continue | StatusCode::NoContent
        )
    }
}

fn get_header<'a>(res: &'a str, header: &'a str) -> Option<&'a str> {
    let header_str = format!("{}: ", header);
    if let Some(o) = res.find(&header_str) {
        Some(&res[o + header_str.len()..o + res[o..].find('\r').unwrap()])
    } else {
        None
    }
}

fn get_status_code(res: &str) -> Result<StatusCode, Error> {
    if let Some(o) = res.find("HTTP/1.1") {
        Ok(StatusCode::parse(
            &res[o + "HTTP/1.1 ".len()..res[o..].find('\r').unwrap()],
        )?)
    } else {
        Err(Error::MissingProtocol)
    }
}

fn parse_http_response(socket: &mut UnixStream) -> Result<Option<String>, Error> {
    let mut res = String::new();
    let mut body_offset = None;
    let mut content_length: Option<usize> = None;
    loop {
        let mut bytes = vec![0; 256];
        let count = socket.read(&mut bytes).map_err(Error::Socket)?;
        res.push_str(std::str::from_utf8(&bytes[0..count]).unwrap());

        // End of headers
        if let Some(o) = res.find("\r\n\r\n") {
            body_offset = Some(o + "\r\n\r\n".len());

            // With all headers available we can see if there is any body
            content_length = if let Some(length) = get_header(&res, "Content-Length") {
                Some(length.trim().parse().map_err(Error::ContentLengthParsing)?)
            } else {
                None
            };

            if content_length.is_none() {
                break;
            }
        }

        if let Some(body_offset) = body_offset {
            if let Some(content_length) = content_length {
                if res.len() >= content_length + body_offset {
                    break;
                }
            }
        }
    }
    let body_string = content_length.and(Some(String::from(&res[body_offset.unwrap()..])));
    let status_code = get_status_code(&res)?;

    if status_code.is_server_error() {
        Err(Error::ServerResponse(status_code, body_string))
    } else {
        Ok(body_string)
    }
}

fn simple_api_command(
    socket: &mut UnixStream,
    method: &str,
    c: &str,
    request_body: Option<&str>,
) -> Result<(), Error> {
    socket
        .write_all(
            format!(
                "{} /api/v1/vm.{} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n",
                method, c
            )
            .as_bytes(),
        )
        .map_err(Error::Socket)?;

    if let Some(request_body) = request_body {
        socket
            .write_all(format!("Content-Length: {}\r\n", request_body.len()).as_bytes())
            .map_err(Error::Socket)?;
    }

    socket.write_all(b"\r\n").map_err(Error::Socket)?;

    if let Some(request_body) = request_body {
        socket
            .write_all(request_body.as_bytes())
            .map_err(Error::Socket)?;
    }

    socket.flush().map_err(Error::Socket)?;

    if let Some(body) = parse_http_response(socket)? {
        println!("{}", body);
    }
    Ok(())
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

    let desired_ram_w_balloon: Option<u64> = if let Some(balloon) = balloon {
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
        desired_ram_w_balloon,
    };

    simple_api_command(
        socket,
        "PUT",
        "resize",
        Some(&serde_json::to_string(&resize).unwrap()),
    )
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
}

fn add_device_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let device_config = vmm::config::DeviceConfig::parse(config).map_err(Error::AddDeviceConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-device",
        Some(&serde_json::to_string(&device_config).unwrap()),
    )
}

fn remove_device_api_command(socket: &mut UnixStream, id: &str) -> Result<(), Error> {
    let remove_device_data = vmm::api::VmRemoveDeviceData { id: id.to_owned() };

    simple_api_command(
        socket,
        "PUT",
        "remove-device",
        Some(&serde_json::to_string(&remove_device_data).unwrap()),
    )
}

fn add_disk_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let disk_config = vmm::config::DiskConfig::parse(config).map_err(Error::AddDiskConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-disk",
        Some(&serde_json::to_string(&disk_config).unwrap()),
    )
}

fn add_fs_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let fs_config = vmm::config::FsConfig::parse(config).map_err(Error::AddFsConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-fs",
        Some(&serde_json::to_string(&fs_config).unwrap()),
    )
}

fn add_pmem_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let pmem_config = vmm::config::PmemConfig::parse(config).map_err(Error::AddPmemConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-pmem",
        Some(&serde_json::to_string(&pmem_config).unwrap()),
    )
}

fn add_net_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let net_config = vmm::config::NetConfig::parse(config).map_err(Error::AddNetConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-net",
        Some(&serde_json::to_string(&net_config).unwrap()),
    )
}

fn add_vsock_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let vsock_config = vmm::config::VsockConfig::parse(config).map_err(Error::AddVsockConfig)?;

    simple_api_command(
        socket,
        "PUT",
        "add-vsock",
        Some(&serde_json::to_string(&vsock_config).unwrap()),
    )
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
}

fn restore_api_command(socket: &mut UnixStream, config: &str) -> Result<(), Error> {
    let restore_config = vmm::config::RestoreConfig::parse(config).map_err(Error::Restore)?;

    simple_api_command(
        socket,
        "PUT",
        "restore",
        Some(&serde_json::to_string(&restore_config).unwrap()),
    )
}

fn do_command(matches: &ArgMatches) -> Result<(), Error> {
    let mut socket =
        UnixStream::connect(matches.value_of("api-socket").unwrap()).map_err(Error::Socket)?;

    match matches.subcommand_name() {
        Some("info") => simple_api_command(&mut socket, "GET", "info", None),
        Some("counters") => simple_api_command(&mut socket, "GET", "counters", None),
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
        Some(c) => simple_api_command(&mut socket, "PUT", c, None),
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
                        .help("New memory with balloon size in bytes (supports K/M/G suffix)")
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
