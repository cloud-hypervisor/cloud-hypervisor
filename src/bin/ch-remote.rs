// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use(crate_authors)]
extern crate clap;
extern crate serde_json;
extern crate vmm;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process;

#[derive(Debug)]
enum Error {
    Socket(std::io::Error),
    StatusCodeParsing(std::num::ParseIntError),
    MissingProtocol,
    ContentLengthParsing(std::num::ParseIntError),
    ServerResponse(StatusCode),
    InvalidCPUCount(std::num::ParseIntError),
    InvalidMemorySize(std::num::ParseIntError),
    AddDeviceConfig(vmm::config::Error),
    AddDiskConfig(vmm::config::Error),
    AddPmemConfig(vmm::config::Error),
    AddNetConfig(vmm::config::Error),
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

    fn check(self) -> Result<(), Error> {
        match self {
            StatusCode::OK | StatusCode::Continue | StatusCode::NoContent => Ok(()),
            _ => Err(Error::ServerResponse(self)),
        }
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

    get_status_code(&res)?.check()?;

    Ok(content_length.and(Some(String::from(&res[body_offset.unwrap()..]))))
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
) -> Result<(), Error> {
    let desired_vcpus: Option<u8> = if let Some(cpus) = cpus {
        Some(cpus.parse().map_err(Error::InvalidCPUCount)?)
    } else {
        None
    };

    let desired_ram: Option<u64> = if let Some(memory) = memory {
        Some(memory.parse().map_err(Error::InvalidMemorySize)?)
    } else {
        None
    };

    let resize = vmm::api::VmResizeData {
        desired_vcpus,
        desired_ram,
    };

    simple_api_command(
        socket,
        "PUT",
        "resize",
        Some(&serde_json::to_string(&resize).unwrap()),
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

fn do_command(matches: &ArgMatches) -> Result<(), Error> {
    let mut socket =
        UnixStream::connect(matches.value_of("api-socket").unwrap()).map_err(Error::Socket)?;

    match matches.subcommand_name() {
        Some("info") => simple_api_command(&mut socket, "GET", "info", None),
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
                .min_values(1)
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
            SubCommand::with_name("remove-device")
                .about("Remove VFIO device")
                .arg(Arg::with_name("id").index(1).help("<device_id>")),
        )
        .subcommand(SubCommand::with_name("info").about("Info on the VM"))
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
                        .help("New memory size (in MiB)")
                        .takes_value(true)
                        .number_of_values(1),
                ),
        )
        .subcommand(SubCommand::with_name("resume").about("Resume the VM"))
        .subcommand(SubCommand::with_name("shutdown").about("Shutdown the VM"));

    let matches = app.get_matches();

    if let Err(e) = do_command(&matches) {
        eprintln!("Error running command: {:?}", e);
        process::exit(1)
    };
}
