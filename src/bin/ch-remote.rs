// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use(crate_authors)]
extern crate clap;

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

fn simple_api_command(socket: &mut UnixStream, method: &str, c: &str) -> Result<(), Error> {
    socket
        .write_all(
            format!(
                "{} /api/v1/vm.{} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n",
                method, c
            )
            .as_bytes(),
        )
        .map_err(Error::Socket)?;
    socket.flush().map_err(Error::Socket)?;

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
                    println!("{}", &res[body_offset..]);
                    break;
                }
            }
        }
    }

    get_status_code(&res)?.check()
}

fn do_command(matches: &ArgMatches) -> Result<(), Error> {
    let mut socket =
        UnixStream::connect(matches.value_of("api-socket").unwrap()).map_err(Error::Socket)?;

    match matches.subcommand_name() {
        Some("info") => simple_api_command(&mut socket, "GET", "info"),
        Some(c) => simple_api_command(&mut socket, "PUT", c),
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
        .subcommand(SubCommand::with_name("info").about("Info on the VM"))
        .subcommand(SubCommand::with_name("pause").about("Pause the VM"))
        .subcommand(SubCommand::with_name("reboot").about("Reboot the VM"))
        .subcommand(SubCommand::with_name("resume").about("Resume the VM"))
        .subcommand(SubCommand::with_name("shutdown").about("Shutdown the VM"));

    let matches = app.get_matches();

    if let Err(e) = do_command(&matches) {
        eprintln!("Error running command: {:?}", e);
        process::exit(1)
    };
}
