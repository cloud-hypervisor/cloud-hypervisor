// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! NBD URI parsing.
//!
//! Supports the subset of the NBD URI specification
//! (<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/uri.md>)
//! that does not require TLS:
//!
//! - `nbd://[host][:port][/export]`
//! - `nbd+unix:///[export]?socket=<path>`

use std::fmt;
use std::path::PathBuf;
use std::str::{self, FromStr};

use thiserror::Error;

use super::proto::NBD_DEFAULT_PORT;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NbdUriError {
    #[error("Unsupported NBD URI scheme \"{0}\"")]
    UnsupportedScheme(String),
    #[error("NBD over TLS (\"{0}\") is not supported")]
    TlsNotSupported(String),
    #[error("Invalid NBD URI: {0}")]
    Invalid(&'static str),
    #[error("Invalid port \"{0}\" in NBD URI")]
    InvalidPort(String),
    #[error("Unsupported query parameter \"{0}\" in NBD URI")]
    UnsupportedQuery(String),
}

/// Where an NBD server is reachable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NbdAddress {
    Tcp { host: String, port: u16 },
    Unix { path: PathBuf },
}

/// Parsed NBD URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbdUri {
    pub(crate) address: NbdAddress,
    pub(crate) export: String,
}

impl NbdUri {
    /// Returns the Unix socket path if the URI uses the Unix transport.
    pub fn socket_path(&self) -> Option<&PathBuf> {
        match &self.address {
            NbdAddress::Unix { path } => Some(path),
            NbdAddress::Tcp { .. } => None,
        }
    }
}

impl fmt::Display for NbdUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            NbdAddress::Tcp { host, port } if host.contains(':') => {
                write!(f, "nbd://[{host}]:{port}/{}", self.export)
            }
            NbdAddress::Tcp { host, port } => write!(f, "nbd://{host}:{port}/{}", self.export),
            NbdAddress::Unix { path } => {
                write!(f, "nbd+unix:///{}?socket={}", self.export, path.display())
            }
        }
    }
}

fn percent_decode(s: &str) -> Result<String, NbdUriError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or(NbdUriError::Invalid("bad percent encoding"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| NbdUriError::Invalid("export name is not UTF-8"))
}

fn parse_authority(authority: &str) -> Result<(String, u16), NbdUriError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or(NbdUriError::Invalid("unterminated IPv6 address"))?;
        let port = match rest {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or(NbdUriError::Invalid("garbage after IPv6 address"))?,
            ),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };

    let host = if host.is_empty() { "localhost" } else { host };
    let port = match port {
        None | Some("") => NBD_DEFAULT_PORT,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| NbdUriError::InvalidPort(p.to_string()))?,
    };
    Ok((host.to_string(), port))
}

impl FromStr for NbdUri {
    type Err = NbdUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or(NbdUriError::Invalid("missing scheme"))?;
        let scheme = scheme.to_ascii_lowercase();
        let unix = match scheme.as_str() {
            "nbd" => false,
            "nbd+unix" => true,
            "nbds" | "nbds+unix" => return Err(NbdUriError::TlsNotSupported(scheme)),
            _ => return Err(NbdUriError::UnsupportedScheme(scheme)),
        };

        if rest.contains('#') {
            return Err(NbdUriError::Invalid("fragments are not supported"));
        }
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, Some(q)),
            None => (rest, None),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let export = percent_decode(path)?;

        let mut socket = None;
        for param in query.into_iter().flat_map(|q| q.split('&')) {
            if param.is_empty() {
                continue;
            }
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            match key {
                "socket" if unix => socket = Some(PathBuf::from(percent_decode(value)?)),
                _ => return Err(NbdUriError::UnsupportedQuery(key.to_string())),
            }
        }

        let address = if unix {
            if !authority.is_empty() {
                return Err(NbdUriError::Invalid(
                    "nbd+unix URIs must not contain a host",
                ));
            }
            let path = socket
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(NbdUriError::Invalid("nbd+unix URIs require ?socket=<path>"))?;
            NbdAddress::Unix { path }
        } else {
            let (host, port) = parse_authority(authority)?;
            NbdAddress::Tcp { host, port }
        };

        if export.len() > super::proto::NBD_MAX_STRING_SIZE {
            return Err(NbdUriError::Invalid("export name too long"));
        }

        Ok(NbdUri { address, export })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: &str, port: u16, export: &str) -> NbdUri {
        NbdUri {
            address: NbdAddress::Tcp {
                host: host.to_string(),
                port,
            },
            export: export.to_string(),
        }
    }

    #[test]
    fn parse_tcp() {
        assert_eq!(
            "nbd://10.0.0.1:1234/vol0".parse(),
            Ok(tcp("10.0.0.1", 1234, "vol0"))
        );
        assert_eq!(
            "nbd://example.com".parse(),
            Ok(tcp("example.com", NBD_DEFAULT_PORT, ""))
        );
        assert_eq!(
            "nbd:///".parse(),
            Ok(tcp("localhost", NBD_DEFAULT_PORT, ""))
        );
        assert_eq!("nbd://[::1]:99/a%20b".parse(), Ok(tcp("::1", 99, "a b")));
        assert_eq!(
            "nbd://host//abs".parse(),
            Ok(tcp("host", NBD_DEFAULT_PORT, "/abs"))
        );
    }

    #[test]
    fn parse_unix() {
        assert_eq!(
            "nbd+unix:///exp?socket=/run/nbd.sock".parse(),
            Ok(NbdUri {
                address: NbdAddress::Unix {
                    path: PathBuf::from("/run/nbd.sock")
                },
                export: "exp".to_string(),
            })
        );
    }

    #[test]
    fn display_round_trip() {
        for s in [
            "nbd://host:10809/x",
            "nbd://[::1]:10809/x",
            "nbd+unix:///x?socket=/tmp/s",
        ] {
            let uri: NbdUri = s.parse().unwrap();
            assert_eq!(uri.to_string(), s);
        }
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(
            "nbds://host/x".parse::<NbdUri>(),
            Err(NbdUriError::TlsNotSupported(_))
        ));
        assert!(matches!(
            "nbds+unix:///x?socket=/s".parse::<NbdUri>(),
            Err(NbdUriError::TlsNotSupported(_))
        ));
        assert!(matches!(
            "http://host/x".parse::<NbdUri>(),
            Err(NbdUriError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            "nbd://host:0/x".parse::<NbdUri>(),
            Err(NbdUriError::InvalidPort(_))
        ));
        assert!(matches!(
            "nbd://host:abc/x".parse::<NbdUri>(),
            Err(NbdUriError::InvalidPort(_))
        ));
        "nbd+unix:///x".parse::<NbdUri>().unwrap_err();
        "nbd+unix://host/x?socket=/s".parse::<NbdUri>().unwrap_err();
        assert!(matches!(
            "nbd://host/x?socket=/s".parse::<NbdUri>(),
            Err(NbdUriError::UnsupportedQuery(_))
        ));
        "nbd://host/%zz".parse::<NbdUri>().unwrap_err();
        "/path/to/file".parse::<NbdUri>().unwrap_err();
    }
}
