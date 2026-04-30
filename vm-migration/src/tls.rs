// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! TLS support for migration streams over TCP.
//!
//! This module wraps `rustls` to provide a blocking [`TlsStream`] for migration
//! traffic. [`TlsStream::new_client`] authenticates the server against
//! `ca-cert.pem` and the expected hostname, and presents `client-cert.pem` and
//! `client-key.pem` for mutual TLS (mTLS) authentication. [`TlsServerConfig`] loads
//! `server-cert.pem` and `server-key.pem`, trusts client certificates issued by
//! the CA in `ca-cert.pem`, and [`TlsStream::new_server`] uses that
//! configuration to establish the server side of the connection.
//!
//! [`TlsStream`] implements [`Read`], [`Write`], [`ReadVolatile`],
//! [`WriteVolatile`], and [`AsFd`] so it can be used by the transport layer like
//! other migration streams. All data must pass through rustls; direct I/O on the
//! underlying socket would bypass TLS processing and break the connection.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::result;
use std::sync::Arc;

use log::warn;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName};
use rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use thiserror::Error;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::MigratableError;

const CA_CERT_FILE: &str = "ca-cert.pem";
const CLIENT_CERT_FILE: &str = "client-cert.pem";
const CLIENT_KEY_FILE: &str = "client-key.pem";
const SERVER_CERT_FILE: &str = "server-cert.pem";
const SERVER_KEY_FILE: &str = "server-key.pem";

/// Identifies which side of live migration uses a TLS certificate directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsEndpoint {
    Client,
    Server,
}

impl TlsEndpoint {
    fn required_files(self) -> [&'static str; 3] {
        match self {
            Self::Client => [CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE],
            Self::Server => [CA_CERT_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE],
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "migration client",
            Self::Server => "migration server",
        }
    }
}

/// Validation errors for a migration TLS certificate directory.
#[derive(Error, Debug)]
pub enum TlsConfigError {
    #[error("TLS directory does not exist or is inaccessible: {path}: {source}")]
    DirectoryMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("TLS directory must point to a directory: {path}")]
    NotADirectory { path: PathBuf },

    #[error("Missing required TLS file for {endpoint}: {path}")]
    MissingFile {
        endpoint: &'static str,
        path: PathBuf,
    },

    #[error("Required TLS path for {endpoint} must be a regular file: {path}")]
    NotAFile {
        endpoint: &'static str,
        path: PathBuf,
    },

    #[error("Required TLS file for {endpoint} is not readable: {path}: {source}")]
    FileRead {
        endpoint: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("Failed to inspect required TLS file for {endpoint}: {path}: {source}")]
    FileMetadata {
        endpoint: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Validates that a TLS directory contains all files required by the endpoint.
///
/// Each required file must exist, be a regular file, and be readable by the
/// current Cloud Hypervisor process.
pub fn validate_tls_dir(
    cert_dir: &Path,
    endpoint: TlsEndpoint,
) -> result::Result<(), TlsConfigError> {
    let metadata = fs::metadata(cert_dir).map_err(|source| TlsConfigError::DirectoryMetadata {
        path: cert_dir.to_path_buf(),
        source,
    })?;

    if !metadata.is_dir() {
        return Err(TlsConfigError::NotADirectory {
            path: cert_dir.to_path_buf(),
        });
    }

    for file_name in endpoint.required_files() {
        let path = cert_dir.join(file_name);
        let endpoint_name = endpoint.as_str();

        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(TlsConfigError::MissingFile {
                    endpoint: endpoint_name,
                    path,
                });
            }
            Err(source) => {
                return Err(TlsConfigError::FileMetadata {
                    endpoint: endpoint_name,
                    path,
                    source,
                });
            }
        };

        if !metadata.is_file() {
            return Err(TlsConfigError::NotAFile {
                endpoint: endpoint_name,
                path,
            });
        }

        if let Err(source) = File::open(&path) {
            return Err(TlsConfigError::FileRead {
                endpoint: endpoint_name,
                path,
                source,
            });
        }
    }

    Ok(())
}

/// Errors that can occur when establishing a TLS-encrypted migration channel.
#[derive(Error, Debug)]
pub enum TlsError {
    #[error("The provided hostname could not be parsed")]
    InvalidDnsName(#[source] InvalidDnsNameError),

    #[error("Rustls protocol error")]
    RustlsError(#[from] rustls::Error),

    #[error("Rustls verifier configuration error")]
    RustlsVerifierBuilderError(#[source] VerifierBuilderError),

    #[error("Rustls protocol IO error")]
    RustlsIoError(#[from] std::io::Error),

    #[error("TLS handshake stalled: no read/write progress while handshake is still in progress")]
    HandshakeError,

    #[error("Error handling PEM file")]
    RustlsPemError(#[from] rustls::pki_types::pem::Error),
}

/// Wraps the concrete rustls stream for either side (server or client) of the
/// TLS connection.
///
/// [`TlsStream`] uses this enum to store a [`StreamOwned`] with either a
/// [`ClientConnection`] or [`ServerConnection`] while exposing a single
/// transport-agnostic API.
#[derive(Debug)]
enum TlsStreamParticipant {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

/// Server/Client-agnostic TLS stream.
pub struct TlsStream {
    stream: TlsStreamParticipant,
    // We have to implement [`ReadVolatile`] and [`WriteVolatile`] for
    // [`TlsStream`]. We use this buffer to avoid allocating a new buffer for
    // every volatile read or write.
    buf: Vec<u8>,
}

impl TlsStream {
    /// The maximum size of [`TlsStream::buf`]. This keeps the reusable buffer
    /// from growing without bound.
    const BUF_SIZE: usize = 64 /* KiB */ << 10;

    /// Creates a client [`TlsStream`].
    ///
    /// The client verifies the server certificate against `ca-cert.pem` and the
    /// provided `hostname`, and presents the certificate chain in
    /// `client-cert.pem` together with the private key in `client-key.pem` for
    /// mutual TLS authentication.
    pub fn new_client(
        socket: TcpStream,
        cert_dir: &Path,
        hostname: &str,
    ) -> result::Result<Self, MigratableError> {
        let root_store = load_root_store(&cert_dir.join(CA_CERT_FILE))?;
        let client_certs = load_cert_chain(&cert_dir.join(CLIENT_CERT_FILE))?;
        let client_key = load_private_key(&cert_dir.join(CLIENT_KEY_FILE))?;

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;
        let config = Arc::new(config);

        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(TlsError::InvalidDnsName)
            .map_err(MigratableError::Tls)?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)
                .map_err(MigratableError::Tls)?;
            // No handshake progress on a connection that should be handshaking, we treat
            // that as a failure.
            if rd == 0 && wr == 0 {
                Err(MigratableError::Tls(TlsError::HandshakeError))?;
            }
        }

        Ok(Self {
            stream: TlsStreamParticipant::Client(tls),
            buf: Vec::new(),
        })
    }

    /// Creates a server [`TlsStream`]. Encrypts and decrypts data sent through
    /// this stream using the certificates and key from the provided
    /// [`TlsServerConfig`].
    pub fn new_server(
        socket: TcpStream,
        config: &TlsServerConfig,
    ) -> result::Result<Self, MigratableError> {
        let conn = ServerConnection::new(config.config.clone())
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)
                .map_err(MigratableError::Tls)?;
            // No handshake progress on a connection that should be handshaking, we treat
            // that as a failure.
            if rd == 0 && wr == 0 {
                Err(MigratableError::Tls(TlsError::HandshakeError))?;
            }
        }

        Ok(Self {
            stream: TlsStreamParticipant::Server(tls),
            buf: Vec::new(),
        })
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.stream {
            TlsStreamParticipant::Client(s) => Read::read(s, buf),
            TlsStreamParticipant::Server(s) => Read::read(s, buf),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            TlsStreamParticipant::Client(s) => Write::write(s, buf),
            TlsStreamParticipant::Server(s) => Write::write(s, buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            TlsStreamParticipant::Client(s) => Write::flush(s),
            TlsStreamParticipant::Server(s) => Write::flush(s),
        }
    }
}

// Reading from or writing to these FDs would break the connection, because
// those reads or writes wouldn't go through rustls. But the FD is necessary to
// listen for incoming connections.
impl AsFd for TlsStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.stream {
            TlsStreamParticipant::Client(s) => s.get_ref().as_fd(),
            TlsStreamParticipant::Server(s) => s.get_ref().as_fd(),
        }
    }
}

impl ReadVolatile for TlsStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        vs: &mut VolatileSlice<B>,
    ) -> result::Result<usize, VolatileMemoryError> {
        let len = vs.len().min(Self::BUF_SIZE);

        if len == 0 {
            return Ok(0);
        }

        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }

        let n = {
            let (stream, buf) = (&mut self.stream, &mut self.buf[..len]);

            match stream {
                TlsStreamParticipant::Client(s) => Read::read(s, buf),
                TlsStreamParticipant::Server(s) => Read::read(s, buf),
            }
            .map_err(VolatileMemoryError::IOError)?
        };

        if n == 0 {
            return Ok(0);
        }

        vs.copy_from(&self.buf[..n]);
        Ok(n)
    }
}

impl WriteVolatile for TlsStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        vs: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        let len = vs.len().min(Self::BUF_SIZE);

        if len == 0 {
            return Ok(0);
        }

        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }

        let buf = &mut self.buf[..len];
        let n = vs.copy_to(&mut buf[..len]);

        if n == 0 {
            return Ok(0);
        }

        let n = match &mut self.stream {
            TlsStreamParticipant::Client(s) => Write::write(s, &buf[..n]),
            TlsStreamParticipant::Server(s) => Write::write(s, &buf[..n]),
        }
        .map_err(VolatileMemoryError::IOError)?;

        Ok(n)
    }
}

/// Carries a TLS server configuration. Intended to be turned into a [`TlsStream`]
/// when paired with a [`TcpStream`].
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    /// This config is shared between all server connections.
    config: Arc<ServerConfig>,
}

impl TlsServerConfig {
    /// Creates a [`TlsServerConfig`] from the certificate chain in
    /// `server-cert.pem`, the private key in `server-key.pem`, and the client
    /// trust anchors in `ca-cert.pem`.
    ///
    /// Client certificates presented during the TLS handshake must chain to a CA in
    /// `ca-cert.pem`.
    pub fn new(cert_dir: &Path) -> result::Result<Self, MigratableError> {
        let server_certs = load_cert_chain(&cert_dir.join(SERVER_CERT_FILE))?;
        let server_key = load_private_key(&cert_dir.join(SERVER_KEY_FILE))?;
        // Trust anchors used to verify client certificates for mTLS.
        let client_roots = Arc::new(load_root_store(&cert_dir.join(CA_CERT_FILE))?);

        let client_verifier = WebPkiClientVerifier::builder(client_roots)
            .build()
            .map_err(TlsError::RustlsVerifierBuilderError)
            .map_err(MigratableError::Tls)?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;
        let config = Arc::new(config);
        Ok(Self { config })
    }
}

/// Loads trusted CA certificates into a root store, i.e. the set of trust anchors
/// used to verify the peer's certificate chain.
fn load_root_store(cert_path: &Path) -> result::Result<RootCertStore, MigratableError> {
    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(cert_path)
            .map_err(TlsError::RustlsPemError)
            .map_err(MigratableError::Tls)?
            .map(|cert| cert.map_err(TlsError::RustlsPemError))
            .collect::<Result<Vec<CertificateDer<'static>>, TlsError>>()
            .map_err(MigratableError::Tls)?,
    );

    if ignored > 0 {
        warn!(
            "Ignored {ignored} certificate(s) while loading TLS CA file {}",
            cert_path.display()
        );
    }

    Ok(root_store)
}

/// Loads a certificate chain to present during the TLS handshake.
fn load_cert_chain(
    cert_path: &Path,
) -> result::Result<Vec<CertificateDer<'static>>, MigratableError> {
    CertificateDer::pem_file_iter(cert_path)
        .map_err(TlsError::RustlsPemError)
        .map_err(MigratableError::Tls)?
        .map(|cert| cert.map_err(TlsError::RustlsPemError))
        .collect::<Result<Vec<CertificateDer<'static>>, TlsError>>()
        .map_err(MigratableError::Tls)
}

/// Loads the private key that proves ownership of the presented certificate chain.
fn load_private_key(key_path: &Path) -> result::Result<PrivateKeyDer<'static>, MigratableError> {
    PrivateKeyDer::from_pem_file(key_path)
        .map_err(TlsError::RustlsPemError)
        .map_err(MigratableError::Tls)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{fs, process};

    use super::*;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "cloud-hypervisor-{name}-{}-{unique}",
                process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn add_file(&self, file_name: &str) {
            fs::write(self.path.join(file_name), b"test").unwrap();
        }

        fn add_client_files(&self) {
            self.add_file(CA_CERT_FILE);
            self.add_file(CLIENT_CERT_FILE);
            self.add_file(CLIENT_KEY_FILE);
        }

        fn add_server_files(&self) {
            self.add_file(CA_CERT_FILE);
            self.add_file(SERVER_CERT_FILE);
            self.add_file(SERVER_KEY_FILE);
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn validate_tls_dir_accepts_complete_client_directory() {
        let dir = TestDir::new("tls-client");
        dir.add_client_files();

        validate_tls_dir(&dir.path, TlsEndpoint::Client).unwrap();
    }

    #[test]
    fn validate_tls_dir_accepts_complete_server_directory() {
        let dir = TestDir::new("tls-server");
        dir.add_server_files();

        validate_tls_dir(&dir.path, TlsEndpoint::Server).unwrap();
    }

    #[test]
    fn validate_tls_dir_rejects_missing_role_specific_file() {
        let dir = TestDir::new("tls-missing-client-key");
        dir.add_file(CA_CERT_FILE);
        dir.add_file(CLIENT_CERT_FILE);

        let err = validate_tls_dir(&dir.path, TlsEndpoint::Client).unwrap_err();
        let err = err.to_string();
        assert!(err.contains(CLIENT_KEY_FILE), "unexpected error: {err}");
    }

    #[test]
    fn validate_tls_dir_rejects_non_file_entry() {
        let dir = TestDir::new("tls-non-file");
        dir.add_file(CA_CERT_FILE);
        dir.add_file(CLIENT_KEY_FILE);
        fs::create_dir(dir.path.join(CLIENT_CERT_FILE)).unwrap();

        let err = validate_tls_dir(&dir.path, TlsEndpoint::Client).unwrap_err();
        let err = err.to_string();
        assert!(err.contains(CLIENT_CERT_FILE), "unexpected error: {err}");
    }
}
