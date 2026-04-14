// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::TcpStream;
use std::path::Path;
use std::result;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use thiserror::Error;

use crate::MigratableError;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("The provided hostname could not be parsed")]
    InvalidDnsName(#[source] InvalidDnsNameError),

    #[error("Rustls protocol error")]
    RustlsError(#[from] rustls::Error),

    #[error("Rustls protocol IO error")]
    RustlsIoError(#[from] std::io::Error),

    #[error("Error during TLS handshake: {0}")]
    HandshakeError(String),

    #[error("Error handling PEM file")]
    RustlsPemError(#[from] rustls::pki_types::pem::Error),
}

// TLS connections have a server (listens for a connection) and a client (
// initiates a connection).
#[derive(Debug)]
enum TlsStreamParticipant {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

/// Server/Client-agnostic TLS stream.
pub struct TlsStream {
    stream: TlsStreamParticipant,
}

impl TlsStream {
    /// Creates a client [`TlsStream`]. Encrypts and decrypts data sent through
    /// this stream using the CA certificate from `ca-cert.pem` in the given
    /// directory. The given hostname must match a subject name in the server
    /// certificate presented during the TLS handshake.
    pub fn new_client(
        socket: TcpStream,
        cert_dir: &Path,
        hostname: &str,
    ) -> result::Result<Self, MigratableError> {
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(
            CertificateDer::pem_file_iter(cert_dir.join("ca-cert.pem"))
                .map_err(TlsError::RustlsPemError)?
                .map(|cert| cert.map_err(TlsError::RustlsPemError))
                .collect::<Result<Vec<CertificateDer<'_>>, TlsError>>()?,
        );
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let config = Arc::new(config);
        let server_name =
            ServerName::try_from(hostname.to_string()).map_err(TlsError::InvalidDnsName)?;
        let conn = ClientConnection::new(config.clone(), server_name.clone())
            .map_err(TlsError::RustlsError)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)?;
            if rd == 0 && wr == 0 {
                Err(TlsError::HandshakeError(
                    "EOF during TLS handshake".to_string(),
                ))?;
            }
        }

        Ok(Self {
            stream: TlsStreamParticipant::Client(tls),
        })
    }

    /// Creates a server [`TlsStream`]. Encrypts and decrypts data sent through
    /// this stream using the certificates and key from the provided
    /// [`TlsServerConfig`].
    pub fn new_server(
        socket: TcpStream,
        config: &TlsServerConfig,
    ) -> result::Result<Self, MigratableError> {
        let conn = ServerConnection::new(config.config.clone()).map_err(TlsError::RustlsError)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)?;
            if rd == 0 && wr == 0 {
                Err(TlsError::HandshakeError(
                    "EOF during TLS handshake".to_string(),
                ))?;
            }
        }

        Ok(Self {
            stream: TlsStreamParticipant::Server(tls),
        })
    }
}

/// Carries a server-TLS-config. Intended to be turned into a [`TlsStream`]
/// when paired with a [`TcpStream`].
#[derive(Debug)]
pub struct TlsServerConfig {
    config: Arc<ServerConfig>,
}

impl TlsServerConfig {
    /// Creates a [`TlsServerConfig`] from the certificate chain in
    /// `server-cert.pem` and the private key in `server-key.pem`.
    pub fn new(cert_dir: &Path) -> result::Result<Self, MigratableError> {
        let certs = CertificateDer::pem_file_iter(cert_dir.join("server-cert.pem"))
            .map_err(TlsError::RustlsPemError)?
            .map(|cert| cert.map_err(TlsError::RustlsPemError))
            .collect::<Result<Vec<CertificateDer<'_>>, TlsError>>()?;
        let key = PrivateKeyDer::from_pem_file(cert_dir.join("server-key.pem"))
            .map_err(TlsError::RustlsPemError)?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(TlsError::RustlsError)?;
        let config = Arc::new(config);
        Ok(Self { config })
    }
}
