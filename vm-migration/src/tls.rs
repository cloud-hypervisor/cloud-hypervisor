// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::TcpStream;
use std::path::Path;
use std::result;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
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
}
