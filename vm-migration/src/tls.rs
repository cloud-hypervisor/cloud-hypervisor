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

use std::net::TcpStream;
use std::path::Path;
use std::result;
use std::sync::Arc;

use log::warn;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName};
use rustls::server::VerifierBuilderError;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use thiserror::Error;

use crate::MigratableError;

const CA_CERT_FILE: &str = "ca-cert.pem";
const CLIENT_CERT_FILE: &str = "client-cert.pem";
const CLIENT_KEY_FILE: &str = "client-key.pem";

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
}

/// Server/Client-agnostic TLS stream.
pub struct TlsStream {
    stream: TlsStreamParticipant,
}

impl TlsStream {
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
        })
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
