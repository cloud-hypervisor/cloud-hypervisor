use std::net::IpAddr; 
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::net::TcpListener;
use httparse::{Request, EMPTY_HEADER, Error as HttpError};
use bytes::BytesMut;
use serde::{Serialize, Deserialize};

use crate::CreateMappingRequest;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("HTTP parse error: {0}")]
    HttpParse(#[from] HttpError),
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMapping {
    pub domain: String,
    pub private_ip: IpAddr,
}

// Simple API client
#[derive(Clone)]
pub struct ApiClient {
    endpoint: String,
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(endpoint: String) -> Self {
        log::info!("Creating API Client with endpoint {endpoint}");
        Self {
            endpoint,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_instance(&self, domain: &str) -> Result<InstanceMapping, ProxyError> {
        log::info!("Attempting to get instance {domain} ip");
        self.client
            .get(&format!("{}/instances/mapping/{}", self.endpoint, domain))
            .send()
            .await?
            .json()
            .await
            .map_err(ProxyError::Request)
    }

    pub async fn create_mapping(&self, domain: &str, private_ip: IpAddr) -> Result<InstanceMapping, ProxyError> {
        log::info!("Attempting to post instance mapping domain: {domain} ip: {private_ip}");
        let mapping_request = CreateMappingRequest {
            domain: domain.to_string(),
            private_ip
        };

        log::info!("Posting request to {}", self.endpoint);
        self.client
            .post(&format!("{}/instances/mapping", self.endpoint))
            .json(&mapping_request)
            .send()
            .await?
            .json()
            .await
            .map_err(ProxyError::Request)
    }
}

// Basic proxy service
pub struct Proxy {
    api_client: ApiClient,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Proxy {
    pub fn new(api_endpoint: String, cert_path: Option<&str>, key_path: Option<&str>) -> Result<Self, ProxyError> {
        log::info!("Attempting to create Proxy Server");
        // Load and configure TLS
        if let (Some(cp), Some(kp)) = (cert_path, key_path) {
            let cert_file = std::fs::File::open(cp)
                .map_err(|e| ProxyError::Tls(format!("Failed to open cert: {}", e)))?;
            let key_file = std::fs::File::open(kp)
                .map_err(|e| ProxyError::Tls(format!("Failed to open key: {}", e)))?;

            let mut cert = std::io::BufReader::new(cert_file);
            let mut key = std::io::BufReader::new(key_file);

            let cert_chain = rustls_pemfile::certs(&mut cert)
                .map_err(|e| ProxyError::Tls(e.to_string()))?
                .into_iter()
                .map(Certificate)
                .collect();

            let key = rustls_pemfile::pkcs8_private_keys(&mut key)
                .map_err(|e| ProxyError::Tls(e.to_string()))?
                .first()
                .ok_or_else(|| ProxyError::Tls("No private key found".into()))?
                .clone();

            let config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(cert_chain, PrivateKey(key))
                .map_err(|e| ProxyError::Tls(e.to_string()))?;

            return Ok(Self {
                api_client: ApiClient::new(api_endpoint),
                tls_acceptor: Some(TlsAcceptor::from(Arc::new(config))), 
            });
        } else {
            log::info!("Successfully built Proxy Server, returning...");
            return Ok(Self {
                api_client: ApiClient::new(api_endpoint),
                tls_acceptor: None,
            })
        }
    }

    pub async fn start(&self) -> Result<(), ProxyError> {
        log::info!("Binding TCP Listeners");
        let http = TcpListener::bind("0.0.0.0:80").await?;
        log::info!("Binded http TCP Listener");
        let https = TcpListener::bind("0.0.0.0:443").await?;
        log::info!("Binded https TCP Listener");
        let ssh = TcpListener::bind("0.0.0.0:22").await?;
        log::info!("Binded ssh TCP Listener");


        log::info!(
            "Proxy server started:\n HTTP on port 80, HTTPS on port 443, SSH on port 22"
        );

        loop {
            tokio::select! {
                //TODO: store all threads in a FuturesUnordered and handle as they complete
                result = http.accept() => {
                    if let Ok((socket, _)) = result {
                        let api_client = self.api_client.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_http(socket, api_client).await {
                                log::error!("HTTP error: {}", e);
                            }
                        });
                    }
                }
                result = https.accept() => {
                    if let Ok((socket, _)) = result {
                        let api_client = self.api_client.clone();
                        let acceptor = self.tls_acceptor.clone();
                        if let Some(accp) = acceptor {
                            tokio::spawn(async move {
                                if let Err(e) = handle_https(socket, accp, api_client).await {
                                    log::error!("HTTPS error: {}", e);
                                }
                            });
                        }
                    }
                }
                result = ssh.accept() => {
                    if let Ok((socket, _)) = result {
                        let api_client = self.api_client.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ssh(socket, api_client).await {
                                log::error!("SSH error: {}", e);
                            }
                        });
                    }
                }
            }
        }
    }
}

// HTTP handling
async fn handle_http(mut client: TcpStream, api_client: ApiClient) -> Result<(), ProxyError> {
    let mut buffer = BytesMut::with_capacity(8192);
    
    // Read headers
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        client.read_buf(&mut buffer).await?;
        if buffer.is_empty() {
            return Err(ProxyError::Protocol("Connection closed while reading headers".into()));
        }
    }

    // Parse headers to get Host
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    let status = req.parse(&buffer)?;
    
    // Extract host
    let host = req.headers.iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .ok_or_else(|| ProxyError::Protocol("No host header".into()))?;

    // Get instance mapping
    let mapping = api_client.get_instance(host).await?;
    
    // Connect to backend
    let mut server = TcpStream::connect((mapping.private_ip, 80)).await?;

    // Forward request
    server.write_all(&buffer[..status.unwrap()]).await?;
    
    // Proxy traffic
    io::copy_bidirectional(&mut client, &mut server).await?;

    Ok(())
}

// HTTPS handling
async fn handle_https(
    client: TcpStream,
    acceptor: TlsAcceptor,
    api_client: ApiClient
) -> Result<(), ProxyError> {
    let mut tls_stream = acceptor.accept(client).await
        .map_err(|e| ProxyError::Tls(format!("Handshake failed: {}", e)))?;

    // Extract SNI hostname from connection
    let server_name = tls_stream
        .get_ref()
        .1  // Get ServerConnection from (ClientConnection, ServerConnection)
        .sni_hostname()
        .ok_or_else(|| ProxyError::Protocol("No SNI hostname".into()))?;

    // Get instance mapping
    let mapping = api_client.get_instance(server_name).await?;
    
    // Connect to backend
    let mut server = TcpStream::connect((mapping.private_ip, 443)).await?;

    // Proxy traffic
    io::copy_bidirectional(&mut tls_stream, &mut server).await?;

    Ok(())
}

// SSH handling
async fn handle_ssh(mut client: TcpStream, api_client: ApiClient) -> Result<(), ProxyError> {
    let mut buf = [0u8; 1024];
    
    // Read initial SSH handshake
    let n = client.read(&mut buf).await?;
    
    // Extract hostname from SSH connection data
    let data = std::str::from_utf8(&buf[..n])
        .map_err(|_| ProxyError::Protocol("Invalid SSH data".into()))?;
    
    // Very basic hostname extraction - would need proper SSH protocol parsing
    let hostname = data.split('@').nth(1)
        .and_then(|s| s.split(' ').next())
        .ok_or_else(|| ProxyError::Protocol("No hostname in SSH connection".into()))?;

    let mapping = api_client.get_instance(hostname).await?;
    
    // Connect to backend
    let mut server = TcpStream::connect((mapping.private_ip, 22)).await?;
    
    // Forward initial data
    server.write_all(&buf[..n]).await?;
    
    // Proxy remaining traffic
    io::copy_bidirectional(&mut client, &mut server).await?;

    Ok(())
}
