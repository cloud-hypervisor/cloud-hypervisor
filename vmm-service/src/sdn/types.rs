//! Core types and interfaces for the Formation SDN implementation
//! This module defines the fundamental building blocks that the rest of the
//! SDN system uses
use thiserror::Error;

/// Errors that can occur in the SDN operations
#[derive(Error, Debug)]
pub enum  NetworkError {
    #[error("Flow rule error: {0}")]
    FlowError(String),
    #[error("Virtual host error: {0}")]
    VirtualHostError(String),
    #[error("Network namespace error: {0}")]
    NamespaceError(String),
    #[error("DNS error: {0}")]
    DnsError(String),
    #[error("Invali configuration error: {0}")]
    ConfigError(String),
    #[error("System error: {0}")]
    SystemError(String),
    #[error("Netlink error: {0}")]
    Netlink(String),
    #[error("Interface error: {0}")]
    Interface(String),
    #[error("Address error: {0}")]
    Address(String),
    #[error("No IPs available within range")]
    NoAvailableIps,
    #[error("Error allocating MAC address to VM: {0}")]
    MacAllocationError(String),
    #[error("MAC address is invalid: {0}")]
    InvalidMacAddress(String)
}
