//! Command Line Interface for the VMM Service
//!
//! This module provides the CLI functionality for both the service and configuration
//! management. It separates concerns between argument parsing, command processing,
//! and output formatting

mod args;

pub use args::*;

/// CLI operation modes to distinguish between service and config operations
#[derive(Debug, Clone)]
pub enum CliMode {
    /// Run the VMM Service
    Service(ServiceOptions),
    /// Run the config wizard
    Configure(ConfigOptions),
    /// Show service status
    Status
}

/// Options specific to running the service
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    /// Path to config file
    pub config_path: Option<String>,
    /// Subscriber address for message broker
    pub subscriber_addr: String,
    /// Publisher address for message broker 
    pub publisher_addr: String
}

/// Options specific to configuration operations
#[derive(Debug, Clone)]
pub struct ConfigOptions {
    /// Path to save the generated config
    pub output_path: Option<String>,
    /// Whether to use interactive mode
    pub interactive: bool,
}
