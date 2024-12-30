use std::path::PathBuf;
use clap::{Parser, Subcommand};
use crate::error::VmmError;
use super::{CliMode, ServiceOptions, ConfigOptions};

#[derive(Parser, Debug)]
#[command(name = "vmm-service", about = "Formation VMM Service")]
pub struct CliArgs {
    /// Enable debug logging
    #[arg(short, long)]
    pub debug: bool,

    /// Command to execute
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Run the VMM service
    #[command(name = "run")]
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Message broker subscriber address
        #[arg(long, default_value = "127.0.0.1:5556")]
        sub_addr: String,

        /// Message broker Publish Address
        #[arg(long, default_value = "127.0.0.1:5555")]
        pub_addr: String,

        /// Run configuration wizard before starting service
        #[arg(short, long)]
        wizard: bool,
    },

    /// Configure the VMM Service
    #[command(name = "config")]
    Configure {
        /// Path to save configuration
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Run in non-interactive_mode
        #[arg(long)]
        non_interactive: bool,

        /// Start service after configuration
        #[arg(short, long)]
        start: bool,

        /// Subscriber address (when starting service)
        #[arg(long, default_value = "127.0.0.1:5556")]
        sub_addr: String,

        /// Publisher address (when starting service)
        #[arg(long, default_value = "127.0.0.1:5555")]
        pub_addr: String,
    },

    /// Show service status
    #[command(name = "status")]
    Status,
}

impl CliArgs {
    /// Parse arguments into the appropriate CLI Mode
    pub fn into_mode(self) -> Result<CliMode, VmmError> {
        match self.command {
            CliCommand::Run { config, sub_addr, pub_addr, .. } => {
                Ok(CliMode::Service(ServiceOptions {
                    config_path: config.map(|p| p.to_string_lossy().to_string()),
                    subscriber_addr: sub_addr,
                    publisher_addr: pub_addr
                }))
            }
            CliCommand::Configure { output, non_interactive, .. } => {
                Ok(CliMode::Configure(
                    ConfigOptions { 
                        output_path: output.map(|p| p.to_string_lossy().to_string()), 
                        interactive: !non_interactive 
                    }
                ))
            }
            CliCommand::Status => Ok(CliMode::Status)
        }
    }
}

/// Options that can be provided via CLI or Config File
#[derive(Debug, Clone)]
pub struct CliOpts {
    pub config_path: Option<String>,
    pub subscriber_addr: String,
    pub publisher_addr: String,
    pub debug: bool,
}

impl Default for CliOpts {
    fn default() -> Self {
        Self {
            config_path: None,
            publisher_addr: "127.0.0.1:5555".to_string(),
            subscriber_addr: "127.0.0.1:5556".to_string(),
            debug: false
        }
    }
}
