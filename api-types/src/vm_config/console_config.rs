// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::error::Error;
use std::path::PathBuf;

#[cfg(target_arch = "x86_64")]
use devices::debug_console;
use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pci_device_common_config::{PciDeviceCommonConfig, PciDeviceCommonConfigParseError};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ConsoleOutputMode {
    Off,
    Pty,
    Tty,
    File,
    Socket,
    Null,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CommonConsoleConfigParseError {
    /// Missing file value for console
    #[error("Path missing when using file console mode")]
    ConsoleFileMissing,
    /// Missing socket path for console
    #[error("Path missing when using socket console mode")]
    ConsoleSocketPathMissing,
    /// No mode given for console
    #[error("Error parsing --console: invalid console mode given")]
    ParseConsoleInvalidModeGiven,
}

/// Common configuration for plain console configs.
///
/// Independent of PCI or legacy devices.
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CommonConsoleConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    #[serde(default)]
    pub socket: Option<PathBuf>,
}

impl CommonConsoleConfig {
    const VALUELESS_OPTIONS: &[&str] = &["off", "pty", "tty", "null"];
    const VALUE_OPTIONS: &[&str] = &["file", "socket"];

    fn parse<T>(console: &str) -> Result<Self, T>
    where
        T: Error + From<CommonConsoleConfigParseError> + From<OptionParserError>,
    {
        let mut parser = OptionParser::new();
        parser
            .add_all_valueless(Self::VALUELESS_OPTIONS)
            .add_all(Self::VALUE_OPTIONS);
        parser.parse_subset(console)?;

        let mut file: Option<PathBuf> = None;
        let mut socket: Option<PathBuf> = None;
        let mut mode: ConsoleOutputMode = ConsoleOutputMode::Off;

        if parser.is_set("off") {
        } else if parser.is_set("pty") {
            mode = ConsoleOutputMode::Pty;
        } else if parser.is_set("tty") {
            mode = ConsoleOutputMode::Tty;
        } else if parser.is_set("null") {
            mode = ConsoleOutputMode::Null;
        } else if parser.is_set("file") {
            mode = ConsoleOutputMode::File;
            file = Some(PathBuf::from(
                parser
                    .get("file")
                    .ok_or(CommonConsoleConfigParseError::ConsoleFileMissing)?,
            ));
        } else if parser.is_set("socket") {
            mode = ConsoleOutputMode::Socket;
            socket =
                Some(PathBuf::from(parser.get("socket").ok_or(
                    CommonConsoleConfigParseError::ConsoleSocketPathMissing,
                )?));
        } else {
            Err(CommonConsoleConfigParseError::ParseConsoleInvalidModeGiven)?;
        }

        Ok(Self { mode, file, socket })
    }
}

/// Configuration for a legacy serial console device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SerialConfig {
    #[serde(flatten)]
    pub common: CommonConsoleConfig,
}

impl SerialConfig {
    pub const SYNTAX: &str = "Control serial port: \"off|null|pty|tty|file=<path>|socket=<path>\"";

    pub fn parse(serial: &str) -> Result<Self, SerialConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add_all_valueless(CommonConsoleConfig::VALUELESS_OPTIONS)
            .add_all(CommonConsoleConfig::VALUE_OPTIONS);
        parser
            .parse(serial)
            .map_err(SerialConfigParseError::Parse)?;

        let common = CommonConsoleConfig::parse::<SerialConfigParseError>(serial)?;
        Ok(Self { common })
    }
}

#[derive(Debug, Error)]
pub enum SerialConfigParseError {
    #[error("Failed to parse serial configuration")]
    Parse(#[from] OptionParserError),
    #[error("Failed to parse common console configuration")]
    CommonConsole(#[from] CommonConsoleConfigParseError),
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            common: CommonConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Null,
                socket: None,
            },
        }
    }
}

/// Configuration for a virtio-console device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConsoleConfig {
    #[serde(flatten)]
    pub common: CommonConsoleConfig,
    #[serde(default, flatten)]
    pub pci_common: PciDeviceCommonConfig,
}

impl ConsoleConfig {
    pub const SYNTAX: &str = "Control (virtio) console: \"off|null|pty|tty|file=<path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>,pci_device_id=<pci_slot>\"";

    pub fn parse(console: &str) -> Result<Self, ConsoleConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add_all_valueless(CommonConsoleConfig::VALUELESS_OPTIONS)
            .add_all(CommonConsoleConfig::VALUE_OPTIONS)
            .add_all(PciDeviceCommonConfig::OPTIONS_IOMMU);
        parser
            .parse(console)
            .map_err(ConsoleConfigParseError::Parse)?;

        let common = CommonConsoleConfig::parse::<ConsoleConfigParseError>(console)?;
        let pci_common = PciDeviceCommonConfig::parse(console)
            .map_err(ConsoleConfigParseError::PciDeviceCommon)?;

        Ok(Self { common, pci_common })
    }
}

#[derive(Debug, Error)]
pub enum ConsoleConfigParseError {
    #[error("Failed to parse console configuration")]
    Parse(#[from] OptionParserError),
    #[error("Failed to parse common console configuration")]
    CommonConsole(#[from] CommonConsoleConfigParseError),
    #[error("Failed to parse PCI device configuration")]
    PciDeviceCommon(#[source] PciDeviceCommonConfigParseError),
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            common: CommonConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                socket: None,
            },
            pci_common: PciDeviceCommonConfig::default(),
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DebugConsoleConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    /// Optionally dedicated I/O-port, if the default port should not be used.
    pub iobase: Option<u16>,
}

#[cfg(target_arch = "x86_64")]
impl Default for DebugConsoleConfig {
    fn default() -> Self {
        Self {
            file: None,
            mode: ConsoleOutputMode::Off,
            iobase: Some(debug_console::DEFAULT_PORT as u16),
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Error)]
pub enum DebugConsoleConfigParseError {
    #[error("Failed to parse debug console configuration")]
    Parse(#[source] OptionParserError),
    #[error("Debug console file path is missing")]
    FileMissing,
    #[error("Debug console output mode is missing or invalid")]
    InvalidMode,
    #[error("Invalid debug console I/O port: {0}")]
    InvalidIoPortHex(String),
}

#[cfg(target_arch = "x86_64")]
impl DebugConsoleConfig {
    pub fn parse(debug_console_ops: &str) -> Result<Self, DebugConsoleConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add_valueless("off")
            .add_valueless("pty")
            .add_valueless("tty")
            .add_valueless("null")
            .add("file")
            .add("iobase");
        parser
            .parse(debug_console_ops)
            .map_err(DebugConsoleConfigParseError::Parse)?;

        let mut file: Option<PathBuf> = None;
        let mut iobase: Option<u16> = None;
        let mut mode: ConsoleOutputMode = ConsoleOutputMode::Off;

        if parser.is_set("off") {
        } else if parser.is_set("pty") {
            mode = ConsoleOutputMode::Pty;
        } else if parser.is_set("tty") {
            mode = ConsoleOutputMode::Tty;
        } else if parser.is_set("null") {
            mode = ConsoleOutputMode::Null;
        } else if parser.is_set("file") {
            mode = ConsoleOutputMode::File;
            file = Some(PathBuf::from(
                parser
                    .get("file")
                    .ok_or(DebugConsoleConfigParseError::FileMissing)?,
            ));
        } else {
            return Err(DebugConsoleConfigParseError::InvalidMode);
        }

        if parser.is_set("iobase")
            && let Some(iobase_opt) = parser.get("iobase")
        {
            if !iobase_opt.starts_with("0x") {
                return Err(DebugConsoleConfigParseError::InvalidIoPortHex(
                    iobase_opt.to_owned(),
                ));
            }
            iobase = Some(u16::from_str_radix(&iobase_opt[2..], 16).map_err(|_| {
                DebugConsoleConfigParseError::InvalidIoPortHex(iobase_opt.to_owned())
            })?);
        }

        Ok(Self { file, mode, iobase })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        CommonConsoleConfig, ConsoleConfig, ConsoleConfigParseError, ConsoleOutputMode,
        PciDeviceCommonConfig,
    };

    #[test]
    fn test_console_parsing() -> Result<(), ConsoleConfigParseError> {
        let console_config = |mode, file, socket, iommu| ConsoleConfig {
            common: CommonConsoleConfig { file, mode, socket },
            pci_common: PciDeviceCommonConfig {
                iommu,
                ..Default::default()
            },
        };

        ConsoleConfig::parse("").unwrap_err();
        ConsoleConfig::parse("badmode").unwrap_err();
        assert_eq!(
            ConsoleConfig::parse("off")?,
            console_config(ConsoleOutputMode::Off, None, None, false)
        );
        assert_eq!(
            ConsoleConfig::parse("pty")?,
            console_config(ConsoleOutputMode::Pty, None, None, false)
        );
        assert_eq!(
            ConsoleConfig::parse("tty")?,
            console_config(ConsoleOutputMode::Tty, None, None, false)
        );
        assert_eq!(
            ConsoleConfig::parse("null")?,
            console_config(ConsoleOutputMode::Null, None, None, false)
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console")?,
            console_config(
                ConsoleOutputMode::File,
                Some(PathBuf::from("/tmp/console")),
                None,
                false
            )
        );
        assert_eq!(
            ConsoleConfig::parse("null,iommu=on")?,
            console_config(ConsoleOutputMode::Null, None, None, true)
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console,iommu=on")?,
            console_config(
                ConsoleOutputMode::File,
                Some(PathBuf::from("/tmp/console")),
                None,
                true
            )
        );
        assert_eq!(
            ConsoleConfig::parse("socket=/tmp/serial.sock,iommu=on")?,
            console_config(
                ConsoleOutputMode::Socket,
                None,
                Some(PathBuf::from("/tmp/serial.sock")),
                true
            )
        );
        Ok(())
    }
}
