// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct TpmConfig {
    pub socket: PathBuf,
}

#[derive(Debug, Error)]
pub enum TpmConfigParseError {
    #[error("Failed to parse TPM configuration")]
    Parse(#[source] OptionParserError),
    #[error("TPM socket path is missing")]
    SocketMissing,
}

impl TpmConfig {
    pub const SYNTAX: &'static str = "TPM device \
        \"(UNIX Domain Socket from swtpm) socket=</path/to/a/socket>\"";

    pub fn parse(tpm: &str) -> Result<Self, TpmConfigParseError> {
        let mut parser = OptionParser::new();
        parser.add("socket");
        parser.parse(tpm).map_err(TpmConfigParseError::Parse)?;
        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(TpmConfigParseError::SocketMissing)?;
        Ok(TpmConfig { socket })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{TpmConfig, TpmConfigParseError};

    #[test]
    fn test_tpm_parsing() -> Result<(), TpmConfigParseError> {
        // path is required
        TpmConfig::parse("").unwrap_err();
        assert_eq!(
            TpmConfig::parse("socket=/var/run/tpm.sock")?,
            TpmConfig {
                socket: PathBuf::from("/var/run/tpm.sock"),
            }
        );
        Ok(())
    }
}
